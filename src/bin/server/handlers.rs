use std::io::{Read, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use rand::Rng;
use serde_json::{json, Value};
use sha2::Digest;
use ssh_key::public::PublicKey;
use ssh_key::HashAlg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};

use wirewrench::auth as wauth;
use wirewrench::target::protocol;
use wirewrench::{Command, Response};

use super::auth as srv_auth;
use super::frame;
use super::lock::{LockGuard, LockState, SessionLock};
use super::session::{
    CtrlQueue, ManagedSession, SessionManager, TUNNEL_EVENT_QUEUE, TunnelEntry, TunnelEvent, Tunnels,
    overflow_reason,
};
use super::shells;

// ── Control connection (Unix socket or TCP) ────────────────────────────────

/// A control connection from a `ww` client.  Normally the Unix socket at
/// `DEFAULT_SOCKET`; when `ww-server --control-port` is used, clients may also
/// connect over TCP (see `ww --host` / `ww --port`).
pub enum ControlStream {
    Unix(std::os::unix::net::UnixStream),
    Tcp(std::net::TcpStream),
}

impl Read for ControlStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ControlStream::Unix(s) => s.read(buf),
            ControlStream::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for ControlStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ControlStream::Unix(s) => s.write(buf),
            ControlStream::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ControlStream::Unix(s) => s.flush(),
            ControlStream::Tcp(s) => s.flush(),
        }
    }
}

impl ControlStream {
    pub fn try_clone(&self) -> std::io::Result<ControlStream> {
        match self {
            ControlStream::Unix(s) => s.try_clone().map(ControlStream::Unix),
            ControlStream::Tcp(s) => s.try_clone().map(ControlStream::Tcp),
        }
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            ControlStream::Unix(s) => s.set_read_timeout(dur),
            ControlStream::Tcp(s) => s.set_read_timeout(dur),
        }
    }

    pub fn set_nonblocking(&self, nb: bool) -> std::io::Result<()> {
        match self {
            ControlStream::Unix(s) => s.set_nonblocking(nb),
            ControlStream::Tcp(s) => s.set_nonblocking(nb),
        }
    }

    /// Convert a blocking control stream into a tokio async stream (used by
    /// the tunnel relay).
    pub fn into_async(self) -> std::io::Result<AsyncControl> {
        self.set_nonblocking(true)?;
        Ok(match self {
            ControlStream::Unix(s) => AsyncControl::Unix(tokio::net::UnixStream::from_std(s)?),
            ControlStream::Tcp(s) => AsyncControl::Tcp(tokio::net::TcpStream::from_std(s)?),
        })
    }
}

/// An async-wrapped control connection.
pub enum AsyncControl {
    Unix(tokio::net::UnixStream),
    Tcp(tokio::net::TcpStream),
}

impl tokio::io::AsyncRead for AsyncControl {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            AsyncControl::Unix(s) => Pin::new(s).poll_read(cx, buf),
            AsyncControl::Tcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for AsyncControl {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            AsyncControl::Unix(s) => Pin::new(s).poll_write(cx, buf),
            AsyncControl::Tcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            AsyncControl::Unix(s) => Pin::new(s).poll_flush(cx),
            AsyncControl::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            AsyncControl::Unix(s) => Pin::new(s).poll_shutdown(cx),
            AsyncControl::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ── Shared types for file-transfer commands ────────────────────────────────

#[derive(serde::Deserialize)]
pub struct PushCommand { pub path: String, pub size: u64, #[serde(default = "def_timeout")] pub timeout: f64 }

#[derive(serde::Deserialize)]
pub struct PullCommand { pub path: String, #[serde(default = "def_timeout")] pub timeout: f64 }

fn def_timeout() -> f64 { 30.0 }

struct SmartTransfer {
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    ctrl_queue: CtrlQueue,
    ift: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
}

/// Extract the smart-session fields for a file transfer, checking alive and
/// acquiring the `in_file_transfer` flag.  Sends an error response on failure
/// and returns `None`.
///
/// When `tcp_msg` is `Some`, a dumb TCP shell gets that error instead of the
/// generic "Shell not found" message.
async fn prepare_smart_transfer(
    id: u32,
    manager: &Arc<Mutex<SessionManager>>,
    stream: &mut ControlStream,
    tcp_msg: Option<&str>,
) -> Result<Option<SmartTransfer>> {
    let mut t: Option<SmartTransfer> = None;
    let mut err: Option<&str> = None;
    {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Smart(s)) if s.alive.load(Ordering::SeqCst) => {
                t = Some(SmartTransfer {
                    writer: Arc::clone(&s.writer),
                    ctrl_queue: Arc::clone(&s.ctrl_queue),
                    ift: Arc::clone(&s.in_file_transfer),
                    alive: Arc::clone(&s.alive),
                });
            }
            Some(ManagedSession::Tcp(_, _)) if tcp_msg.is_some() => {
                err = tcp_msg;
            }
            _ => {
                err = Some("Shell not found");
            }
        }
    } // lock dropped

    if let Some(msg) = err {
        respond_error(stream, msg).await;
        return Ok(None);
    }

    let t = t.unwrap(); // safe: err is None so t is Some
    if !t.alive.load(Ordering::SeqCst) {
        respond_error(stream, "Target dead").await;
        return Ok(None);
    }
    if t.ift.load(Ordering::SeqCst)
        || t.ift
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        respond_error(stream, "File transfer already in progress").await;
        return Ok(None);
    }
    Ok(Some(t))
}

// ── JSON helpers ───────────────────────────────────────────────────────────

/// Write a serializable value as JSON + newline to a control stream.
async fn respond_json(stream: &mut ControlStream, val: &impl serde::Serialize) -> Result<()> {
    let j = serde_json::to_string(val)? + "\n";
    stream.write_all(j.as_bytes())?;
    Ok(())
}

/// Write a success response — `{status:"ok", output: msg}`.
async fn respond_ok(stream: &mut ControlStream, msg: impl Into<String>) {
    let _ = respond_json(stream, &Response::with_output(msg.into())).await;
}

/// Write an error response — `{status:"error", message: msg}`.
async fn respond_error(stream: &mut ControlStream, msg: impl Into<String>) {
    let _ = respond_json(stream, &Response::error(msg.into())).await;
}

// ── Authentication (TCP control port only) ────────────────────────────────

/// Write a JSON value as a line to a control stream (blocking).
fn write_json_line(stream: &mut ControlStream, val: &impl serde::Serialize) -> Result<()> {
    let j = serde_json::to_string(val)? + "\n";
    stream.write_all(j.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// Read one `\n`-terminated line from a blocking control stream,
/// **byte-at-a-time**, so no bytes belonging to the *next* message (or to an
/// early tunnel payload) can be swallowed by a `BufReader`.  Because it never
/// over-reads, there is no leftover buffer to hand on.
fn read_line_raw(stream: &mut ControlStream) -> Result<Vec<u8>> {
    const MAX_LINE: usize = 64 * 1024;
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if stream.read(&mut byte)? == 0 {
            anyhow::bail!("control connection closed");
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        anyhow::ensure!(line.len() <= MAX_LINE, "control line too long");
    }
    Ok(line)
}

/// Run the SSH-style auth handshake on a TCP control connection.  Returns
/// `true` if the client authenticated, `false` if the connection should be
/// closed (a failure response has already been sent).
fn authenticate(
    stream: &mut ControlStream,
    keys_path: &Path,
    identity_out: &mut Option<String>,
) -> Result<bool> {
    // Per-connection key load (fail closed): rotation applies immediately.
    let keys = match srv_auth::load_authorized_keys(keys_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[!] Control-port auth keys unavailable, rejecting connection: {e}");
            let _ = write_json_line(stream, &json!({"status":"error","message":"authentication unavailable"}));
            return Ok(false);
        }
    };

    // Relax the read timeout for the auth phase.
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;

    let mut challenge = [0u8; wauth::CHALLENGE_LEN];
    rand::rng().fill_bytes(&mut challenge);
    let challenge_b64 = wauth::b64_encode(&challenge);

    for _ in 0..wauth::MAX_OFFERS {
        let line = read_line_raw(stream)?;
        let msg: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(_) => {
                let _ = write_json_line(stream, &json!({"status":"error","message":"authentication required"}));
                return Ok(false);
            }
        };

        match msg["type"].as_str() {
            Some("auth_offer") => {
                let Some(key_str) = msg["key"].as_str() else {
                    let _ = write_json_line(stream, &json!({"type":"auth_reject"}));
                    continue;
                };
                let offered = match PublicKey::from_openssh(key_str) {
                    Ok(p) => p,
                    Err(_) => {
                        let _ = write_json_line(stream, &json!({"type":"auth_reject"}));
                        continue;
                    }
                };
                let Some(authorized) = keys.iter().find(|k| *k == &offered) else {
                    let _ = write_json_line(stream, &json!({"type":"auth_reject"}));
                    continue;
                };

                let _ = write_json_line(stream, &json!({"type":"auth_challenge","challenge": challenge_b64}));

                let line = read_line_raw(stream)?;
                let sig_msg: Value = serde_json::from_slice(&line)?;
                if sig_msg["type"] != "auth_sign" {
                    let _ = write_json_line(stream, &json!({"status":"error","message":"authentication failed"}));
                    return Ok(false);
                }
                let Some(sig_b64) = sig_msg["signature"].as_str() else {
                    let _ = write_json_line(stream, &json!({"status":"error","message":"authentication failed"}));
                    return Ok(false);
                };

                let key_blob = offered.to_bytes()?;
                let payload = wauth::signed_payload(&challenge, &key_blob);

                if srv_auth::verify_signature(authorized, &payload, sig_b64) {
                    let fingerprint = authorized.fingerprint(HashAlg::Sha256);
                    eprintln!("[+] Control-port auth ok: {fingerprint} (TCP)");
                    *identity_out = Some(format!("{fingerprint} (key)"));
                    let _ = write_json_line(stream, &json!({"status":"ok"}));
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    return Ok(true);
                }

                eprintln!("[-] Control-port auth failed: bad signature (TCP)");
                let _ = write_json_line(stream, &json!({"status":"error","message":"authentication failed"}));
                return Ok(false);
            }
            _ => {
                // Not an auth message (e.g. an old client sending a command).
                let _ = write_json_line(stream, &json!({"status":"error","message":"authentication required"}));
                return Ok(false);
            }
        }
    }

    let _ = write_json_line(stream, &json!({"status":"error","message":"too many authentication attempts"}));
    Ok(false)
}

// ── Control connection identity ────────────────────────────────────────────

/// Identity and lease policy of one control connection.  Session locks are
/// owned by this connection id, so a lock is released as soon as the handler
/// returns — which is the moment the client's socket closes, even if the
/// client was killed.  (See `super::lock`.)
#[derive(Clone)]
pub struct ConnCtx {
    pub id: u64,
    /// `"unix"` or `"tcp"`.
    pub transport: &'static str,
    pub authenticated: bool,
    /// Human-readable holder identity (`ben (uid=1000)`, a key fingerprint, …).
    pub owner: String,
    /// Lease TTL.  `None` for Unix sockets, where close is reliable and a
    /// half-open connection is impossible.
    pub lease: Option<Duration>,
}

impl ConnCtx {
    #[must_use]
    pub fn json(&self) -> Value {
        json!({
            "transport": self.transport,
            "authenticated": self.authenticated,
            "identity": self.owner,
            "lease_secs": self.lease.map(|d| d.as_secs()),
        })
    }
}

/// `list` view of a lock that refused a request.
fn lock_json(state: &LockState, conn: u64) -> Value {
    json!({
        "owner": state.owner,
        "mine": state.conn == conn,
        "held_for": state.held_for(),
        "expires_in": state.expires_in(),
    })
}

/// Acquire the session lock for `conn`, honouring `--wait` and `--force`.
///
/// On contention this writes the `busy` response itself and returns `Ok(None)`.
/// The returned guard releases the lock when dropped, so the caller must keep
/// it alive for as long as the session is in use.
async fn acquire_or_refuse(
    lock: &Arc<SessionLock>,
    conn: &ConnCtx,
    cmd: &Command,
    stream: &mut ControlStream,
    ttl: Option<Duration>,
) -> Result<Option<LockGuard>> {
    if cmd.force {
        return Ok(Some(lock.force_acquire(conn.id, &conn.owner, ttl)));
    }
    match lock.acquire(conn.id, &conn.owner, ttl, cmd.wait.unwrap_or(0.0)).await {
        Ok(guard) => Ok(Some(guard)),
        Err(held) => {
            let msg = format!(
                "session is locked by {} for {:.0}s (use --force to take it over, or --wait SECS)",
                held.owner,
                held.held_for()
            );
            respond_json(stream, &Response::busy(msg, lock_json(&held, conn.id))).await?;
            Ok(None)
        }
    }
}

/// Resolve a uid to a user name via `/etc/passwd` (no extra dependency).
fn uid_name(uid: u32) -> Option<String> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let mut fields = line.split(':');
        let (name, _, id) = (fields.next(), fields.next(), fields.next());
        if let (Some(name), Some(id)) = (name, id)
            && id.parse::<u32>() == Ok(uid)
            && !name.is_empty()
        {
            return Some(name.to_string());
        }
    }
    None
}

// ── Handle a single control client ─────────────────────────────────────────

/// Handle a `ww` client connected over the Unix control socket (never authenticated).
pub async fn handle_control_unix(
    stream: tokio::net::UnixStream,
    manager: Arc<Mutex<SessionManager>>,
    conn_id: u64,
    lease: Option<Duration>,
) -> Result<()> {
    let owner = match stream.peer_cred() {
        Ok(cred) => {
            let uid = cred.uid();
            match uid_name(uid) {
                Some(name) => format!("{name} (uid={uid})"),
                None => format!("uid={uid}"),
            }
        }
        Err(_) => "local unix socket".to_string(),
    };
    let conn = ConnCtx { id: conn_id, transport: "unix", authenticated: false, owner, lease };
    let stream = stream.into_std()?;
    handle_control_conn(ControlStream::Unix(stream), manager, None, &conn).await
}

/// Handle a `ww` client connected over the optional TCP control port
/// (`ww-server --control-port`).
pub async fn handle_control_tcp(
    stream: tokio::net::TcpStream,
    manager: Arc<Mutex<SessionManager>>,
    auth_keys_path: Option<Arc<std::path::PathBuf>>,
    conn_id: u64,
    lease: Option<Duration>,
) -> Result<()> {
    let owner = stream.peer_addr().map_or_else(|_| "tcp peer".to_string(), |a| a.to_string());
    let conn = ConnCtx { id: conn_id, transport: "tcp", authenticated: false, owner, lease };
    let stream = stream.into_std()?;
    let keys = auth_keys_path.as_deref().map(std::path::PathBuf::as_path);
    handle_control_conn(ControlStream::Tcp(stream), manager, keys, &conn).await
}

async fn handle_control_conn(
    mut stream: ControlStream,
    manager: Arc<Mutex<SessionManager>>,
    auth_keys_path: Option<&Path>,
    conn: &ConnCtx,
) -> Result<()> {
    let mut conn = conn.clone();
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    if let Some(path) = auth_keys_path {
        // `authenticate` performs blocking std I/O for up to `MAX_OFFERS`
        // reads; a blocking region keeps it off the async worker threads (it
        // requires the multi-threaded runtime, see main.rs).
        let mut identity = None;
        if !tokio::task::block_in_place(|| authenticate(&mut stream, path, &mut identity))? {
            return Ok(());
        }
        if let Some(id) = identity {
            conn.authenticated = true;
            conn.owner = id;
        }
    }

    // Read the command line.  With no auth configured, tolerate a stray
    // `auth_offer` from a client that has a key, and tell it auth isn't needed.
    // The read is byte-at-a-time and blocking, so it runs in a blocking region
    // too — otherwise a peer dribbling bytes could starve the runtime.
    let line = loop {
        let line = tokio::task::block_in_place(|| read_line_raw(&mut stream))?;
        if auth_keys_path.is_none()
            && let Ok(v) = serde_json::from_slice::<Value>(&line)
            && v["type"] == "auth_offer"
        {
            let _ = write_json_line(&mut stream, &json!({"type":"auth_not_required"}));
            continue;
        }
        break line;
    };

    let cmd: Command = serde_json::from_slice(&line)?;
    let action = cmd.action.clone();

    match action.as_str() {
        "list" => {
            let shells = {
                let mg = manager.lock().await;
                json!(mg.list(conn.id))
            };
            let resp = Response::with_shells(shells).with_connection(conn.json());
            respond_json(&mut stream, &resp).await?;
        }
        "send" => send_handler(cmd, &manager, &mut stream, &conn).await?,
        "read" => read_handler(cmd, &manager, &mut stream, &conn).await?,
        "push" => push_handler(cmd, &manager, &mut stream).await?,
        "pull" => pull_handler(cmd, &manager, &mut stream).await?,
        "targ_cancel" => targ_cancel_handler(cmd, &manager).await?,
        "close" => {
            let mut mg = manager.lock().await;
            mg.remove(cmd.id.unwrap_or(0));
            respond_json(&mut stream, &Response::ok()).await?;
        }
        "interact" => interact_handler(cmd, &manager, &mut stream, &conn).await?,
        "connect" => return connect_handler(cmd, &manager, stream).await,
        _ => respond_json(&mut stream, &Response::error(format!("Unknown action: {action}"))).await?,
    }
    Ok(())
}

// ── Send handler ────────────────────────────────────────────────────────────

async fn send_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
    stream: &mut ControlStream,
    conn: &ConnCtx,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let command = cmd.data.as_deref().unwrap_or_default().trim().to_string();
    let timeout = cmd.timeout.unwrap_or(3.0);

    // Single lock — look up session and dispatch
    let mg = manager.lock().await;
    match mg.sessions.get(&id) {
        Some(ManagedSession::Smart(s)) => {
            if !s.alive.load(Ordering::SeqCst) {
                return respond_json(stream, &Response::error("Target dead")).await;
            }
            if s.in_file_transfer.load(Ordering::SeqCst) {
                return respond_json(stream, &Response::error("Session busy with file transfer")).await;
            }

            // FRAME_CMD: per-command sh -c, stateless, bounded output with exit code.
            let seq = s.next_cmd_seq.fetch_add(1, Ordering::SeqCst);
            let (tx, rx) = tokio::sync::oneshot::channel();
            {
                let mut map = s.pending_cmds.lock().await;
                map.insert(seq, tx);
            }

            let req = protocol::CmdRequest { seq, cmd: command };
            {
                let mut w = s.writer.lock().await;
                frame::write_json_frame(&mut *w, protocol::FRAME_CMD, &req).await?;
            }
            drop(mg);

            // For Smart sessions, ww-target signals command completion deterministically.
            // timeout <= 0 means "wait as long as it takes"; otherwise cap at the given value.
            async fn await_result(
                rx: tokio::sync::oneshot::Receiver<protocol::CmdResult>,
                timeout: f64,
            ) -> std::result::Result<protocol::CmdResult, &'static str> {
                if timeout > 0.0 {
                    match tokio::time::timeout(std::time::Duration::from_secs_f64(timeout), rx).await {
                        Ok(Ok(r)) => Ok(r),
                        Ok(Err(_)) => Err("Internal error: response channel closed"),
                        Err(_) => Err("Command timed out"),
                    }
                } else {
                    rx.await.map_err(|_| "Internal error: response channel closed")
                }
            }

            match await_result(rx, timeout).await {
                Ok(result) => {
                    let resp = Response::with_output_exit(result.stdout, result.exit_code, result.stderr);
                    respond_json(stream, &resp).await
                }
                Err(msg) => respond_json(stream, &Response::error(msg)).await,
            }
        }
        Some(ManagedSession::Tcp(s, b)) => {
            let writer = Arc::clone(&s.writer);
            let buf = Arc::clone(b);
            let lock = Arc::clone(&s.lock);
            drop(mg);

            // Dumb shells are unframed: commands are written raw and output is
            // read from one shared buffer, so only one client may use the
            // session at a time.  The guard lives until this handler returns —
            // i.e. until the client's connection closes, however that happens.
            let tcp_timeout = if timeout > 0.0 { timeout } else { 3.0 };
            // Keep the lease valid for at least as long as this command may run,
            // so the reaper cannot free the session mid-command over TCP.
            let ttl = conn.lease.map(|d| d.max(Duration::from_secs_f64(tcp_timeout.max(0.0) + 60.0)));
            let guard = match acquire_or_refuse(&lock, conn, &cmd, stream, ttl).await? {
                Some(g) => g,
                None => return Ok(()),
            };

            // Discard anything a previous holder left in the shared buffer, so
            // its output cannot be mistaken for ours.
            buf.lock().await.clear();

            let to_send = format!("{command}\n");
            {
                let mut w = writer.lock().await;
                w.write_all(to_send.as_bytes()).await?;
            }
            let resp = respond_read_locked(&buf, tcp_timeout, &guard).await;
            drop(guard);
            respond_json(stream, &resp).await
        }
        None => respond_json(stream, &Response::error("Shell not found")).await,
    }
}

// ── Read handler ────────────────────────────────────────────────────────────

async fn read_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
    stream: &mut ControlStream,
    conn: &ConnCtx,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let timeout = cmd.timeout.unwrap_or(0.2);

    let found = {
        let mg = manager.lock().await;
        mg.sessions.get(&id).map(|s| match s {
            ManagedSession::Smart(sm) => (Arc::clone(&sm.shell_buf), None),
            ManagedSession::Tcp(_, b) => (Arc::clone(b), Some(ManagedSession::lock(s))),
        })
    };

    match found {
        Some((buf, Some(lock))) => {
            let guard = match acquire_or_refuse(&lock, conn, &cmd, stream, conn.lease).await? {
                Some(g) => g,
                None => return Ok(()),
            };
            let resp = respond_read_locked(&buf, timeout, &guard).await;
            drop(guard);
            respond_json(stream, &resp).await
        }
        Some((buf, None)) => {
            let output = shells::read_from_buf(&buf, timeout).await;
            respond_json(stream, &Response::with_output(output)).await
        }
        None => respond_json(stream, &Response::error("Shell not found")).await,
    }
}

// ── Push handler (smart only) ───────────────────────────────────────────────

async fn push_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
    stream: &mut ControlStream,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let pc: PushCommand = match serde_json::from_str(&cmd.data.unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => {
            respond_error(stream, format!("Invalid push: {e}")).await;
            return Ok(());
        }
    };

    let Some(transfer) = prepare_smart_transfer(id, manager, stream, Some("Push only supported on smart (ww-target) sessions")).await? else { return Ok(()) };
    let SmartTransfer { writer, ctrl_queue, ift, alive: _ } = transfer;

    // Read file data from the control socket.  The declared size is
    // peer-supplied, so it is capped before anything is allocated or read.
    if pc.size > MAX_PUSH_SIZE {
        ift.store(false, Ordering::SeqCst);
        respond_error(
            stream,
            format!("Push rejected: {} bytes exceeds the {MAX_PUSH_SIZE}-byte limit", pc.size),
        )
        .await;
        return Ok(());
    }
    let size: usize = pc.size.try_into()?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    // These are blocking std reads on an async worker thread (and they can take
    // as long as the uploader needs), so they run in a blocking region.
    let read_result = tokio::task::block_in_place(|| -> std::io::Result<Option<Vec<u8>>> {
        let mut data = Vec::with_capacity(size.min(16 * 1024 * 1024));
        while data.len() < size {
            let want = (size - data.len()).min(65536);
            let mut chunk = vec![0_u8; want];
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                return Ok(None);
            }
            data.extend_from_slice(&chunk[..n]);
        }
        Ok(Some(data))
    });
    let data = match read_result {
        Ok(Some(data)) => data,
        Ok(None) => {
            ift.store(false, Ordering::SeqCst);
            respond_error(stream, "Connection closed during push").await;
            return Ok(());
        }
        Err(e) => {
            ift.store(false, Ordering::SeqCst);
            respond_error(stream, format!("Push read failed: {e}")).await;
            return Ok(());
        }
    };

    let srv_hash = {
        let mut h = sha2::Sha256::new();
        h.update(&data);
        frame::hex_encode(&h.finalize())
    };

    // Send push_start
    let ps = protocol::PushStart::new(pc.path.clone(), pc.size, srv_hash.clone());
    {
        let mut w = writer.lock().await;
        frame::write_json_frame(&mut *w, protocol::FRAME_FILE_CTRL, &ps).await?;
    }

    // Wait for push_ready
    let _ready = if let Some((_, p)) = shells::read_ctrl_queue_msg(&ctrl_queue, pc.timeout).await { if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&p) { v } else {
        ift.store(false, Ordering::SeqCst);
        respond_error(stream, "Invalid push_ready response").await;
        return Ok(());
    } } else {
        ift.store(false, Ordering::SeqCst);
        respond_error(stream, "Push ready timeout").await;
        return Ok(());
    };

    // Send file data in chunks
    let chunk_size: usize = 65536;
    for chunk in data.chunks(chunk_size) {
        let mut w = writer.lock().await;
        frame::write_frame(&mut *w, protocol::FRAME_FILE_DATA, chunk).await?;
    }

    // Send push_done
    let pd = protocol::PushDone::new(srv_hash.clone());
    {
        let mut w = writer.lock().await;
        frame::write_json_frame(&mut *w, protocol::FRAME_HASH, &pd).await?;
    }

    // Wait for verification
    let resp_v = if let Some((_, p)) = shells::read_ctrl_queue_msg(&ctrl_queue, pc.timeout).await { if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&p) { v } else {
        ift.store(false, Ordering::SeqCst);
        respond_error(stream, "Invalid push verify response").await;
        return Ok(());
    } } else {
        ift.store(false, Ordering::SeqCst);
        respond_error(stream, "Push verify timeout").await;
        return Ok(());
    };

    if resp_v["type"] == "push_verified" {
        respond_ok(stream, format!("Uploaded '{}' — hash verified (SHA-256: {})", pc.path, srv_hash)).await;
    } else if resp_v["type"] == "push_error" {
        respond_error(
            stream,
            format!("Push failed on target: {}", resp_v["message"].as_str().unwrap_or("?")),
        )
        .await;
    } else {
        respond_error(
            stream,
            format!("Unexpected response: {}", resp_v["type"].as_str().unwrap_or("?")),
        )
        .await;
    }
    ift.store(false, Ordering::SeqCst);
    Ok(())
}

// ── Pull handler (smart only) ───────────────────────────────────────────────

async fn pull_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
    stream: &mut ControlStream,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let pc: PullCommand = match serde_json::from_str(&cmd.data.unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => {
            respond_error(stream, format!("Invalid pull: {e}")).await;
            return Ok(());
        }
    };

    let Some(transfer) = prepare_smart_transfer(id, manager, stream, Some("Smart session required")).await? else { return Ok(()) };
    let SmartTransfer { writer, ctrl_queue, ift, alive: _ } = transfer;

    let pr = protocol::PullRequest::new(pc.path.clone());
    {
        let mut w = writer.lock().await;
        frame::write_json_frame(&mut *w, protocol::FRAME_FILE_CTRL, &pr).await?;
    }

    // Wait for pull_meta
    let meta = if let Some((_, p)) = shells::read_ctrl_queue_msg(&ctrl_queue, pc.timeout).await { if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&p) { v } else {
        ift.store(false, Ordering::SeqCst);
        respond_error(stream, "Invalid download meta").await;
        return Ok(());
    } } else {
        ift.store(false, Ordering::SeqCst);
        respond_error(stream, "Pull meta timeout").await;
        return Ok(());
    };

    if meta["type"] == "push_error" {
        ift.store(false, Ordering::SeqCst);
        respond_error(stream, format!("Pull failed on target: {}", meta["message"].as_str().unwrap_or("?"))).await;
        return Ok(());
    }
    if meta["type"] != "pull_meta" {
        ift.store(false, Ordering::SeqCst);
        respond_error(stream, format!("Expected pull_meta, got {}", meta["type"].as_str().unwrap_or("?"))).await;
        return Ok(());
    }

    let size: usize = meta["size"].as_u64().unwrap_or(0).try_into()?;
    let expected_hash = meta["hash"].as_str().unwrap_or("").to_string();

    // Read FILE_DATA entries from ctrl_queue until HASH
    let mut file_data: Vec<u8> = Vec::with_capacity(size);
    let start = std::time::Instant::now();
    loop {
        let remaining = pc.timeout - start.elapsed().as_secs_f64();
        if remaining <= 0.0 {
            ift.store(false, Ordering::SeqCst);
            respond_error(stream, "Pull data timeout").await;
            return Ok(());
        }
        match shells::read_ctrl_queue_msg(&ctrl_queue, remaining).await {
            Some((protocol::FRAME_FILE_DATA, payload)) => {
                file_data.extend_from_slice(&payload);
            }
            Some((protocol::FRAME_HASH, payload)) => {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    if v["type"] == "push_done" {
                        break;
                    } else if v["type"] == "push_error" {
                        ift.store(false, Ordering::SeqCst);
                        respond_error(stream, format!("Download failed: {}", v["message"].as_str().unwrap_or("?"))).await;
                        return Ok(());
                    }
                }
            }
            _ => {
                ift.store(false, Ordering::SeqCst);
                respond_error(stream, "Download data error").await;
                return Ok(());
            }
        }
    }

    ift.store(false, Ordering::SeqCst);

    // Send success JSON + raw file bytes
    let resp = json!({"status":"ok","output":format!("Downloaded '{}' ({} bytes, hash: {})", pc.path, size, expected_hash)});
    let resp_line = serde_json::to_string(&resp).unwrap_or_default() + "\n";
    let _ = stream.write_all(resp_line.as_bytes());
    let _ = stream.write_all(&(size as u64).to_le_bytes());
    let _ = stream.write_all(&file_data);
    let _ = stream.flush();
    Ok(())
}

// ── Cancel handler ──────────────────────────────────────────────────────────

async fn targ_cancel_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    if let Some(writer) = {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Smart(s)) => Some(Arc::clone(&s.writer)),
            _ => None,
        }
    } {
        let mut w = writer.lock().await;
        let _ = frame::write_frame(&mut *w, protocol::FRAME_CANCEL, &[]).await;
    }
    Ok(())
}

// ── Connect handler (TCP tunnels) ──────────────────────────────────────────

const MAX_TUNNELS_PER_SESSION: usize = 64;

/// Largest file body the control connection will buffer for a `push`.
const MAX_PUSH_SIZE: u64 = 512 * 1024 * 1024;

#[derive(serde::Deserialize)]
pub struct ConnectCommand {
    pub host: String,
    pub port: u16,
    #[serde(default = "def_timeout")]
    pub timeout: f64,
}

/// Handle `{"action":"connect", …}`: ask the target to dial `host:port` and
/// relay the resulting stream over this control connection until either side
/// closes.
async fn connect_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
    mut stream: ControlStream,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let cc: ConnectCommand = match serde_json::from_str(&cmd.data.unwrap_or_default()) {
        Ok(c) => c,
        Err(e) => {
            respond_error(&mut stream, format!("Invalid connect: {e}")).await;
            return Ok(());
        }
    };

    // Look up the session and reserve a stream id (no await while holding the
    // manager lock).
    let found = {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Smart(s)) if s.alive.load(Ordering::SeqCst) => Some((
                Arc::clone(&s.writer),
                Arc::clone(&s.tunnels),
                s.supports_tunnels,
                s.next_stream_id.fetch_add(1, Ordering::SeqCst),
            )),
            _ => None,
        }
    };
    let Some((writer, tunnels, supports_tunnels, stream_id)) = found else {
        respond_error(&mut stream, "Shell not found").await;
        return Ok(());
    };
    if !supports_tunnels {
        respond_error(
            &mut stream,
            "target agent does not support tunneling — upgrade ww-target",
        )
        .await;
        return Ok(());
    }

    let (tx, mut rx) = mpsc::channel::<TunnelEvent>(TUNNEL_EVENT_QUEUE);
    let overflow: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
    // Check the cap and insert under one lock: two concurrent connects must not
    // both pass the check.
    {
        let mut map = tunnels.lock().await;
        if map.len() >= MAX_TUNNELS_PER_SESSION {
            drop(map);
            let resp =
                json!({"status":"error","message":"too many tunnels on this session","errno":24});
            let _ = respond_json(&mut stream, &resp).await;
            return Ok(());
        }
        map.insert(stream_id, TunnelEntry::new(tx, Arc::clone(&overflow)));
    }

    let open = protocol::TunnelOpen {
        stream_id,
        host: cc.host.clone(),
        port: cc.port,
        connect_timeout: cc.timeout,
    };
    {
        let mut w = writer.lock().await;
        if let Err(e) = frame::write_json_frame(&mut *w, protocol::FRAME_TUNNEL_OPEN, &open).await {
            drop(w);
            tunnels.lock().await.remove(&stream_id);
            respond_error(&mut stream, format!("failed to send tunnel open: {e}")).await;
            return Ok(());
        }
    }

    // Wait for the open result.  A target is allowed to emit tunnel bytes
    // before `TUNNEL_OPENED` (a destination that speaks first), so any early
    // `Data` is buffered and replayed once the stream is confirmed.
    let wait = cc.timeout.clamp(0.1, 3600.0) + 5.0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(wait);
    let mut leftover: Vec<u8> = Vec::new();
    let opened = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let event = tokio::time::timeout(remaining, rx.recv()).await;
        match event {
            Ok(Some(TunnelEvent::Opened(opened))) => break opened,
            Ok(Some(TunnelEvent::Data(bytes))) => leftover.extend_from_slice(&bytes),
            Ok(Some(TunnelEvent::Eof)) | Ok(Some(TunnelEvent::Closed(_))) => {
                tunnels.lock().await.remove(&stream_id);
                respond_error(&mut stream, "tunnel closed before it opened").await;
                return Ok(());
            }
            Ok(None) => {
                tunnels.lock().await.remove(&stream_id);
                let reason = overflow_reason(&overflow)
                    .unwrap_or_else(|| "target session closed".to_string());
                respond_error(&mut stream, reason).await;
                return Ok(());
            }
            Err(_) => {
                tunnels.lock().await.remove(&stream_id);
                respond_error(&mut stream, "target did not answer the tunnel request").await;
                return Ok(());
            }
        }
    };

    if !opened.ok {
        tunnels.lock().await.remove(&stream_id);
        let resp = json!({
            "status":"error",
            "message": opened.message.unwrap_or_else(|| "tunnel open failed".into()),
            "errno": opened.errno,
        });
        let _ = respond_json(&mut stream, &resp).await;
        return Ok(());
    }

    // Success: tell the client, then relay raw bytes.
    let resp = json!({"status":"ok","bound": opened.bound});
    let line = serde_json::to_string(&resp).unwrap_or_default() + "\n";
    if stream.write_all(line.as_bytes()).is_err() || stream.flush().is_err() {
        tunnels.lock().await.remove(&stream_id);
        return Ok(());
    }
    stream.set_read_timeout(None)?;

    let control = match stream.into_async() {
        Ok(c) => c,
        Err(e) => {
            tunnels.lock().await.remove(&stream_id);
            return Err(e.into());
        }
    };
    relay_tunnel(control, writer, rx, leftover, stream_id, tunnels, overflow).await;
    Ok(())
}

/// Relay bytes between the async control stream and the target session until
/// either side closes, then release the tunnel sender.
async fn relay_tunnel(
    control: AsyncControl,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    mut rx: mpsc::Receiver<TunnelEvent>,
    leftover: Vec<u8>,
    stream_id: u32,
    tunnels: Tunnels,
    overflow: Arc<StdMutex<Option<String>>>,
) {
    let _ = relay_tunnel_inner(control, &writer, &mut rx, leftover, stream_id, &overflow).await;
    tunnels.lock().await.remove(&stream_id);
}

async fn write_tunnel_close(
    writer: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    stream_id: u32,
    reason: &str,
) {
    let close = protocol::TunnelClose { stream_id, reason: reason.to_string() };
    if let Ok(json) = serde_json::to_vec(&close) {
        let mut w = writer.lock().await;
        let _ = frame::write_frame(&mut *w, protocol::FRAME_TUNNEL_CLOSE, &json).await;
    }
}

async fn relay_tunnel_inner(
    mut control: AsyncControl,
    writer: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    rx: &mut mpsc::Receiver<TunnelEvent>,
    leftover: Vec<u8>,
    stream_id: u32,
    overflow: &StdMutex<Option<String>>,
) -> Result<()> {
    let mut control_open = true;

    if !leftover.is_empty() {
        let payload = protocol::tunnel_data_payload(stream_id, &leftover);
        let mut w = writer.lock().await;
        frame::write_frame(&mut *w, protocol::FRAME_TUNNEL_DATA, &payload).await?;
    }

    /// One step of the relay, decided inside `select!` and acted on outside it
    /// (so `control` is not borrowed while we write to it).
    enum Act {
        ToTarget(Vec<u8>),
        ToControl(Vec<u8>),
        TargetEof,
        TargetClosed(String),
        ClientEof,
        ClientErr,
        SessionGone,
    }

    let mut buf = vec![0_u8; 32 * 1024];
    loop {
        let act = if control_open {
            tokio::select! {
                event = rx.recv() => match event {
                    Some(TunnelEvent::Data(bytes)) => Act::ToControl(bytes),
                    Some(TunnelEvent::Eof) => Act::TargetEof,
                    Some(TunnelEvent::Closed(reason)) => Act::TargetClosed(reason),
                    Some(TunnelEvent::Opened(_)) => continue,
                    None => Act::SessionGone,
                },
                read = control.read(&mut buf) => match read {
                    Ok(0) => Act::ClientEof,
                    Ok(n) => Act::ToTarget(buf[..n].to_vec()),
                    Err(_) => Act::ClientErr,
                },
            }
        } else {
            match rx.recv().await {
                Some(TunnelEvent::Data(bytes)) => Act::ToControl(bytes),
                Some(TunnelEvent::Eof) => Act::TargetEof,
                Some(TunnelEvent::Closed(reason)) => Act::TargetClosed(reason),
                Some(TunnelEvent::Opened(_)) => continue,
                None => Act::SessionGone,
            }
        };

        match act {
            Act::ToTarget(bytes) => write_tunnel_data(writer, stream_id, &bytes).await?,
            Act::ToControl(bytes) => {
                control.write_all(&bytes).await?;
                control.flush().await?;
            }
            // The target's destination reached EOF: half-close our write side
            // of the control connection so the local client sees EOF.
            Act::TargetEof => control.shutdown().await?,
            Act::TargetClosed(reason) => {
                write_tunnel_close(writer, stream_id, &reason).await;
                return Ok(());
            }
            // The local client closed its write side: half-close the target.
            Act::ClientEof => {
                write_tunnel_eof(writer, stream_id).await?;
                control_open = false;
            }
            Act::ClientErr => {
                write_tunnel_close(writer, stream_id, "control read failed").await;
                return Ok(());
            }
            Act::SessionGone => {
                // `None` means either the session died or this stream was
                // dropped for being too slow — say which.
                let reason = overflow_reason(overflow)
                    .unwrap_or_else(|| "session closed".to_string());
                write_tunnel_close(writer, stream_id, &reason).await;
                return Ok(());
            }
        }
    }
}

async fn write_tunnel_data(
    writer: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    stream_id: u32,
    bytes: &[u8],
) -> Result<()> {
    let payload = protocol::tunnel_data_payload(stream_id, bytes);
    let mut w = writer.lock().await;
    frame::write_frame(&mut *w, protocol::FRAME_TUNNEL_DATA, &payload).await?;
    Ok(())
}

async fn write_tunnel_eof(
    writer: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    stream_id: u32,
) -> Result<()> {
    let mut w = writer.lock().await;
    frame::write_frame(&mut *w, protocol::FRAME_TUNNEL_EOF, &stream_id.to_le_bytes()).await?;
    Ok(())
}

// ── Interact handler ────────────────────────────────────────────────────────

/// Spawn a thread that reads from a tokio buf and writes raw bytes to a control stream.
fn spawn_buf_to_socket(
    buf: Arc<Mutex<Vec<u8>>>,
    mut socket: ControlStream,
    alive: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    pc: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async move {
            loop {
                if done.load(Ordering::SeqCst) || !alive.load(Ordering::SeqCst) || pc.load(Ordering::SeqCst) {
                    break;
                }
                let mut b = buf.lock().await;
                if b.is_empty() {
                    drop(b);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                } else {
                    let data = b.clone();
                    b.clear();
                    drop(b);
                    if socket.write_all(&data).is_err() {
                        pc.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
        });
    });
}

/// Spawn a thread that reads from a control stream and writes to a tokio TCP writer.
/// `framed` — if true, data is wrapped in `FRAME_SHELL`; otherwise raw bytes.
fn spawn_socket_to_writer(
    mut socket: ControlStream,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    done: Arc<AtomicBool>,
    pc: Arc<AtomicBool>,
    framed: bool,
) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let _ = rt.block_on(async move {
            let mut buf2 = [0u8; 65536];
            let _ = socket.set_read_timeout(Some(Duration::from_secs(1)));
            loop {
                if done.load(Ordering::SeqCst) || pc.load(Ordering::SeqCst) {
                    break;
                }
                match socket.read(&mut buf2) {
                    Ok(0) => {
                        pc.store(true, Ordering::SeqCst);
                        break;
                    }
                    Ok(n) => {
                        let data = buf2[..n].to_vec();
                        let mut w = writer.lock().await;
                        let r = if framed {
                            frame::write_frame(&mut *w, protocol::FRAME_SHELL, &data).await
                        } else {
                            w.write_all(&data).await
                        };
                        if r.is_err() {
                            pc.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => {
                        pc.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        });
    });
}

/// Common tail for Smart and TCP interact: bridge buf→socket and socket→writer.
async fn run_interact_bridge(
    buf: Arc<Mutex<Vec<u8>>>,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    stream: &mut ControlStream,
    alive: Arc<AtomicBool>,
    framed: bool,
    lease: Option<(&LockGuard, Option<Duration>)>,
) {
    let done = Arc::new(AtomicBool::new(false));
    let pc = Arc::new(AtomicBool::new(false));

    spawn_buf_to_socket(
        Arc::clone(&buf),
        stream.try_clone().unwrap(),
        Arc::clone(&alive),
        Arc::clone(&done),
        Arc::clone(&pc),
    );
    spawn_socket_to_writer(
        stream.try_clone().unwrap(),
        Arc::clone(&writer),
        Arc::clone(&done),
        Arc::clone(&pc),
        framed,
    );

    let mut last_refresh = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if !alive.load(Ordering::SeqCst) || pc.load(Ordering::SeqCst) {
            break;
        }
        // Keep the session lock alive while attached, and detach if it went
        // away (lease lapsed, or someone force-took it) instead of silently
        // sharing the shell.
        if let Some((guard, ttl)) = lease
            && last_refresh.elapsed() >= Duration::from_secs(10)
        {
            if guard.still_held() {
                guard.refresh(ttl);
                last_refresh = Instant::now();
            } else {
                let _ = stream.write_all(b"\r\n[!] session lock expired or was taken over; detaching\r\n");
                let _ = stream.flush();
                break;
            }
        }
    }
    done.store(true, Ordering::SeqCst);
}

async fn interact_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
    stream: &mut ControlStream,
    conn: &ConnCtx,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);

    let found = {
        let mg = manager.lock().await;
        mg.sessions.get(&id).map(|s| match s {
            ManagedSession::Smart(sm) => (
                Arc::clone(&sm.writer),
                Arc::clone(&sm.shell_buf),
                Arc::clone(&sm.alive),
                Some(Arc::clone(&sm.in_file_transfer)),
                ManagedSession::lock(s),
                true,
            ),
            ManagedSession::Tcp(sm, b) => (
                Arc::clone(&sm.writer),
                Arc::clone(b),
                Arc::clone(&sm.alive),
                None,
                ManagedSession::lock(s),
                false,
            ),
        })
    };

    let Some((writer, buf, alive, ift, lock, framed)) = found else {
        return respond_json(stream, &Response::error("Shell not found")).await;
    };
    if let Some(ift) = &ift
        && ift.load(Ordering::SeqCst)
    {
        return respond_json(stream, &Response::error("Session busy with file transfer")).await;
    }

    // Interactive attach takes the lock on both kinds: `send` is per-command on
    // ww-target, but the bridge still shares one output buffer, so two attached
    // clients would collide.
    let guard = match acquire_or_refuse(&lock, conn, &cmd, stream, conn.lease).await? {
        Some(g) => g,
        None => return Ok(()),
    };

    respond_json(stream, &serde_json::json!({"status":"ok","message":"Entering interactive mode"})).await?;
    stream.write_all(b"\r\n[+] Interactive mode. Press Ctrl+C to detach\r\n")?;
    stream.flush()?;
    if !framed {
        // Dumb shell: start from a clean buffer under our lock.
        buf.lock().await.clear();
    }
    run_interact_bridge(buf, writer, stream, alive, framed, Some((&guard, conn.lease))).await;
    drop(guard);
    Ok(())
}

// ── Shared helper ───────────────────────────────────────────────────────────

/// Poll a dumb-shell's shared buffer, but stop polling as soon as the lock is
/// gone (someone used `--force`), so we cannot steal the new holder's output.
async fn respond_read_locked(buf: &Mutex<Vec<u8>>, timeout: f64, guard: &LockGuard) -> Response {
    let start = Instant::now();
    loop {
        if !guard.still_held() {
            // Displaced: leave the buffer alone; it may hold the new holder's data.
            return Response::with_output(String::new());
        }
        {
            let mut b = buf.lock().await;
            if !b.is_empty() {
                let out = String::from_utf8_lossy(&b).to_string();
                b.clear();
                return Response::with_output(out);
            }
        }
        if start.elapsed().as_secs_f64() >= timeout {
            return Response::with_output(String::new());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
