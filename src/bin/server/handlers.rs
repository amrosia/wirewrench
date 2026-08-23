use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rand::Rng;
use serde_json::{json, Value};
use sha2::Digest;
use ssh_key::public::PublicKey;
use ssh_key::HashAlg;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use wirewrench::auth as wauth;
use wirewrench::target::protocol;
use wirewrench::{Command, Response};

use super::auth as srv_auth;
use super::frame;
use super::session::{CtrlQueue, ManagedSession, SessionManager};
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

/// Run the SSH-style auth handshake on a TCP control connection.  Returns
/// `true` if the client authenticated, `false` if the connection should be
/// closed (a failure response has already been sent).
fn authenticate(
    reader: &mut BufReader<&mut ControlStream>,
    writer: &mut ControlStream,
    keys_path: &Path,
) -> Result<bool> {
    // Per-connection key load (fail closed): rotation applies immediately.
    let keys = match srv_auth::load_authorized_keys(keys_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[!] Control-port auth keys unavailable, rejecting connection: {e}");
            let _ = write_json_line(writer, &json!({"status":"error","message":"authentication unavailable"}));
            return Ok(false);
        }
    };

    // Relax the read timeout for the auth phase.
    reader.get_mut().set_read_timeout(Some(Duration::from_secs(15)))?;

    let mut challenge = [0u8; wauth::CHALLENGE_LEN];
    rand::rng().fill_bytes(&mut challenge);
    let challenge_b64 = wauth::b64_encode(&challenge);

    let mut line = String::new();

    for _ in 0..wauth::MAX_OFFERS {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(false);
        }
        let msg: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => {
                let _ = write_json_line(writer, &json!({"status":"error","message":"authentication required"}));
                return Ok(false);
            }
        };

        match msg["type"].as_str() {
            Some("auth_offer") => {
                let Some(key_str) = msg["key"].as_str() else {
                    let _ = write_json_line(writer, &json!({"type":"auth_reject"}));
                    continue;
                };
                let offered = match PublicKey::from_openssh(key_str) {
                    Ok(p) => p,
                    Err(_) => {
                        let _ = write_json_line(writer, &json!({"type":"auth_reject"}));
                        continue;
                    }
                };
                let Some(authorized) = keys.iter().find(|k| *k == &offered) else {
                    let _ = write_json_line(writer, &json!({"type":"auth_reject"}));
                    continue;
                };

                let _ = write_json_line(writer, &json!({"type":"auth_challenge","challenge": challenge_b64}));

                line.clear();
                let n = reader.read_line(&mut line)?;
                if n == 0 {
                    return Ok(false);
                }
                let sig_msg: Value = serde_json::from_str(line.trim())?;
                if sig_msg["type"] != "auth_sign" {
                    let _ = write_json_line(writer, &json!({"status":"error","message":"authentication failed"}));
                    return Ok(false);
                }
                let Some(sig_b64) = sig_msg["signature"].as_str() else {
                    let _ = write_json_line(writer, &json!({"status":"error","message":"authentication failed"}));
                    return Ok(false);
                };

                let key_blob = offered.to_bytes()?;
                let payload = wauth::signed_payload(&challenge, &key_blob);

                if srv_auth::verify_signature(authorized, &payload, sig_b64) {
                    eprintln!("[+] Control-port auth ok: {} (TCP)", authorized.fingerprint(HashAlg::Sha256));
                    let _ = write_json_line(writer, &json!({"status":"ok"}));
                    reader.get_mut().set_read_timeout(Some(Duration::from_secs(5)))?;
                    return Ok(true);
                }

                eprintln!("[-] Control-port auth failed: bad signature (TCP)");
                let _ = write_json_line(writer, &json!({"status":"error","message":"authentication failed"}));
                return Ok(false);
            }
            _ => {
                // Not an auth message (e.g. an old client sending a command).
                let _ = write_json_line(writer, &json!({"status":"error","message":"authentication required"}));
                return Ok(false);
            }
        }
    }

    let _ = write_json_line(writer, &json!({"status":"error","message":"too many authentication attempts"}));
    Ok(false)
}

// ── Handle a single control client ─────────────────────────────────────────

/// Handle a `ww` client connected over the Unix control socket (never authenticated).
pub async fn handle_control_unix(
    stream: tokio::net::UnixStream,
    manager: Arc<Mutex<SessionManager>>,
) -> Result<()> {
    let stream = stream.into_std()?;
    handle_control_conn(ControlStream::Unix(stream), manager, None).await
}

/// Handle a `ww` client connected over the optional TCP control port
/// (`ww-server --control-port`).
pub async fn handle_control_tcp(
    stream: tokio::net::TcpStream,
    manager: Arc<Mutex<SessionManager>>,
    auth_keys_path: Option<Arc<std::path::PathBuf>>,
) -> Result<()> {
    let stream = stream.into_std()?;
    let keys = auth_keys_path.as_deref().map(std::path::PathBuf::as_path);
    handle_control_conn(ControlStream::Tcp(stream), manager, keys).await
}

async fn handle_control_conn(
    mut stream: ControlStream,
    manager: Arc<Mutex<SessionManager>>,
    auth_keys_path: Option<&Path>,
) -> Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut writer = stream.try_clone()?;
    let mut buf_reader = BufReader::new(&mut stream);

    if let Some(path) = auth_keys_path
        && !authenticate(&mut buf_reader, &mut writer, path)?
    {
        return Ok(());
    }

    // Read the command line.  With no auth configured, tolerate a stray
    // `auth_offer` from a client that has a key, and tell it auth isn't needed.
    let mut line = String::new();
    loop {
        line.clear();
        let n = buf_reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        if auth_keys_path.is_none()
            && let Ok(v) = serde_json::from_str::<Value>(line.trim())
            && v["type"] == "auth_offer"
        {
            let _ = write_json_line(&mut writer, &json!({"type":"auth_not_required"}));
            continue;
        }
        break;
    }

    let cmd: Command = serde_json::from_str(line.trim())?;
    let action = &cmd.action;
    let push_buffered = buf_reader.buffer().to_vec();
    drop(buf_reader);

    match action.as_str() {
        "list" => {
            let mg = manager.lock().await;
            respond_json(&mut stream, &Response::with_shells(json!(mg.list()))).await?;
        }
        "send" => send_handler(cmd, &manager, &mut stream).await?,
        "read" => read_handler(cmd, &manager, &mut stream).await?,
        "push" => push_handler(cmd, &manager, &mut stream, push_buffered).await?,
        "pull" => pull_handler(cmd, &manager, &mut stream).await?,
        "targ_cancel" => targ_cancel_handler(cmd, &manager).await?,
        "close" => {
            let mut mg = manager.lock().await;
            mg.remove(cmd.id.unwrap_or(0));
            respond_json(&mut stream, &Response::ok()).await?;
        }
        "interact" => interact_handler(cmd, &manager, &mut stream).await?,
        _ => respond_json(&mut stream, &Response::error(format!("Unknown action: {action}"))).await?,
    }
    Ok(())
}

// ── Send handler ────────────────────────────────────────────────────────────

async fn send_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
    stream: &mut ControlStream,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let command = cmd.data.unwrap_or_default().trim().to_string();
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
            let to_send = format!("{command}\n");
            {
                let mut w = s.writer.lock().await;
                w.write_all(to_send.as_bytes()).await?;
            }
            let tcp_timeout = if timeout > 0.0 { timeout } else { 3.0 };
            let resp = respond_read(b, tcp_timeout).await;
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
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let timeout = cmd.timeout.unwrap_or(0.2);

    let mg = manager.lock().await;
    let buf = match mg.sessions.get(&id) {
        Some(ManagedSession::Smart(s)) => Some(Arc::clone(&s.shell_buf)),
        Some(ManagedSession::Tcp(_, b)) => Some(Arc::clone(b)),
        None => None,
    };
    drop(mg);

    match buf {
        Some(buf) => {
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
    buffered: Vec<u8>,
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

    // Read file data from control socket
    let size: usize = pc.size.try_into()?;
    let mut data = Vec::with_capacity(size);
    let fb = buffered.len().min(size);
    if fb > 0 {
        data.extend_from_slice(&buffered[..fb]);
    }
    if size > fb {
        let mut raw = stream
            .try_clone()
            .map_err(|e| anyhow::anyhow!("clone: {e}"))?;
        raw.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut rest = vec![0u8; size - fb];
        raw.read_exact(&mut rest)?;
        data.extend_from_slice(&rest);
    }

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

    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if !alive.load(Ordering::SeqCst) || pc.load(Ordering::SeqCst) {
            break;
        }
    }
    done.store(true, Ordering::SeqCst);
}

async fn interact_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
    stream: &mut ControlStream,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);

    // Smart
    if let Some((writer, buf, alive, ift)) = {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Smart(s)) => Some((
                Arc::clone(&s.writer),
                Arc::clone(&s.shell_buf),
                Arc::clone(&s.alive),
                Arc::clone(&s.in_file_transfer),
            )),
            _ => None,
        }
    } {
        if ift.load(Ordering::SeqCst) {
            return respond_json(stream, &Response::error("Session busy with file transfer")).await;
        }
        respond_json(stream, &serde_json::json!({"status":"ok","message":"Entering interactive mode"})).await?;
        stream.write_all(b"\r\n[+] Interactive mode. Press Ctrl+C to detach\r\n")?;
        stream.flush()?;
        run_interact_bridge(buf, writer, stream, alive, true).await;
        return Ok(());
    }

    // TCP
    if let Some((sw, sb, alive)) = {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Tcp(s, b)) => {
                Some((Arc::clone(&s.writer), Arc::clone(b), Arc::clone(&s.alive)))
            }
            _ => None,
        }
    } {
        respond_json(stream, &serde_json::json!({"status":"ok","message":"Entering interactive mode"})).await?;
        stream.write_all(b"\r\n[+] Interactive mode. Press Ctrl+C to detach\r\n")?;
        run_interact_bridge(sb, sw, stream, alive, false).await;
        return Ok(());
    }

    respond_json(stream, &Response::error("Shell not found")).await
}

// ── Shared helper ───────────────────────────────────────────────────────────

async fn respond_read(buf: &Mutex<Vec<u8>>, timeout: f64) -> Response {
    Response::with_output(shells::read_from_buf(buf, timeout).await)
}
