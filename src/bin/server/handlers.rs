use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde_json::json;
use sha2::Digest;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use wirewrench::target::protocol;
use wirewrench::{Command, Response};

use super::frame;
use super::session::{CtrlQueue, ManagedSession, SessionManager};
use super::shells;

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
    stream: &mut std::os::unix::net::UnixStream,
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

/// Write a serializable value as JSON + newline to a Unix socket.
async fn respond_json(stream: &mut std::os::unix::net::UnixStream, val: &impl serde::Serialize) -> Result<()> {
    let j = serde_json::to_string(val)? + "\n";
    stream.write_all(j.as_bytes())?;
    Ok(())
}

/// Write a success response — `{status:"ok", output: msg}`.
async fn respond_ok(stream: &mut std::os::unix::net::UnixStream, msg: impl Into<String>) {
    let _ = respond_json(stream, &Response::with_output(msg.into())).await;
}

/// Write an error response — `{status:"error", message: msg}`.
async fn respond_error(stream: &mut std::os::unix::net::UnixStream, msg: impl Into<String>) {
    let _ = respond_json(stream, &Response::error(msg.into())).await;
}

// ── Handle a single control client ─────────────────────────────────────────

pub async fn handle_control(
    stream: tokio::net::UnixStream,
    manager: Arc<Mutex<SessionManager>>,
) -> Result<()> {
    let mut stream: std::os::unix::net::UnixStream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf_reader = BufReader::new(&stream);
    let mut line = String::new();
    buf_reader.read_line(&mut line)?;
    if line.is_empty() { return Ok(()); }
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
        #[cfg(feature = "web")]
        "register_web" => {
            let config: wirewrench::WebShellConfig = match serde_json::from_str(&cmd.data.unwrap_or_default()) {
                Ok(c) => c,
                Err(e) => {
                    respond_json(&mut stream, &Response::error(format!("Invalid config: {}", e))).await?;
                    return Ok(());
                }
            };
            let id = { let mut mg = manager.lock().await; mg.add_web(config) };
            respond_json(&mut stream, &Response::with_shells(json!({"id": id}))).await?;
        }
        "interact" => interact_handler(cmd, &manager, &mut stream).await?,
        _ => respond_json(&mut stream, &Response::error(format!("Unknown action: {}", action))).await?,
    }
    Ok(())
}

// ── Send handler ────────────────────────────────────────────────────────────

async fn send_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
    stream: &mut std::os::unix::net::UnixStream,
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
            let to_send = format!("{}\n", command);
            {
                let mut w = s.writer.lock().await;
                frame::write_frame(&mut *w, protocol::FRAME_SHELL, to_send.as_bytes()).await?;
            }
            let resp = respond_read(&s.shell_buf, timeout).await;
            respond_json(stream, &resp).await
        }
        Some(ManagedSession::Tcp(s, b)) => {
            let to_send = format!("{}\n", command);
            {
                let mut w = s.writer.lock().await;
                w.write_all(to_send.as_bytes()).await?;
            }
            let resp = respond_read(b, timeout).await;
            respond_json(stream, &resp).await
        }
        #[cfg(feature = "web")]
        Some(ManagedSession::Web(s)) => {
            let config = wirewrench::WebShellConfig {
                url: s.url.clone(),
                injection_point: s.injection_point.clone(),
                method: s.method.clone(),
                body_template: s.body_template.clone(),
                headers: s.headers.clone(),
                cookie: s.cookie.clone(),
            };
            drop(mg);
            match shells::web_shell_exec(&config, &command).await {
                Ok(body) => respond_json(stream, &Response::with_output(body)).await,
                Err(e) => respond_json(stream, &Response::error(e.to_string())).await,
            }
        }
        None => respond_json(stream, &Response::error("Shell not found")).await,
    }
}

// ── Read handler ────────────────────────────────────────────────────────────

async fn read_handler(
    cmd: Command,
    manager: &Arc<Mutex<SessionManager>>,
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let timeout = cmd.timeout.unwrap_or(0.2);

    let mg = manager.lock().await;
    let buf = match mg.sessions.get(&id) {
        Some(ManagedSession::Smart(s)) => Some(Arc::clone(&s.shell_buf)),
        Some(ManagedSession::Tcp(_, b)) => Some(Arc::clone(b)),
        #[cfg(feature = "web")]
        Some(ManagedSession::Web(s)) => Some(Arc::clone(&s.buf)),
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
    stream: &mut std::os::unix::net::UnixStream,
    buffered: Vec<u8>,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let pc: PushCommand = match serde_json::from_str(&cmd.data.unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => {
            respond_error(stream, format!("Invalid push: {}", e)).await;
            return Ok(());
        }
    };

    let transfer = match prepare_smart_transfer(id, manager, stream, Some("Push only supported on smart (ww-target) sessions")).await? {
        Some(t) => t,
        None => return Ok(()),
    };
    let SmartTransfer { writer, ctrl_queue, ift, alive: _ } = transfer;

    // Read file data from control socket
    let size = pc.size as usize;
    let mut data = Vec::with_capacity(size);
    let fb = buffered.len().min(size);
    if fb > 0 {
        data.extend_from_slice(&buffered[..fb]);
    }
    if size > fb {
        let mut raw = stream
            .try_clone()
            .map_err(|e| anyhow::anyhow!("clone: {}", e))?;
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
    let _ready = match shells::read_ctrl_queue_msg(&ctrl_queue, pc.timeout).await {
        Some((_, p)) => match serde_json::from_slice::<serde_json::Value>(&p) {
            Ok(v) => v,
            Err(_) => {
                ift.store(false, Ordering::SeqCst);
                respond_error(stream, "Invalid push_ready response").await;
                return Ok(());
            }
        },
        None => {
            ift.store(false, Ordering::SeqCst);
            respond_error(stream, "Push ready timeout").await;
            return Ok(());
        }
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
    let resp_v = match shells::read_ctrl_queue_msg(&ctrl_queue, pc.timeout).await {
        Some((_, p)) => match serde_json::from_slice::<serde_json::Value>(&p) {
            Ok(v) => v,
            Err(_) => {
                ift.store(false, Ordering::SeqCst);
                respond_error(stream, "Invalid push verify response").await;
                return Ok(());
            }
        },
        None => {
            ift.store(false, Ordering::SeqCst);
            respond_error(stream, "Push verify timeout").await;
            return Ok(());
        }
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
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let pc: PullCommand = match serde_json::from_str(&cmd.data.unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => {
            respond_error(stream, format!("Invalid pull: {}", e)).await;
            return Ok(());
        }
    };

    let transfer = match prepare_smart_transfer(id, manager, stream, Some("Smart session required")).await? {
        Some(t) => t,
        None => return Ok(()),
    };
    let SmartTransfer { writer, ctrl_queue, ift, alive: _ } = transfer;

    let pr = protocol::PullRequest::new(pc.path.clone());
    {
        let mut w = writer.lock().await;
        frame::write_json_frame(&mut *w, protocol::FRAME_FILE_CTRL, &pr).await?;
    }

    // Wait for pull_meta
    let meta = match shells::read_ctrl_queue_msg(&ctrl_queue, pc.timeout).await {
        Some((_, p)) => match serde_json::from_slice::<serde_json::Value>(&p) {
            Ok(v) => v,
            Err(_) => {
                ift.store(false, Ordering::SeqCst);
                respond_error(stream, "Invalid download meta").await;
                return Ok(());
            }
        },
        None => {
            ift.store(false, Ordering::SeqCst);
            respond_error(stream, "Pull meta timeout").await;
            return Ok(());
        }
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

    let size = meta["size"].as_u64().unwrap_or(0) as usize;
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

/// Spawn a thread that reads from a tokio buf and writes raw bytes to a Unix socket.
fn spawn_buf_to_socket(
    buf: Arc<Mutex<Vec<u8>>>,
    mut socket: std::os::unix::net::UnixStream,
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
                if !b.is_empty() {
                    let data = b.clone();
                    b.clear();
                    drop(b);
                    if socket.write_all(&data).is_err() {
                        pc.store(true, Ordering::SeqCst);
                        break;
                    }
                } else {
                    drop(b);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        });
    });
}

/// Spawn a thread that reads from a Unix socket and writes to a tokio TCP writer.
/// `framed` — if true, data is wrapped in FRAME_SHELL; otherwise raw bytes.
fn spawn_socket_to_writer(
    mut socket: std::os::unix::net::UnixStream,
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
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
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
    stream: &mut std::os::unix::net::UnixStream,
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
    stream: &mut std::os::unix::net::UnixStream,
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

    // Web
    #[cfg(feature = "web")]
    if let Some((config, _buf)) = {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Web(s)) => Some((
                wirewrench::WebShellConfig {
                    url: s.url.clone(),
                    injection_point: s.injection_point.clone(),
                    method: s.method.clone(),
                    body_template: s.body_template.clone(),
                    headers: s.headers.clone(),
                    cookie: s.cookie.clone(),
                },
                Arc::clone(&s.buf),
            )),
            _ => None,
        }
    } {
        let _ = manager;
        stream.write_all(b"\r\n[+] Web shell interactive mode (Ctrl+C to detach)\r\n>> ")?;
        stream.flush()?;
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        'outer: loop {
            let mut cb = Vec::new();
            let mut tmp = [0u8; 65536];
            'rl: loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break 'outer,
                    Ok(n) => {
                        for &b in &tmp[..n] {
                            if b == 0x03 {
                                break 'outer;
                            }
                            if b == b'\n' {
                                break 'rl;
                            }
                            cb.push(b);
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break 'outer,
                }
            }
            let cmd = String::from_utf8_lossy(&cb).trim().to_string();
            if cmd.is_empty() {
                continue;
            }
            match shells::web_shell_exec(&config, &cmd).await {
                Ok(body) => {
                    stream.write_all(body.replace('\n', "\r\n").as_bytes())?;
                    stream.write_all(b"\r\n>> ")?;
                    stream.flush()?;
                }
                Err(e) => {
                    let m = format!("\r\n[!] {}\r\n", e);
                    stream.write_all(m.as_bytes())?;
                    stream.flush()?;
                }
            }
        }
        return Ok(());
    }

    respond_json(stream, &Response::error("Shell not found")).await
}

// ── Shared helper ───────────────────────────────────────────────────────────

async fn respond_read(buf: &Mutex<Vec<u8>>, timeout: f64) -> Response {
    Response::with_output(shells::read_from_buf(buf, timeout).await)
}
