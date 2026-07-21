use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader as AsyncBufReader};
use tokio::sync::Mutex;

use crate::ShellInfo;

// ── TCP shell session ──────────────────────────────────────────────────────

pub struct ShellSession {
    pub id: u32,
    pub addr: String,
    pub created: f64,
    pub alive: Arc<AtomicBool>,
    pub writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl ShellSession {
    pub fn new(id: u32, addr: String, stream: tokio::net::TcpStream, initial_data: Vec<u8>) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let (reader, writer) = stream.into_split();
        let alive = Arc::new(AtomicBool::new(true));
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(initial_data));
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

    pub fn info(&self) -> ShellInfo {
        ShellInfo { id: self.id, addr: self.addr.clone(), created: self.created, alive: self.alive.load(Ordering::SeqCst), kind: Some("tcp".into()) }
    }

    pub fn close(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self._reader_handle.abort();
    }
}

// ── Target session ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TargetCmdState {
    #[allow(dead_code)]
    pub cmd_id: String,
    pub output_buf: Vec<u8>,
    pub completed: bool,
    pub exit_code: Option<i32>,
}

pub struct TargetShared {
    pub alive: AtomicBool,
    pub cmd_state: Mutex<Option<TargetCmdState>>,
    pub push_channel: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<(String, String)>>>,
    pub cwd: Mutex<String>,
    pub pull_channel: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<String>>>,
}

pub struct TargetSession {
    pub id: u32,
    pub addr: String,
    pub created: f64,
    pub writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    pub shared: Arc<TargetShared>,
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl TargetSession {
    pub async fn new(id: u32, addr: String, stream: tokio::net::TcpStream, _leftover: Vec<u8>) -> Self {
        let (reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));

        let shared = Arc::new(TargetShared {
            alive: AtomicBool::new(true),
            cmd_state: Mutex::new(None),
            push_channel: tokio::sync::Mutex::new(None),
            cwd: Mutex::new(String::new()),
            pull_channel: tokio::sync::Mutex::new(None),
        });

        let shared_clone = Arc::clone(&shared);
        let reader_handle = tokio::spawn(async move {
            let mut reader = AsyncBufReader::new(reader);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => { shared_clone.alive.store(false, Ordering::SeqCst); break; }
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() { continue; }
                        let msg: serde_json::Value = match serde_json::from_str(trimmed) { Ok(v) => v, Err(_) => continue };
                        match msg["type"].as_str().unwrap_or("") {
                            "stdout" | "stderr" => {
                                let data = msg["data"].as_str().unwrap_or("");
                                let mut cs = shared_clone.cmd_state.lock().await;
                                if let Some(ref mut state) = *cs { state.output_buf.extend_from_slice(data.as_bytes()); }
                            }
                            "done" => {
                                let code = msg["exit_code"].as_i64().unwrap_or(-1);
                                let mut cs = shared_clone.cmd_state.lock().await;
                                if let Some(ref mut state) = *cs { state.completed = true; state.exit_code = Some(code as i32); }
                            }
                            "push_done" => {
                                let path = msg["path"].as_str().unwrap_or("").to_string();
                                let hash = msg["hash"].as_str().unwrap_or("").to_string();
                                let mut pc = shared_clone.push_channel.lock().await;
                                if let Some(tx) = pc.take() { let _ = tx.send((path, hash)); }
                            }
                            "push_error" => {
                                let path = msg["path"].as_str().unwrap_or("").to_string();
                                let err_msg = msg["message"].as_str().unwrap_or("unknown error");
                                let payload = serde_json::json!({"type":"push_error","path":path,"message":err_msg}).to_string();
                                let mut sent = false;
                                let mut pc = shared_clone.push_channel.lock().await;
                                if let Some(tx) = pc.take() {
                                    if tx.send((msg["path"].as_str().unwrap_or("").to_string(), format!("error:{}", err_msg))).is_ok() { sent = true; }
                                }
                                drop(pc);
                                if !sent {
                                    let mut pc = shared_clone.pull_channel.lock().await;
                                    if let Some(tx) = pc.take() { let _ = tx.send(payload); }
                                }
                            }
                            "pull_data" => {
                                let raw = serde_json::to_string(&msg).unwrap_or_default();
                                let mut pc = shared_clone.pull_channel.lock().await;
                                if let Some(tx) = pc.take() { let _ = tx.send(raw); }
                            }
                            _ => {}
                        }
                    }
                    Err(_) => { shared_clone.alive.store(false, Ordering::SeqCst); break; }
                }
            }
        });

        Self { id, addr, created: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(), writer, shared, _reader_handle: reader_handle }
    }

    pub fn info(&self) -> ShellInfo {
        ShellInfo { id: self.id, addr: format!("[ww-target] {}", self.addr), created: self.created, alive: self.shared.alive.load(Ordering::SeqCst), kind: Some("target".into()) }
    }

    pub fn close(&mut self) {
        self.shared.alive.store(false, Ordering::SeqCst);
        self._reader_handle.abort();
    }
}

// ── Web shell session ──────────────────────────────────────────────────────

#[cfg(feature = "web")]
pub struct WebShellSession {
    pub id: u32,
    pub url: String,
    pub injection_point: String,
    pub method: String,
    pub body_template: Option<String>,
    pub headers: Vec<String>,
    pub cookie: Option<String>,
    pub created: f64,
    pub alive: Arc<AtomicBool>,
    pub buf: Arc<Mutex<Vec<u8>>>,
}

#[cfg(feature = "web")]
impl WebShellSession {
    pub fn new(id: u32, config: crate::WebShellConfig) -> Self {
        Self {
            id, url: config.url, injection_point: config.injection_point, method: config.method,
            body_template: config.body_template, headers: config.headers, cookie: config.cookie,
            created: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            alive: Arc::new(AtomicBool::new(true)),
            buf: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn info(&self) -> ShellInfo {
        ShellInfo { id: self.id, addr: format!("[web] {}", self.url), created: self.created, alive: self.alive.load(Ordering::SeqCst), kind: Some("web".into()) }
    }
}

// ── Managed sessions ───────────────────────────────────────────────────────

pub enum ManagedSession {
    Tcp(ShellSession, Arc<Mutex<Vec<u8>>>),
    Target(TargetSession),
    #[cfg(feature = "web")]
    Web(WebShellSession),
}

impl ManagedSession {
    pub fn info(&self) -> ShellInfo {
        match self {
            ManagedSession::Tcp(s, _) => s.info(),
            ManagedSession::Target(s) => s.info(),
            #[cfg(feature = "web")]
            ManagedSession::Web(s) => s.info(),
        }
    }

    pub fn alive(&self) -> bool {
        match self {
            ManagedSession::Tcp(s, _) => s.alive.load(Ordering::SeqCst),
            ManagedSession::Target(s) => s.shared.alive.load(Ordering::SeqCst),
            #[cfg(feature = "web")]
            ManagedSession::Web(s) => s.alive.load(Ordering::SeqCst),
        }
    }
}

// ── Session manager ────────────────────────────────────────────────────────

pub struct SessionManager {
    pub sessions: HashMap<u32, ManagedSession>,
    next_id: u32,
}

impl SessionManager {
    pub fn new() -> Self {
        Self { sessions: HashMap::new(), next_id: 1 }
    }

    pub fn add_tcp(&mut self, addr: String, stream: tokio::net::TcpStream, initial: Vec<u8>) -> u32 {
        let id = self.next_id; self.next_id += 1;
        let (session, buf) = ShellSession::new(id, addr, stream, initial);
        self.sessions.insert(id, ManagedSession::Tcp(session, buf)); id
    }

    pub async fn add_target(&mut self, addr: String, stream: tokio::net::TcpStream, leftover: Vec<u8>) -> u32 {
        let id = self.next_id; self.next_id += 1;
        let session = TargetSession::new(id, addr, stream, leftover).await;
        self.sessions.insert(id, ManagedSession::Target(session)); id
    }

    #[cfg(feature = "web")]
    pub fn add_web(&mut self, config: crate::WebShellConfig) -> u32 {
        let id = self.next_id; self.next_id += 1;
        self.sessions.insert(id, ManagedSession::Web(WebShellSession::new(id, config))); id
    }

    pub fn remove(&mut self, id: u32) {
        if let Some(s) = self.sessions.remove(&id) {
            match s {
                ManagedSession::Tcp(mut s, _) => s.close(),
                ManagedSession::Target(mut s) => s.close(),
                #[cfg(feature = "web")]
                ManagedSession::Web(_) => {}
            }
        }
    }

    pub fn list(&self) -> Vec<ShellInfo> {
        self.sessions.values().map(|s| s.info()).collect()
    }
}
