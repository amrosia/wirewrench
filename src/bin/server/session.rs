use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

use wirewrench::target::protocol;
use wirewrench::ShellInfo;

use super::frame;

/// Control-message queue: (message_type, payload) pairs from a ww-target session.
pub type CtrlQueue = Arc<Mutex<std::collections::VecDeque<(u8, Vec<u8>)>>>;

// ── TCP shell session (dumb reverse shell) ────────────────────────────────

pub struct ShellSession {
    id: u32,
    addr: String,
    created: f64,
    pub alive: Arc<AtomicBool>,
    pub writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl ShellSession {
    pub fn new(id: u32, addr: String, stream: tokio::net::TcpStream) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let (reader, writer) = stream.into_split();
        let alive = Arc::new(AtomicBool::new(true));
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let buf_clone = Arc::clone(&buf);
        let alive_clone = Arc::clone(&alive);

        let reader_handle = tokio::spawn(async move {
            let mut r = reader;
            let mut tmp = vec![0u8; 65536];
            loop {
                match r.read(&mut tmp).await {
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
        ShellInfo { id: self.id, addr: self.addr.clone(), created: self.created, alive: self.alive.load(Ordering::SeqCst) }
    }

    pub fn close(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self._reader_handle.abort();
    }
}

// ── Smart session (ww-target on port 4446) ─────────────────────────────────

pub struct SmartSession {
    id: u32,
    addr: String,
    created: f64,
    pub writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    pub shell_buf: Arc<Mutex<Vec<u8>>>,
    pub ctrl_queue: CtrlQueue,
    pub alive: Arc<AtomicBool>,
    pub in_file_transfer: Arc<AtomicBool>,
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl SmartSession {
    pub fn new(id: u32, addr: String, stream: tokio::net::TcpStream) -> Self {
        let (reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));
        let alive = Arc::new(AtomicBool::new(true));
        let shell_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let ctrl_queue: CtrlQueue = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let in_file_transfer = Arc::new(AtomicBool::new(false));

        let shell_clone = Arc::clone(&shell_buf);
        let ctrl_clone = Arc::clone(&ctrl_queue);
        let alive_clone = Arc::clone(&alive);
        let ift_clone = Arc::clone(&in_file_transfer);

        let reader_handle = tokio::spawn(async move {
            let mut r = reader;
            loop {
                let (ftype, payload) = match frame::read_frame(&mut r).await {
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

    pub fn info(&self) -> ShellInfo {
        ShellInfo { id: self.id, addr: format!("[ww-target] {}", self.addr), created: self.created, alive: self.alive.load(Ordering::SeqCst) }
    }

    pub fn close(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self._reader_handle.abort();
    }
}

// ── Web shell session ─────────────────────────────────────────────────────

#[cfg(feature = "web")]
pub struct WebShellSession {
    pub id: u32,
    pub url: String,
    pub injection_point: String,
    pub method: String,
    pub body_template: Option<String>,
    pub headers: Vec<String>,
    pub cookie: Option<String>,
    created: f64,
    pub alive: Arc<AtomicBool>,
    pub buf: Arc<Mutex<Vec<u8>>>,
}

#[cfg(feature = "web")]
impl WebShellSession {
    pub fn new(id: u32, config: wirewrench::WebShellConfig) -> Self {
        Self {
            id, url: config.url, injection_point: config.injection_point, method: config.method,
            body_template: config.body_template, headers: config.headers, cookie: config.cookie,
            created: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            alive: Arc::new(AtomicBool::new(true)),
            buf: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn info(&self) -> ShellInfo {
        ShellInfo { id: self.id, addr: format!("[web] {}", self.url), created: self.created, alive: self.alive.load(Ordering::SeqCst) }
    }
}

// ── Managed session enum ─────────────────────────────────────────────────

pub enum ManagedSession {
    Tcp(ShellSession, Arc<Mutex<Vec<u8>>>),
    Smart(SmartSession),
    #[cfg(feature = "web")]
    Web(WebShellSession),
}

impl ManagedSession {
    pub fn info(&self) -> ShellInfo {
        match self {
            ManagedSession::Tcp(s, _) => s.info(),
            ManagedSession::Smart(s) => s.info(),
            #[cfg(feature = "web")]
            ManagedSession::Web(s) => s.info(),
        }
    }

    pub fn alive(&self) -> bool {
        match self {
            ManagedSession::Tcp(s, _) => s.alive.load(Ordering::SeqCst),
            ManagedSession::Smart(s) => s.alive.load(Ordering::SeqCst),
            #[cfg(feature = "web")]
            ManagedSession::Web(s) => s.alive.load(Ordering::SeqCst),
        }
    }

    pub fn close(&mut self) {
        match self {
            ManagedSession::Tcp(s, _) => s.close(),
            ManagedSession::Smart(s) => s.close(),
            #[cfg(feature = "web")]
            ManagedSession::Web(_) => {}
        }
    }
}

// ── Session manager ───────────────────────────────────────────────────────

pub struct SessionManager {
    pub sessions: HashMap<u32, ManagedSession>,
    next_id: u32,
}

impl SessionManager {
    pub fn new() -> Self {
        Self { sessions: HashMap::new(), next_id: 1 }
    }

    pub fn add_tcp(&mut self, addr: String, stream: tokio::net::TcpStream) -> u32 {
        let id = self.next_id; self.next_id += 1;
        let (session, buf) = ShellSession::new(id, addr, stream);
        self.sessions.insert(id, ManagedSession::Tcp(session, buf)); id
    }

    pub fn add_smart(&mut self, addr: String, stream: tokio::net::TcpStream) -> u32 {
        let id = self.next_id; self.next_id += 1;
        let session = SmartSession::new(id, addr, stream);
        self.sessions.insert(id, ManagedSession::Smart(session)); id
    }

    #[cfg(feature = "web")]
    pub fn add_web(&mut self, config: wirewrench::WebShellConfig) -> u32 {
        let id = self.next_id; self.next_id += 1;
        self.sessions.insert(id, ManagedSession::Web(WebShellSession::new(id, config))); id
    }

    pub fn remove(&mut self, id: u32) {
        if let Some(mut s) = self.sessions.remove(&id) {
            s.close();
        }
    }

    pub fn list(&self) -> Vec<ShellInfo> {
        self.sessions.values().map(|s| s.info()).collect()
    }
}
