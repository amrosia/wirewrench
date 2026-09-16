use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, mpsc, oneshot};

use wirewrench::target::protocol;
use wirewrench::ShellInfo;

use super::frame;

/// Control-message queue: (`message_type`, payload) pairs from a ww-target session.
pub type CtrlQueue = Arc<Mutex<std::collections::VecDeque<(u8, Vec<u8>)>>>;

// ── TCP shell session (dumb reverse shell) ────────────────────────────────

pub struct ShellSession {
    id: u32,
    addr: String,
    created: f64,
    pub alive: Arc<AtomicBool>,
    pub writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    reader_handle: tokio::task::JoinHandle<()>,
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
                    Ok(0) | Err(_) => { alive_clone.store(false, Ordering::SeqCst); break; }
                    Ok(n) => { let mut b = buf_clone.lock().await; b.extend_from_slice(&tmp[..n]); }
                }
            }
        });

        let session = Self {
            id, addr,
            created: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            alive: Arc::clone(&alive),
            writer: Arc::new(Mutex::new(writer)),
            reader_handle,
        };
        (session, buf)
    }

    pub fn info(&self) -> ShellInfo {
        ShellInfo { id: self.id, addr: self.addr.clone(), created: self.created, alive: self.alive.load(Ordering::SeqCst), platform: None }
    }

    pub fn close(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self.reader_handle.abort();
    }
}

// ── Smart session (ww-target on port 4446) ─────────────────────────────────

pub type PendingCmds = Arc<Mutex<HashMap<u64, oneshot::Sender<protocol::CmdResult>>>>;

/// Events delivered from a ww-target session's reader task to a tunnel relay.
pub enum TunnelEvent {
    Opened(protocol::TunnelOpened),
    Data(Vec<u8>),
    Eof,
    Closed(String),
}

/// One tunnel stream: the event channel to its relay plus the reason the
/// sender was dropped, if it had to be (so the relay can report an accurate
/// close reason instead of guessing).
pub struct TunnelEntry {
    pub tx: mpsc::Sender<TunnelEvent>,
    pub overflow: Arc<std::sync::Mutex<Option<String>>>,
}

impl TunnelEntry {
    #[must_use]
    pub fn new(tx: mpsc::Sender<TunnelEvent>, overflow: Arc<std::sync::Mutex<Option<String>>>) -> Self {
        Self { tx, overflow }
    }
}

/// The reason recorded for a dropped entry, if any.
#[must_use]
pub fn overflow_reason(overflow: &std::sync::Mutex<Option<String>>) -> Option<String> {
    overflow.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
}

/// Depth of one stream's event queue (a full queue resets that stream only).
pub const TUNNEL_EVENT_QUEUE: usize = 64;

pub type Tunnels = Arc<Mutex<HashMap<u32, TunnelEntry>>>;

/// Deliver a tunnel event to its relay.  When the relay is gone or too slow
/// the sender is dropped — which unblocks it — and the reason is recorded so
/// the relay reports "consumer too slow" rather than "session closed".
async fn deliver_tunnel(tunnels: &Tunnels, stream_id: u32, event: TunnelEvent) {
    let mut map = tunnels.lock().await;
    let Some(entry) = map.get(&stream_id) else { return };
    if entry.tx.try_send(event).is_err() {
        let overflow = Arc::clone(&entry.overflow);
        map.remove(&stream_id);
        *overflow.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some("consumer too slow".to_string());
    }
}

pub struct SmartSession {
    id: u32,
    addr: String,
    created: f64,
    platform: Option<String>,
    /// Capabilities advertised by the target during the handshake.
    #[allow(dead_code)] // kept for introspection; `supports_tunnels` is derived
    pub features: Vec<String>,
    pub supports_tunnels: bool,
    pub writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    pub shell_buf: Arc<Mutex<Vec<u8>>>,
    pub ctrl_queue: CtrlQueue,
    pub alive: Arc<AtomicBool>,
    pub in_file_transfer: Arc<AtomicBool>,
    pub next_cmd_seq: AtomicU64,
    pub pending_cmds: PendingCmds,
    pub tunnels: Tunnels,
    pub next_stream_id: AtomicU32,
    reader_handle: tokio::task::JoinHandle<()>,
}

impl SmartSession {
    pub fn new(id: u32, addr: String, platform: Option<String>, features: Vec<String>, stream: tokio::net::TcpStream) -> Self {
        let (reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));
        let alive = Arc::new(AtomicBool::new(true));
        let shell_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let ctrl_queue: CtrlQueue = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let in_file_transfer = Arc::new(AtomicBool::new(false));
        let pending_cmds: PendingCmds = Arc::new(Mutex::new(HashMap::new()));
        let supports_tunnels = features.iter().any(|f| f == protocol::FEATURE_TUNNEL);
        let tunnels: Tunnels = Arc::new(Mutex::new(HashMap::new()));

        let shell_clone = Arc::clone(&shell_buf);
        let ctrl_clone = Arc::clone(&ctrl_queue);
        let alive_clone = Arc::clone(&alive);
        let ift_clone = Arc::clone(&in_file_transfer);
        let pending_clone = Arc::clone(&pending_cmds);
        let tunnels_clone = Arc::clone(&tunnels);

        let reader_handle = tokio::spawn(async move {
            let mut r = reader;
            loop {
                let Ok((ftype, payload)) = frame::read_frame(&mut r).await else { alive_clone.store(false, Ordering::SeqCst); break; };
                match ftype {
                    protocol::FRAME_SHELL => {
                        let mut b = shell_clone.lock().await;
                        b.extend_from_slice(&payload);
                    }
                    protocol::FRAME_FILE_CTRL | protocol::FRAME_FILE_DATA | protocol::FRAME_HASH => {
                        let mut q = ctrl_clone.lock().await;
                        q.push_back((ftype, payload));
                    }
                    protocol::FRAME_CMD_RESULT => {
                        if let Ok(result) = serde_json::from_slice::<protocol::CmdResult>(&payload) {
                            let mut map = pending_clone.lock().await;
                            if let Some(tx) = map.remove(&result.seq) {
                                let _ = tx.send(result);
                            }
                        }
                    }
                    protocol::FRAME_CANCEL => {
                        ift_clone.store(false, Ordering::SeqCst);
                    }
                    protocol::FRAME_TUNNEL_OPENED => {
                        if let Ok(opened) = serde_json::from_slice::<protocol::TunnelOpened>(&payload) {
                            let id = opened.stream_id;
                            deliver_tunnel(&tunnels_clone, id, TunnelEvent::Opened(opened)).await;
                        }
                    }
                    protocol::FRAME_TUNNEL_DATA => {
                        if let Some(id) = protocol::tunnel_stream_id(&payload) {
                            deliver_tunnel(&tunnels_clone, id, TunnelEvent::Data(payload[4..].to_vec())).await;
                        }
                    }
                    protocol::FRAME_TUNNEL_EOF => {
                        if let Some(id) = protocol::tunnel_stream_id(&payload) {
                            deliver_tunnel(&tunnels_clone, id, TunnelEvent::Eof).await;
                        }
                    }
                    protocol::FRAME_TUNNEL_CLOSE => {
                        if let Ok(close) = serde_json::from_slice::<protocol::TunnelClose>(&payload) {
                            deliver_tunnel(&tunnels_clone, close.stream_id, TunnelEvent::Closed(close.reason)).await;
                        }
                    }
                    _ => {}
                }
            }
            // Session death must wake every relay blocked in `recv()`.  Drop
            // all senders so each relay sees `None` and closes its control
            // connection.
            tunnels_clone.lock().await.clear();
        });

        Self { id, addr, created: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(), platform, features, supports_tunnels, writer, shell_buf, ctrl_queue, alive, in_file_transfer, next_cmd_seq: AtomicU64::new(1), pending_cmds, tunnels, next_stream_id: AtomicU32::new(1), reader_handle }
    }

    pub fn info(&self) -> ShellInfo {
        ShellInfo { id: self.id, addr: format!("[ww-target] {}", self.addr), created: self.created, alive: self.alive.load(Ordering::SeqCst), platform: self.platform.clone() }
    }

    pub fn close(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self.reader_handle.abort();
    }
}

// ── Managed session enum ─────────────────────────────────────────────────

pub enum ManagedSession {
    Tcp(ShellSession, Arc<Mutex<Vec<u8>>>),
    Smart(SmartSession),
}

impl ManagedSession {
    pub fn info(&self) -> ShellInfo {
        match self {
            ManagedSession::Tcp(s, _) => s.info(),
            ManagedSession::Smart(s) => s.info(),
        }
    }

    pub fn alive(&self) -> bool {
        match self {
            ManagedSession::Tcp(s, _) => s.alive.load(Ordering::SeqCst),
            ManagedSession::Smart(s) => s.alive.load(Ordering::SeqCst),
        }
    }

    pub fn close(&mut self) {
        match self {
            ManagedSession::Tcp(s, _) => s.close(),
            ManagedSession::Smart(s) => s.close(),
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

    pub fn add_smart(&mut self, addr: String, platform: Option<String>, features: Vec<String>, stream: tokio::net::TcpStream) -> u32 {
        let id = self.next_id; self.next_id += 1;
        let session = SmartSession::new(id, addr, platform, features, stream);
        self.sessions.insert(id, ManagedSession::Smart(session)); id
    }

    pub fn remove(&mut self, id: u32) {
        if let Some(mut s) = self.sessions.remove(&id) {
            s.close();
        }
    }

    pub fn list(&self) -> Vec<ShellInfo> {
        self.sessions.values().map(ManagedSession::info).collect()
    }
}
