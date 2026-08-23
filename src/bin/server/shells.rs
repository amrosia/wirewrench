use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use wirewrench::target::protocol;

use super::frame;
use super::session::{ManagedSession, SessionManager};

// ── TCP listener for dumb shells (port 4444) ──────────────────────────────

pub async fn tcp_listener(manager: Arc<Mutex<SessionManager>>, host: &str, port: u16) -> Result<()> {
    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind TCP on {addr}"))?;
    eprintln!("[+] Listening for reverse shells on {addr}");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let addr = peer.to_string();
                let mgr = Arc::clone(&manager);
                tokio::spawn(async move {
                    let id = { let mut mg = mgr.lock().await; mg.add_tcp(addr.clone(), stream) };
                    eprintln!("[+] Shell #{id} caught from {addr}");
                    wait_for_disconnect(&mgr, id, None).await;
                });
            }
            Err(e) => eprintln!("[-] Accept error: {e}"),
        }
    }
}

// ── Smart listener for ww-target (port 4446) ──────────────────────────────

pub async fn smart_listener(manager: Arc<Mutex<SessionManager>>, host: &str, port: u16) -> Result<()> {
    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind smart port on {addr}"))?;
    eprintln!("[+] Listening for ww-target on {addr}");

    loop {
        match listener.accept().await {
            Ok((mut stream, peer)) => {
                let addr = peer.to_string();
                let mgr = Arc::clone(&manager);
                tokio::spawn(async move {
                    // Read handshake frame
                    let (ftype, payload) = match frame::read_frame(&mut stream).await {
                        Ok(v) => v,
                        Err(e) => { eprintln!("[-] Smart handshake read error: {e}"); return; }
                    };
                    if ftype != protocol::FRAME_HANDSHAKE {
                        eprintln!("[-] Expected handshake from {addr}, got frame {ftype}");
                        return;
                    }
                    let hs: protocol::Handshake = match serde_json::from_slice(&payload) {
                        Ok(h) => h,
                        Err(e) => { eprintln!("[-] Invalid handshake from {addr}: {e}"); return; }
                    };

                    let id = { let mut mg = mgr.lock().await; mg.add_smart(addr.clone(), stream) };

                    // Send handshake response
                    let session_id = uuid::Uuid::new_v4().to_string();
                    let resp = protocol::Handshake::new_server(session_id);
                    let res = {
                        let mg = mgr.lock().await;
                        match mg.sessions.get(&id) {
                            Some(ManagedSession::Smart(s)) => {
                                let mut w = s.writer.lock().await;
                                frame::write_json_frame(&mut *w, protocol::FRAME_HANDSHAKE, &resp).await
                            }
                            _ => Ok(()),
                        }
                    }; match res {
                        Ok(()) => eprintln!("[+] [ww-target] Session #{} from {} ({})", id, addr, hs.hostname.as_deref().unwrap_or("?")),
                        Err(e) => { eprintln!("[-] Failed to send handshake to #{id}: {e}"); return; }
                    }

                    wait_for_disconnect(&mgr, id, Some("target")).await;
                });
            }
            Err(e) => eprintln!("[-] Smart accept error: {e}"),
        }
    }
}

/// Wait for a session to become dead, then remove it.
async fn wait_for_disconnect(manager: &Arc<Mutex<SessionManager>>, id: u32, kind: Option<&str>) {
    loop {
        let alive = { let mg = manager.lock().await; mg.sessions.get(&id).is_some_and(super::session::ManagedSession::alive) };
        if !alive { break; }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    {
        let mut mg = manager.lock().await;
        mg.remove(id);
    }
    match kind {
        Some(k) => eprintln!("[-] [ww-{k}] Session #{id} disconnected"),
        None => eprintln!("[-] Shell #{id} disconnected"),
    }
}

// ── Generic polling helpers ──────────────────────────────────────────────────

/// Poll a `Mutex`-protected resource with a timeout, sleeping 50ms between attempts.
/// Returns `None` if the timeout expires before the extractor returns `Some`.
async fn poll_with_timeout<T, R>(
    resource: &Mutex<T>,
    timeout: f64,
    extract: impl Fn(&mut T) -> Option<R>,
) -> Option<R> {
    let start = std::time::Instant::now();
    loop {
        let mut guard = resource.lock().await;
        if let Some(result) = extract(&mut guard) {
            return Some(result);
        }
        drop(guard);
        if start.elapsed().as_secs_f64() >= timeout {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Read available bytes from a buffer, clearing it, up to `timeout` seconds.
pub async fn read_from_buf(buf: &Mutex<Vec<u8>>, timeout: f64) -> String {
    poll_with_timeout(buf, timeout, |b| {
        if b.is_empty() {
            None
        } else {
            let s = String::from_utf8_lossy(b).to_string();
            b.clear();
            Some(s)
        }
    })
    .await
    .unwrap_or_default()
}

/// Pop the next item from a control-queue, waiting up to `timeout` seconds.
pub async fn read_ctrl_queue_msg(
    q: &Mutex<std::collections::VecDeque<(u8, Vec<u8>)>>,
    timeout: f64,
) -> Option<(u8, Vec<u8>)> {
    poll_with_timeout(q, timeout, std::collections::VecDeque::pop_front).await
}
