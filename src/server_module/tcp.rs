use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::target::protocol;
use crate::server_module::sessions::SessionManager;

pub async fn tcp_listener(manager: Arc<Mutex<SessionManager>>, host: &str, port: u16) -> Result<()> {
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind TCP on {}", addr))?;
    eprintln!("[+] Listening for reverse shells on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let mgr = Arc::clone(&manager);
                let addr = peer.to_string();
                tokio::spawn(async move {
                    handle_connection(mgr, stream, addr).await;
                });
            }
            Err(e) => eprintln!("[-] Accept error: {}", e),
        }
    }
}

async fn handle_connection(manager: Arc<Mutex<SessionManager>>, mut stream: TcpStream, addr: String) {
    let mut peek_buf = [0u8; 4096];
    let peek_result = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut peek_buf)).await;

    match peek_result {
        Ok(Ok(0)) => return,
        Ok(Ok(n)) => {
            let data = &peek_buf[..n];
            if let Some(nl_pos) = data.iter().position(|&b| b == b'\n') {
                if let Ok(line) = std::str::from_utf8(&data[..nl_pos]) {
                    if protocol::is_handshake(line) {
                        let id = {
                            let mut mg = manager.lock().await;
                            mg.add_target(addr.clone(), stream, vec![]).await
                        };
                        eprintln!("[+] [ww-target] Session #{} from {}", id, addr);
                        loop {
                            let alive = { let mg = manager.lock().await; mg.sessions.get(&id).map(|s| s.alive()).unwrap_or(false) };
                            if !alive { break; }
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                        let mut mg = manager.lock().await; mg.remove(id);
                        eprintln!("[-] [ww-target] Session #{} disconnected", id);
                        return;
                    }
                }
            }
            let id = { let mut mg = manager.lock().await; mg.add_tcp(addr.clone(), stream, data.to_vec()) };
            eprintln!("[+] Shell #{} caught from {}", id, addr);
            loop {
                let alive = { let mg = manager.lock().await; mg.sessions.get(&id).map(|s| s.alive()).unwrap_or(false) };
                if !alive { break; }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let mut mg = manager.lock().await; mg.remove(id);
            eprintln!("[-] Shell #{} disconnected", id);
        }
        _ => {
            let id = { let mut mg = manager.lock().await; mg.add_tcp(addr.clone(), stream, vec![]) };
            eprintln!("[+] Shell #{} caught from {}", id, addr);
            loop {
                let alive = { let mg = manager.lock().await; mg.sessions.get(&id).map(|s| s.alive()).unwrap_or(false) };
                if !alive { break; }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let mut mg = manager.lock().await; mg.remove(id);
            eprintln!("[-] Shell #{} disconnected", id);
        }
    }
}
