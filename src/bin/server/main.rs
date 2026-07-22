mod frame;
mod session;
mod shells;
mod handlers;

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use wirewrench::{DEFAULT_PORT, DEFAULT_SMART_PORT, DEFAULT_SOCKET};

use session::SessionManager;

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

// ── Control server (Unix socket) ─────────────────────────────────────────

async fn control_server(manager: Arc<Mutex<SessionManager>>, socket_path: &str) -> Result<()> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind Unix socket at {socket_path}"))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o777))?;
    eprintln!("[+] Control socket at {socket_path}");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let mgr = Arc::clone(&manager);
                tokio::spawn(async move {
                    if let Err(e) = handlers::handle_control(stream, mgr).await {
                        eprintln!("[-] Control handler error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[-] Control accept error: {e}"),
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
        if let Err(e) = shells::tcp_listener(mgr1, &host1, args.port).await {
            eprintln!("[-] TCP listener error: {e}");
        }
    });

    let mgr2 = Arc::clone(&manager);
    let host2 = args.host.clone();
    tokio::spawn(async move {
        if let Err(e) = shells::smart_listener(mgr2, &host2, args.smart_port).await {
            eprintln!("[-] Smart listener error: {e}");
        }
    });

    let sock = args.socket.clone();
    control_server(manager, &sock).await
}
