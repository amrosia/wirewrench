#[cfg(not(unix))]
compile_error!("ww-server is only intended to be built for unix platforms");

mod frame;
mod session;
mod shells;
mod handlers;
mod auth;
#[path = "../config.rs"]
mod config;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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

    /// Also accept `ww` control connections over TCP on this port (e.g. `ww -H host:4445`)
    #[arg(short = 'c', long = "control-port")]
    control_port: Option<u16>,

    /// Public key(s) authorized on the control port: a file or folder in ssh
    /// `authorized_keys` format.  Requires --control-port.
    #[arg(short = 'k', long = "auth-keys")]
    auth_keys: Option<String>,
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
                    if let Err(e) = handlers::handle_control_unix(stream, mgr).await {
                        eprintln!("[-] Control handler error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[-] Control accept error: {e}"),
        }
    }
}

// ── Control server (TCP, optional) ─────────────────────────────────────────

/// Optional TCP listener for `ww` client control connections
/// (`ww-server --control-port`).  The Unix socket is always served too.
async fn control_tcp_server(
    manager: Arc<Mutex<SessionManager>>,
    host: &str,
    port: u16,
    auth_keys_path: Option<Arc<PathBuf>>,
) -> Result<()> {
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind control TCP at {addr}"))?;
    eprintln!("[+] Control TCP listener at {addr} (connect with `ww -H {host}:{port}`)");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let mgr = Arc::clone(&manager);
                let keys = auth_keys_path.clone();
                tokio::spawn(async move {
                    if let Err(e) = handlers::handle_control_tcp(stream, mgr, keys).await {
                        eprintln!("[-] Control TCP handler error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[-] Control TCP accept error: {e}"),
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Resolve the authorized-keys path: CLI --auth-keys wins over server.conf.
    let auth_keys_path: Option<PathBuf> = match &args.auth_keys {
        Some(p) => Some(PathBuf::from(p)),
        None => config::Config::load("server.conf")
            .and_then(|c| c.get("control_public_keys").map(|v| PathBuf::from(config::expand_tilde(v)))),
    };

    if args.auth_keys.is_some() && args.control_port.is_none() {
        anyhow::bail!("--auth-keys requires --control-port");
    }

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

    if let Some(control_port) = args.control_port {
        if let Some(ref p) = auth_keys_path {
            let n = auth::load_authorized_keys(p)
                .with_context(|| format!("invalid --auth-keys path '{}'", p.display()))?
                .len();
            eprintln!("[+] Control TCP auth enabled ({n} key(s) from {})", p.display());
        } else {
            eprintln!("[!] ⚠ WARNING: control TCP listener on {}:{} is running WITHOUT authentication", args.host, control_port);
            eprintln!("[!]   Anyone who can reach this port can run commands on your shells.");
            eprintln!("[!]   Enable key auth: --auth-keys <FILE|DIR>, or set control_public_keys in");
            eprintln!("[!]   ~/.config/wirewrench/server.conf");
        }
        let mgr3 = Arc::clone(&manager);
        let host3 = args.host.clone();
        let keys = auth_keys_path.map(Arc::new);
        tokio::spawn(async move {
            if let Err(e) = control_tcp_server(mgr3, &host3, control_port, keys).await {
                eprintln!("[-] Control TCP listener error: {e}");
            }
        });
    } else {
        eprintln!("[+] Control TCP disabled (use --control-port, e.g. -c 4445)");
    }

    let sock = args.socket.clone();
    control_server(manager, &sock).await
}
