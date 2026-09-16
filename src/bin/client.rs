#[cfg(not(unix))]
compile_error!("ww is only intended to be built for unix platforms");

#[path = "config.rs"]
mod config;

use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use ssh_key::private::PrivateKey;
use signature::{SignatureEncoding, Signer};

use wirewrench::auth as wauth;
use wirewrench::DEFAULT_SOCKET;

#[derive(Parser)]
#[command(name = "ww", about = "Interact with managed reverse shells")]
struct Cli {
    /// Unix control socket path
    #[arg(short = 's', long, default_value = DEFAULT_SOCKET)]
    socket: String,

    /// Connect over TCP instead of the Unix socket, as HOST:PORT (e.g. 10.0.0.5:4445).
    /// The port is required — there is no default control port.  Overrides
    /// `host` in client.conf.
    #[arg(short = 'H', long)]
    host: Option<String>,

    /// Private key for control-port authentication (like `ssh -i`); defaults
    /// to `identity` in ~/.config/wirewrench/client.conf
    #[arg(short = 'i', long)]
    identity: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List active shells
    List,
    /// Send a command to a shell and return output
    Send {
        id: u32,
        /// Read command from stdin instead of positional argument
        #[arg(short = 's', long)]
        stdin: bool,
        /// Timeout in seconds before giving up on output (default: 0 = no timeout for ww-target; dumb shells still default to 3s)
        #[arg(short = 't', long, default_value = "0.0")]
        timeout: f64,
        /// Command to execute (all remaining arguments, no extra quoting needed)
        #[arg(trailing_var_arg = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Interact with a shell (Ctrl+C to detach)
    Interact { id: u32 },
    /// Close/kill a shell
    Close { id: u32 },
    /// Run commands from a plain-text script file, one command per line
    ///
    /// Lines starting with `#` are treated as comments and skipped.
    /// Empty lines are also skipped.  Each command is sent to the shell
    /// sequentially (with a 300 ms delay between them) and its output
    /// is printed to stdout.
    ///
    /// The file is a simple list of commands — not a shell script.
    /// Pipes, redirects, variables, and other shell syntax are passed
    /// verbatim to the remote shell and are NOT interpreted locally.
    Script { id: u32, file: String },
    /// Target (ww-target) operations: push, pull, cancel
    Targ {
        #[command(subcommand)]
        action: TargAction,
    },
    /// Forward a local TCP port to a host reachable by the target
    Forward {
        id: u32,
        /// Local listen spec: `[bind:]lport:host:port` (default bind 127.0.0.1)
        #[arg(short = 'L', long = "listen")]
        listen: String,
        /// Seconds to wait for the target to connect (default 10)
        #[arg(short = 't', long, default_value_t = 10.0)]
        timeout: f64,
    },
    /// SOCKS5 / HTTP CONNECT proxy through the target
    Socks {
        id: u32,
        /// Local listen address
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
        /// Resolve destination names locally instead of on the target
        #[arg(long)]
        local_dns: bool,
        /// Require SOCKS5 username/password auth (RFC 1929)
        #[arg(long)]
        socks_user: Option<String>,
        /// SOCKS5 password (use with --socks-user)
        #[arg(long)]
        socks_pass: Option<String>,
        /// Disable HTTP CONNECT; only speak SOCKS5
        #[arg(long)]
        socks_only: bool,
        /// Seconds to wait for the target to connect (default 10)
        #[arg(long, default_value_t = 10.0)]
        connect_timeout: f64,
        /// Stop the listener if the target session disconnects
        #[arg(long)]
        exit_on_disconnect: bool,
    },
}

#[derive(Subcommand)]
enum TargAction {
    /// Upload a file to the target
    Upload {
        id: u32,
        local: String,
        remote: Option<String>,
        #[arg(short = 't', long, default_value = "30.0")]
        timeout: f64,
    },
    /// Download a file from the target
    Download {
        id: u32,
        remote: String,
        local: Option<String>,
        #[arg(short = 't', long, default_value = "30.0")]
        timeout: f64,
    },
    /// Cancel an ongoing file transfer
    Cancel {
        id: u32,
    },
}

// ── Connection (Unix socket or TCP) ────────────────────────────────────────

/// A connection to `ww-server`: either the Unix control socket or the
/// optional TCP control port (`ww-server --control-port`).
enum ClientStream {
    Unix(std::os::unix::net::UnixStream),
    Tcp(std::net::TcpStream),
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ClientStream::Unix(s) => s.read(buf),
            ClientStream::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ClientStream::Unix(s) => s.write(buf),
            ClientStream::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ClientStream::Unix(s) => s.flush(),
            ClientStream::Tcp(s) => s.flush(),
        }
    }
}

impl ClientStream {
    fn try_clone(&self) -> std::io::Result<ClientStream> {
        match self {
            ClientStream::Unix(s) => s.try_clone().map(ClientStream::Unix),
            ClientStream::Tcp(s) => s.try_clone().map(ClientStream::Tcp),
        }
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            ClientStream::Unix(s) => s.set_read_timeout(dur),
            ClientStream::Tcp(s) => s.set_read_timeout(dur),
        }
    }

    fn shutdown_write(&self) -> std::io::Result<()> {
        match self {
            ClientStream::Unix(s) => s.shutdown(std::net::Shutdown::Write),
            ClientStream::Tcp(s) => s.shutdown(std::net::Shutdown::Write),
        }
    }
}

/// Open a raw TCP connection to `host:port`.
fn tcp_connect(host: &str, port: u16) -> Result<ClientStream> {
    let stream = std::net::TcpStream::connect((host, port))
        .with_context(|| format!("Cannot connect to '{host}:{port}'. Is ww-server running with --control-port?"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(ClientStream::Tcp(stream))
}

/// Open the Unix control socket.
fn unix_connect(socket: &str) -> Result<ClientStream> {
    let stream = std::os::unix::net::UnixStream::connect(Path::new(socket))
        .with_context(|| format!("Cannot connect to '{socket}'. Is ww-server running?"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(ClientStream::Unix(stream))
}

/// Resolved client connection settings plus private keys loaded once.
#[derive(Clone)]
struct ClientConfig {
    /// `Some((host, port))` for the TCP control channel; `None` for the Unix socket.
    host: Option<(String, u16)>,
    socket: String,
    ids: Identities,
}

/// Private keys loaded once and reused for every control connection.
#[derive(Clone)]
struct Identities(Arc<Vec<(PrivateKey, ssh_key::PublicKey)>>);

impl Identities {
    fn empty() -> Self {
        Self(Arc::new(Vec::new()))
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ClientConfig {
    /// Resolve the control target (CLI `--host` / client.conf) and load any
    /// configured private keys once.
    fn resolve(cli: &Cli) -> Result<Self> {
        let host = match resolve_host(cli)? {
            Some(addr) => {
                let label = if cli.host.is_some() { "--host" } else { "client.conf 'host'" };
                Some(parse_host_port(&addr, label)?)
            }
            None => None,
        };
        let ids = if host.is_some() {
            load_identities(cli)?
        } else {
            Identities::empty()
        };
        Ok(Self { host, socket: cli.socket.clone(), ids })
    }

    /// Open a control connection.  When a host is configured, connects and
    /// authenticates over TCP; otherwise the Unix socket path is used (never
    /// authenticated).
    fn connect(&self) -> Result<ClientStream> {
        if let Some((host, port)) = &self.host {
            let mut stream = tcp_connect(host, *port)?;
            if self.ids.is_empty() {
                return Ok(stream);
            }
            match auth_handshake(&mut stream, &self.ids)? {
                AuthOutcome::Authenticated => Ok(stream),
                AuthOutcome::ProceedNoAuth => {
                    eprintln!("info: you specified a key but the server does not use authentication — proceeding without key");
                    Ok(stream)
                }
                AuthOutcome::Reconnect => {
                    eprintln!("info: you specified a key but the server does not use authentication — proceeding without key");
                    tcp_connect(host, *port)
                }
            }
        } else {
            unix_connect(&self.socket)
        }
    }
}

/// Load all configured private keys once (`-i`, or client.conf `identity`).
fn load_identities(cli: &Cli) -> Result<Identities> {
    let paths = resolve_identities(cli)?;
    let mut keys = Vec::new();
    for path in paths {
        keys.push(load_private_key(&path)?);
    }
    Ok(Identities(Arc::new(keys)))
}

/// Resolve the control target: `-H/--host` if given, otherwise the `host =`
/// line in client.conf.  CLI takes precedence over config.
fn resolve_host(cli: &Cli) -> Result<Option<String>> {
    if let Some(h) = &cli.host {
        return Ok(Some(h.clone()));
    }
    if let Some(cfg) = config::Config::load("client.conf")
        && let Some(h) = cfg.get("host")
    {
        return Ok(Some(config::expand_tilde(h)));
    }
    Ok(None)
}

/// Resolve private-key identities: `-i/--identity` if given, otherwise the
/// `identity =` lines in client.conf (possibly several, tried in order).
fn resolve_identities(cli: &Cli) -> Result<Vec<String>> {
    if let Some(i) = &cli.identity {
        return Ok(vec![i.clone()]);
    }
    if let Some(cfg) = config::Config::load("client.conf") {
        return Ok(cfg
            .get_all("identity")
            .into_iter()
            .map(|p| config::expand_tilde(&p))
            .collect());
    }
    Ok(Vec::new())
}

/// Prompt for a passphrase on the terminal (no echo).  Errors if stdin is not
/// a terminal.
fn prompt_passphrase(path: &str) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("identity '{path}' is passphrase-encrypted; cannot prompt without a terminal");
    }
    rpassword::prompt_password(format!("Passphrase for '{path}': "))
        .map_err(|e| anyhow::anyhow!("failed to read passphrase: {e}"))
}

/// Load a private key, prompting for a passphrase (up to 3 attempts) if it is
/// encrypted.
fn load_private_key(path: &str) -> Result<(PrivateKey, ssh_key::PublicKey)> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read identity file '{path}'"))?;
    let mut key = PrivateKey::from_openssh(pem.as_bytes())
        .with_context(|| format!("cannot parse identity '{path}'"))?;
    if key.is_encrypted() {
        for _ in 0..3 {
            let pw = prompt_passphrase(path)?;
            if let Ok(dec) = key.decrypt(pw.as_bytes()) {
                key = dec;
                break;
            }
        }
        if key.is_encrypted() {
            anyhow::bail!("wrong passphrase for identity '{path}'");
        }
    }
    let public_key = key.public_key().clone();
    Ok((key, public_key))
}

/// Result of the client-side auth handshake.
enum AuthOutcome {
    /// Authenticated; the connection is ready for commands.
    Authenticated,
    /// Server said auth isn't required (`auth_not_required`); same connection
    /// is ready for commands.
    ProceedNoAuth,
    /// Server doesn't speak auth (old server); the caller must reconnect.
    Reconnect,
}

/// Write a JSON value as a line to a client stream.
fn write_line(stream: &mut ClientStream, val: &Value) -> Result<()> {
    let j = serde_json::to_string(val)? + "\n";
    stream.write_all(j.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// Read a single JSON line from a client stream.
fn read_line_json(stream: &mut ClientStream) -> Result<Value> {
    let mut reader = BufReader::new(&mut *stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.is_empty() {
        anyhow::bail!("connection closed by server");
    }
    serde_json::from_str(line.trim())
        .map_err(|e| anyhow::anyhow!("invalid server response: {e}"))
}

/// Perform the SSH-style auth handshake over an already-connected TCP stream.
fn auth_handshake(stream: &mut ClientStream, ids: &Identities) -> Result<AuthOutcome> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut tried = 0usize;
    let mut last_fp = String::new();

    for (private_key, public_key) in ids.0.iter() {
        let openssh = public_key
            .to_openssh()
            .map_err(|e| anyhow::anyhow!("failed to encode public key: {e}"))?;

        write_line(stream, &serde_json::json!({"type":"auth_offer","key": openssh}))?;
        let resp = match read_line_json(stream) {
            Ok(v) => v,
            Err(_) => return Ok(AuthOutcome::Reconnect), // old server closed the connection
        };

        match resp["type"].as_str() {
            Some("auth_challenge") => {
                let challenge = wauth::b64_decode(resp["challenge"].as_str().unwrap_or(""))
                    .ok_or_else(|| anyhow::anyhow!("invalid challenge from server"))?;
                let key_blob = public_key
                    .to_bytes()
                    .map_err(|e| anyhow::anyhow!("failed to encode public key: {e}"))?;
                let payload = wauth::signed_payload(&challenge, &key_blob);
                let sig: ssh_key::Signature = Signer::try_sign(private_key, &payload)
                    .map_err(|e| anyhow::anyhow!("signing failed: {e}"))?;
                let sig_b64 = wauth::b64_encode(&sig.to_vec());
                write_line(stream, &serde_json::json!({"type":"auth_sign","signature": sig_b64}))?;
                let resp2 = read_line_json(stream)
                    .map_err(|_| anyhow::anyhow!("connection closed during authentication"))?;
                if resp2["status"] == "ok" {
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    return Ok(AuthOutcome::Authenticated);
                }
                let msg = resp2["message"].as_str().unwrap_or("authentication failed");
                anyhow::bail!("{msg}");
            }
            Some("auth_reject") => {
                tried += 1;
                last_fp = public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
                continue;
            }
            Some("auth_not_required") => return Ok(AuthOutcome::ProceedNoAuth),
            _ => return Ok(AuthOutcome::Reconnect), // unexpected / old server
        }
    }

    if tried == 0 {
        anyhow::bail!("no usable identities");
    }
    anyhow::bail!("server rejected public key {last_fp} (tried {tried} key(s))")
}

/// Parse a `HOST:PORT` string (e.g. `10.0.0.5:4445` or `[::1]:4445`).
/// A port is mandatory — there is no default.  `label` names the value's
/// source for error messages (`--host` or `client.conf 'host'`).
fn parse_host_port(addr: &str, label: &str) -> Result<(String, u16)> {
    let (host, port) = addr.rsplit_once(':')
        .with_context(|| format!("Invalid {label} '{addr}': expected HOST:PORT (e.g. 10.0.0.5:4445)"))?;
    let port: u16 = port.parse()
        .with_context(|| format!("Invalid {label} '{addr}': port must be a number between 1 and 65535"))?;
    if port == 0 {
        anyhow::bail!("Invalid {label} '{addr}': port must be between 1 and 65535");
    }
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    Ok((host, port))
}

/// The actionable message shown when the server demands a key the client
/// didn't provide.
fn auth_required_hint() -> &'static str {
    "authentication required — provide a private key with -i/--identity or set 'identity' in ~/.config/wirewrench/client.conf"
}

/// Print a server error message, adding actionable context for the
/// "authentication required" case.
fn print_server_error(msg: &str) {
    if msg == "authentication required" {
        eprintln!("Error: {}", auth_required_hint());
    } else {
        eprintln!("Error: {msg}");
    }
}

fn send_cmd(cfg: &ClientConfig, cmd: &Value) -> Result<Value> {
    let mut stream = cfg.connect()?;
    let json = serde_json::to_string(cmd)? + "\n";
    stream.write_all(json.as_bytes())?;
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let val: Value = serde_json::from_str(line.trim())?;
    if val["status"].as_str() == Some("error") && val["message"].as_str() == Some("authentication required") {
        anyhow::bail!(auth_required_hint());
    }
    Ok(val)
}

fn send_cmd_raw(cfg: &ClientConfig, cmd: &Value) -> Result<ClientStream> {
    let mut stream = cfg.connect()?;
    let json = serde_json::to_string(cmd)? + "\n";
    stream.write_all(json.as_bytes())?;
    Ok(stream)
}

// ── List ───────────────────────────────────────────────────────────────────

fn cmd_list(cfg: &ClientConfig) -> Result<()> {
    let resp = send_cmd(cfg, &serde_json::json!({"action": "list"}))?;
    if resp["status"] == "ok" {
        let shells = &resp["shells"];
        let arr = shells.as_array().map_or(&[] as &[serde_json::Value], std::vec::Vec::as_slice);
        if arr.is_empty() {
            println!("No active shells.");
        } else {
            println!("{:<5} {:<25} {:<7} {:<16} Age", "ID", "Address", "Alive", "Platform");
            println!("{}", "-".repeat(60));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();
            for s in arr {
                let id = s["id"].as_u64().unwrap_or(0);
                let addr = s["addr"].as_str().unwrap_or("?");
                let alive = s["alive"].as_bool().unwrap_or(false);
                let created = s["created"].as_f64().unwrap_or(0.0);
                let platform = s["platform"].as_str().unwrap_or("-");
                let age = (now - created) as u64;
                let alive_str = if alive { "✓" } else { "✗" };
                println!("{id:<5} {addr:<25} {alive_str:<7} {platform:<16} {age}s");
            }
        }
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {msg}");
    }
    Ok(())
}

// ── Send ───────────────────────────────────────────────────────────────────

fn cmd_send(cfg: &ClientConfig, id: u32, command: &str, timeout: f64) -> Result<()> {
    let resp = send_cmd(cfg, &serde_json::json!({
        "action": "send", "id": id, "data": format!("{}\n", command),
        "timeout": timeout
    }))?;
    if resp["status"] == "error" {
        let msg = resp["message"].as_str().unwrap_or("Unknown");
        eprintln!("Error: {msg}");
        return Ok(());
    }
    // Smart sessions (ww-target) always include an `exit_code`, meaning the
    // command ran to completion on the target.  Dumb shells only report
    // output read within the polling window, so the timeout warning only
    // applies to those.
    let has_exit_code = resp["exit_code"].is_i64();
    if let Some(out) = resp["output"].as_str() {
        if out.is_empty() {
            if !has_exit_code {
                eprintln!("Warning: no output received. Try increasing --timeout (-t) if you expected output.");
            }
        } else {
            print!("{out}");
            if !out.ends_with('\n') {
                println!();
            }
        }
    }
    if let Some(err) = resp["stderr"].as_str().filter(|e| !e.is_empty()) {
        eprint!("{err}");
        if !err.ends_with('\n') {
            eprintln!();
        }
    }
    if let Some(ec) = resp["exit_code"].as_i64() {
        eprintln!("exit code: {ec}");
    }
    Ok(())
}

// ── Close ──────────────────────────────────────────────────────────────────

fn cmd_close(cfg: &ClientConfig, id: u32) -> Result<()> {
    let resp = send_cmd(cfg, &serde_json::json!({
        "action": "close", "id": id
    }))?;
    if resp["status"] == "ok" {
        println!("Shell #{id} closed.");
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {msg}");
    }
    Ok(())
}

// ── Script ─────────────────────────────────────────────────────────────────

fn cmd_script(cfg: &ClientConfig, id: u32, file: &str) -> Result<()> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("Cannot read file '{file}'"))?;
    let lines: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    println!("[+] Running {} commands on shell #{}", lines.len(), id);
    for cmd in &lines {
        println!("\n→ {cmd}");
        let resp = send_cmd(cfg, &serde_json::json!({
            "action": "send", "id": id, "data": format!("{}\n", cmd)
        }))?;
        if resp["status"] == "error" {
            eprintln!("  Error: {}", resp["message"].as_str().unwrap_or("?"));
            continue;
        }
        std::thread::sleep(Duration::from_millis(300));
        let resp = send_cmd(cfg, &serde_json::json!({
            "action": "read", "id": id, "timeout": 2.0
        }))?;
        if resp["status"] == "ok"
            && let Some(out) = resp["output"].as_str()
                && !out.is_empty() {
                    print!("{out}");
                }
    }
    Ok(())
}

// ── Targ push ──────────────────────────────────────────────────────────────

fn cmd_targ_upload(cfg: &ClientConfig, id: u32, local: &str, remote: Option<&str>, timeout: f64) -> Result<()> {
    let file_data = std::fs::read(local)
        .with_context(|| format!("Cannot read file '{local}'"))?;
    let size = file_data.len();

    let remote_path = match remote {
        Some(p) => p.to_string(),
        None => std::path::Path::new(local).file_name().map_or_else(|| local.to_string(), |n| n.to_string_lossy().into_owned()),
    };

    let push_data = serde_json::json!({"path": remote_path, "size": size, "timeout": timeout});
    let mut stream = cfg.connect()?;
    stream.set_read_timeout(Some(Duration::from_secs((timeout + 5.0).max(10.0) as u64)))?;

    let cmd_json = serde_json::json!({"action":"push","id":id,"data":push_data.to_string()});
    let json_line = serde_json::to_string(&cmd_json)? + "\n";
    stream.write_all(json_line.as_bytes())?;
    stream.write_all(&file_data)?;
    stream.flush()?;

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let resp: Value = serde_json::from_str(line.trim())?;
    if resp["status"] == "ok" {
        println!("{}", resp["output"].as_str().unwrap_or("Upload completed"));
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        print_server_error(msg);
    }
    Ok(())
}

// ── Targ pull ──────────────────────────────────────────────────────────────

fn cmd_targ_download(cfg: &ClientConfig, id: u32, remote: &str, local: Option<&str>, timeout: f64) -> Result<()> {
    let pull_data = serde_json::json!({"path": remote, "timeout": timeout});
    let mut stream = cfg.connect()?;
    stream.set_read_timeout(Some(Duration::from_secs((timeout + 5.0).max(10.0) as u64)))?;

    let cmd_json = serde_json::json!({"action":"pull","id":id,"data":pull_data.to_string()});
    let json_line = serde_json::to_string(&cmd_json)? + "\n";
    stream.write_all(json_line.as_bytes())?;
    stream.flush()?;

    // Read JSON response line byte-by-byte to avoid swallowing file data
    let mut resp_buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if stream.read_exact(&mut byte).is_err() { break; }
        if byte[0] == b'\n' { break; }
        resp_buf.push(byte[0]);
    }
    let resp: Value = if let Ok(v) = serde_json::from_slice(&resp_buf) { v } else { eprintln!("Error: invalid response from server"); return Ok(()); };
    if resp["status"] != "ok" {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        print_server_error(msg);
        return Ok(());
    }

    // Read file size (u64 LE) then raw bytes
    let mut size_buf = [0u8; 8];
    if stream.read_exact(&mut size_buf).is_err() {
        eprintln!("Error: failed to read file size");
        return Ok(());
    }
    let file_size: usize = u64::from_le_bytes(size_buf).try_into()?;

    let mut file_data = vec![0u8; file_size];
    if file_size > 0
        && stream.read_exact(&mut file_data).is_err() {
            eprintln!("Error: failed to read file data");
            return Ok(());
        }

    // Determine local path
    let local_path = match local {
        Some(p) => p.to_string(),
        None => std::path::Path::new(remote).file_name().map_or_else(|| "downloaded".to_string(), |n| n.to_string_lossy().into_owned()),
    };

    // Write to file
    std::fs::write(&local_path, &file_data)
        .with_context(|| format!("Failed to write '{local_path}'"))?;

    println!("{}", resp["output"].as_str().unwrap_or("Download completed"));
    Ok(())
}

// ── Targ cancel ────────────────────────────────────────────────────────────

fn cmd_targ_cancel(cfg: &ClientConfig, id: u32) -> Result<()> {
    let resp = send_cmd(cfg, &serde_json::json!({"action":"targ_cancel","id":id}))?;
    if resp["status"] == "ok" {
        println!("Cancel sent for session #{id}");
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {msg}");
    }
    Ok(())
}

// ── Tunnels: forward / socks ───────────────────────────────────────────────

/// Parse `[bind:]lport:host:port` (default bind `127.0.0.1`).
fn parse_forward_spec(spec: &str) -> Result<(String, u16, String, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (bind, lport, host, port) = match parts.as_slice() {
        [l, h, p] => ("127.0.0.1", *l, *h, *p),
        [b, l, h, p] => (*b, *l, *h, *p),
        _ => anyhow::bail!("invalid listen spec '{spec}': expected [bind:]lport:host:port"),
    };
    let lport: u16 = lport.parse().with_context(|| format!("invalid local port in '{spec}'"))?;
    let port: u16 = port.parse().with_context(|| format!("invalid remote port in '{spec}'"))?;
    if lport == 0 || port == 0 {
        anyhow::bail!("invalid listen spec '{spec}': ports must be between 1 and 65535");
    }
    Ok((bind.to_string(), lport, host.to_string(), port))
}

/// Parse a `HOST:PORT` listen address for the SOCKS listener.
fn parse_listen_addr(listen: &str) -> Result<(String, u16)> {
    let (host, port) = listen
        .rsplit_once(':')
        .with_context(|| format!("invalid --listen '{listen}': expected HOST:PORT"))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid --listen '{listen}': bad port"))?;
    Ok((host.trim_start_matches('[').trim_end_matches(']').to_string(), port))
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "::1" || host == "[::1]" || host.starts_with("127.")
}

/// Error from `open_stream`, carrying the target errno for SOCKS reply mapping.
#[derive(Debug)]
struct OpenStreamError {
    message: String,
    errno: i32,
}

impl std::fmt::Display for OpenStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OpenStreamError {}

/// Ask the server to open a tunnel through session `id` to `host:port` and
/// return the control stream, positioned for raw relay.  The reply is read
/// byte-at-a-time so no tunnel bytes are swallowed.
fn open_stream(
    cfg: &ClientConfig,
    id: u32,
    host: &str,
    port: u16,
    timeout: f64,
) -> std::result::Result<ClientStream, OpenStreamError> {
    let io_err = |message: String| OpenStreamError { message, errno: 0 };
    let mut stream = cfg.connect().map_err(|e| io_err(format!("{e:#}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs_f64(
            timeout.clamp(1.0, 3600.0) + 10.0,
        )))
        .map_err(|e| io_err(e.to_string()))?;

    let data = serde_json::json!({"host": host, "port": port, "timeout": timeout}).to_string();
    let cmd = serde_json::json!({"action": "connect", "id": id, "data": data});
    let line = serde_json::to_string(&cmd).map_err(|e| io_err(e.to_string()))? + "\n";
    if stream.write_all(line.as_bytes()).is_err() || stream.flush().is_err() {
        return Err(io_err("failed to send connect request".into()));
    }

    let mut buf = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        if stream.read_exact(&mut byte).is_err() {
            return Err(io_err("connection closed while opening tunnel".into()));
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > 64 * 1024 {
            return Err(io_err("oversized tunnel reply".into()));
        }
    }
    let resp: Value = serde_json::from_slice(&buf).map_err(|e| io_err(format!("invalid tunnel reply: {e}")))?;
    if resp["status"].as_str() == Some("ok") {
        let _ = stream.set_read_timeout(None);
        Ok(stream)
    } else {
        Err(OpenStreamError {
            message: resp["message"].as_str().unwrap_or("tunnel open failed").to_string(),
            errno: resp["errno"].as_i64().unwrap_or(0).try_into().unwrap_or(0),
        })
    }
}

/// Relay a local TCP socket <-> tunnel control stream, propagating half-close
/// in both directions.
fn relay_local(local: std::net::TcpStream, mut control: ClientStream) -> Result<()> {
    let mut local_read = local.try_clone()?;
    let mut control_write = control.try_clone()?;
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut local_read, &mut control_write);
        let _ = control_write.shutdown_write();
    });
    let mut local_write = local;
    let _ = std::io::copy(&mut control, &mut local_write);
    let _ = local_write.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
    Ok(())
}

/// `ww forward <id> -L [bind:]lport:host:port` — one local port, one tunnel
/// per accepted connection.
fn cmd_forward(cfg: &ClientConfig, id: u32, listen: &str, timeout: f64) -> Result<()> {
    let (bind, lport, host, rport) = parse_forward_spec(listen)?;
    let listener = std::net::TcpListener::bind((bind.as_str(), lport))
        .with_context(|| format!("cannot bind {bind}:{lport}"))?;
    eprintln!("[+] Forwarding {bind}:{lport} -> {host}:{rport} via session #{id}");
    loop {
        match listener.accept() {
            Ok((client, _)) => {
                let cfg = cfg.clone();
                let host = host.clone();
                std::thread::spawn(move || {
                    match open_stream(&cfg, id, &host, rport, timeout) {
                        Ok(stream) => {
                            let _ = relay_local(client, stream);
                        }
                        Err(e) => eprintln!("[-] forward: {e}"),
                    }
                });
            }
            Err(e) => eprintln!("[-] forward accept error: {e}"),
        }
    }
}

/// `ww socks <id>` — SOCKS5 + HTTP CONNECT proxy on one local port.
#[allow(clippy::too_many_arguments)]
fn cmd_socks(
    cfg: &ClientConfig,
    id: u32,
    listen: &str,
    local_dns: bool,
    socks_user: Option<String>,
    socks_pass: Option<String>,
    socks_only: bool,
    connect_timeout: f64,
    exit_on_disconnect: bool,
) -> Result<()> {
    if socks_user.is_some() != socks_pass.is_some() {
        anyhow::bail!("--socks-user and --socks-pass must be given together");
    }
    let auth = match (socks_user.as_deref(), socks_pass.as_deref()) {
        (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
        _ => None,
    };
    let (bind, port) = parse_listen_addr(listen)?;
    if !is_loopback_host(&bind) {
        eprintln!("[!] ⚠ WARNING: SOCKS proxy bound to non-loopback address {bind}:{port}");
        eprintln!("[!]   Anyone who can reach it can pivot through the target.");
    }
    let listener = std::net::TcpListener::bind((bind.as_str(), port))
        .with_context(|| format!("cannot bind {bind}:{port}"))?;
    listener.set_nonblocking(true)?;
    eprintln!("[+] SOCKS5/HTTP-CONNECT proxy on {bind}:{port} via session #{id}");

    let disconnected = Arc::new(AtomicBool::new(false));
    let hinted = Arc::new(AtomicBool::new(false));
    loop {
        if exit_on_disconnect && disconnected.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((client, peer)) => {
                let _ = client.set_nonblocking(false);
                let cfg = cfg.clone();
                let auth = auth.clone();
                let disconnected = Arc::clone(&disconnected);
                let hinted = Arc::clone(&hinted);
                std::thread::spawn(move || {
                    handle_socks_client(
                        client,
                        &cfg,
                        id,
                        auth,
                        local_dns,
                        socks_only,
                        connect_timeout,
                        &disconnected,
                        &hinted,
                    );
                });
                let _ = peer;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("[-] socks accept error: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

fn resolve_dest(req: &wirewrench::socks::Request, local_dns: bool) -> (String, u16) {
    if !local_dns {
        return (req.host.clone(), req.port);
    }
    match (req.host.as_str(), req.port).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => (a.ip().to_string(), a.port()),
            None => (req.host.clone(), req.port),
        },
        Err(_) => (req.host.clone(), req.port),
    }
}

fn note_disconnect(disconnected: &AtomicBool, hinted: &AtomicBool) {
    disconnected.store(true, Ordering::SeqCst);
    if !hinted.swap(true, Ordering::SeqCst) {
        eprintln!("[!] target session disconnected — listener kept; use --exit-on-disconnect to stop");
    }
}

fn is_missing_session(message: &str) -> bool {
    message.contains("Shell not found") || message.contains("does not support tunneling")
}

fn http_code_from_errno(errno: i32) -> (u16, &'static str) {
    match errno {
        110 | 60 | 10060 => (504, "Gateway Timeout"),
        _ => (502, "Bad Gateway"),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_socks_client(
    mut client: std::net::TcpStream,
    cfg: &ClientConfig,
    id: u32,
    auth: Option<(String, String)>,
    local_dns: bool,
    socks_only: bool,
    connect_timeout: f64,
    disconnected: &AtomicBool,
    hinted: &AtomicBool,
) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));

    // Detect the protocol without consuming payload (`peek`, not a BufReader).
    let mut first = [0_u8; 1];
    match client.peek(&mut first) {
        Ok(0) | Err(_) => return,
        Ok(_) => {}
    }

    if wirewrench::socks::detect_proto(first[0]) == wirewrench::socks::Proto::HttpConnect {
        if socks_only {
            wirewrench::socks::write_http_reply(&mut client, 501, "Not Implemented");
            return;
        }
        let req = match wirewrench::socks::read_http_connect(&mut client) {
            Ok(r) => r,
            Err(wirewrench::socks::Error::NotConnect) => {
                wirewrench::socks::write_http_reply(&mut client, 501, "Not Implemented");
                return;
            }
            Err(_) => {
                wirewrench::socks::write_http_reply(&mut client, 400, "Bad Request");
                return;
            }
        };
        let (host, port) = resolve_dest(&req, local_dns);
        match open_stream(cfg, id, &host, port, connect_timeout) {
            Ok(stream) => {
                wirewrench::socks::write_http_reply(&mut client, 200, "Connection established");
                let _ = client.set_read_timeout(None);
                let _ = relay_local(client, stream);
            }
            Err(e) => {
                let (code, reason) = http_code_from_errno(e.errno);
                wirewrench::socks::write_http_reply(&mut client, code, reason);
                if is_missing_session(&e.message) {
                    note_disconnect(disconnected, hinted);
                }
            }
        }
        return;
    }

    // SOCKS5
    let auth_ref = auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
    match wirewrench::socks::greet(&mut client, auth_ref) {
        Ok(true) => {}
        _ => return,
    }
    let req = match wirewrench::socks::read_request(&mut client) {
        Ok(r) => r,
        Err(wirewrench::socks::Error::Code(code)) => {
            wirewrench::socks::write_reply(&mut client, code);
            return;
        }
        Err(_) => return,
    };
    let (host, port) = resolve_dest(&req, local_dns);
    match open_stream(cfg, id, &host, port, connect_timeout) {
        Ok(stream) => {
            wirewrench::socks::write_reply(&mut client, 0x00);
            let _ = client.set_read_timeout(None);
            let _ = relay_local(client, stream);
        }
        Err(e) => {
            let code = wirewrench::socks::reply_code_from_errno(e.errno);
            wirewrench::socks::write_reply(&mut client, code);
            if is_missing_session(&e.message) {
                note_disconnect(disconnected, hinted);
            }
        }
    }
}

// ── Interact ───────────────────────────────────────────────────────────────

fn cmd_interact(cfg: &ClientConfig, id: u32) -> Result<()> {
    use rustyline::DefaultEditor;
    use rustyline::error::ReadlineError;

    let mut stream = send_cmd_raw(cfg, &serde_json::json!({
        "action": "interact", "id": id
    }))?;

    // Read JSON response
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&mut stream);
        reader.read_line(&mut line)?;
    }
    let resp: Value = serde_json::from_str(line.trim())?;
    if resp["status"] != "ok" {
        let msg = resp["message"].as_str().unwrap_or("Unknown");
        print_server_error(msg);
        return Ok(());
    }

    let mut rl = DefaultEditor::new()
        .map_err(|e| anyhow::anyhow!("Failed to create rustyline editor: {e}"))?;

    println!("Entering interactive mode (Ctrl+C to detach)");

    // Thread: read from Unix socket → channel
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut stream_clone = stream.try_clone()?;
    std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            match stream_clone.read(&mut buf) {
                Ok(0) => { let _ = tx.send(vec![]); break; }
                Ok(n) => { let _ = tx.send(buf[..n].to_vec()); }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => { let _ = tx.send(vec![]); break; }
            }
        }
    });

    // Drain any initial output
    std::thread::sleep(Duration::from_millis(50));
    while let Ok(data) = rx.try_recv() {
        std::io::stdout().write_all(&data).ok();
        std::io::stdout().flush().ok();
    }

    // Readline loop
    loop {
        match rl.readline(">> ") {
            Ok(line) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }
                rl.add_history_entry(trimmed.as_str())
                    .map_err(|e| anyhow::anyhow!("Failed to add history: {e}"))?;
                let to_send = format!("{trimmed}\n");
                if stream.write_all(to_send.as_bytes()).is_err() {
                    break;
                }
                if stream.flush().is_err() {
                    break;
                }
                // Read and print output until a short timeout
                while let Ok(data) = rx.recv_timeout(Duration::from_millis(300)) {
                    if data.is_empty() {
                        break;
                    }
                    std::io::stdout().write_all(&data).ok();
                    std::io::stdout().flush().ok();
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!();
                break;
            }
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("Readline error: {e}");
                break;
            }
        }
    }

    Ok(())
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = ClientConfig::resolve(&cli)?;
    match &cli.command {
        Commands::List => cmd_list(&cfg),
        Commands::Send { id, command, stdin, timeout } => {
            let cmd_str = if *stdin {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                command.join(" ")
            };
            cmd_send(&cfg, *id, &cmd_str, *timeout)
        }
        Commands::Interact { id } => cmd_interact(&cfg, *id),
        Commands::Close { id } => cmd_close(&cfg, *id),
        Commands::Script { id, file } => cmd_script(&cfg, *id, file),
        Commands::Targ { action } => match action {
            TargAction::Upload { id, local, remote, timeout } => {
                cmd_targ_upload(&cfg, *id, local, remote.as_deref(), *timeout)
            }
            TargAction::Download { id, remote, local, timeout } => {
                cmd_targ_download(&cfg, *id, remote, local.as_deref(), *timeout)
            }
            TargAction::Cancel { id } => cmd_targ_cancel(&cfg, *id),
        },
        Commands::Forward { id, listen, timeout } => cmd_forward(&cfg, *id, listen, *timeout),
        Commands::Socks {
            id,
            listen,
            local_dns,
            socks_user,
            socks_pass,
            socks_only,
            connect_timeout,
            exit_on_disconnect,
        } => cmd_socks(
            &cfg,
            *id,
            listen,
            *local_dns,
            socks_user.clone(),
            socks_pass.clone(),
            *socks_only,
            *connect_timeout,
            *exit_on_disconnect,
        ),
    }
}
