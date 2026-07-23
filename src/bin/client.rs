use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;

use wirewrench::DEFAULT_SOCKET;

#[derive(Parser)]
#[command(name = "ww", about = "Interact with managed reverse shells")]
struct Cli {
    #[arg(short = 's', long, default_value = DEFAULT_SOCKET)]
    socket: String,

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
    /// Register a web shell with the server (curl-like flags)
    #[cfg(feature = "web")]
    Web {
        /// Target URL containing injection point marker
        url: String,
        /// Injection point marker [default: BLUB]
        #[arg(short = 'i', long, default_value = "BLUB")]
        injection_point: String,
        /// HTTP method, curl-style: -X POST
        #[arg(short = 'X', long = "request", default_value = "GET")]
        method: String,
        /// Request body / POST data, curl-style: -d "cmd=BLUB"
        #[arg(short = 'd', long = "data")]
        data: Option<String>,
        /// Additional HTTP headers, curl-style: -H "Name: Value" (repeatable)
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Cookie string, curl-style: -b "name=value"
        #[arg(short = 'b', long = "cookie")]
        cookie: Option<String>,
    },
    /// Target (ww-target) operations: push, pull, cancel
    Targ {
        #[command(subcommand)]
        action: TargAction,
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

// ── Unix socket connection ─────────────────────────────────────────────────

fn connect(socket_path: &str) -> Result<std::os::unix::net::UnixStream> {
    let stream = std::os::unix::net::UnixStream::connect(Path::new(socket_path))
        .with_context(|| format!("Cannot connect to '{socket_path}'. Is ww-server running?"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(stream)
}

fn send_cmd(socket_path: &str, cmd: &Value) -> Result<Value> {
    let mut stream = connect(socket_path)?;
    let json = serde_json::to_string(cmd)? + "\n";
    stream.write_all(json.as_bytes())?;
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let val: Value = serde_json::from_str(line.trim())?;
    Ok(val)
}

fn send_cmd_raw(socket_path: &str, cmd: &Value) -> Result<std::os::unix::net::UnixStream> {
    let mut stream = connect(socket_path)?;
    let json = serde_json::to_string(cmd)? + "\n";
    stream.write_all(json.as_bytes())?;
    Ok(stream)
}

// ── List ───────────────────────────────────────────────────────────────────

fn cmd_list(socket_path: &str) -> Result<()> {
    let resp = send_cmd(socket_path, &serde_json::json!({"action": "list"}))?;
    if resp["status"] == "ok" {
        let shells = &resp["shells"];
        let arr = shells.as_array().map_or(&[] as &[serde_json::Value], std::vec::Vec::as_slice);
        if arr.is_empty() {
            println!("No active shells.");
        } else {
            println!("{:<5} {:<25} {:<7} Age", "ID", "Address", "Alive");
            println!("{}", "-".repeat(50));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();
            for s in arr {
                let id = s["id"].as_u64().unwrap_or(0);
                let addr = s["addr"].as_str().unwrap_or("?");
                let alive = s["alive"].as_bool().unwrap_or(false);
                let created = s["created"].as_f64().unwrap_or(0.0);
                let age = (now - created) as u64;
                let alive_str = if alive { "✓" } else { "✗" };
                println!("{id:<5} {addr:<25} {alive_str:<7} {age}s");
            }
        }
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {msg}");
    }
    Ok(())
}

// ── Send ───────────────────────────────────────────────────────────────────

fn cmd_send(socket_path: &str, id: u32, command: &str, timeout: f64) -> Result<()> {
    let resp = send_cmd(socket_path, &serde_json::json!({
        "action": "send", "id": id, "data": format!("{}\n", command),
        "timeout": timeout
    }))?;
    if resp["status"] == "error" {
        let msg = resp["message"].as_str().unwrap_or("Unknown");
        eprintln!("Error: {msg}");
        return Ok(());
    }
    if let Some(out) = resp["output"].as_str() {
        if out.is_empty() {
            eprintln!("Warning: no output received. Try increasing --timeout (-t) if you expected output.");
        } else {
            print!("{out}");
            if !out.ends_with('\n') {
                println!();
            }
        }
    }
    if let Some(ec) = resp["exit_code"].as_i64() {
        eprintln!("exit code: {ec}");
    }
    Ok(())
}

// ── Close ──────────────────────────────────────────────────────────────────

fn cmd_close(socket_path: &str, id: u32) -> Result<()> {
    let resp = send_cmd(socket_path, &serde_json::json!({
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

fn cmd_script(socket_path: &str, id: u32, file: &str) -> Result<()> {
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
        let resp = send_cmd(socket_path, &serde_json::json!({
            "action": "send", "id": id, "data": format!("{}\n", cmd)
        }))?;
        if resp["status"] == "error" {
            eprintln!("  Error: {}", resp["message"].as_str().unwrap_or("?"));
            continue;
        }
        std::thread::sleep(Duration::from_millis(300));
        let resp = send_cmd(socket_path, &serde_json::json!({
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



// ── Web shell registration ────────────────────────────────────────────────

#[cfg(feature = "web")]
fn cmd_web(
    socket_path: &str,
    url: &str,
    injection_point: &str,
    method: &str,
    data: Option<&str>,
    headers: &[String],
    cookie: Option<&str>,
) -> Result<()> {
    // Validate injection point is present exactly once
    let target = data.unwrap_or(url);
    let count = target.matches(injection_point).count();
    match count {
        0 => {
            eprintln!("Error: No injection point '{injection_point}' found in '{target}'");
            eprintln!("       Add '{injection_point}' to your URL or -d data string");
            return Ok(());
        }
        1 => {} // ok
        _ => {
            eprintln!("Error: Too many '{injection_point}' injection points in '{target}'");
            return Ok(());
        }
    }

    // Build config and send to server
    let config = serde_json::json!({
        "url": url,
        "injection_point": injection_point,
        "method": method,
        "body_template": data,
        "headers": headers,
        "cookie": cookie,
    });

    let resp = send_cmd(socket_path, &serde_json::json!({
        "action": "register_web",
        "data": config.to_string(),
    }))?;

    if resp["status"] == "ok" {
        let id = resp["shells"]["id"].as_u64().unwrap_or(0);
        println!("[+] Web shell registered as session #{id}");
        println!("[+] Use 'ww send {id} \"command\"' or 'ww interact {id}'");
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {msg}");
    }

    Ok(())
}

// ── Targ push ──────────────────────────────────────────────────────────────

fn cmd_targ_upload(socket_path: &str, id: u32, local: &str, remote: Option<&str>, timeout: f64) -> Result<()> {
    let file_data = std::fs::read(local)
        .with_context(|| format!("Cannot read file '{local}'"))?;
    let size = file_data.len();

    let remote_path = match remote {
        Some(p) => p.to_string(),
        None => std::path::Path::new(local).file_name().map_or_else(|| local.to_string(), |n| n.to_string_lossy().into_owned()),
    };

    let push_data = serde_json::json!({"path": remote_path, "size": size, "timeout": timeout});
    let mut stream = connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs((timeout + 5.0).max(10.0) as u64)))?;

    let cmd_json = serde_json::json!({"action":"push","id":id,"data":push_data.to_string()});
    let json_line = serde_json::to_string(&cmd_json)? + "\n";
    stream.write_all(json_line.as_bytes())?;
    stream.write_all(&file_data)?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let resp: Value = serde_json::from_str(line.trim())?;
    if resp["status"] == "ok" {
        println!("{}", resp["output"].as_str().unwrap_or("Upload completed"));
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {msg}");
    }
    Ok(())
}

// ── Targ pull ──────────────────────────────────────────────────────────────

fn cmd_targ_download(socket_path: &str, id: u32, remote: &str, local: Option<&str>, timeout: f64) -> Result<()> {
    let pull_data = serde_json::json!({"path": remote, "timeout": timeout});
    let mut stream = connect(socket_path)?;
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
        eprintln!("Error: {msg}");
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

fn cmd_targ_cancel(socket_path: &str, id: u32) -> Result<()> {
    let resp = send_cmd(socket_path, &serde_json::json!({"action":"targ_cancel","id":id}))?;
    if resp["status"] == "ok" {
        println!("Cancel sent for session #{id}");
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {msg}");
    }
    Ok(())
}

// ── Interact ───────────────────────────────────────────────────────────────

fn cmd_interact(socket_path: &str, id: u32) -> Result<()> {
    use rustyline::DefaultEditor;
    use rustyline::error::ReadlineError;

    let mut stream = send_cmd_raw(socket_path, &serde_json::json!({
        "action": "interact", "id": id
    }))?;

    // Read JSON response
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&stream);
        reader.read_line(&mut line)?;
    }
    let resp: Value = serde_json::from_str(line.trim())?;
    if resp["status"] != "ok" {
        let msg = resp["message"].as_str().unwrap_or("Unknown");
        eprintln!("Error: {msg}");
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
    match &cli.command {
        Commands::List => cmd_list(&cli.socket),
        Commands::Send { id, command, stdin, timeout } => {
            let cmd_str = if *stdin {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                command.join(" ")
            };
            cmd_send(&cli.socket, *id, &cmd_str, *timeout)
        }
        Commands::Interact { id } => cmd_interact(&cli.socket, *id),
        Commands::Close { id } => cmd_close(&cli.socket, *id),
        Commands::Script { id, file } => cmd_script(&cli.socket, *id, file),
        #[cfg(feature = "web")]
        Commands::Web { url, injection_point, method, data, headers, cookie } => {
            cmd_web(&cli.socket, url, injection_point, method, data.as_deref(), headers, cookie.as_deref())
        }
        Commands::Targ { action } => match action {
            TargAction::Upload { id, local, remote, timeout } => {
                cmd_targ_upload(&cli.socket, *id, local, remote.as_deref(), *timeout)
            }
            TargAction::Download { id, remote, local, timeout } => {
                cmd_targ_download(&cli.socket, *id, remote, local.as_deref(), *timeout)
            }
            TargAction::Cancel { id } => {
                cmd_targ_cancel(&cli.socket, *id)
            }
        }
    }
}
