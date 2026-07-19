use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use termios::{Termios, ECHO, ICANON, ISIG, VMIN, VTIME, TCSADRAIN};

// Raw FFI for isatty to avoid adding the libc crate
#[cfg(unix)]
unsafe extern "C" {
    fn isatty(fd: std::os::raw::c_int) -> std::os::raw::c_int;
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
    /// Send a command to a shell (non-interactive)
    Send {
        id: u32,
        /// Wait for output with this timeout in seconds
        #[arg(short = 'w', long)]
        wait: bool,
        /// Read command from stdin instead of positional argument
        #[arg(short = 's', long)]
        stdin: bool,
        /// Timeout in seconds when using --wait (default: 3.0)
        #[arg(short = 't', long, default_value = "3.0")]
        timeout: f64,
        /// Command to execute (all remaining arguments, no extra quoting needed)
        #[arg(trailing_var_arg = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Interact with a shell (Ctrl+C to detach)
    Interact { id: u32 },
    /// Close/kill a shell
    Close { id: u32 },
    /// Run commands from a file
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
}

// ── Unix socket connection ─────────────────────────────────────────────────

fn connect(socket_path: &str) -> Result<std::os::unix::net::UnixStream> {
    let stream = std::os::unix::net::UnixStream::connect(Path::new(socket_path))
        .with_context(|| format!("Cannot connect to '{}'. Is ww-server running?", socket_path))?;
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
        let arr = shells.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
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
                println!("{:<5} {:<25} {:<7} {}s", id, addr, alive_str, age);
            }
        }
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {}", msg);
    }
    Ok(())
}

// ── Send ───────────────────────────────────────────────────────────────────

fn cmd_send(socket_path: &str, id: u32, command: &str, wait: bool, timeout: f64) -> Result<()> {
    let resp = send_cmd(socket_path, &serde_json::json!({
        "action": "send", "id": id, "data": format!("{}\n", command),
        "wait": wait, "timeout": timeout
    }))?;
    if resp["status"] == "error" {
        let msg = resp["message"].as_str().unwrap_or("Unknown");
        eprintln!("Error: {}", msg);
        return Ok(());
    }
    if wait {
        if let Some(out) = resp["output"].as_str() {
            if !out.is_empty() {
                print!("{}", out);
                if !out.ends_with('\n') {
                    println!();
                }
            }
        }
    }
    Ok(())
}

// ── Close ──────────────────────────────────────────────────────────────────

fn cmd_close(socket_path: &str, id: u32) -> Result<()> {
    let resp = send_cmd(socket_path, &serde_json::json!({
        "action": "close", "id": id
    }))?;
    if resp["status"] == "ok" {
        println!("Shell #{} closed.", id);
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {}", msg);
    }
    Ok(())
}

// ── Script ─────────────────────────────────────────────────────────────────

fn cmd_script(socket_path: &str, id: u32, file: &str) -> Result<()> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("Cannot read file '{}'", file))?;
    let lines: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    println!("[+] Running {} commands on shell #{}", lines.len(), id);
    for cmd in &lines {
        println!("\n→ {}", cmd);
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
                    print!("{}", out);
                }
    }
    Ok(())
}

// ── Interactive mode ───────────────────────────────────────────────────────

fn set_raw_mode(fd: std::os::unix::io::RawFd) -> Result<Termios> {
    let mut term = Termios::from_fd(fd)?;
    let old = term;
    // Non-canonical mode, no echo, no signal generation (so Ctrl+C byte 0x03
    // reaches stdin instead of being intercepted as SIGINT)
    term.c_lflag &= !(ICANON | ECHO | ISIG);
    // Set VMIN=1, VTIME=0 for character-by-character read
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 0;
    termios::tcsetattr(fd, TCSADRAIN, &term)?;
    Ok(old)
}

// ── Web shell registration ────────────────────────────────────────────────

#[cfg(feature = "web")]
fn cmd_web(
    socket_path: &str,
    url: &str,
    injection_point: &str,
    method: &str,
    data: &Option<String>,
    headers: &[String],
    cookie: &Option<String>,
) -> Result<()> {
    // Validate injection point is present exactly once
    let target = data.as_deref().unwrap_or(url);
    let count = target.matches(injection_point).count();
    match count {
        0 => {
            eprintln!("Error: No injection point '{}' found in '{}'", injection_point, target);
            eprintln!("       Add '{}' to your URL or -d data string", injection_point);
            return Ok(());
        }
        1 => {} // ok
        _ => {
            eprintln!("Error: Too many '{}' injection points in '{}'", injection_point, target);
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
        println!("[+] Web shell registered as session #{}", id);
        println!("[+] Use 'ww send {} \"command\"' or 'ww interact {}'", id, id);
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {}", msg);
    }

    Ok(())
}

fn cmd_interact(socket_path: &str, id: u32) -> Result<()> {
    let stdin_fd = std::io::stdin().as_raw_fd();
    let is_tty = unsafe { isatty(stdin_fd) } != 0;
    let mut old_term: Option<Termios> = None;
    let sigint = Arc::new(AtomicBool::new(false));

    if is_tty {
        match set_raw_mode(stdin_fd) {
            Ok(t) => old_term = Some(t),
            Err(e) => eprintln!("Warning: could not set raw mode: {}", e),
        }
    }

    // Install SIGINT handler: in raw mode with ISIG disabled, Ctrl+C arrives
    // as byte 0x03 in stdin, so this handler only fires for external SIGINT
    // (e.g. kill from another terminal).
    let sigint_flag = Arc::clone(&sigint);
    let restore_term = old_term;
    let rfd = stdin_fd;
    ctrlc::set_handler(move || {
        sigint_flag.store(true, Ordering::SeqCst);
        if let Some(ref term) = restore_term {
            let _ = termios::tcsetattr(rfd, TCSADRAIN, term);
        }
    }).ok();

    let result = interact_inner(socket_path, id, &sigint);

    // Restore terminal
    if let Some(ref term) = old_term {
        let _ = termios::tcsetattr(stdin_fd, TCSADRAIN, term);
    }

    result
}

/// Return value from `process_byte` — tells the caller whether to continue or detach.
#[derive(PartialEq)]
enum ByteAction {
    Continue,
    Detach,
}

fn interact_inner(
    socket_path: &str,
    id: u32,
    sigint: &AtomicBool,
) -> Result<()> {
    // Connect and send interact command
    let mut stream = send_cmd_raw(socket_path, &serde_json::json!({
        "action": "interact", "id": id
    }))?;

    // Read JSON response (using a scope to drop the BufReader immediately)
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&stream);
        reader.read_line(&mut line)?;
    }
    let resp: Value = serde_json::from_str(line.trim())?;
    if resp["status"] != "ok" {
        let msg = resp["message"].as_str().unwrap_or("Unknown");
        eprintln!("Error: {}", msg);
        return Ok(());
    }

    stream.set_read_timeout(Some(Duration::from_millis(50)))?;

    let mut buf: Vec<u8> = Vec::new();
    let mut cursor: usize = 0;
    let mut prev_len: usize = 0;
    let mut escape: Option<Vec<u8>> = None;

    // ── Thread: read from socket → channel ────────────────────────────
    let mut stream_clone = stream.try_clone()?;
    let (sock_tx, sock_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    std::thread::spawn(move || {
        let mut tmp = [0u8; 65536];
        loop {
            match stream_clone.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    let data = tmp[..n].to_vec();
                    if sock_tx.send(data).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    // ── Thread: read from stdin → channel ─────────────────────────────
    // Reads up to 64 KB at once (terminal sends escape sequences as a burst)
    let done = Arc::new(AtomicBool::new(false));
    let done_stdin = Arc::clone(&done);
    let (stdin_tx, stdin_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    std::thread::spawn(move || {
        let mut tmp = [0u8; 65536];
        loop {
            if done_stdin.load(Ordering::SeqCst) {
                break;
            }
            match std::io::stdin().read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    let data = tmp[..n].to_vec();
                    if stdin_tx.send(data).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // ── Main loop: poll both channels ─────────────────────────────────
    loop {
        if sigint.load(Ordering::SeqCst) {
            println!("[~] Detached (shell #{} still alive)", id);
            break;
        }

        // Check socket data (non-blocking try)
        match sock_rx.try_recv() {
            Ok(data) => {
                // Clear editing line, write remote output, redraw buffer
                let s: String = String::from_utf8_lossy(&buf).into();
                write!(std::io::stdout(), "\r{:width$}\r", "", width = prev_len)?;
                std::io::stdout().write_all(&data)?;
                if !buf.is_empty() {
                    write!(std::io::stdout(), "{}", &s[..cursor.min(s.len())])?;
                }
                std::io::stdout().flush()?;
            }
            Err(TryRecvError::Disconnected) => {
                break;  // Socket thread exited, connection closed
            }
            _ => {}  // No data yet
        }

        // Check stdin with a short timeout so we also keep polling the
        // socket and sigint flag
        match stdin_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(data) => {
                for &b in &data {
                    if process_byte(b, &mut buf, &mut cursor, &mut prev_len, &mut escape, &mut stream)?
                        == ByteAction::Detach
                    {
                        println!("[~] Detached (shell #{} still alive)", id);
                        done.store(true, Ordering::SeqCst);
                        return Ok(());
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                // No stdin data — loop back to check socket/sigint
            }
            Err(RecvTimeoutError::Disconnected) => {
                break;  // Stdin thread exited (EOF)
            }
        }
    }

    done.store(true, Ordering::SeqCst);
    Ok(())
}

/// Process a single byte from stdin in the interactive loop.
/// Returns `Detach` on Ctrl+C (caller should exit the loop).
fn process_byte(
    b: u8,
    buf: &mut Vec<u8>,
    cursor: &mut usize,
    prev_len: &mut usize,
    escape: &mut Option<Vec<u8>>,
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<ByteAction> {
    // ── Escape sequence parsing ────────────────────────────────
    if let Some(esc) = escape {
        esc.push(b);
        // If this is the 2nd byte (after \x1b) and it's '[', keep collecting
        if esc.len() == 2 && b == b'[' {
            return Ok(ByteAction::Continue);
        }
        // Complete on final byte (0x40-0x7e)
        if (0x40..=0x7e).contains(&b)
            && let Some(seq) = std::mem::take(escape)
        {
            handle_escape(&seq, buf, cursor, prev_len);
        }
        return Ok(ByteAction::Continue);
    }

    if b == 0x1b {
        *escape = Some(vec![b]);
        return Ok(ByteAction::Continue);
    }

    // ── Single-byte control chars ──────────────────────────────
    match b {
        0x03 => {  // Ctrl+C → detach
            write!(std::io::stdout(), "\r{:width$}\r", "", width = *prev_len)?;
            std::io::stdout().flush()?;
            return Ok(ByteAction::Detach);
        }
        0x0a => {  // Enter
            let line = [&buf[..], b"\n"].concat();
            std::io::stdout().write_all(b"\r\n")?;
            std::io::stdout().flush()?;
            stream.write_all(&line)?;
            stream.flush()?;
            buf.clear();
            *cursor = 0;
            *prev_len = 0;
        }
        0x08 | 0x7f => {  // Backspace
            if *cursor > 0 {
                *cursor -= 1;
                buf.remove(*cursor);
                *cursor = refresh_line(buf, *cursor, prev_len);
            }
        }
        0x01 => {  // Ctrl+A → home
            while *cursor > 0 {
                *cursor -= 1;
                std::io::stdout().write_all(b"\x08")?;
            }
            std::io::stdout().flush()?;
        }
        0x05 => {  // Ctrl+E → end
            let tail: Vec<u8> = buf[*cursor..].to_vec();
            std::io::stdout().write_all(&tail)?;
            *cursor = buf.len();
            std::io::stdout().flush()?;
        }
        0x15 => {  // Ctrl+U → kill line
            buf.clear();
            *cursor = refresh_line(buf, 0, prev_len);
        }
        0x0b => {  // Ctrl+K → kill to end
            buf.truncate(*cursor);
            *cursor = refresh_line(buf, *cursor, prev_len);
        }
        0x17 => {  // Ctrl+W → kill word backward
            if *cursor > 0 {
                let end = *cursor;
                while *cursor > 0 && buf[*cursor - 1] == b' ' {
                    *cursor -= 1;
                }
                while *cursor > 0 && buf[*cursor - 1] != b' ' {
                    *cursor -= 1;
                }
                buf.drain(*cursor..end);
                *cursor = refresh_line(buf, *cursor, prev_len);
            }
        }
        _ if b >= 0x20 => {  // Printable
            buf.insert(*cursor, b);
            *cursor += 1;
            *cursor = refresh_line(buf, *cursor, prev_len);
        }
        _ => {}  // Other control chars ignored
    }

    Ok(ByteAction::Continue)
}

fn refresh_line(buf: &[u8], cursor: usize, prev_len: &mut usize) -> usize {
    let s = String::from_utf8_lossy(buf);
    let len = s.len();
    // Carriage return + buffer content (overwrites from column 0)
    write!(std::io::stdout(), "\r{}", s).ok();
    // If shorter than before, pad with spaces to erase leftovers
    if len < *prev_len {
        write!(std::io::stdout(), "{:width$}", "", width = *prev_len - len).ok();
    }
    // Carriage return + buffer up to cursor for cursor positioning
    write!(std::io::stdout(), "\r{}", &s[..cursor.min(len)]).ok();
    std::io::stdout().flush().ok();
    *prev_len = len;
    cursor
}

fn handle_escape(seq: &[u8], buf: &mut Vec<u8>, cursor: &mut usize, prev_len: &mut usize) {
    use std::io::Write;
    match seq {
        s if s == b"\x1b[C" => {  // Right
            if *cursor < buf.len() {
                std::io::stdout().write_all(&[buf[*cursor]]).ok();
                *cursor += 1;
                std::io::stdout().flush().ok();
            }
        }
        s if s == b"\x1b[D" => {  // Left
            if *cursor > 0 {
                *cursor -= 1;
                std::io::stdout().write_all(b"\x08").ok();
                std::io::stdout().flush().ok();
            }
        }
        s if s == b"\x1b[H" || s == b"\x1b[1~" => {  // Home
            while *cursor > 0 {
                *cursor -= 1;
                std::io::stdout().write_all(b"\x08").ok();
            }
            std::io::stdout().flush().ok();
        }
        s if s == b"\x1b[F" || s == b"\x1b[4~" => {  // End
            let tail: Vec<u8> = buf[*cursor..].to_vec();
            std::io::stdout().write_all(&tail).ok();
            *cursor = buf.len();
            std::io::stdout().flush().ok();
        }
        s if s == b"\x1b[3~" => {  // Delete
            if *cursor < buf.len() {
                buf.remove(*cursor);
                let new_cursor = refresh_line(buf, *cursor, prev_len);
                *cursor = new_cursor;
            }
        }
        // Alt+b or Ctrl+Left
        s if s == b"\x1bb" || (s.len() > 3 && s.ends_with(b"D") && s.contains(&b';')) => {
            word_back(buf, cursor, prev_len);
        }
        // Alt+f or Ctrl+Right
        s if s == b"\x1bf" || (s.len() > 3 && s.ends_with(b"C") && s.contains(&b';')) => {
            word_fwd(buf, cursor, prev_len);
        }
        _ => {}  // Unknown sequences ignored
    }
}

fn word_back(buf: &[u8], cursor: &mut usize, prev_len: &mut usize) {
    if *cursor == 0 { return; }
    let mut pos = *cursor - 1;
    while pos > 0 && buf[pos] == b' ' {
        pos -= 1;
    }
    while pos > 0 && buf[pos] != b' ' {
        pos -= 1;
    }
    let new_cursor = if pos == 0 && buf[0] != b' ' {
        0
    } else {
        pos + if buf[pos] == b' ' { 1 } else { 0 }
    };
    *cursor = refresh_line(buf, new_cursor, prev_len);
}

fn word_fwd(buf: &[u8], cursor: &mut usize, prev_len: &mut usize) {
    if *cursor >= buf.len() { return; }
    let mut pos = *cursor;
    while pos < buf.len() && buf[pos] != b' ' {
        pos += 1;
    }
    while pos < buf.len() && buf[pos] == b' ' {
        pos += 1;
    }
    *cursor = refresh_line(buf, pos, prev_len);
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::List => cmd_list(&cli.socket),
        Commands::Send { id, command, wait, stdin, timeout } => {
            let cmd_str = if *stdin {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                command.join(" ")
            };
            cmd_send(&cli.socket, *id, &cmd_str, *wait, *timeout)
        }
        Commands::Interact { id } => cmd_interact(&cli.socket, *id),
        Commands::Close { id } => cmd_close(&cli.socket, *id),
        Commands::Script { id, file } => cmd_script(&cli.socket, *id, file),
        #[cfg(feature = "web")]
        Commands::Web { url, injection_point, method, data, headers, cookie } => {
            cmd_web(&cli.socket, url, injection_point, method, data, headers, cookie)
        }
    }
}
