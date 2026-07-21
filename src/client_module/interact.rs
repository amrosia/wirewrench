use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;
use termios::{Termios, ECHO, ICANON, ISIG, VMIN, VTIME, TCSADRAIN};

#[cfg(unix)]
unsafe extern "C" { fn isatty(fd: std::os::raw::c_int) -> std::os::raw::c_int; }

thread_local! { static INTERACT_PROMPT: RefCell<String> = const { RefCell::new(String::new()) }; }

fn set_raw_mode(fd: std::os::unix::io::RawFd) -> Result<Termios> {
    let mut term = Termios::from_fd(fd)?;
    let old = term;
    term.c_lflag &= !(ICANON | ECHO | ISIG);
    term.c_cc[VMIN] = 1; term.c_cc[VTIME] = 0;
    termios::tcsetattr(fd, TCSADRAIN, &term)?;
    Ok(old)
}

// ── Interact dispatch ───────────────────────────────────────────────────────

pub fn cmd_interact(socket_path: &str, id: u32) -> Result<()> {
    let stream = crate::client_module::cmds::send_cmd_raw(socket_path, &serde_json::json!({"action":"interact","id":id}))?;

    let mut line = String::new();
    { let mut reader = BufReader::new(&stream); reader.read_line(&mut line)?; }
    let resp: Value = serde_json::from_str(line.trim())?;
    if resp["status"] != "ok" {
        let msg = resp["message"].as_str().unwrap_or("Unknown");
        eprintln!("Error: {}", msg); return Ok(());
    }

    interact_rl(stream)
}

// ── Rustyline interact (target sessions) ────────────────────────────────────

fn interact_rl(mut stream: std::os::unix::net::UnixStream) -> Result<()> {
    use rustyline::DefaultEditor; use rustyline::error::ReadlineError;

    let mut rl = DefaultEditor::new().map_err(|e| anyhow::anyhow!("Failed to create rustyline editor: {}", e))?;

    println!("Entering target interactive mode (Ctrl+C to detach)");

    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut stream_clone = stream.try_clone().map_err(|e| anyhow::anyhow!("Failed to clone stream: {}", e))?;
    std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            match stream_clone.read(&mut buf) {
                Ok(0) => { let _ = tx.send(vec![]); break; }
                Ok(n) => { let _ = tx.send(buf[..n].to_vec()); }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => { let _ = tx.send(vec![]); break; }
            }
        }
    });

    std::thread::sleep(Duration::from_millis(50));
    loop { match rx.try_recv() { Ok(data) => { std::io::stdout().write_all(&data).ok(); std::io::stdout().flush().ok(); } Err(TryRecvError::Empty) => break, _ => break, } }

    loop {
        match rl.readline(">> ") {
            Ok(line) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() { continue; }
                rl.add_history_entry(trimmed.as_str()).map_err(|e| anyhow::anyhow!("Failed to add history: {}", e))?;
                let to_send = format!("{}\n", trimmed);
                if stream.write_all(to_send.as_bytes()).is_err() { break; }
                if stream.flush().is_err() { break; }
                loop {
                    match rx.recv_timeout(Duration::from_millis(300)) {
                        Ok(data) => { if data.is_empty() { break; } std::io::stdout().write_all(&data).ok(); std::io::stdout().flush().ok(); }
                        Err(RecvTimeoutError::Timeout) => break, Err(_) => break,
                    }
                }
            }
            Err(ReadlineError::Interrupted) => { println!(""); break; }
            Err(ReadlineError::Eof) => break,
            Err(e) => { eprintln!("Readline error: {}", e); break; }
        }
    }

    Ok(())
}

// ── Legacy interact (dumb shells) ──────────────────────────────────────────

#[derive(PartialEq)]
enum ByteAction { Continue, Detach }

fn interact_inner(_socket_path: &str, id: u32, sigint: &AtomicBool, mut stream: std::os::unix::net::UnixStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(50)))?;
    let mut buf: Vec<u8> = Vec::new();
    let mut cursor: usize = 0;
    let mut prev_len: usize = 0;
    let mut escape: Option<Vec<u8>> = None;

    let mut stream_clone = stream.try_clone()?;
    let (sock_tx, sock_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut tmp = [0u8; 65536];
        loop {
            match stream_clone.read(&mut tmp) {
                Ok(0) => break, Ok(n) => { let data = tmp[..n].to_vec(); if sock_tx.send(data).is_err() { break; } }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
    });

    let done = Arc::new(AtomicBool::new(false));
    let done_stdin = Arc::clone(&done);
    let (stdin_tx, stdin_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut tmp = [0u8; 65536];
        loop { if done_stdin.load(Ordering::SeqCst) { break; } match std::io::stdin().read(&mut tmp) { Ok(0) => break, Ok(n) => { let data = tmp[..n].to_vec(); if stdin_tx.send(data).is_err() { break; } } Err(_) => break, } }
    });

    loop {
        if sigint.load(Ordering::SeqCst) { println!("[~] Detached (shell #{} still alive)", id); break; }
        match sock_rx.try_recv() {
            Ok(data) => {
                let s: String = String::from_utf8_lossy(&buf).into();
                write!(std::io::stdout(), "\r{:width$}\r", "", width = prev_len)?;
                std::io::stdout().write_all(&data)?;
                if data.ends_with(b"> ") { INTERACT_PROMPT.with(|p| *p.borrow_mut() = "> ".to_string()); }
                if !buf.is_empty() { let pr = INTERACT_PROMPT.with(|p| p.borrow().clone()); write!(std::io::stdout(), "{}{}", pr, &s[..cursor.min(s.len())])?; }
                std::io::stdout().flush()?;
            }
            Err(TryRecvError::Disconnected) => break,
            _ => {}
        }
        match stdin_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(data) => { for &b in &data { if process_byte(b, &mut buf, &mut cursor, &mut prev_len, &mut escape, &mut stream)? == ByteAction::Detach { println!("[~] Detached (shell #{} still alive)", id); done.store(true, Ordering::SeqCst); return Ok(()); } } }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    done.store(true, Ordering::SeqCst);
    Ok(())
}

fn process_byte(b: u8, buf: &mut Vec<u8>, cursor: &mut usize, prev_len: &mut usize, escape: &mut Option<Vec<u8>>, stream: &mut std::os::unix::net::UnixStream) -> Result<ByteAction> {
    if let Some(esc) = escape { esc.push(b); if esc.len() == 2 && b == b'[' { return Ok(ByteAction::Continue); } if (0x40..=0x7e).contains(&b) && let Some(seq) = std::mem::take(escape) { handle_escape(&seq, buf, cursor, prev_len); } return Ok(ByteAction::Continue); }
    if b == 0x1b { *escape = Some(vec![b]); return Ok(ByteAction::Continue); }
    match b {
        0x03 => { write!(std::io::stdout(), "\r{:width$}\r", "", width = *prev_len)?; std::io::stdout().flush()?; return Ok(ByteAction::Detach); }
        0x0a => { let line = [&buf[..], b"\n"].concat(); std::io::stdout().write_all(b"\r\n")?; std::io::stdout().flush()?; stream.write_all(&line)?; stream.flush()?; buf.clear(); *cursor = 0; *prev_len = 0; }
        0x08 | 0x7f => { if *cursor > 0 { *cursor -= 1; buf.remove(*cursor); *cursor = refresh_line(buf, *cursor, prev_len); } }
        0x01 => { let pr_len = INTERACT_PROMPT.with(|p| p.borrow().len()); while *cursor > 0 { *cursor -= 1; std::io::stdout().write_all(b"\x08")?; } for _ in 0..pr_len { std::io::stdout().write_all(b"\x08")?; } std::io::stdout().flush()?; }
        0x05 => { let tail: Vec<u8> = buf[*cursor..].to_vec(); std::io::stdout().write_all(&tail)?; *cursor = buf.len(); std::io::stdout().flush()?; }
        0x15 => { buf.clear(); *cursor = refresh_line(buf, 0, prev_len); }
        0x0b => { buf.truncate(*cursor); *cursor = refresh_line(buf, *cursor, prev_len); }
        0x17 => { if *cursor > 0 { let end = *cursor; while *cursor > 0 && buf[*cursor - 1] == b' ' { *cursor -= 1; } while *cursor > 0 && buf[*cursor - 1] != b' ' { *cursor -= 1; } buf.drain(*cursor..end); *cursor = refresh_line(buf, *cursor, prev_len); } }
        _ if b >= 0x20 || b == b'\t' => { buf.insert(*cursor, b); *cursor += 1; *cursor = refresh_line(buf, *cursor, prev_len); }
        _ => {}
    }
    Ok(ByteAction::Continue)
}

fn refresh_line(buf: &[u8], cursor: usize, prev_len: &mut usize) -> usize {
    let s = String::from_utf8_lossy(buf);
    let len = s.len();
    let prompt = INTERACT_PROMPT.with(|p| p.borrow().clone());
    write!(std::io::stdout(), "\r{}{}", prompt, s).ok();
    let display_len = len + prompt.len();
    if display_len < *prev_len { write!(std::io::stdout(), "{:width$}", "", width = *prev_len - display_len).ok(); }
    write!(std::io::stdout(), "\r{}{}", prompt, &s[..cursor.min(len)]).ok();
    std::io::stdout().flush().ok();
    *prev_len = display_len;
    cursor
}

fn handle_escape(seq: &[u8], buf: &mut Vec<u8>, cursor: &mut usize, prev_len: &mut usize) {
    use std::io::Write;
    match seq {
        s if s == b"\x1b[C" => { if *cursor < buf.len() { std::io::stdout().write_all(&[buf[*cursor]]).ok(); *cursor += 1; std::io::stdout().flush().ok(); } }
        s if s == b"\x1b[D" => { if *cursor > 0 { *cursor -= 1; std::io::stdout().write_all(b"\x08").ok(); std::io::stdout().flush().ok(); } }
        s if s == b"\x1b[H" || s == b"\x1b[1~" => { while *cursor > 0 { *cursor -= 1; std::io::stdout().write_all(b"\x08").ok(); } std::io::stdout().flush().ok(); }
        s if s == b"\x1b[F" || s == b"\x1b[4~" => { let tail: Vec<u8> = buf[*cursor..].to_vec(); std::io::stdout().write_all(&tail).ok(); *cursor = buf.len(); std::io::stdout().flush().ok(); }
        s if s == b"\x1b[3~" => { if *cursor < buf.len() { buf.remove(*cursor); let new_cursor = refresh_line(buf, *cursor, prev_len); *cursor = new_cursor; } }
        s if s == b"\x1bb" || (s.len() > 3 && s.ends_with(b"D") && s.contains(&b';')) => { word_back(buf, cursor, prev_len); }
        s if s == b"\x1bf" || (s.len() > 3 && s.ends_with(b"C") && s.contains(&b';')) => { word_fwd(buf, cursor, prev_len); }
        _ => {}
    }
}

fn word_back(buf: &[u8], cursor: &mut usize, prev_len: &mut usize) {
    if *cursor == 0 { return; }
    let mut pos = *cursor - 1;
    while pos > 0 && buf[pos] == b' ' { pos -= 1; }
    while pos > 0 && buf[pos] != b' ' { pos -= 1; }
    let new_cursor = if pos == 0 && buf[0] != b' ' { 0 } else { pos + if buf[pos] == b' ' { 1 } else { 0 } };
    *cursor = refresh_line(buf, new_cursor, prev_len);
}

fn word_fwd(buf: &[u8], cursor: &mut usize, prev_len: &mut usize) {
    if *cursor >= buf.len() { return; }
    let mut pos = *cursor;
    while pos < buf.len() && buf[pos] != b' ' { pos += 1; }
    while pos < buf.len() && buf[pos] == b' ' { pos += 1; }
    *cursor = refresh_line(buf, pos, prev_len);
}
