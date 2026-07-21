use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;


// ── Socket helpers ──────────────────────────────────────────────────────────

pub fn connect(socket_path: &str) -> Result<std::os::unix::net::UnixStream> {
    let stream = std::os::unix::net::UnixStream::connect(Path::new(socket_path))
        .with_context(|| format!("Cannot connect to '{}'. Is ww-server running?", socket_path))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(stream)
}

pub fn send_cmd(socket_path: &str, cmd: &Value) -> Result<Value> {
    let mut stream = connect(socket_path)?;
    let json = serde_json::to_string(cmd)? + "\n";
    stream.write_all(json.as_bytes())?;
    let mut reader = BufReader::new(&stream);
    let mut line = String::new(); reader.read_line(&mut line)?;
    Ok(serde_json::from_str(line.trim())?)
}

pub fn send_cmd_raw(socket_path: &str, cmd: &Value) -> Result<std::os::unix::net::UnixStream> {
    let mut stream = connect(socket_path)?;
    let json = serde_json::to_string(cmd)? + "\n";
    stream.write_all(json.as_bytes())?;
    Ok(stream)
}

// ── List ────────────────────────────────────────────────────────────────────

pub fn cmd_list(socket_path: &str) -> Result<()> {
    let resp = send_cmd(socket_path, &serde_json::json!({"action": "list"}))?;
    if resp["status"] == "ok" {
        let arr = resp["shells"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
        if arr.is_empty() { println!("No active shells."); }
        else {
            println!("{:<5} {:<25} {:<7} Age", "ID", "Address", "Alive");
            println!("{}", "-".repeat(50));
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
            for s in arr {
                let id = s["id"].as_u64().unwrap_or(0);
                let addr = s["addr"].as_str().unwrap_or("?");
                let alive = s["alive"].as_bool().unwrap_or(false);
                let created = s["created"].as_f64().unwrap_or(0.0);
                println!("{:<5} {:<25} {:<7} {}s", id, addr, if alive { "✓" } else { "✗" }, (now - created) as u64);
            }
        }
    } else { let msg = resp["message"].as_str().unwrap_or("Unknown error"); eprintln!("Error: {}", msg); }
    Ok(())
}

// ── Send ────────────────────────────────────────────────────────────────────

pub fn cmd_send(socket_path: &str, id: u32, command: &str, wait: bool, timeout: f64) -> Result<()> {
    let resp = send_cmd(socket_path, &serde_json::json!({"action":"send","id":id,"data":format!("{}\n",command),"wait":wait,"timeout":timeout}))?;
    if resp["status"] == "error" { let msg = resp["message"].as_str().unwrap_or("Unknown"); eprintln!("Error: {}", msg); return Ok(()); }
    if wait {
        if let Some(out) = resp["output"].as_str() { if !out.is_empty() { print!("{}", out); if !out.ends_with('\n') { println!(); } } }
        if let Some(code) = resp["exit_code"].as_i64() { println!("[exit code: {}]", code); }
    }
    Ok(())
}

// ── Close ──────────────────────────────────────────────────────────────────

pub fn cmd_close(socket_path: &str, id: u32) -> Result<()> {
    let resp = send_cmd(socket_path, &serde_json::json!({"action":"close","id":id}))?;
    if resp["status"] == "ok" { println!("Shell #{} closed.", id); }
    else { let msg = resp["message"].as_str().unwrap_or("Unknown error"); eprintln!("Error: {}", msg); }
    Ok(())
}

// ── Script ─────────────────────────────────────────────────────────────────

pub fn cmd_script(socket_path: &str, id: u32, file: &str) -> Result<()> {
    let content = std::fs::read_to_string(file).with_context(|| format!("Cannot read file '{}'", file))?;
    let lines: Vec<&str> = content.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    println!("[+] Running {} commands on shell #{}", lines.len(), id);
    for cmd in &lines {
        println!("\n→ {}", cmd);
        let resp = send_cmd(socket_path, &serde_json::json!({"action":"send","id":id,"data":format!("{}\n",cmd)}))?;
        if resp["status"] == "error" { eprintln!("  Error: {}", resp["message"].as_str().unwrap_or("?")); continue; }
        std::thread::sleep(Duration::from_millis(300));
        let resp = send_cmd(socket_path, &serde_json::json!({"action":"read","id":id,"timeout":2.0}))?;
        if resp["status"] == "ok" && let Some(out) = resp["output"].as_str() && !out.is_empty() { print!("{}", out); }
    }
    Ok(())
}

// ── Web shell registration ─────────────────────────────────────────────────

#[cfg(feature = "web")]
pub fn cmd_web(socket_path: &str, url: &str, injection_point: &str, method: &str, data: &Option<String>, headers: &[String], cookie: &Option<String>) -> Result<()> {
    let target = data.as_deref().unwrap_or(url);
    let count = target.matches(injection_point).count();
    match count {
        0 => { eprintln!("Error: No injection point '{}' found in '{}'", injection_point, target); eprintln!("       Add '{}' to your URL or -d data string", injection_point); return Ok(()); }
        1 => {}
        _ => { eprintln!("Error: Too many '{}' injection points in '{}'", injection_point, target); return Ok(()); }
    }
    let config = serde_json::json!({"url":url,"injection_point":injection_point,"method":method,"body_template":data,"headers":headers,"cookie":cookie});
    let resp = send_cmd(socket_path, &serde_json::json!({"action":"register_web","data":config.to_string()}))?;
    if resp["status"] == "ok" {
        let id = resp["shells"]["id"].as_u64().unwrap_or(0);
        println!("[+] Web shell registered as session #{}", id);
        println!("[+] Use 'ww send {} \"command\"' or 'ww interact {}'", id, id);
    } else { let msg = resp["message"].as_str().unwrap_or("Unknown error"); eprintln!("Error: {}", msg); }
    Ok(())
}

// ── Targ push ──────────────────────────────────────────────────────────────

pub fn cmd_targ_push(socket_path: &str, id: u32, local: &str, remote: Option<&str>, timeout: f64) -> Result<()> {
    let file_data = std::fs::read(local).with_context(|| format!("Cannot read file '{}'", local))?;
    let size = file_data.len();

    let remote_path = match remote {
        Some(p) => p.to_string(),
        None => std::path::Path::new(local).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| local.to_string()),
    };

    let push_data = serde_json::json!({"path": remote_path, "size": size, "timeout": timeout});
    let mut stream = std::os::unix::net::UnixStream::connect(Path::new(socket_path))
        .with_context(|| format!("Cannot connect to '{}'. Is ww-server running?", socket_path))?;
    stream.set_read_timeout(Some(Duration::from_secs((timeout + 5.0).max(10.0) as u64)))?;

    let cmd_json = serde_json::json!({"action":"push","id":id,"data":push_data.to_string()});
    let json_line = serde_json::to_string(&cmd_json)? + "\n";
    stream.write_all(json_line.as_bytes())?;
    stream.write_all(&file_data)?; stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new(); reader.read_line(&mut line)?;
    let resp: Value = serde_json::from_str(line.trim())?;
    if resp["status"] == "ok" { println!("{}", resp["output"].as_str().unwrap_or("Push completed")); }
    else { let msg = resp["message"].as_str().unwrap_or("Unknown error"); eprintln!("Error: {}", msg); }
    Ok(())
}

// ── Targ pull ──────────────────────────────────────────────────────────────

pub fn cmd_targ_pull(socket_path: &str, id: u32, remote: &str, _local: Option<&str>, timeout: f64) -> Result<()> {
    let pull_data = serde_json::json!({"path": remote, "timeout": timeout});
    let mut stream = std::os::unix::net::UnixStream::connect(Path::new(socket_path))
        .with_context(|| format!("Cannot connect to '{}'. Is ww-server running?", socket_path))?;
    stream.set_read_timeout(Some(Duration::from_secs((timeout + 5.0).max(10.0) as u64)))?;

    let cmd_json = serde_json::json!({"action":"pull","id":id,"data":pull_data.to_string()});
    let json_line = serde_json::to_string(&cmd_json)? + "\n";
    stream.write_all(json_line.as_bytes())?; stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new(); reader.read_line(&mut line)?;
    let resp: Value = serde_json::from_str(line.trim())?;
    if resp["status"] == "ok" { println!("{}", resp["output"].as_str().unwrap_or("Pull completed")); }
    else { let msg = resp["message"].as_str().unwrap_or("Unknown error"); eprintln!("Error: {}", msg); }
    Ok(())
}
