//! Framed binary protocol shared by `ww-server` and `ww-target`.
//!
//! Frame layout: `[type: u8][len: u32 LE][payload: len bytes]`.

use serde::{Deserialize, Serialize};

// ── Frame types ─────────────────────────────────────────────────────────────

/// Raw shell stdin/stdout bytes (interactive mode).
pub const FRAME_SHELL: u8 = 0x01;
/// Initial identity exchange.
pub const FRAME_HANDSHAKE: u8 = 0x02;
/// File transfer coordination (JSON).
pub const FRAME_FILE_CTRL: u8 = 0x03;
/// Raw file bytes during push.
pub const FRAME_FILE_DATA: u8 = 0x04;
/// Abort file transfer.
pub const FRAME_CANCEL: u8 = 0x05;
/// SHA-256 verification (JSON).
pub const FRAME_HASH: u8 = 0x06;
/// Heartbeat.
pub const FRAME_KEEPALIVE: u8 = 0x07;
/// Execute `sh -c` command (JSON: `{seq, cmd}`).
pub const FRAME_CMD: u8 = 0x08;
/// Command result (JSON: `{seq, exit_code, stdout, stderr}`).
pub const FRAME_CMD_RESULT: u8 = 0x09;

// ── Handshake ───────────────────────────────────────────────────────────────

/// Initial identity exchange. Client sends hostname/platform, server replies
/// with a session id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub session_id: Option<String>,
    pub hostname: Option<String>,
    pub platform: Option<String>,
}

impl Handshake {
    #[must_use]
    pub fn new_client(hostname: Option<String>, platform: Option<String>) -> Self {
        Self { session_id: None, hostname, platform }
    }

    #[must_use]
    pub fn new_server(session_id: impl Into<String>) -> Self {
        Self { session_id: Some(session_id.into()), hostname: None, platform: None }
    }
}

// ── Command execution ───────────────────────────────────────────────────────

/// Server → target: execute `sh -c cmd`, correlate results via `seq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdRequest {
    pub seq: u64,
    pub cmd: String,
}

/// Target → server: result of a `FRAME_CMD` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdResult {
    pub seq: u64,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

// ── File transfer messages ──────────────────────────────────────────────────

/// Server → target: start a push of `path` (`size` bytes, SHA-256 `hash`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushStart {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
    pub size: u64,
    pub hash: String,
}

impl PushStart {
    #[must_use]
    pub fn new(path: String, size: u64, hash: String) -> Self {
        Self { kind: "push_start".into(), path, size, hash }
    }
}

/// Target → server: ready to receive `FRAME_FILE_DATA` frames for `path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushReady {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
}

impl PushReady {
    #[must_use]
    pub fn new(path: String) -> Self {
        Self { kind: "push_ready".into(), path }
    }
}

/// Target → server: push finished; `hash` is the verified SHA-256 of the data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushVerified {
    #[serde(rename = "type")]
    pub kind: String,
    pub hash: String,
}

impl PushVerified {
    #[must_use]
    pub fn new(hash: String) -> Self {
        Self { kind: "push_verified".into(), hash }
    }
}

/// Either side: a transfer failed with `message`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushError {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
    pub message: String,
}

impl PushError {
    #[must_use]
    pub fn new(path: String, message: String) -> Self {
        Self { kind: "push_error".into(), path, message }
    }
}

/// Target → server: metadata for a pull of `path` (`size` bytes, SHA-256 `hash`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullMeta {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
    pub size: u64,
    pub hash: String,
}

impl PullMeta {
    #[must_use]
    pub fn new(path: String, size: u64, hash: String) -> Self {
        Self { kind: "pull_meta".into(), path, size, hash }
    }
}

/// Server → target: request a pull of `path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
}

impl PullRequest {
    #[must_use]
    pub fn new(path: String) -> Self {
        Self { kind: "pull".into(), path }
    }
}

/// Target → server: push complete, `hash` is the SHA-256 of the sent data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushDone {
    #[serde(rename = "type")]
    pub kind: String,
    pub hash: String,
}

impl PushDone {
    #[must_use]
    pub fn new(hash: String) -> Self {
        Self { kind: "push_done".into(), hash }
    }
}
