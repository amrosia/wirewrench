pub mod target;

use serde::{Deserialize, Serialize};

/// Control socket path
pub const DEFAULT_SOCKET: &str = "/tmp/wirewrench.sock";
pub const DEFAULT_PORT: u16 = 4444;
pub const DEFAULT_SMART_PORT: u16 = 4446;

#[derive(Deserialize)]
pub struct Command {
    pub action: String,
    pub id: Option<u32>,
    pub data: Option<String>,
    pub timeout: Option<f64>,
}

#[derive(Serialize)]
pub struct Response {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shells: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

impl Response {
    #[must_use]
    pub fn ok() -> Self {
        Self { status: "ok".into(), message: None, shells: None, output: None, exit_code: None, stderr: None }
    }
    pub fn error(msg: impl Into<String>) -> Self {
        Self { status: "error".into(), message: Some(msg.into()), shells: None, output: None, exit_code: None, stderr: None }
    }
    #[must_use]
    pub fn with_shells(shells: serde_json::Value) -> Self {
        Self { status: "ok".into(), message: None, shells: Some(shells), output: None, exit_code: None, stderr: None }
    }
    #[must_use]
    pub fn with_output(out: String) -> Self {
        Self { status: "ok".into(), message: None, shells: None, output: Some(out), exit_code: None, stderr: None }
    }
    #[must_use]
    pub fn with_output_exit(out: String, code: i32, stderr: String) -> Self {
        Self {
            status: "ok".into(),
            message: None,
            shells: None,
            output: Some(out),
            exit_code: Some(code),
            stderr: if stderr.is_empty() { None } else { Some(stderr) },
        }
    }
}

// ── Shell session info ─────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct ShellInfo {
    pub id: u32,
    pub addr: String,
    pub created: f64,
    pub alive: bool,
}
