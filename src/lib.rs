use serde::{Deserialize, Serialize};

/// Control socket path
pub const DEFAULT_SOCKET: &str = "/tmp/wirewrench.sock";
pub const DEFAULT_PORT: u16 = 4444;

// ── Web shell config (serialized in Command.data for register_web) ────────

#[cfg(feature = "web")]
#[derive(Debug, Clone, Deserialize)]
pub struct WebShellConfig {
    pub url: String,
    pub injection_point: String,
    pub method: String,
    pub body_template: Option<String>,
    pub headers: Vec<String>,
    pub cookie: Option<String>,
}

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
}

impl Response {
    pub fn ok() -> Self {
        Self { status: "ok".into(), message: None, shells: None, output: None }
    }
    pub fn error(msg: impl Into<String>) -> Self {
        Self { status: "error".into(), message: Some(msg.into()), shells: None, output: None }
    }
    pub fn with_shells(shells: serde_json::Value) -> Self {
        Self { status: "ok".into(), message: None, shells: Some(shells), output: None }
    }
    pub fn with_output(out: String) -> Self {
        Self { status: "ok".into(), message: None, shells: None, output: Some(out) }
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
