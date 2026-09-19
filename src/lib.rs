pub mod socks;
pub mod target;

use serde::{Deserialize, Serialize};

/// Control socket path
pub const DEFAULT_SOCKET: &str = "/tmp/wirewrench.sock";
pub const DEFAULT_PORT: u16 = 4444;
pub const DEFAULT_SMART_PORT: u16 = 4446;

/// SSH-style key authentication for the TCP control port.
pub mod auth {
    /// Magic prefix bound into every signature, domain-separating our auth
    /// protocol from any other use of the same keys.
    pub const MAGIC: &[u8] = b"wirewrench-auth-v1";

    /// Length of the per-connection random challenge.
    pub const CHALLENGE_LEN: usize = 32;

    /// Maximum number of key offers a client may make per connection.
    pub const MAX_OFFERS: usize = 8;

    /// The exact bytes a client signs and the server verifies:
    /// `MAGIC ‖ challenge ‖ offered public key blob`.
    pub fn signed_payload(challenge: &[u8], key_blob: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(MAGIC.len() + challenge.len() + key_blob.len());
        msg.extend_from_slice(MAGIC);
        msg.extend_from_slice(challenge);
        msg.extend_from_slice(key_blob);
        msg
    }

    /// Base64-encode bytes (standard alphabet, padded).
    pub fn b64_encode(data: &[u8]) -> String {
        use base64ct::Encoding;
        base64ct::Base64::encode_string(data)
    }

    /// Base64-decode; `None` on invalid input.
    pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
        use base64ct::Encoding;
        base64ct::Base64::decode_vec(s).ok()
    }
}

#[derive(Deserialize)]
pub struct Command {
    pub action: String,
    pub id: Option<u32>,
    pub data: Option<String>,
    pub timeout: Option<f64>,
    /// Break an existing session lock rather than failing with `busy`.
    #[serde(default)]
    pub force: bool,
    /// Seconds to wait for a busy session lock before giving up (0 = immediate).
    #[serde(default)]
    pub wait: Option<f64>,
}

#[derive(Serialize)]
pub struct Response {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Machine-readable reason for a failure (e.g. `busy`, `locked`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shells: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    /// Details of the lock that refused this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock: Option<serde_json::Value>,
    /// The client's own control connection: transport + authentication state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<serde_json::Value>,
}

impl Response {
    fn base(status: &str) -> Self {
        Self {
            status: status.to_string(),
            message: None,
            code: None,
            shells: None,
            output: None,
            exit_code: None,
            stderr: None,
            lock: None,
            connection: None,
        }
    }
    #[must_use]
    pub fn ok() -> Self {
        Self::base("ok")
    }
    pub fn error(msg: impl Into<String>) -> Self {
        let mut r = Self::base("error");
        r.message = Some(msg.into());
        r
    }
    /// A session is locked by somebody else.
    pub fn busy(msg: impl Into<String>, lock: serde_json::Value) -> Self {
        let mut r = Self::error(msg);
        r.code = Some("busy".into());
        r.lock = Some(lock);
        r
    }
    #[must_use]
    pub fn with_shells(shells: serde_json::Value) -> Self {
        let mut r = Self::base("ok");
        r.shells = Some(shells);
        r
    }
    #[must_use]
    pub fn with_output(out: String) -> Self {
        let mut r = Self::base("ok");
        r.output = Some(out);
        r
    }
    #[must_use]
    pub fn with_output_exit(out: String, code: i32, stderr: String) -> Self {
        let mut r = Self::base("ok");
        r.output = Some(out);
        r.exit_code = Some(code);
        r.stderr = if stderr.is_empty() { None } else { Some(stderr) };
        r
    }
    #[must_use]
    pub fn with_connection(mut self, connection: serde_json::Value) -> Self {
        self.connection = Some(connection);
        self
    }
}

// ── Shell session info ─────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct ShellInfo {
    pub id: u32,
    pub addr: String,
    pub created: f64,
    pub alive: bool,
    /// Target platform reported during the smart handshake (e.g. "windows/x86_64").
    /// `None` for dumb TCP shells, which don't perform a handshake.
    pub platform: Option<String>,
    /// Current exclusive lock, for sessions that need one (dumb shells).
    /// `None` for lock-free sessions (ww-target `send`, and free dumb shells).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock: Option<ShellLockInfo>,
}

/// Who holds a session lock, as reported by `list`.
#[derive(Serialize, Clone)]
pub struct ShellLockInfo {
    /// Human-readable holder (uid / key fingerprint / peer address).
    pub owner: String,
    /// True when *this* control connection is the holder.
    pub mine: bool,
    /// Seconds the lock has been held.
    pub held_for: f64,
    /// Seconds until the lease lapses, if the lock has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<f64>,
}
