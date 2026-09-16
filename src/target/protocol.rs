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

// ── Tunneling (P2+) ─────────────────────────────────────────────────────────

/// Server → target: open a tunnel stream (JSON `TunnelOpen`).
pub const FRAME_TUNNEL_OPEN: u8 = 0x0A;
/// Target → server: result of a tunnel open (JSON `TunnelOpened`).
pub const FRAME_TUNNEL_OPENED: u8 = 0x0B;
/// Both: raw tunnel bytes (`[stream_id: u32 LE][bytes]`).
pub const FRAME_TUNNEL_DATA: u8 = 0x0C;
/// Both: half-close of one direction (`[stream_id: u32 LE]`).
pub const FRAME_TUNNEL_EOF: u8 = 0x0D;
/// Both: tear down a tunnel stream (JSON `TunnelClose`).
pub const FRAME_TUNNEL_CLOSE: u8 = 0x0E;

/// Feature name advertised in the handshake when the agent supports tunnels.
pub const FEATURE_TUNNEL: &str = "tunnel";

/// Maximum number of bytes carried in a single `FRAME_TUNNEL_DATA` payload.
pub const MAX_TUNNEL_DATA: usize = 32 * 1024;

/// Upper bound on a single frame payload, enforced by both peers before
/// allocating.  The largest legitimate payload is a 64 KiB file-data chunk
/// (`FRAME_FILE_DATA`); `MAX_TUNNEL_DATA` is far below this.
pub const MAX_FRAME_PAYLOAD: usize = 8 * 1024 * 1024;

/// Server → target: request a TCP connection to `host:port` as `stream_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelOpen {
    pub stream_id: u32,
    pub host: String,
    pub port: u16,
    pub connect_timeout: f64,
}

/// Target → server: outcome of a `TunnelOpen` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelOpened {
    pub stream_id: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Either side: close a tunnel stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelClose {
    pub stream_id: u32,
    pub reason: String,
}

/// Build the payload of a `FRAME_TUNNEL_DATA` frame: 4-byte LE stream id ‖ data.
#[must_use]
pub fn tunnel_data_payload(stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&stream_id.to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// Extract the stream id from a `FRAME_TUNNEL_DATA` / `FRAME_TUNNEL_EOF` payload.
/// Returns `None` when the payload is shorter than 4 bytes.
#[must_use]
pub fn tunnel_stream_id(payload: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = payload.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

// ── Handshake ───────────────────────────────────────────────────────────────

/// Initial identity exchange. Client sends hostname/platform/features,
/// server replies with a session id (and echoes its own features).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub session_id: Option<String>,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    /// Optional capabilities; absent on old peers (`serde(default)`).
    #[serde(default)]
    pub features: Vec<String>,
}

impl Handshake {
    #[must_use]
    pub fn new_client(
        hostname: Option<String>,
        platform: Option<String>,
        features: Vec<String>,
    ) -> Self {
        Self { session_id: None, hostname, platform, features }
    }

    #[must_use]
    pub fn new_server(session_id: impl Into<String>, features: Vec<String>) -> Self {
        Self {
            session_id: Some(session_id.into()),
            hostname: None,
            platform: None,
            features,
        }
    }

    /// Whether the peer advertised `feature` during the handshake.
    #[must_use]
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
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

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_data_payload_roundtrip() {
        let payload = tunnel_data_payload(0xDEAD_BEEF, b"hello");
        assert_eq!(tunnel_stream_id(&payload), Some(0xDEAD_BEEF));
        assert_eq!(&payload[4..], b"hello");
    }

    #[test]
    fn tunnel_data_payload_empty_data() {
        let payload = tunnel_data_payload(7, &[]);
        assert_eq!(payload.len(), 4);
        assert_eq!(tunnel_stream_id(&payload), Some(7));
    }

    #[test]
    fn tunnel_data_payload_full_chunk() {
        let data = vec![0xAB_u8; MAX_TUNNEL_DATA];
        let payload = tunnel_data_payload(42, &data);
        assert_eq!(payload.len(), MAX_TUNNEL_DATA + 4);
        assert_eq!(tunnel_stream_id(&payload), Some(42));
        assert_eq!(&payload[4..], &data[..]);
    }

    #[test]
    fn tunnel_stream_id_short_payloads() {
        assert_eq!(tunnel_stream_id(&[]), None);
        assert_eq!(tunnel_stream_id(&[0x01]), None);
        assert_eq!(tunnel_stream_id(&[0x01, 0x02]), None);
        assert_eq!(tunnel_stream_id(&[0x01, 0x02, 0x03]), None);
        assert_eq!(tunnel_stream_id(&[1, 0, 0, 0]), Some(1));
    }

    #[test]
    fn tunnel_stream_id_ignores_trailing_bytes() {
        let payload = tunnel_data_payload(9, b"ignored-trailer");
        assert_eq!(tunnel_stream_id(&payload), Some(9));
    }

    #[test]
    fn frame_limits_admit_every_tunnel_frame() {
        const { assert!(MAX_TUNNEL_DATA + 4 <= MAX_FRAME_PAYLOAD) };
    }

    #[test]
    fn handshake_feature_roundtrip() {
        let hs = Handshake::new_client(
            Some("host".into()),
            Some("linux/x86_64".into()),
            vec![FEATURE_TUNNEL.to_string()],
        );
        let json = serde_json::to_string(&hs).unwrap();
        let back: Handshake = serde_json::from_str(&json).unwrap();
        assert!(back.has_feature(FEATURE_TUNNEL));
        assert!(!back.has_feature("nope"));
    }

    #[test]
    fn handshake_without_features_field_deserializes() {
        // Old peers omit `features` entirely. Fetching:
        let old = r#"{"session_id":null,"hostname":"h","platform":"p"}"#;
        let hs: Handshake = serde_json::from_str(old).unwrap();
        assert!(hs.features.is_empty());
        assert!(!hs.has_feature(FEATURE_TUNNEL));
    }

    #[test]
    fn handshake_server_roundtrip() {
        let hs = Handshake::new_server("id-1", vec![FEATURE_TUNNEL.to_string()]);
        let json = serde_json::to_string(&hs).unwrap();
        let back: Handshake = serde_json::from_str(&json).unwrap();
        assert_eq!(back.session_id.as_deref(), Some("id-1"));
        assert!(back.has_feature(FEATURE_TUNNEL));
    }
}
