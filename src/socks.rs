//! Minimal SOCKS5 (RFC 1928 / RFC 1929) and HTTP CONNECT helpers.
//!
//! `ww socks` accepts local proxy connections, translates each into a
//! `ww-target` tunnel, and returns exact RFC-shaped replies.  This module is
//! pure `std` so it is unit-testable without any runtime.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// SOCKS5 reply code: address type not supported.
pub const ATYP_NOT_SUPPORTED: u8 = 0x08;
/// SOCKS5 reply code: command not supported.
pub const CMD_NOT_SUPPORTED: u8 = 0x07;

/// Wall-clock budget for one handshake.
///
/// Every byte read checks the deadline, so a peer that dribbles one byte at a
/// time cannot keep a thread alive indefinitely.  A single `read` may still
/// block for the socket's own read timeout, so the effective bound is
/// `budget + read timeout`.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    #[must_use]
    pub fn after(budget: Duration) -> Self {
        Self { at: Instant::now() + budget }
    }

    #[must_use]
    pub fn expired(&self) -> bool {
        Instant::now() >= self.at
    }
}

/// The protocol a local client speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Socks5,
    HttpConnect,
}

/// First-byte protocol detection.  `0x05` is SOCKS5; everything else is
/// treated as an HTTP CONNECT request.
#[must_use]
pub fn detect_proto(first_byte: u8) -> Proto {
    if first_byte == 0x05 {
        Proto::Socks5
    } else {
        Proto::HttpConnect
    }
}

/// A requested destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub host: String,
    pub port: u16,
}

/// Protocol-level error.  `Code` carries the SOCKS5 reply code to send before
/// closing; `NotConnect` means "reply HTTP 501"; `Timeout` means the handshake
/// budget expired.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Code(u8),
    NotConnect,
    Timeout,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Code(c) => write!(f, "protocol error (reply 0x{c:02x})"),
            Error::NotConnect => write!(f, "not an HTTP CONNECT request"),
            Error::Timeout => write!(f, "handshake deadline expired"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// `read_exact` that honours a [`Deadline`].  Unlike `Read::read_exact` it does
/// not retry forever on a slow peer, and it reports a clean [`Error::Timeout`].
fn read_exact<S: Read>(s: &mut S, buf: &mut [u8], deadline: Deadline) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        match s.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                )));
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(())
}

/// Constant-time byte comparison, used for the RFC 1929 credentials so the
/// comparison does not leak how many leading bytes matched.
#[must_use]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SOCKS5 method selection.  `auth` enables username/password (RFC 1929); when
/// it is set, authentication is **required** and a client offering only
/// "no authentication" is rejected with `0xFF` (RFC 1928).  Returns `false`
/// when the client was rejected (a reply has already been written).
pub fn greet<S: Read + Write>(
    s: &mut S,
    auth: Option<(&str, &str)>,
    deadline: Deadline,
) -> Result<bool> {
    let mut head = [0_u8; 2];
    read_exact(s, &mut head, deadline)?;
    if head[0] != 0x05 {
        // Unsupported version: NO ACCEPTABLE METHODS.
        s.write_all(&[0x05, 0xFF])?;
        s.flush()?;
        return Ok(false);
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0_u8; nmethods];
    read_exact(s, &mut methods, deadline)?;

    // When credentials are configured, auth is mandatory: silently accepting
    // 0x00 here would make `--socks-user/--socks-pass` a no-op.
    let method = if auth.is_some() {
        if methods.contains(&0x02) { 0x02 } else { 0xFF }
    } else if methods.contains(&0x00) {
        0x00
    } else {
        0xFF
    };
    s.write_all(&[0x05, method])?;
    s.flush()?;

    match method {
        0xFF => Ok(false),
        0x02 => match auth {
            Some(creds) => userpass_auth(s, creds, deadline),
            None => Ok(false),
        },
        _ => Ok(true),
    }
}

/// RFC 1929 username/password sub-negotiation.
fn userpass_auth<S: Read + Write>(
    s: &mut S,
    (user, pass): (&str, &str),
    deadline: Deadline,
) -> Result<bool> {
    let mut head = [0_u8; 2];
    read_exact(s, &mut head, deadline)?;
    if head[0] != 0x01 {
        s.write_all(&[0x01, 0x01])?;
        s.flush()?;
        return Ok(false);
    }
    let mut username = vec![0_u8; head[1] as usize];
    read_exact(s, &mut username, deadline)?;
    let mut plen = [0_u8; 1];
    read_exact(s, &mut plen, deadline)?;
    let mut password = vec![0_u8; plen[0] as usize];
    read_exact(s, &mut password, deadline)?;

    let ok = ct_eq(&username, user.as_bytes()) && ct_eq(&password, pass.as_bytes());
    s.write_all(&[0x01, if ok { 0x00 } else { 0x01 }])?;
    s.flush()?;
    Ok(ok)
}

/// Read a SOCKS5 CONNECT request.  `ATYP 0x03` is passed through as a
/// hostname (the target resolves it).  `BIND`/`UDP ASSOCIATE` and unknown
/// address types yield the matching reply code.
pub fn read_request<S: Read + Write>(s: &mut S, deadline: Deadline) -> Result<Request> {
    let mut head = [0_u8; 4];
    read_exact(s, &mut head, deadline)?;
    if head[0] != 0x05 {
        return Err(Error::Code(0x01));
    }
    if head[2] != 0x00 {
        // RSV must be zero (RFC 1928 §4).
        return Err(Error::Code(0x01));
    }
    let cmd = head[1];
    let atyp = head[3];
    if cmd != 0x01 {
        return Err(Error::Code(CMD_NOT_SUPPORTED));
    }

    let host = match atyp {
        0x01 => {
            let mut b = [0_u8; 4];
            read_exact(s, &mut b, deadline)?;
            Ipv4Addr::from(b).to_string()
        }
        0x03 => {
            let mut l = [0_u8; 1];
            read_exact(s, &mut l, deadline)?;
            if l[0] == 0 {
                // A zero-length domain name can never be dialled.
                return Err(Error::Code(0x01));
            }
            let mut d = vec![0_u8; l[0] as usize];
            read_exact(s, &mut d, deadline)?;
            match String::from_utf8(d) {
                Ok(h) => h,
                Err(_) => return Err(Error::Code(0x01)),
            }
        }
        0x04 => {
            let mut b = [0_u8; 16];
            read_exact(s, &mut b, deadline)?;
            Ipv6Addr::from(b).to_string()
        }
        _ => return Err(Error::Code(ATYP_NOT_SUPPORTED)),
    };

    let mut port = [0_u8; 2];
    read_exact(s, &mut port, deadline)?;
    Ok(Request { host, port: u16::from_be_bytes(port) })
}

/// Write a SOCKS5 reply with `BND.ADDR = 0.0.0.0` and `BND.PORT = 0`.
pub fn write_reply<S: Write>(s: &mut S, code: u8) {
    let _ = s.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    let _ = s.flush();
}

/// Maximum number of header lines accepted in an HTTP CONNECT request.
pub const MAX_HTTP_HEADERS: usize = 64;

/// Read an HTTP `CONNECT host:port HTTP/1.1` request plus its headers.
pub fn read_http_connect<S: Read + Write>(s: &mut S, deadline: Deadline) -> Result<Request> {
    let line = read_line(s, deadline)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(Error::NotConnect);
    }

    let (host, port_str) = if let Some(rest) = target.strip_prefix('[') {
        rest.split_once("]:").ok_or(Error::Code(0x01))?
    } else {
        target.rsplit_once(':').ok_or(Error::Code(0x01))?
    };
    let port: u16 = port_str.parse().map_err(|_| Error::Code(0x01))?;
    if host.is_empty() {
        return Err(Error::Code(0x01));
    }

    // Consume headers up to the blank line, bounded so a peer cannot stream
    // header lines forever.
    let mut headers = 0_usize;
    loop {
        if read_line(s, deadline)?.is_empty() {
            break;
        }
        headers += 1;
        if headers > MAX_HTTP_HEADERS {
            return Err(Error::Code(0x01));
        }
    }
    Ok(Request { host: host.to_string(), port })
}

/// Write an HTTP response status line and a blank line.
pub fn write_http_reply<S: Write>(s: &mut S, code: u16, reason: &str) {
    let _ = write!(s, "HTTP/1.1 {code} {reason}\r\n\r\n");
    let _ = s.flush();
}

/// Read one CRLF-terminated line, byte-at-a-time (never over-reads) and within
/// `deadline`.
fn read_line<S: Read>(s: &mut S, deadline: Deadline) -> Result<String> {
    let mut buf = Vec::new();
    let mut b = [0_u8; 1];
    loop {
        read_exact(s, &mut b, deadline)?;
        if b[0] == b'\n' {
            break;
        }
        if b[0] != b'\r' {
            buf.push(b[0]);
        }
        if buf.len() > 8192 {
            return Err(Error::Code(0x01));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Map a `raw_os_error()` (Unix errno or WinSock code, as reported by the
/// target) to a SOCKS5 reply code.
#[must_use]
pub fn reply_code_from_errno(errno: i32) -> u8 {
    match errno {
        // ECONNREFUSED: Linux 111, macOS/BSD 61, WinSock 10061
        111 | 61 | 10061 => 0x05,
        // ENETUNREACH: Linux 101, macOS/BSD 51, WinSock 10051
        101 | 51 | 10051 => 0x03,
        // EHOSTUNREACH: Linux 113, macOS/BSD 65, WinSock 10065
        113 | 65 | 10065 => 0x04,
        // ETIMEDOUT: Linux 110, macOS/BSD 60, WinSock 10060
        110 | 60 | 10060 => 0x06,
        // EMFILE / WSAEMFILE
        24 | 10024 => 0x01,
        _ => 0x01,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A generous budget for fixtures that are expected to answer promptly.
    fn dl() -> Deadline {
        Deadline::after(Duration::from_secs(5))
    }

    /// A duplex-ish fixture: writes are appended to `out`, reads come from `input`.
    struct Fixture {
        input: Cursor<Vec<u8>>,
        out: Vec<u8>,
    }

    impl Fixture {
        fn new(input: &[u8]) -> Self {
            Self { input: Cursor::new(input.to_vec()), out: Vec::new() }
        }
    }

    impl Read for Fixture {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl Write for Fixture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.out.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn detect() {
        assert_eq!(detect_proto(0x05), Proto::Socks5);
        assert_eq!(detect_proto(b'G'), Proto::HttpConnect);
        assert_eq!(detect_proto(0x00), Proto::HttpConnect);
    }

    #[test]
    fn greet_no_auth() {
        let mut f = Fixture::new(&[0x05, 0x01, 0x00]);
        assert!(greet(&mut f, None, dl()).unwrap());
        assert_eq!(f.out, vec![0x05, 0x00]);
    }

    #[test]
    fn greet_userpass_ok() {
        let mut input = vec![0x05, 0x02, 0x00, 0x02];
        input.extend_from_slice(&[0x01, 3, b'b', b'o', b'b', 4, b'p', b'a', b's', b's']);
        let mut f = Fixture::new(&input);
        assert!(greet(&mut f, Some(("bob", "pass")), dl()).unwrap());
        assert_eq!(f.out, vec![0x05, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn greet_userpass_fail() {
        let mut input = vec![0x05, 0x01, 0x02];
        input.extend_from_slice(&[0x01, 3, b'b', b'o', b'b', 4, b'p', b'a', b's', b's']);
        let mut f = Fixture::new(&input);
        assert!(!greet(&mut f, Some(("bob", "wrong")), dl()).unwrap());
        assert_eq!(f.out, vec![0x05, 0x02, 0x01, 0x01]);
    }

    /// Regression: credentials are configured, but the client only offers
    /// "no authentication".  The server must refuse (0xFF), not fall back to
    /// no-auth, otherwise `--socks-user/--socks-pass` is a no-op.
    #[test]
    fn greet_userpass_required_rejects_no_auth_client() {
        let mut f = Fixture::new(&[0x05, 0x01, 0x00]);
        assert!(!greet(&mut f, Some(("bob", "secret")), dl()).unwrap());
        assert_eq!(f.out, vec![0x05, 0xFF]);
    }

    /// Same, when the client offers an unrelated method as well.
    #[test]
    fn greet_userpass_required_rejects_unknown_method() {
        let mut f = Fixture::new(&[0x05, 0x02, 0x00, 0x01]);
        assert!(!greet(&mut f, Some(("bob", "secret")), dl()).unwrap());
        assert_eq!(f.out, vec![0x05, 0xFF]);
    }

    #[test]
    fn greet_no_acceptable_method() {
        let mut f = Fixture::new(&[0x05, 0x01, 0x01]);
        assert!(!greet(&mut f, None, dl()).unwrap());
        assert_eq!(f.out, vec![0x05, 0xFF]);
    }

    #[test]
    fn greet_bad_version() {
        let mut f = Fixture::new(&[0x04, 0x01, 0x00]);
        assert!(!greet(&mut f, None, dl()).unwrap());
        assert_eq!(f.out, vec![0x05, 0xFF]);
    }

    #[test]
    fn greet_deadline_expired() {
        let mut f = Fixture::new(&[0x05, 0x01, 0x00]);
        assert!(matches!(
            greet(&mut f, None, Deadline::after(Duration::ZERO)),
            Err(Error::Timeout)
        ));
        assert!(f.out.is_empty());
    }

    #[test]
    fn request_atyp_ipv4() {
        let mut f = Fixture::new(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90]);
        assert_eq!(
            read_request(&mut f, dl()).unwrap(),
            Request { host: "127.0.0.1".into(), port: 8080 }
        );
    }

    #[test]
    fn request_atyp_domain() {
        let mut input = vec![0x05, 0x01, 0x00, 0x03, 11];
        input.extend_from_slice(b"example.com");
        input.extend_from_slice(&[0x00, 0x50]);
        let mut f = Fixture::new(&input);
        assert_eq!(
            read_request(&mut f, dl()).unwrap(),
            Request { host: "example.com".into(), port: 80 }
        );
    }

    #[test]
    fn request_atyp_ipv6() {
        let mut input = vec![0x05, 0x01, 0x00, 0x04];
        input.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        input.extend_from_slice(&[0x01, 0xBB]);
        let mut f = Fixture::new(&input);
        assert_eq!(
            read_request(&mut f, dl()).unwrap(),
            Request { host: "::1".into(), port: 443 }
        );
    }

    #[test]
    fn request_bind_rejected() {
        let mut f = Fixture::new(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(read_request(&mut f, dl()), Err(Error::Code(CMD_NOT_SUPPORTED))));
    }

    #[test]
    fn request_udp_rejected() {
        let mut f = Fixture::new(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(read_request(&mut f, dl()), Err(Error::Code(CMD_NOT_SUPPORTED))));
    }

    #[test]
    fn request_unknown_atyp() {
        let mut f = Fixture::new(&[0x05, 0x01, 0x00, 0x09]);
        assert!(matches!(read_request(&mut f, dl()), Err(Error::Code(ATYP_NOT_SUPPORTED))));
    }

    #[test]
    fn request_bad_version() {
        let mut f = Fixture::new(&[0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        assert!(matches!(read_request(&mut f, dl()), Err(Error::Code(0x01))));
    }

    #[test]
    fn request_nonzero_rsv_rejected() {
        let mut f = Fixture::new(&[0x05, 0x01, 0xFF, 0x01, 127, 0, 0, 1, 0, 80]);
        assert!(matches!(read_request(&mut f, dl()), Err(Error::Code(0x01))));
    }

    #[test]
    fn request_empty_domain_rejected() {
        let mut f = Fixture::new(&[0x05, 0x01, 0x00, 0x03, 0, 0x00, 0x50]);
        assert!(matches!(read_request(&mut f, dl()), Err(Error::Code(0x01))));
    }

    #[test]
    fn request_truncated() {
        let mut f = Fixture::new(&[0x05, 0x01]);
        assert!(matches!(read_request(&mut f, dl()), Err(Error::Io(_))));
    }

    #[test]
    fn write_reply_shape() {
        let mut f = Fixture::new(&[]);
        write_reply(&mut f, 0x00);
        assert_eq!(f.out, vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn http_connect_ok() {
        let input = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut f = Fixture::new(input);
        assert_eq!(
            read_http_connect(&mut f, dl()).unwrap(),
            Request { host: "example.com".into(), port: 443 }
        );
    }

    #[test]
    fn http_connect_not_connect() {
        let mut f = Fixture::new(b"GET http://example.com/ HTTP/1.1\r\n\r\n");
        assert!(matches!(read_http_connect(&mut f, dl()), Err(Error::NotConnect)));
    }

    #[test]
    fn http_connect_malformed_target() {
        let mut f = Fixture::new(b"CONNECT noport HTTP/1.1\r\n\r\n");
        assert!(matches!(read_http_connect(&mut f, dl()), Err(Error::Code(0x01))));
    }

    #[test]
    fn http_connect_truncated() {
        let mut f = Fixture::new(b"CONNECT example.com:443 HTTP/1.1\r\n");
        assert!(matches!(read_http_connect(&mut f, dl()), Err(Error::Io(_))));
    }

    #[test]
    fn http_connect_too_many_headers() {
        let mut input = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        for _ in 0..MAX_HTTP_HEADERS + 2 {
            input.extend_from_slice(b"X-Pad: 1\r\n");
        }
        input.extend_from_slice(b"\r\n");
        let mut f = Fixture::new(&input);
        assert!(matches!(read_http_connect(&mut f, dl()), Err(Error::Code(0x01))));
    }

    #[test]
    fn http_reply_shape() {
        let mut f = Fixture::new(&[]);
        write_http_reply(&mut f, 200, "Connection established");
        assert_eq!(
            String::from_utf8(f.out).unwrap(),
            "HTTP/1.1 200 Connection established\r\n\r\n"
        );
    }

    #[test]
    fn ct_eq_matches_only_equal_slices() {
        assert!(ct_eq(b"bob", b"bob"));
        assert!(!ct_eq(b"bob", b"boc"));
        assert!(!ct_eq(b"bob", b"bobby"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn errno_mapping() {
        // Unix + macOS + WinSock tables.
        for e in [111, 61, 10061] {
            assert_eq!(reply_code_from_errno(e), 0x05);
        }
        for e in [101, 51, 10051] {
            assert_eq!(reply_code_from_errno(e), 0x03);
        }
        for e in [113, 65, 10065] {
            assert_eq!(reply_code_from_errno(e), 0x04);
        }
        for e in [110, 60, 10060] {
            assert_eq!(reply_code_from_errno(e), 0x06);
        }
        for e in [24, 10024] {
            assert_eq!(reply_code_from_errno(e), 0x01);
        }
        assert_eq!(reply_code_from_errno(0), 0x01);
        assert_eq!(reply_code_from_errno(-1), 0x01);
    }
}
