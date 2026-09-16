# Plan: TCP tunneling / SOCKS5 through `ww-target`

**Status: implemented — v3.4.0 (P1–P4), review fixes in v3.4.1.**  See
`CHANGELOG.md` and §13 ("Where the shipped code differs from this plan").  There
was never a `v3.3.0` release: the "P1+P2+P3 → 3.3.0" split below was folded into
the single 3.4.0 release, and the version numbers in §11 are therefore history,
not a promise.

**Goal.** Reach hosts only the target can reach: `ww forward` (one port) and `ww socks`
(SOCKS5 proxy), both dialing from `ww-target`.

**Rule: the target never listens.** No new port anywhere, no new connection. Tunnels are
streams on the connection the agent already opened to `:4446` (the same one that carries
`send`/`upload`/`download`). The operator's `ww` opens a local loopback port as the abstraction.

---

## 1. Wire format — `src/target/protocol.rs`

```rust
pub const FRAME_TUNNEL_OPEN:   u8 = 0x0A;   // srv → tgt  JSON {stream_id, host, port, connect_timeout}
pub const FRAME_TUNNEL_OPENED: u8 = 0x0B;   // tgt → srv  JSON {stream_id, ok, bound?, errno?, message?}
pub const FRAME_TUNNEL_DATA:   u8 = 0x0C;   // both      [stream_id: u32 LE][bytes]
pub const FRAME_TUNNEL_EOF:    u8 = 0x0D;   // both      [stream_id: u32 LE]  half-close
pub const FRAME_TUNNEL_CLOSE:  u8 = 0x0E;   // both      JSON {stream_id, reason}

pub const FEATURE_TUNNEL: &str = "tunnel";
pub const MAX_TUNNEL_DATA: usize = 32 * 1024;

#[derive(Serialize, Deserialize)] pub struct TunnelOpen   { pub stream_id: u32, pub host: String, pub port: u16, pub connect_timeout: f64 }
#[derive(Serialize, Deserialize)] pub struct TunnelOpened { pub stream_id: u32, pub ok: bool, pub bound: Option<String>, pub errno: Option<i32>, pub message: Option<String> }
#[derive(Serialize, Deserialize)] pub struct TunnelClose  { pub stream_id: u32, pub reason: String }

// shared by both ends, unit-testable
pub fn tunnel_data_payload(stream_id: u32, data: &[u8]) -> Vec<u8>;   // 4-byte LE id ‖ data
pub fn tunnel_stream_id(payload: &[u8]) -> Option<u32>;
```

`Handshake` (same file) gains `#[serde(default)] pub features: Vec<String>`; update
`Handshake::new_client(hostname, platform, features)` and `new_server(session_id, features)`,
plus `pub fn has_feature(&self, f: &str) -> bool`. Call sites to fix: `src/bin/target.rs:224`
(`run_session` handshake write), `src/bin/server/shells.rs:69` (response), and the platform
plumbing in `shells.rs:60`/`session.rs`.

Frames are additive: old peers log "unknown frame type" and ignore them.

## 2. P1 — `ww-target` reader/writer restructure (no new features; fixes 2 bugs)

Files: `src/bin/target.rs` only. **Do this before any tunnel code.**

- **P1.1 Single writer.** Add `type Outbound = (u8, Vec<u8>);` and
  `fn spawn_writer(stream: TcpStream) -> std::io::Result<SyncSender<Outbound>>` — one thread,
  `rx.recv()` → `write_frame`, loop. All producers send on the clone. Delete the three
  `stream.try_clone()` writer paths in `run_session`.
  *Done when:* no code path calls `write_frame` outside `spawn_writer`.
- **P1.2 Single reader loop.** Rework `run_session(stream: &TcpStream, shell: &Shell, server: &str)`
  into `let mut st = SessionState::new(...); loop { let (t, p) = read_frame(&mut reader)?;
  dispatch(&mut st, t, p)?; }` with
  `fn dispatch(st, ftype, payload) -> Result<()>` handling SHELL / FILE_CTRL / CANCEL / CMD /
  HASH / KEEPALIVE / TUNNEL_*.
- **P1.3 Push/pull as state machines.** `handle_push` and `handle_pull` currently *loop on the
  socket* (`src/bin/target.rs` ~line 300+) and drop any frame that isn't theirs. Replace with
  `enum Transfer { Idle, Push { path, expected, remaining, data: Vec<u8> }, Pull { data: Vec<u8>, sent: usize } }`
  stored in `SessionState`, pumped by `dispatch` via
  `fn push_frame(st, ftype, payload) -> Result<()>` and `fn pull_pump(st) -> Result<()>`
  (`pull_pump` sends one `FRAME_FILE_DATA` chunk per call, then `push_done`).
- **P1.4 Bounded queues.** `std::sync::mpsc::sync_channel(1024)` for `Outbound`; on `send`
  error (writer thread died) bail out of `run_session`.
  *As shipped:* the inbound (socket → dispatcher) queue is bounded as well —
  `sync_channel(INBOUND_QUEUE)`, 256 frames — and every tunnel stream owns a bounded writer queue
  (`TUNNEL_WRITE_QUEUE`, 64 commands) driven by its own thread, so a stalled destination cannot
  block the dispatcher.
- **P1.5 Regression test.** In `tests/e2e_target.sh`, before the fix: start a background output
  loop on the target (`ww send 1 "nohup sh -c 'while :; do echo tick; sleep 0.01; done' &"`),
  then `ww targ upload` a ~5 MB file and assert the hash verifies and the session is still
  alive. *Must fail/flap before P1, pass after.*
- Gate: `cargo check && cargo clippy && PATH="$PWD/target/release:$PATH" bash tests/e2e_target.sh`
  (all existing tests 1–12 green).

## 3. P2 — target dialer + server routing

**P2.1 `src/bin/server/session.rs`**
- `pub enum TunnelEvent { Opened(TunnelOpened), Data(Vec<u8>), Eof, Closed(String) }`
- `SmartSession` gains: `features: Vec<String>`, `supports_tunnels: bool`,
  `tunnels: Arc<Mutex<HashMap<u32, mpsc::Sender<TunnelEvent>>>>`,
  `next_stream_id: AtomicU32`.
- In the reader task (`SmartSession::new`), add arms: `FRAME_TUNNEL_OPENED/DATA/EOF/CLOSE` →
  look up `tunnels` by `stream_id` and `try_send` the event (skip when absent; on full, record the
  reason out-of-band on `TunnelEntry::overflow`, then drop the sender so the relay unblocks and
  reports `consumer too slow` instead of `session closed`). Keep `FRAME_FILE_*` on `ctrl_queue`.
  *As shipped:* the reason is recorded before the sender is dropped and read back by the relay —
  see `session.rs::deliver_tunnel` and `handlers.rs::relay_tunnel_inner`.
- **Session death must wake every relay.** A relay blocked in `rx.recv()` never re-checks
  `alive`. When the reader task exits, `std::mem::take(&mut *tunnels.lock().await)` and drop all
  senders → every relay sees `None` and closes its control connection (e2e case 19).
- `SmartSession::new(id, addr, platform, features, stream)`;
  `SessionManager::add_smart(addr, platform, features, stream)`.
- Call site: `src/bin/server/shells.rs::smart_listener` — pass `hs.features`.

**P2.2 `src/bin/target.rs` — tunnel streams**
- `struct TunnelStream { dest: TcpStream, out: SyncSender<Outbound>, last_activity: Arc<AtomicU64>,
  closed_read: bool, closed_write: bool, closing: bool }` (`last_activity` = epoch milliseconds);
  `SessionState.streams: HashMap<u32, TunnelStream>`, `max_streams: usize`,
  `idle_timeout: Duration`, `server_addr: String`.
- `fn tunnel_open(st, o: TunnelOpen) -> Result<()>`:
  - reject if `st.streams.len() >= st.max_streams` → `TunnelOpened{ok:false, errno: Some(EMFILE)}`;
  - reject if `(o.host, o.port)` is the agent's own server (`st.server_addr`, best-effort:
    string match plus `peer_addr` IP match) → `ok:false, message:"refusing to dial own server"`;
  - `TcpStream::connect_timeout` per resolved addr (`ToSocketAddrs`, budget
    `o.connect_timeout`), `set_nodelay(true)`, `set_read_timeout(1s)`, `set_write_timeout(10s)`;
  - on failure → `TunnelOpened{ok:false, errno: err.raw_os_error(), message}`;
  - on success → insert stream, 
    `TunnelOpened{ok:true, bound: local_addr}`, and *only then* start the read half:
    `spawn_tunnel_reader(id, dest.try_clone()?, out.clone(), last_activity.clone())`.  `OPENED`
    must be the first frame of the stream — both producers share one FIFO outbound queue, so
    starting the reader first would let a destination that speaks first race its own `OPENED`.
    *As shipped:* the socket's write half belongs to a per-stream writer thread started before the
    announcement (`spawn_tunnel_writer`), and the reader starts after it.
- `fn spawn_tunnel_reader(stream_id, dest, out, last_activity)`: loop
  `read` → `out.send(FRAME_TUNNEL_DATA, tunnel_data_payload(id, chunk))`;
  `Ok(0)` → `FRAME_TUNNEL_EOF`; error → `FRAME_TUNNEL_CLOSE`. On `ReadTimeout`, if
  `last_activity` is older than `idle_timeout` → close the stream, else continue.
- Inbound: `tunnel_write(st, id, bytes)` → `dest.write_all` (bumps `last_activity`);
  timeout/`BrokenPipe` → `tunnel_close(st, id, "write failed")`.
  `FRAME_TUNNEL_EOF` → `dest.shutdown(Shutdown::Write)`, set `closed_write = true`;
  reader `Ok(0)` → send `FRAME_TUNNEL_EOF`, set `closed_read = true`.
  **Removal rule:** as soon as `closed_read && closed_write` — or on `FRAME_TUNNEL_CLOSE`, a
  write error, an idle reap, or `out.send()` failing — remove from `streams`, drop `dest`, and
  emit `FRAME_TUNNEL_CLOSE{reason}` exactly once (guard with a `closing: bool`).
- `Args` gains `--max-streams` (default 64), `--idle-timeout` (default 600).
- Unit tests in `src/target/protocol.rs`: payload round-trip incl. 32 KiB, `tunnel_stream_id`
  on short/oversized payloads.

## 4. P3 — `connect` action + `ww forward` (release 3.3.0)

**P3.1 Runtime.** `Cargo.toml`: tokio features += `"rt-multi-thread"`;
`src/bin/server/main.rs`: drop `flavor = "current_thread"` from `#[tokio::main]`.

**P3.2 Server action — `src/bin/server/handlers.rs`**
- Add `#[derive(serde::Deserialize)] struct ConnectCommand { host: String, port: u16, #[serde(default = "def_timeout")] timeout: f64 }`.
- **Remove the `BufReader`** from `handle_control_conn` and replace it with
  `fn read_line_raw(stream: &mut ControlStream) -> Result<Vec<u8>>` reading byte-at-a-time up to
  64 KiB.  *As shipped:* the helper returns only the line — a byte-at-a-time read cannot
  over-read, so there are no "early tunnel bytes" to hand on, and `connect_handler` builds its own
  prefix if a target nevertheless sends `DATA` before `OPENED`.  This also lets `push_handler`
  drop its `buffered: Vec<u8>` parameter and the `buf_reader.buffer()` hack.
  **`authenticate()` must use the same helper** instead of its own `BufReader`: a dropped
  `BufReader` can swallow bytes belonging to the next message, which would hang the action read
  and silently drop any pipelined bytes after it. After this change no control connection uses
  `BufReader`, which removes that whole bug class.
- New arm in the `match action.as_str()` dispatch:
  `"connect" => return connect_handler(cmd, manager, stream).await,`
  (takes `stream` **by value** — other arms keep `&mut stream`).
- `fn connect_handler(cmd, manager, mut stream: ControlStream) -> Result<()>` (`leftover` is
  built inside, from any early `DATA` event):
  1. `ConnectCommand` from `cmd.data`; enforce `MAX_TUNNELS_PER_SESSION` (`const … = 64`).
  2. Look up `ManagedSession::Smart`, check `alive` and `s.supports_tunnels` (else
     `{"status":"error","message":"target agent does not support tunneling — upgrade ww-target"}`).
  3. `stream_id = s.next_stream_id.fetch_add(1)`, `mpsc::channel(64)`, insert sender into
     `s.tunnels`; write `FRAME_TUNNEL_OPEN` via `s.writer.lock()`.
  4. Await `TunnelEvent::Opened` with `tokio::time::timeout(timeout + 5s)`; error → remove from
     `tunnels`, reply `{"status":"error","message":…,"errno":…}` (hand-rolled `json!`, not
     `Response`, so `src/lib.rs` needs no change).
  5. Success → `{"status":"ok","bound":"ip:port"}` as one line, then
     `relay_tunnel(stream, s.writer.clone(), rx, leftover).await`.
  6. `fn relay_tunnel(control, target_writer, rx, leftover)`: convert `ControlStream` to
     `tokio::net::{TcpStream,UnixStream}` via `from_std` after `set_nonblocking(true)`; loop on
     `tokio::select!` — channel → `frame::write_frame(FRAME_TUNNEL_DATA)`, control read →
     same, `Eof` → `FRAME_TUNNEL_EOF`, `Closed`/error → `FRAME_TUNNEL_CLOSE` and stop.
     Always remove the sender from `s.tunnels` on exit.
- Reuse `prepare_smart_transfer`'s lookup pattern but do **not** touch `in_file_transfer`:
  tunnels and transfers must coexist.
- Error → reply-code mapping lives in `src/socks.rs` (§5) so both commands share it.

**P3.3 Client — `src/bin/client.rs`**
- `Commands::Forward { id: u32, #[arg(short = 'L', long = "listen")] listen: String }`
  where `listen = [bind:]lport:host:port`; parser `fn parse_forward_spec(&str) -> Result<(String /*bind*/, u16, String, u16)>`
  (default bind `127.0.0.1`).
- **Cache identities once.** Replace `load_private_key`-per-connection with
  `struct Identities(Vec<(PrivateKey, PublicKey)>)`, loaded in `main` via
  `fn load_identities(cli: &Cli) -> Result<Identities>`; change `connect(cli: &Cli)` →
  `connect(cli: &Cli, ids: &Identities)` and `auth_handshake(stream, ids: &Identities)`.
  Call sites: `send_cmd`, `send_cmd_raw`, `cmd_targ_upload`, `cmd_targ_download`, new
  `cmd_forward`/`cmd_socks`.
- `fn open_stream(cli, ids, id, host, port, timeout) -> Result<ClientStream>`: `connect()`,
  `set_read_timeout(None)`, write `{"action":"connect","id":…,"data":"{\"host\":…,\"port\":…,\"timeout\":…}"}`,
  read one reply line **byte-at-a-time** (same trick as `cmd_targ_download`, so no tunnel bytes
  are swallowed), return `Ok(stream)` on `status == "ok"`, else `Err` carrying `errno`.
- `fn cmd_forward(...)`: `std::net::TcpListener::bind`; per accepted connection
  `std::thread::spawn` → `open_stream` → `relay_local(client, control)`.
  `fn relay_local(a: impl Read+Write, b: ClientStream)`: two threads with `std::io::copy` and
  `shutdown(Shutdown::Write)` on EOF each way (half-close); add
  `ClientStream::shutdown_write()` and `set_read_timeout`.
- Log to stderr only. `ClientStream` needs no `BufReader` anywhere on this path.

## 5. P4 — `ww socks` (release 3.4.0)

**P4.1 New crate module `src/socks.rs`** (+ `pub mod socks;` in `src/lib.rs`, so `cargo test`
covers it):
```rust
pub enum Proto { Socks5, HttpConnect }
pub fn detect_proto(first_byte: u8) -> Proto;           // 0x05 → Socks5, else HttpConnect
pub struct Request { pub host: String, pub port: u16 }
pub fn greet<S: Read + Write>(s: &mut S, auth: Option<(&str, &str)>) -> Result<bool>; // false = client rejected
pub fn read_request<S: Read + Write>(s: &mut S) -> Result<Request>;    // CMD!=CONNECT → Err(Unsupported)
pub fn write_reply<S: Write>(s: &mut S, code: u8);                     // BND = 0.0.0.0:0
pub fn read_http_connect<S: Read + Write>(s: &mut S) -> Result<Request>; // non-CONNECT → Err(NotConnect)
pub fn write_http_reply<S: Write>(s: &mut S, code: u16, reason: &str);
pub fn reply_code_from_errno(errno: i32) -> u8;   // unix: ECONNREFUSED→0x05, ENETUNREACH→0x03,
                                                  // EHOSTUNREACH→0x04, ETIMEDOUT→0x06, EMFILE→0x01
                                                  // winsock: 10061→0x05, 10051→0x03, 10065→0x04,
                                                  // 10060→0x06, 10024→0x01; else 0x01
pub const ATYP_NOT_SUPPORTED: u8 = 0x08;
pub const CMD_NOT_SUPPORTED: u8 = 0x07;
```
Details: accept `ATYP 0x01|0x03|0x04`, pass **ATYP 0x03 through as a hostname**; no-auth
(`0x00`) always offered, `0x02` when `auth` is set (RFC1929 reply `01 00`/`01 01`); `BIND`/UDP
→ `0x07`; unknown ATYP → `0x08`. `#[cfg(test)] mod tests` with byte-vector fixtures for every
branch (greet/no-auth, greet/user-pass/ok, greet/user-pass/fail, no acceptable method,
ATYP 1/3/4, BIND, UDP, bad version, malformed, truncated).

**P4.2 Wiring — `src/bin/client.rs`**
- `Commands::Socks { id: u32, #[arg(long, default_value = "127.0.0.1:1080")] listen: String,
  #[arg(long)] local_dns: bool, #[arg(long)] socks_user: Option<String>,
  #[arg(long)] socks_pass: Option<String>, #[arg(long)] socks_only: bool,
  #[arg(long, default_value_t = 10.0)] connect_timeout: f64, #[arg(long)] exit_on_disconnect: bool }`
- `fn cmd_socks(...)`: warn loudly if the bind host is not loopback. Per client connection:
  `TcpStream::peek` 1 byte on the accepted socket (`peek` on the concrete socket, not a
  `BufReader` — detection must not be able to eat payload) → `detect_proto` →
  `Proto::HttpConnect` (reject with `501` if `--socks-only`) or `Proto::Socks5`; then the
  handshake above; then `open_stream` (host as-is unless `--local-dns`, which resolves in `ww`
  and sends a numeric ATYP=1/ATYP=4); then `write_reply(code)` and `relay_local`.
  On `open_stream` error map `errno` → `reply_code_from_errno`.
- Set `set_read_timeout(Some(10s))` for handshake + `open_stream`, then **clear it
  (`None`)** before the relay — otherwise a client that connects and sends nothing holds a
  thread forever (e2e case 22). No per-connection cap is needed locally: the agent and server
  both cap at 64, and the overflow is reported as `0x01`.
- Both listeners: on control-connection loss close the local client, keep the listener
  (`--exit-on-disconnect` to stop instead).
- **Session lifetime.** Listeners bind to a *session id*. On control-connection loss: close the
  current client, keep listening, print one hint per loss, and fail new connections with `0x01`
  while the id is gone. `ww-target` gets a **new** id when it reconnects, so the escape hatches
  are `--exit-on-disconnect` or a restart with the new id; matching by hostname/platform is a
  later `--follow` flag, not v1.

## 6. P5 — `ww targ scan` / `resolve` (3.5.0, optional)

`FRAME_CMD` already returns stdout; implement as a thin client-side loop over it first
(`ww targ scan <id> <cidr> --ports 22,80`, emitting `host:open-ports`), and only add a real
`FRAME_SCAN`/`FRAME_SCAN_RESULT` pair if the `sh -c` path proves too slow. No root needed.

## 7. CLI surface (final)

```
ww forward <id> -L [bind:]lport:host:port          # default bind 127.0.0.1
ww socks <id> [--listen 127.0.0.1:1080] [--local-dns] [--socks-user U --socks-pass P]
              [--socks-only] [--connect-timeout 10] [--exit-on-disconnect]
ww-target <host> [--max-streams 64] [--idle-timeout 600]
```

## 8. Decisions

| Topic | Choice |
|---|---|
| SOCKS scope | CONNECT only; `BIND`/UDP → `0x07` |
| Library | Hand-rolled `src/socks.rs` (no new deps; `ww` stays synchronous, exact reply codes) |
| DNS | Remote by default (ATYP=3 passthrough), `--local-dns` opt-out |
| Bind | `127.0.0.1:1080` IPv4 loopback; warn on anything else |
| Same port | SOCKS5 + HTTP CONNECT by first-byte sniff; `--socks-only` disables HTTP |
| Limits | 64 streams/session (agent **and** server), 600 s idle, always refuse dialing the agent's own server |
| ACL | None in v1: destinations allow-all, the real control being the loopback-only bind. A CIDR allowlist cannot work with remote DNS anyway — only the target resolves the name |
| Backpressure | `mpsc` per stream, non-blocking `try_send`, overflow → reset that stream only |
| Deferred | UDP ASSOCIATE, TUN/raw-IP, server-side listener, `exec --stream` |

## 9. proxychains compatibility (verified against proxychains-ng 4.17)

1. **Accept ATYP=3 hostnames** — `proxy_dns` is on by default and sends names, not IPs.
2. **Reply within 8 s** (`tcp_connect_time_out`) → `connect_timeout` on the dial, reaped; a
   black-holed SYN must answer `0x06` quickly, not after the OS's ~130 s.
3. **Propagate half-close** — proxychains does *not* hook `shutdown()`, so an app's `SHUT_WR`
   arrives as plain EOF; forward it as `FRAME_TUNNEL_EOF`, don't tear down.
4. **IPv4 numeric proxy address** (`[ProxyList]` rejects hostnames; upstream v6 is "preliminary").
5. **Correct RFC1929** replies when `--socks-user/--socks-pass` is used.

Document, don't fix: TCP only (proxychains is too); nmap needs `-sT -Pn` + numeric IPs (or
`proxy_dns` off, or `nmap --proxies` via our HTTP CONNECT); LD_PRELOAD caveats.

## 10. Tests

- Unit (in-crate): `src/socks.rs` fixtures; `src/target/protocol.rs` frame/payload round-trips;
  `reply_code_from_errno` over both the Unix errno and WinSock tables (a Windows `ww-target`
  otherwise degrades every failure to `0x01`).
- E2E — append to `tests/e2e_target.sh` (reuse its `pass`/`fail`/`header` helpers and the
  `XDG_CONFIG_HOME` isolation; start `python3 -m http.server 8000` in the background).
  *As shipped* these live in the script as **cases 13–20**, whose numbering does not match the
  list below: the script merged some cases, added the P1 concurrent-upload regression as case 13,
  and `src/bin/target.rs` refers to the `WW_NO_TUNNEL` hook as *e2e case 18* (not 20):
  13. `ww forward 1 -L 127.0.0.1:8080:127.0.0.1:8000` + `curl` → body matches. Run once over the
      Unix socket and once over the TCP control port (reuse tests 10–12's setup) to cover the
      post-auth byte path.
  14. `ww socks 1` + `curl --socks5-hostname 127.0.0.1:1080 http://localhost:8000/` → body matches
      (proves ATYP=3).
  15. `curl -x http://127.0.0.1:1080 http://localhost:8000/` works; `--socks-only` refuses;
      `GET http://…` absolute-URI → `501`.
  16. 8 parallel curls through the proxy **while** `ww send` and `ww targ upload` (5 MB) run —
      all bodies correct, hash verifies.
  17. Closed port → `0x05` (assert with a `python3` raw-socket client); `192.0.2.1` →
      `0x06` within `--connect-timeout`.
  18. UDP ASSOCIATE and BIND requests → `0x07`.
  19. Kill `ww-target` mid-tunnel → local client EOF, listener still accepts after the agent
      reconnects.
  20. `WW_NO_TUNNEL=1 ww-target` (test-only env hook in the agent) → `connect` fails with
      "does not support tunneling", no hang.
  21. Read-to-EOF-then-reply server (half-close); `--max-streams 2` → third stream fails.
  22. SOCKS client that connects and sends nothing → dropped by the handshake timeout (no leaked
      thread); session killed mid-relay → blocked relay unblocks (P2.1 cleanup).
- Manual, not CI: proxychains smoke test (`proxychains4 -f … curl ifconfig.me`,
  `proxychains4 nmap -sT -Pn <ip>`). It's LD_PRELOAD and not installed on the runners;
  `curl --socks5-hostname` covers the same wire path.

## 11. Release & docs

- *As shipped:* everything (P1–P4) went out in **3.4.0** — there is no `v3.3.0` tag or
  release.  The split below is what was planned, not what happened; ignore it when checking
  compatibility and use the `tunnel` handshake feature instead of a version number.
- P1+P2+P3 → `Cargo.toml` `version = "3.3.0"`, `CHANGELOG.md` entry, README (protocol table
  +5 rows, `features` note, "Pivoting" section), commit, tag `v3.3.0`, push (AGENTS.md).
- P4 → `3.4.0` (protocol unchanged, so pre-tunneling agents keep working), same procedure.
- README must state: `ww socks` warns if bound off-loopback; proxychains/nmap caveats (§9);
  tunnels need an agent that advertises the `tunnel` feature (shipped in 3.4.0).
- *As shipped:* a follow-up release (3.4.1) fixed the review findings — SOCKS5 auth bypass,
  HTTP CONNECT bypassing that auth, `OPENED`/`DATA` ordering, per-stream write queues,
  bounded queues, teardown leaks, resource caps, and a handshake deadline.

## 12. Caveats to document

1. **No UDP/ICMP** — no QUIC/WireGuard/UDP DNS through the tunnel.
2. Shared single link: heavy or stalled streams affect or reset each other; target reconnect
   kills open streams (listener survives).  *As shipped* a stream whose per-stream write queue
   overflows is reset (reason `stream stalled`) rather than allowed to block the others.

## 13. Where the shipped code differs from this plan

1. **Version numbers.**  No 3.3.0 release (§11); one 3.4.0 release for P1–P4, then 3.4.1 for the
   review fixes.
2. **`read_line_raw`, not `read_json_line`.**  The helper returns only the line: byte-at-a-time
   reads cannot over-read, so there are no leftover bytes to thread through.  `connect_handler`
   builds its own early-data prefix if a target sends `DATA` before `OPENED` (§4).
3. **Overflow reporting.**  A full per-stream event queue cannot carry a `Closed(...)` message
   (that is what made the original wording self-contradictory).  The reason is recorded on
   `TunnelEntry::overflow` just before the sender is dropped, and the relay reports it (§3).
4. **Tunnel stream I/O threads.**  Each stream has a reader thread and a writer thread; the
   writer owns the socket's write half and has a bounded command queue, so a stalled destination
   resets that stream instead of blocking the dispatcher (§3).
5. **Close reasons.**  `stream stalled` (agent), `consumer too slow` (server), `write timeout`,
   `refusing to dial own server` — used instead of a single generic reason.
6. **Extra limits not in the plan:** `MAX_FRAME_PAYLOAD` (8 MiB), `MAX_PUSH_SIZE` (512 MiB),
   `MAX_CONCURRENT_CMDS`/`MAX_CMD_OUTPUT` on the agent, `MAX_LOCAL_CONNS` in `ww`, and the
   handshake `Deadline` in `src/socks.rs`.
7. **E2E numbering** (§10) does not match `tests/e2e_target.sh` cases 13–20.
