# Changelog

## v3.5.1 — fix HTTP CONNECT refusals being lost to a TCP reset

- **`ww socks` error replies could vanish.**  When the proxy refused a request
before reading it — HTTP CONNECT on a `--socks-only` or credential-protected
port, or a malformed request — it wrote the `501`/`400` and then dropped the
socket with the request bytes still queued.  Linux answers that with `RST`
instead of `FIN`, and an `RST` discards data already sent, so clients
intermittently saw `Recv failure: Connection reset by peer` instead of the
status line.  This is what made the CI `e2e-linux` job flaky (it failed on the
`--socks-only` 501 check and on the absolute-URI 501 check).  Refusals now
half-close and drain the pending request before closing (bounded, so a peer
cannot make us drain forever), so the reply is always delivered.
- `tests/e2e_target.sh`: the two `501` checks now read the complete status line
and repeat (10× and 5×) so this regression is caught rather than passing by
luck; several other checks use a `recvn` helper instead of a single `recv`,
which could also observe a partial read.

## v3.5.0 — session locks for dumb shells

Dumb reverse shells have no framing: commands are written raw and output is read
from one shared buffer, so two clients using the same shell at once interleaved
commands and stole each other's output.  Each dumb shell now carries an
exclusive lock.

- **Lock ownership is bound to the control connection**, so a lock is released
the instant the holder's connection ends — `ww` exiting, Ctrl-C, a crash, or
`kill -9`.  A shell can no longer be left hardlocked by a dying client
(verified end to end).
- **Lease + reaper** as a second safety net: TCP control connections carry a
300 s lease that is refreshed while the holder works, so a half-open peer
(network partition, killed VM) cannot pin a shell; a background reaper logs every
expiry.  Unix sockets need no lease — the kernel closes the fd.
- **`--force`** breaks a lock held by a client that is alive but stuck, on
`send`, `interact` and `script`.  The displaced holder's pending read stops
immediately, so it cannot steal the new holder's output.
- **`--wait SECS`** queues (FIFO) for a busy shell instead of failing.
- **`ww list` shows the holder**: red lock when another client holds the shell,
green when it is you, `-` when free — or when the session is a `ww-target`,
which is concurrency-safe and never takes a lock.
- **`ww list` shows your own authentication state**: a green `🔓` banner with the
identity when the control connection is key-authenticated, yellow for the local
Unix socket, red for an unauthenticated TCP control port.  Holders are resolved
from `SO_PEERCRED` (`ben (uid=1000)`) or the key fingerprint.  Colour is
suppressed for non-terminals and when `NO_COLOR` is set.
- Stale bytes left in a dumb shell's shared buffer by a previous holder are
drained when the next holder acquires the lock, so output can no longer be
attributed to the wrong command.
- The server no longer holds the global session-manager lock across a dumb
shell's output read, so one client's command no longer stalls `list` (or any
other client) for the length of the timeout.
- `ww send`: flags may now appear after the command.  `command` was a trailing
var-arg, so `ww send 1 "cmd" -t 5` silently ran `cmd -t 5` with the default
timeout; `-t/--force/--wait` are now parsed wherever they appear.
- Protocol: `send`/`read`/`interact` accept `force` and `wait`; `list` returns a
per-shell `lock` object plus a connection-level `connection` object.
- Tests: `tests/e2e_locks.sh` (10 end-to-end checks) and 9 unit tests for the
lock primitive.  No backwards-compatibility shims — upgrade `ww` and
`ww-server` together.

## v3.4.1 — security & robustness fixes for tunneling

- **Security: SOCKS5 auth was bypassable.**  With `--socks-user/--socks-pass`
  set, a client that offered only the *no authentication* method was accepted
  without credentials; RFC 1928 requires `0xFF` in that case.  Auth is now
  mandatory whenever it is configured, with unit tests for the method-selection
  path.
- **Security: HTTP CONNECT bypassed SOCKS5 auth.**  RFC 1929 credentials are
  SOCKS5-only, so on the shared port an unauthenticated HTTP CONNECT used to be
  proxied even with a credential pair configured.  It now answers `501`.
- Tunnel open ordering is guaranteed.  `ww-target` announces a stream before
  starting its read half, and the server buffers early tunnel bytes if a peer
  still sends them before `FRAME_TUNNEL_OPENED`, so a destination that speaks
  first (SSH/SMTP banners) can no longer make the open fail with
  "unexpected tunnel event".
- `ww-target` no longer blocks the entire session on a stalled destination: each
  stream has its own writer thread with a bounded queue, and a stream whose
  queue overflows is reset with the reason `stream stalled` instead of freezing
  every other stream (or silently truncating).
- The `ww-target` inbound (socket → dispatcher) queue is bounded (256 frames), so
  a peer can no longer make the agent buffer frames without limit.
- Server-side close reasons are accurate: a relay dropped for being too slow now
  reports `consumer too slow` instead of `session closed`.
- Session teardown on `ww-target` closes every open tunnel, so destination
  sockets and their threads are no longer leaked for up to `--idle-timeout`.
- Resource limits: frame payloads are capped at `MAX_FRAME_PAYLOAD` (8 MiB) on
  both peers, `push` bodies are capped at 512 MiB (the peer-declared size used
  to drive an unchecked `Vec::with_capacity`), and `ww-target` runs at most 8
  concurrent `FRAME_CMD` processes with 1 MiB of captured output per stream.
- `ww forward`/`ww socks` cap concurrent local connections at 128, and the
  server's per-session tunnel cap is now check-and-insert under a single lock.
- `ww socks`: credentials are compared in constant time, a non-zero `RSV` byte or
  an empty `ATYP 0x03` name is rejected, HTTP request headers are bounded, and
  the whole handshake has a wall-clock deadline so a peer that dribbles bytes
  cannot hold a thread indefinitely.
- `ww socks --socks-pass` can be supplied through `WW_SOCKS_PASS`, keeping it out
  of `ps` output and shell history.
- Control connections run their blocking reads inside `block_in_place`, so a
  slow `ww` client cannot starve the async workers (tunnel relays, session
  readers) on the multi-threaded runtime.
- Docs: the README no longer claims the target *always* refuses to dial its own
  server (it is best-effort, and now also covers resolved addresses), and the
  3.3.0 release notes are corrected (see below).  The pivoting section now also
  states explicitly that `ww forward` maps one fixed destination while
  `ww socks` is the arbitrary-destination listener to point a proxy at.

## v3.4.0 — `ww socks` (SOCKS5 + HTTP CONNECT)

- **`ww socks <id>`** — a SOCKS5 (RFC 1928/1929) and HTTP CONNECT proxy on a
  loopback port, with every connection dialed from `ww-target`:
  - One port speaks both, chosen by the first byte; `--socks-only` disables HTTP
  - `ATYP 0x03` hostnames are forwarded and resolved on the target by default
    (`--local-dns` resolves locally); `BIND`/UDP → `0x07`, unknown ATYP → `0x08`
  - `--socks-user`/`--socks-pass` enable RFC 1929 auth; `--connect-timeout` and
    `--exit-on-disconnect` are configurable; a loud warning is printed when the
    proxy is bound off-loopback
  - Exact errno→reply-code mapping (`ECONNREFUSED → 0x05`, `ENETUNREACH → 0x03`,
    `EHOSTUNREACH → 0x04`, `ETIMEDOUT → 0x06`, `EMFILE → 0x01`) across the Unix
    and WinSock errno tables
  - Half-close is propagated, so read-to-EOF-then-reply servers and proxychains
    work
- Protocol unchanged from the pre-tunneling protocol, so v3.2.0 agents keep
  working: they do not advertise `tunnel`, and `connect` is refused with an
  actionable message.

## v3.3.0 — TCP tunneling (`ww forward`) — folded into v3.4.0

> No **v3.3.0** release was ever published: this work and `ww socks` shipped
> together as v3.4.0, and there is no `v3.3.0` git tag.  `ww-target --version`
> (or a `ww list` session that advertises the `tunnel` feature) is a better
> compatibility check than a version number.

- **`ww forward <id> -L [bind:]lport:host:port`** — forward a local TCP port to a
  host reachable only by the target.  Tunnels are streams on the existing smart
  connection (frames `0x0A`–`0x0E`); the target never listens.
- **`ww-target` restructure** (also fixes two latent bugs):
  - a single writer thread owns the socket and one reader loop dispatches every
    frame, so a push/pull no longer drops concurrent frames
  - push/pull are now state machines pumped by the dispatcher; the outbound
    channel is bounded (backpressure)
- Server-side tunnel routing with per-stream `mpsc` backpressure, 64 streams per
  session, and session death waking every blocked relay.
- Handshake gains an optional `features` list; `ww-target` advertises `"tunnel"`
  and the server refuses `connect` for agents that don't.
- `ww-target` gains `--max-streams` (default 64) and `--idle-timeout`
  (default 600 s).
- Control connections no longer use a `BufReader`: command/auth lines are read
  byte-at-a-time, so no pipelined tunnel bytes can be swallowed.
- `ww-server` now runs on a multi-threaded tokio runtime.

## v3.2.0 — TCP control channel & key authentication

- **Optional TCP control channel** — `ww-server -c/--control-port <PORT>` also listens
  for `ww` client connections over TCP (in addition to the Unix socket, which always
  stays active); `ww -H <host>:<port>` connects over TCP instead of the socket — the
  port is mandatory (no default)
- **SSH-style key authentication for the control port** — `ww-server -k/--auth-keys
  <FILE|DIR>` (requires `-c`) authorizes ed25519/RSA/ECDSA public keys in ssh
  `authorized_keys` format; `ww -i/--identity <KEY>` authenticates with a private key
  (encrypted keys prompt for a passphrase). Running `-c` without `-k` prints a loud
  unauthenticated warning; keys never apply to the Unix socket.
- **Config files** — `~/.config/wirewrench/server.conf` (`control_public_keys`) and
  `~/.config/wirewrench/client.conf` (`identity`, repeatable; `host = HOST:PORT` for a
  default control target) store default paths.  Explicit flags override config values.

## v3.1.0 — Cross-platform `ww-target`

- **`ww-target` is now cross-platform**: builds and runs on Linux, macOS, and Windows
  - Platform shell abstraction — interactive shell and per-command execution use
    `/bin/sh` on Unix and `%COMSPEC%` (`cmd.exe /C`) on Windows
  - `--shell` CLI flag overrides the default shell on any platform
  - Windows: LF→CRLF translation on shell stdin; CRLF→LF normalization of command output
  - Hostname detection falls back to the `hostname` command when `HOSTNAME`/`COMPUTERNAME` are unset
- **`ww` and `ww-server` are now gated to Unix** — non-Unix builds fail at compile
  time with `ww is only intended to be built for unix platforms`
- **`ww list` shows a Platform column** — smart sessions report their OS/arch from
  the handshake (e.g. `windows/x86_64`, `macos/aarch64`, `linux/x86_64`)
- CI: whole-suite gate checks (Unix pass, Windows fails with the intended message),
  Linux musl release, `ww-target.exe` (windows-gnu via mingw), macOS per-arch
  `ww-target`, and the Linux e2e suite
- Fixed `tests/e2e_target.sh` to match the current CLI (`ww send 1 …`, `ww targ upload`,
  capture stderr for exit codes)

## v3.0.0 — Drop web shell support; pure Rust dependency tree

- `ww send` now returns stderr from smart (ww-target) sessions to the client and prints it there, instead of logging it in `ww-server`
- `ww send` no longer prints the misleading `--timeout` warning for smart sessions when a command produces no output (ww-target reports the exit code deterministically)
- Documented that dumb shells must merge stderr into the socket (e.g. `ncat ... --sh-exec "/bin/bash 2>&1"`) for `ww send` to capture error output
- **Removed the `web` feature** and all web-shell support (`ww web`, `register_web`, web-shell sessions). The dependency tree is now 100% pure Rust — no `reqwest`/`rustls`/`ring`/C compiler — so musl targets build self-contained via `rust-lld`.

## v2.3.0 — No default timeout for smart sessions

- Default `--timeout` / `-t` changed from `3.0` to `0.0` (no timeout) for `ww send`
- Smart (ww-target) sessions: server waits indefinitely for `FRAME_CMD_RESULT` — ww-target signals command completion deterministically
- Explicit `-t` still works as a safety cap when needed
- Dumb TCP shells fall back to 3s default when no timeout is given

## v2.2.0 — Deterministic command execution with exit codes

- **`FRAME_CMD` (0x08) / `FRAME_CMD_RESULT` (0x09)** — new protocol frames for per-command execution
- **ww-target**: each `ww send` command spawns a fresh `sh -c` process, captures stdout/stderr/exit code via `wait_with_output()`
- **No stale output**: per-command sequence numbers correlate `FRAME_CMD` ↔ `FRAME_CMD_RESULT`; late-arriving output from previous commands is silently dropped
- Server-side per-command oneshot channels replace shared-buffer polling for smart sessions
- Client displays `exit code: N` when present in the response

## v2.1.0 — Smart agent, file transfers, interactive mode

- **`ww-target`** — lightweight Rust agent connecting back on port :4446 with a framed binary protocol:
  - Handshake, persistent `/bin/sh` for interactive sessions
  - Shell output relayed via `FRAME_SHELL` frames
  - File transfer support (push/pull with SHA-256 verification)
  - Automatic reconnection with configurable poll interval
- **File transfers**: `ww targ upload` / `ww targ download` / `ww targ cancel`
- **Interactive mode** (`ww interact`) now uses `rustyline` for full line editing, history, and word navigation
- **Script mode** (`ww script`) improved — separate `send` + `read` calls with 300ms delay for reliable output capture
- `--stdin` flag added to `ww send` for piping commands
- `--wait` parameter removed (replaced by `-t` / `--timeout`)
- Various clippy fixes and code simplifications

## v2.0.0 — Complete rework: from web shell tool to remote shell toolkit

- Complete project rewrite as a client-server remote shell toolkit
- **Server** (`ww-server`): listens for TCP reverse shells and web shells, manages sessions via Unix socket API
- **Client** (`ww`): connects to server — list, send commands, interactive shell, script from file, register web shells
- **Web shell support** (feature-gated via `web` feature, enabled by default):
  - Register web shells with the server using curl-like flags (`-X`, `-d`, `-H`, `-b`, `-i`)
  - Commands are injected via URL or body, responses managed by the server
- Interactive mode with raw terminal, line editing, Ctrl+C detach (shell stays alive)
- Backward-incompatible: replaces the old single-binary REPL with the client-server model

## v1.1.2
- Added `--diff` (`-d`) flag to show only changes from the first command's output.
  - The first request's output is stored as a baseline; subsequent requests display only the characters that differ.
  - Useful for filtering out static page content and focusing on dynamic command output.

## v1.1.1
Changed default executable name from `wirewrench` to `ww` for less typing

## v1.1.0
Added command history navigation using arrow keys
