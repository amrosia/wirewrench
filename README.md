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
# Start the server (listens for reverse shells on :4444)
ww-server

# In another terminal, register a web shell
ww web https://target.com/shell.php?cmd=BLUB

# Send commands
ww send 1 "whoami"
ww send 1 "id"

# Interactive mode (Ctrl+C to detach, shell stays alive)
ww interact 1

# List active shells
ww list

# Run commands from a script file
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
# List shells
ww list

# Send a command to a shell
ww send 1 "uname -a"

# Interactive shell session (Ctrl+C to detach)
ww interact 1

# Run commands from a file
ww script 1 payloads.txt

# Register a web shell (curl-like flags)
ww web -X POST -d "cmd=BLUB" -H "X-Custom: value" https://target.com/shell.php

# Close/kill a shell
ww close 1
```

### Web Shell Registration

The `ww web` command accepts curl-style flags:

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
