# Changelog

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
