# Changelog

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
