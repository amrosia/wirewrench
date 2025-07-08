# WireWrench

Instead of manually modifying the URL each time a command needs to be executed, and having to URL encode characters, WireWrench automates the injection process, allowing pentesters to focus on payloads and responses rather than repetitive typing.

## Features

- Command injection automation through URL parameter manipulation
- URL-safe encoding of special characters automatically handled
- REPL-style interface with:
  - Command history navigation
  - Tab completion support
  - Graceful exit handling
- Structured error reporting and diagnostics
- Custom injection point markers

## Use Cases

- Testing PHP, custom, GET web shells.
- Automating repeated payload injection in parameter-based command injections.


## Examples

```shell
# Default injection point ("BLUB")
ww https://target.com/shell.php?cmd=BLUB

# Custom injection marker ("INJECT")
ww -i INJECT https://target.com/panel.php?exec=INJECT
```

## Installation

Currently WireWrench is only available with `cargo` or downloading the binary from `Releases`

### Using cargo
```shell
cargo install wirewrench
```