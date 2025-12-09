# Changelog

## Unreleased

## v1.1.2
- Added `--diff` (`-d`) flag to show only changes from the first command's output.
  - The first request's output is stored as a baseline; subsequent requests display only the characters that differ.
  - Useful for filtering out static page content and focusing on dynamic command output.

## v1.1.1
Changed default executable name from `wirewrench` to `ww` for less typing

## v1.1.0
Added command history navigation using arrow keys