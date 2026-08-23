# Development shell for cross-compiling `ww-target` to Windows.
#
# Usage:
#   nix-shell                      # one-shot: builds ww-target.exe, then drops
#                                  # you into the shell (Ctrl-D to leave)
#   WW_BUILD_WINDOWS=0 nix-shell   # skip the auto-build, just enter the shell
#   nix-shell --run build-windows  # build explicitly (works from anywhere)
#
# Provides:
#   - pkgsCross.mingwW64.stdenv.cc — the mingw-w64 cross toolchain
#     (x86_64-w64-mingw32-gcc, binutils, CRT, Windows API import libraries)
#   - An empty libpthread.a stub + RUSTFLAGS so rustc's unconditional
#     `-l:libpthread.a` on the windows-gnu target resolves.
#
# Why the stub: nixpkgs' mingw-w64 is built with mcfgthread instead of
# winpthreads, so no libpthread.a exists. Rust's std uses native Win32
# threads on Windows and never references pthread symbols, so an EMPTY
# archive satisfies the linker safely. Not needed on Debian/Ubuntu
# (gcc-mingw-w64-x86-64 ships winpthreads).
#
# Note: `ww` and `ww-server` intentionally fail to build for Windows
# (unix-only by design) — always pass `--bin ww-target`.

{ pkgs ? import <nixpkgs> {} }:

let
  target = "x86_64-pc-windows-gnu";

  # Empty static archive that satisfies rustc's `-l:libpthread.a`.
  mingwStubs = pkgs.runCommand "mingw-w64-libpthread-stub" { } ''
    mkdir -p $out
    ${pkgs.binutils}/bin/ar crs $out/libpthread.a
  '';
in
pkgs.mkShell {
  name = "ww-target-windows-build";

  nativeBuildInputs = with pkgs; [
    pkgsCross.mingwW64.stdenv.cc
  ];

  shellHook = ''
    export RUSTFLAGS="-L native=${mingwStubs} ''${RUSTFLAGS:-}"

    build_windows() {
      cargo build --release --target ${target} --bin ww-target
    }

    if [ "''${WW_BUILD_WINDOWS:-1}" != "0" ]; then
      echo "mingw-w64 cross toolchain ready (target: ${target})"
      build_windows
      echo "Built: target/${target}/release/ww-target.exe"
    fi
  '';
}
