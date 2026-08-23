#!/usr/bin/env bash
# End-to-end test suite for ww-target session type.
#
# Tests:
#   1. Server starts, target connects, list shows [ww-target]
#   2. Single command execution with output and exit code
#   3. Non-zero exit code reporting
#   4. File push with SHA-256 hash verification
#   5. Large binary file push with hash match verification
#   6. Multi-line command via --stdin
#   7. Multiple serial commands on same session
#   8. Target reconnect (killed target reconnects)
#   9. Close session
#  10. TCP control channel (ww-server --control-port + ww -H host:port)
#  11. Control-port key authentication (ssh-keygen, --auth-keys, ww -i)
#  12. Config-file defaults (client.conf host + identity, CLI precedence)
#
# Usage: ./tests/e2e_target.sh
# Requires: ww, ww-server, ww-target on PATH (ssh-keygen for tests 11-12)

set -euo pipefail

PASS=0
FAIL=0

cleanup() {
    pkill -9 ww-server 2>/dev/null || true
    pkill -9 ww-target 2>/dev/null || true
    rm -rf /tmp/wirewrench.sock /tmp/ww_test_*
}

# Isolate all tests from any real ~/.config/wirewrench config files.
export XDG_CONFIG_HOME=/tmp/ww_test_xdg_env

pass()  { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
header(){ echo ""; echo "━━━ $1 ━━━"; }

# Ensure binaries exist
for bin in ww ww-server ww-target; do
    if ! command -v "$bin" &>/dev/null; then
        echo "ERROR: $bin not on PATH"
        exit 1
    fi
done

cleanup
trap cleanup EXIT
mkdir -p "$XDG_CONFIG_HOME/wirewrench"

# ─────────────────────────────────────────────────────────────────────────────
header "1. Server starts and target connects"

ww-server &
SRV_PID=$!
sleep 1
if ! kill -0 $SRV_PID 2>/dev/null; then
    fail "Server failed to start"
    exit 1
fi
pass "Server started (PID $SRV_PID)"

ww-target 127.0.0.1 --poll 1 --no-reconnect &
TGT_PID=$!
sleep 2
if ! kill -0 $TGT_PID 2>/dev/null; then
    fail "Target failed to connect"
    exit 1
fi
pass "Target connected"

LIST=$(ww list 2>/dev/null)
if echo "$LIST" | grep -q "\[ww-target\]"; then
    pass "List shows [ww-target] prefix"
else
    fail "List missing [ww-target] prefix"
    echo "  Output: $LIST"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "2. Simple command with output"

OUT=$(ww send 1 "echo hello-test-42" 2>&1)
if echo "$OUT" | grep -q "hello-test-42"; then
    pass "Command output matches"
else
    fail "Expected 'hello-test-42' in output"
    echo "  Got: $OUT"
fi

if echo "$OUT" | grep -q "exit code: 0"; then
    pass "Exit code 0 reported"
else
    fail "Exit code 0 not found"
    echo "  Got: $OUT"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "3. Non-zero exit code"

OUT=$(ww send 1 "exit 77" 2>&1)
if echo "$OUT" | grep -q "exit code: 77"; then
    pass "Exit code 77 reported"
else
    fail "Expected 'exit code: 77'"
    echo "  Got: $OUT"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "4. File push with hash verification"

echo "test-payload-data" > /tmp/ww_test_src.txt
OUT=$(ww targ upload 1 /tmp/ww_test_src.txt /tmp/ww_test_dst.txt 2>/dev/null)
if echo "$OUT" | grep -q "hash verified"; then
    pass "Push reported hash verified"
else
    fail "Push failed"
    echo "  Got: $OUT"
fi

# Verify content on target
OUT=$(ww send 1 "cat /tmp/ww_test_dst.txt" 2>&1)
if echo "$OUT" | grep -q "test-payload-data"; then
    pass "Pushed file content matches on target"
else
    fail "Pushed file content mismatch"
    echo "  Got: $OUT"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "5. Binary file push (4 KB random)"

dd if=/dev/urandom bs=1024 count=4 of=/tmp/ww_test_bin.bin 2>/dev/null
LOCAL_HASH=$(sha256sum /tmp/ww_test_bin.bin | awk '{print $1}')

OUT=$(ww targ upload 1 /tmp/ww_test_bin.bin /tmp/ww_test_bin_dst.bin 2>/dev/null)
if echo "$OUT" | grep -q "$LOCAL_HASH"; then
    pass "Binary push — SHA-256 hash matches server report"
else
    fail "Binary push hash mismatch in report"
    echo "  Expected to contain: $LOCAL_HASH"
    echo "  Got: $OUT"
fi

# Verify hash on target side
OUT=$(ww send 1 "sha256sum /tmp/ww_test_bin_dst.bin" 2>&1)
if echo "$OUT" | grep -q "$LOCAL_HASH"; then
    pass "Binary push — target-side SHA-256 matches local"
else
    fail "Binary push — target hash mismatch"
    echo "  Local:  $LOCAL_HASH"
    echo "  Target: $OUT"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "6. Multi-line command via --stdin"

OUT=$(printf "echo first-line\necho second-line" | ww send --stdin 1 2>&1)
if echo "$OUT" | grep -q "first-line"; then
    pass "Multi-line — first line output"
else
    fail "Multi-line — missing first-line"
fi
if echo "$OUT" | grep -q "second-line"; then
    pass "Multi-line — second line output"
else
    fail "Multi-line — missing second-line"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "7. Serial commands preserve session"

OUT1=$(ww send 1 "echo cmd-a" 2>&1)
OUT2=$(ww send 1 "echo cmd-b" 2>&1)
OUT3=$(ww send 1 "echo cmd-c" 2>&1)
if echo "$OUT1" | grep -q "cmd-a" && echo "$OUT2" | grep -q "cmd-b" && echo "$OUT3" | grep -q "cmd-c"; then
    pass "Three serial commands all succeeded"
else
    fail "Serial commands failed"
    echo "  cmd-a: $OUT1"
    echo "  cmd-b: $OUT2"
    echo "  cmd-c: $OUT3"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "8. Target still alive after multiple commands"

LIST=$(ww list 2>/dev/null)
if echo "$LIST" | grep -q "✓"; then
    pass "Target marked alive after 7 operations"
else
    fail "Target not alive"
    echo "  $LIST"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "9. Close session"

OUT=$(ww close 1 2>/dev/null)
sleep 1
LIST=$(ww list 2>/dev/null)
if echo "$LIST" | grep -q "No active shells"; then
    pass "Session closed and list empty"
else
    # Might still show if new session was created by reconnecting
    # target. Check that session #1 is gone.
    if echo "$LIST" | grep -q "^1[[:space:]]"; then
        fail "Session #1 still listed after close"
        echo "  $LIST"
    else
        pass "Session #1 removed (or reconnected to different ID)"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
header "10. TCP control channel (ww-server --control-port)"

# Second server instance: dumb shells on 4454, smart on 4456, ww control TCP on 4455
ww-server -p 4454 -P 4456 -c 4455 -s /tmp/ww_test_control.sock &
SRV_TCP_PID=$!
sleep 1
if ! kill -0 $SRV_TCP_PID 2>/dev/null; then
    fail "TCP-control server failed to start"
    exit 1
fi
pass "Server started with --control-port"

# ww connects over TCP (no shells on this server yet)
OUT=$(ww -H 127.0.0.1:4455 list 2>/dev/null)
if echo "$OUT" | grep -q "No active shells"; then
    pass "ww over TCP lists empty session table"
else
    fail "ww over TCP list failed"
    echo "  Got: $OUT"
fi

# Connect a target to the second server and drive it over the TCP control channel
ww-target 127.0.0.1 -p 4456 --poll 1 --no-reconnect &
TGT_TCP_PID=$!
sleep 2
OUT=$(ww -H 127.0.0.1:4455 send 1 "echo tcp-control-ok" 2>&1)
if echo "$OUT" | grep -q "tcp-control-ok" && echo "$OUT" | grep -q "exit code: 0"; then
    pass "ww send over TCP control channel"
else
    fail "ww send over TCP failed"
    echo "  Got: $OUT"
fi

# File transfer over the TCP control channel
printf 'tcp-control-push\n' > /tmp/ww_test_tcp_push.txt
OUT=$(ww -H 127.0.0.1:4455 targ upload 1 /tmp/ww_test_tcp_push.txt /tmp/ww_test_tcp_push_dst.txt 2>/dev/null)
if echo "$OUT" | grep -q "hash verified"; then
    pass "ww targ upload over TCP control channel"
else
    fail "Upload over TCP failed"
    echo "  Got: $OUT"
fi

# The Unix socket still works on the same server
OUT=$(ww -s /tmp/ww_test_control.sock send 1 "echo socket-still-up" 2>&1)
if echo "$OUT" | grep -q "socket-still-up"; then
    pass "Unix socket still works alongside TCP control"
else
    fail "Socket command failed on TCP-control server"
    echo "  Got: $OUT"
fi

kill $SRV_TCP_PID 2>/dev/null || true
kill $TGT_TCP_PID 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
header "11. Control-port key authentication"

if command -v ssh-keygen &>/dev/null; then
    KEY=/tmp/ww_test_auth_ed25519
    WRONG=/tmp/ww_test_auth_wrong
    rm -f "$KEY" "$KEY.pub" "$WRONG" "$WRONG.pub"
    ssh-keygen -t ed25519 -N "" -q -f "$KEY" 2>/dev/null
    ssh-keygen -t ed25519 -N "" -q -f "$WRONG" 2>/dev/null

    # 11a. --auth-keys requires --control-port
    if ww-server -k "$KEY.pub" >/dev/null 2>&1; then
        fail "--auth-keys without --control-port should refuse to start"
    else
        pass "--auth-keys without --control-port refuses to start"
    fi

    # 11b. loud warning when -c is used without keys
    ww-server -p 4464 -P 4466 -c 4465 -s /tmp/ww_test_auth_warn.sock > /tmp/ww_test_auth_warn.log 2>&1 &
    WARN_PID=$!
    sleep 1
    if grep -q "WITHOUT authentication" /tmp/ww_test_auth_warn.log; then
        pass "Unauthenticated control port prints loud warning"
    else
        fail "Missing loud warning for unauthenticated control port"
    fi
    kill $WARN_PID 2>/dev/null || true
    sleep 1

    # 11c. authenticated control port (single public-key file)
    ww-server -p 4464 -P 4466 -c 4465 -k "$KEY.pub" -s /tmp/ww_test_auth.sock > /tmp/ww_test_auth_srv.log 2>&1 &
    AUTH_SRV_PID=$!
    sleep 1
    if ! grep -q "auth enabled" /tmp/ww_test_auth_srv.log; then
        fail "Auth-enabled server failed to start"
        cat /tmp/ww_test_auth_srv.log
        exit 1
    fi
    ww-target 127.0.0.1 -p 4466 --poll 1 --no-reconnect >/dev/null 2>&1 &
    AUTH_TGT_PID=$!
    sleep 2

    OUT=$(ww -H 127.0.0.1:4465 list 2>&1 || true)
    if echo "$OUT" | grep -q "authentication required"; then
        pass "No key → authentication required error"
    else
        fail "Expected authentication-required error"
        echo "  Got: $OUT"
    fi

    OUT=$(ww -H 127.0.0.1:4465 -i "$WRONG" list 2>&1 || true)
    if echo "$OUT" | grep -q "rejected"; then
        pass "Wrong key → rejected"
    else
        fail "Expected rejection with wrong key"
        echo "  Got: $OUT"
    fi

    OUT=$(ww -H 127.0.0.1:4465 -i "$KEY" send 1 "echo auth-e2e-ok" 2>&1 || true)
    if echo "$OUT" | grep -q "auth-e2e-ok" && echo "$OUT" | grep -q "exit code: 0"; then
        pass "Authenticated send over TCP control"
    else
        fail "Authenticated send failed"
        echo "  Got: $OUT"
    fi

    OUT=$(ww -s /tmp/ww_test_auth.sock send 1 "echo socket-keyless-ok" 2>&1 || true)
    if echo "$OUT" | grep -q "socket-keyless-ok"; then
        pass "Unix socket works keyless while TCP requires auth"
    else
        fail "Socket keyless command failed"
        echo "  Got: $OUT"
    fi

    printf 'auth-push\n' > /tmp/ww_test_auth_push.txt
    OUT=$(ww -H 127.0.0.1:4465 -i "$KEY" targ upload 1 /tmp/ww_test_auth_push.txt /tmp/ww_test_auth_dst.txt 2>/dev/null || true)
    if echo "$OUT" | grep -q "hash verified"; then
        pass "Authenticated targ upload over TCP control"
    else
        fail "Authenticated upload failed"
        echo "  Got: $OUT"
    fi

    kill $AUTH_SRV_PID 2>/dev/null || true
    kill $AUTH_TGT_PID 2>/dev/null || true
else
    echo "  (skipped: ssh-keygen not on PATH)"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "12. Config-file defaults (client.conf host + identity)"

if [ -f /tmp/ww_test_auth_ed25519.pub ]; then
    CFG_DIR=/tmp/ww_test_cfg
    rm -rf "$CFG_DIR"
    mkdir -p "$CFG_DIR/wirewrench"

    # 12a. config host + identity → works with no flags
    printf 'host = 127.0.0.1:4465\nidentity = /tmp/ww_test_auth_ed25519\n' > "$CFG_DIR/wirewrench/client.conf"
    ww-server -p 4464 -P 4466 -c 4465 -k /tmp/ww_test_auth_ed25519.pub -s /tmp/ww_test_cfg.sock > /tmp/ww_test_cfg_srv.log 2>&1 &
    CFG_SRV_PID=$!
    sleep 1
    ww-target 127.0.0.1 -p 4466 --poll 1 --no-reconnect >/dev/null 2>&1 &
    CFG_TGT_PID=$!
    sleep 2

    OUT=$(XDG_CONFIG_HOME="$CFG_DIR" ww send 1 "echo cfg-defaults-ok" 2>&1 || true)
    if echo "$OUT" | grep -q "cfg-defaults-ok"; then
        pass "client.conf host+identity connect without flags"
    else
        fail "client.conf defaults failed"
        echo "  Got: $OUT"
    fi

    # 12b. config host is used when no -H …
    printf 'host = 127.0.0.1:9\nidentity = /tmp/ww_test_auth_ed25519\n' > "$CFG_DIR/wirewrench/client.conf"
    OUT=$(XDG_CONFIG_HOME="$CFG_DIR" ww send 1 "echo x" 2>&1 || true)
    if echo "$OUT" | grep -q "127.0.0.1:9"; then
        pass "client.conf host used when no -H"
    else
        fail "Config host not used"
        echo "  Got: $OUT"
    fi

    # …but explicit -H overrides the config value
    OUT=$(XDG_CONFIG_HOME="$CFG_DIR" ww -H 127.0.0.1:4465 send 1 "echo cfg-override-ok" 2>&1 || true)
    if echo "$OUT" | grep -q "cfg-override-ok"; then
        pass "CLI -H overrides client.conf host"
    else
        fail "CLI -H override failed"
        echo "  Got: $OUT"
    fi

    kill $CFG_SRV_PID 2>/dev/null || true
    kill $CFG_TGT_PID 2>/dev/null || true
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"
if [ $FAIL -gt 0 ]; then exit 1; fi
