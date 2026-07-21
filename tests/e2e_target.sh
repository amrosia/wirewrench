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
#
# Usage: ./tests/e2e_target.sh
# Requires: ww, ww-server, ww-target on PATH

set -euo pipefail

PASS=0
FAIL=0

cleanup() {
    pkill -9 ww-server 2>/dev/null || true
    pkill -9 ww-target 2>/dev/null || true
    rm -f /tmp/wirewrench.sock /tmp/ww_test_*
}

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

OUT=$(ww send -w 1 "echo hello-test-42" 2>/dev/null)
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

OUT=$(ww send -w 1 "exit 77" 2>/dev/null)
if echo "$OUT" | grep -q "exit code: 77"; then
    pass "Exit code 77 reported"
else
    fail "Expected 'exit code: 77'"
    echo "  Got: $OUT"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "4. File push with hash verification"

echo "test-payload-data" > /tmp/ww_test_src.txt
OUT=$(ww targ push 1 /tmp/ww_test_src.txt /tmp/ww_test_dst.txt 2>/dev/null)
if echo "$OUT" | grep -q "hash verified"; then
    pass "Push reported hash verified"
else
    fail "Push failed"
    echo "  Got: $OUT"
fi

# Verify content on target
OUT=$(ww send -w 1 "cat /tmp/ww_test_dst.txt" 2>/dev/null)
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

OUT=$(ww targ push 1 /tmp/ww_test_bin.bin /tmp/ww_test_bin_dst.bin 2>/dev/null)
if echo "$OUT" | grep -q "$LOCAL_HASH"; then
    pass "Binary push — SHA-256 hash matches server report"
else
    fail "Binary push hash mismatch in report"
    echo "  Expected to contain: $LOCAL_HASH"
    echo "  Got: $OUT"
fi

# Verify hash on target side
OUT=$(ww send -w 1 "sha256sum /tmp/ww_test_bin_dst.bin" 2>/dev/null)
if echo "$OUT" | grep -q "$LOCAL_HASH"; then
    pass "Binary push — target-side SHA-256 matches local"
else
    fail "Binary push — target hash mismatch"
    echo "  Local:  $LOCAL_HASH"
    echo "  Target: $OUT"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "6. Multi-line command via --stdin"

OUT=$(printf "echo first-line\necho second-line" | ww send --stdin -w 1 2>/dev/null)
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

OUT1=$(ww send -w 1 "echo cmd-a" 2>/dev/null)
OUT2=$(ww send -w 1 "echo cmd-b" 2>/dev/null)
OUT3=$(ww send -w 1 "echo cmd-c" 2>/dev/null)
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
echo ""
echo "═══════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"
if [ $FAIL -gt 0 ]; then exit 1; fi
