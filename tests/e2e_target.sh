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
#  13. Concurrent command output + 5 MB upload (P1 regression)
#  14. ww forward over the Unix socket and the TCP control channel
#  15. ww socks: SOCKS5 (ATYP=3) + HTTP CONNECT; --socks-only; absolute-URI 501
#  16. Tunnel error codes (refused / unreachable, BIND, UDP)
#  17. Session death wakes relays; the listener survives a reconnect
#  18. WW_NO_TUNNEL refuses tunneling without hanging
#  19. Half-close propagation and --max-streams
#  20. Idle SOCKS client is dropped by the handshake timeout
#  21. SOCKS5 auth is enforced; HTTP CONNECT is refused when auth is on
#  22. A destination that speaks first is relayed reliably (OPENED/DATA order)
#
# Usage: ./tests/e2e_target.sh
# Requires: ww, ww-server, ww-target on PATH (ssh-keygen for tests 11-12,
#           python3 for tests 13-22)

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
# Tunnel tests (13-20): dedicated server + target on ports 4474/4475/4476.
# ─────────────────────────────────────────────────────────────────────────────

TUN_SOCK=/tmp/ww_test_tunnel.sock
WWW_DIR=/tmp/ww_test_www
HTTP_PORT=8099
LIVE_ID=1

# Kill every helper started by the tunnel tests (called from the EXIT trap).
tunnel_cleanup() {
    for p in ${FWD1:-} ${FWD2:-} ${SOCK1:-} ${SOCK2:-} ${SOCK3:-} ${MAX_SOCK:-} \
             ${HALF_FWD:-} ${NOTUN_FWD:-} ${BG:-} ${TUN_SRV:-} ${TUN_TGT:-} \
             ${HTTP_PID:-} ${HOLD_PID:-} ${HALF_PID:-} ${MAX_SRV:-} ${MAX_TGT:-} \
             ${MAX_HOLD:-} ${NOTUN_SRV:-} ${NOTUN_TGT:-} ${TUNNEL_CLIENT:-} \
             ${SOCK_AUTH:-} ${BANNER_PID:-} ${SOCK_BANNER:-}; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
    sleep 0.3
    for p in ${FWD1:-} ${FWD2:-} ${SOCK1:-} ${SOCK2:-} ${SOCK3:-} ${MAX_SOCK:-} \
             ${HALF_FWD:-} ${NOTUN_FWD:-} ${BG:-} ${TUN_SRV:-} ${TUN_TGT:-} \
             ${HTTP_PID:-} ${HOLD_PID:-} ${HALF_PID:-} ${MAX_SRV:-} ${MAX_TGT:-} \
             ${MAX_HOLD:-} ${NOTUN_SRV:-} ${NOTUN_TGT:-} ${TUNNEL_CLIENT:-} \
             ${SOCK_AUTH:-} ${BANNER_PID:-} ${SOCK_BANNER:-}; do
        [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
    done
}
trap 'cleanup; tunnel_cleanup' EXIT

mkdir -p "$WWW_DIR"
printf 'tunnel-body-ok\n' > "$WWW_DIR/index.html"
python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$WWW_DIR" >/tmp/ww_test_http.log 2>&1 &
HTTP_PID=$!
ww-server -p 4474 -P 4476 -c 4475 -s "$TUN_SOCK" >/tmp/ww_test_tunnel_srv.log 2>&1 &
TUN_SRV=$!
sleep 1
ww-target 127.0.0.1 -p 4476 --poll 1 --no-reconnect >/tmp/ww_test_tunnel_tgt.log 2>&1 &
TUN_TGT=$!
sleep 2

header "13. Concurrent command output + 5 MB upload (P1 regression)"
dd if=/dev/urandom of=/tmp/ww_test_big.bin bs=1M count=5 2>/dev/null
BIGHASH=$(sha256sum /tmp/ww_test_big.bin | awk '{print $1}')
ww -s "$TUN_SOCK" send 1 "i=0; while [ \$i -lt 400 ]; do echo tick-\$i; i=\$((i+1)); sleep 0.005; done; echo bg-done" >/tmp/ww_test_bg.log 2>&1 &
BG=$!
sleep 0.2
OUT=$(ww -s "$TUN_SOCK" targ upload 1 /tmp/ww_test_big.bin /tmp/ww_test_big_dst.bin -t 60 2>/dev/null || true)
wait $BG 2>/dev/null || true
if echo "$OUT" | grep -q "$BIGHASH"; then
    pass "5 MB upload verifies while a command runs concurrently"
else
    fail "concurrent 5 MB upload failed"
    echo "  Got: $OUT"
fi
if grep -q "bg-done" /tmp/ww_test_bg.log; then
    pass "concurrent command completed (no frames dropped)"
else
    fail "concurrent command did not complete"
fi

header "14. ww forward (Unix socket and TCP control channel)"
ww -s "$TUN_SOCK" forward 1 -L 127.0.0.1:8181:127.0.0.1:$HTTP_PORT >/tmp/ww_test_fwd.log 2>&1 &
FWD1=$!
ww -H 127.0.0.1:4475 forward 1 -L 127.0.0.1:8182:127.0.0.1:$HTTP_PORT >/tmp/ww_test_fwd_tcp.log 2>&1 &
FWD2=$!
sleep 1
OUT=$(curl -s --max-time 6 http://127.0.0.1:8181/index.html || true)
if echo "$OUT" | grep -q "tunnel-body-ok"; then
    pass "forward over Unix socket relays the body"
else
    fail "forward over Unix socket failed"
    echo "  Got: $OUT"
fi
OUT=$(curl -s --max-time 6 http://127.0.0.1:8182/index.html || true)
if echo "$OUT" | grep -q "tunnel-body-ok"; then
    pass "forward over TCP control channel relays the body"
else
    fail "forward over TCP control channel failed"
    echo "  Got: $OUT"
fi
kill $FWD1 $FWD2 2>/dev/null || true
sleep 0.3

header "15. ww socks (SOCKS5 ATYP=3, HTTP CONNECT, --socks-only)"
ww -s "$TUN_SOCK" socks 1 --listen 127.0.0.1:18080 >/tmp/ww_test_socks.log 2>&1 &
SOCK1=$!
ww -s "$TUN_SOCK" socks 1 --listen 127.0.0.1:18081 --socks-only >/tmp/ww_test_socks_only.log 2>&1 &
SOCK2=$!
sleep 1
OUT=$(curl -s --max-time 6 --socks5-hostname 127.0.0.1:18080 http://localhost:$HTTP_PORT/index.html || true)
if echo "$OUT" | grep -q "tunnel-body-ok"; then
    pass "SOCKS5 with a hostname (ATYP=3) relays the body"
else
    fail "SOCKS5 hostname request failed"
    echo "  Got: $OUT"
fi
PAR_PIDS=""
for i in 1 2 3 4 5 6 7 8; do
    (curl -s --max-time 8 --socks5-hostname 127.0.0.1:18080 http://localhost:$HTTP_PORT/index.html >"/tmp/ww_test_par_$i.out" 2>/dev/null || true) &
    PAR_PIDS="$PAR_PIDS $!"
done
wait $PAR_PIDS 2>/dev/null || true
PAR_OK=1
for i in 1 2 3 4 5 6 7 8; do
    grep -q "tunnel-body-ok" "/tmp/ww_test_par_$i.out" || PAR_OK=0
done
if [ "$PAR_OK" = 1 ]; then
    pass "8 parallel SOCKS5 tunnels all return the body"
else
    fail "parallel SOCKS5 tunnels failed"
fi

OUT=$(curl -s --max-time 6 -x http://127.0.0.1:18080 --proxytunnel http://localhost:$HTTP_PORT/index.html || true)
if echo "$OUT" | grep -q "tunnel-body-ok"; then
    pass "HTTP CONNECT relays the body"
else
    fail "HTTP CONNECT failed"
    echo "  Got: $OUT"
fi
OUT=$(curl -sS --max-time 6 -x http://127.0.0.1:18081 --proxytunnel http://localhost:$HTTP_PORT/index.html 2>&1 || true)
if echo "$OUT" | grep -q "501"; then
    pass "--socks-only refuses HTTP CONNECT (501)"
else
    fail "--socks-only did not refuse HTTP CONNECT"
    echo "  Got: $OUT"
fi
OUT=$(python3 - <<'PY'
import socket
s=socket.create_connection(('127.0.0.1',18080),timeout=5)
s.sendall(b'GET http://localhost/index.html HTTP/1.1\r\nHost: localhost\r\n\r\n')
try:
    print(s.recv(200).decode(errors='replace').splitlines()[0])
except Exception as e:
    print('err', e)
PY
)
if echo "$OUT" | grep -q "501"; then
    pass "absolute-URI GET via the proxy -> 501"
else
    fail "absolute-URI GET did not get 501"
    echo "  Got: $OUT"
fi

header "16. tunnel error codes (refused, unreachable, BIND, UDP)"
ww -s "$TUN_SOCK" socks 1 --listen 127.0.0.1:18082 --connect-timeout 2 >/tmp/ww_test_socks_to.log 2>&1 &
SOCK3=$!
sleep 1
SOCKS_RAW=$(python3 - <<'PY'
import socket
def req(port, payload):
    s=socket.create_connection(('127.0.0.1',port),timeout=10)
    s.sendall(b'\x05\x01\x00'); s.recv(2)
    s.sendall(payload)
    return s.recv(10).hex()
print('closed', req(18080, b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x09'))
print('blackhole', req(18082, b'\x05\x01\x00\x01\xc0\x00\x02\x01\x00\x50'))
print('bind', req(18080, b'\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50'))
print('udp', req(18080, b'\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x50'))
PY
)
if echo "$SOCKS_RAW" | grep -q "closed 0505"; then
    pass "connection refused -> 0x05"
else
    fail "closed port did not map to 0x05"
    echo "  $SOCKS_RAW"
fi
if echo "$SOCKS_RAW" | grep -qE "blackhole 05(03|04|06)"; then
    pass "unreachable/black-holed host -> 0x03/0x04/0x06"
else
    fail "black-holed host did not map to a network error"
    echo "  $SOCKS_RAW"
fi
if echo "$SOCKS_RAW" | grep -q "bind 0507"; then
    pass "BIND -> 0x07"
else
    fail "BIND did not map to 0x07"
    echo "  $SOCKS_RAW"
fi
if echo "$SOCKS_RAW" | grep -q "udp 0507"; then
    pass "UDP ASSOCIATE -> 0x07"
else
    fail "UDP did not map to 0x07"
    echo "  $SOCKS_RAW"
fi

header "17. session death wakes relays; listener survives reconnect"
python3 - >/tmp/ww_test_hold.log 2>&1 <<'PY' &
import socket
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1',8097)); srv.listen(5)
conns=[]
while True:
    c,_=srv.accept(); conns.append(c)
PY
HOLD_PID=$!
sleep 1
python3 - <<'PY' &
import socket
try:
    s=socket.create_connection(('127.0.0.1',18080),timeout=5)
    s.sendall(b'\x05\x01\x00'); s.recv(2)
    s.sendall(b'\x05\x01\x00\x03\x09' + b'127.0.0.1' + b'\x1f\xa1')
    r=s.recv(10)
    open('/tmp/ww_test_tunnel_reply.txt','w').write(r.hex())
    s.settimeout(20)
    d=s.recv(1)
    open('/tmp/ww_test_tunnel_eof.txt','w').write('eof' if d==b'' else 'data')
except Exception as e:
    open('/tmp/ww_test_tunnel_eof.txt','w').write('err:'+str(e))
PY
TUNNEL_CLIENT=$!
sleep 1.5
kill -9 $TUN_TGT 2>/dev/null || true
sleep 2
if [ -f /tmp/ww_test_tunnel_reply.txt ] && grep -q '^0500' /tmp/ww_test_tunnel_reply.txt; then
    pass "long-lived tunnel opened (0x00)"
else
    fail "long-lived tunnel did not open"
    cat /tmp/ww_test_tunnel_reply.txt 2>/dev/null || true
fi
if [ -f /tmp/ww_test_tunnel_eof.txt ] && grep -q eof /tmp/ww_test_tunnel_eof.txt; then
    pass "session death closed the local tunnel (EOF)"
else
    fail "local tunnel did not see EOF on session death"
    cat /tmp/ww_test_tunnel_eof.txt 2>/dev/null || true
fi
kill $TUNNEL_CLIENT 2>/dev/null || true
ww-target 127.0.0.1 -p 4476 --poll 1 --no-reconnect >/tmp/ww_test_tunnel_tgt2.log 2>&1 &
TUN_TGT=$!
sleep 3
# The agent gets a new session id on reconnect; the listeners stay bound to
# their original id, so remember the new one for the remaining tunnel tests.
LIVE_ID=$(ww -s "$TUN_SOCK" list 2>/dev/null | awk '/\[ww-target\]/{print $1; exit}')
[ -n "$LIVE_ID" ] || LIVE_ID=1
OUT=$(python3 - <<'PY'
import socket
s=socket.create_connection(('127.0.0.1',18080),timeout=5)
s.sendall(b'\x05\x01\x00'); s.recv(2)
s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\xa1')
try:
    print(s.recv(10).hex())
except Exception as e:
    print('err', e)
PY
)
if echo "$OUT" | grep -q '^0501'; then
    pass "listener survives and reports 0x01 for the dead session id"
else
    fail "listener did not report 0x01 after session death"
    echo "  Got: $OUT"
fi
kill $HOLD_PID 2>/dev/null || true

header "18. WW_NO_TUNNEL refuses tunneling (no hang)"
ww-server -p 4484 -P 4486 -s /tmp/ww_test_notun.sock >/tmp/ww_test_notun_srv.log 2>&1 &
NOTUN_SRV=$!
sleep 1
WW_NO_TUNNEL=1 ww-target 127.0.0.1 -p 4486 --poll 1 --no-reconnect >/tmp/ww_test_notun_tgt.log 2>&1 &
NOTUN_TGT=$!
sleep 2
ww -s /tmp/ww_test_notun.sock forward 1 -L 127.0.0.1:8184:127.0.0.1:$HTTP_PORT >/tmp/ww_test_notun_fwd.log 2>&1 &
NOTUN_FWD=$!
sleep 1
curl -s --max-time 4 http://127.0.0.1:8184/index.html >/dev/null 2>&1 || true
sleep 0.3
if grep -q "does not support tunneling" /tmp/ww_test_notun_fwd.log; then
    pass "tunneling refused with an actionable message"
else
    fail "WW_NO_TUNNEL did not produce the expected refusal"
    cat /tmp/ww_test_notun_fwd.log
fi
kill $NOTUN_SRV $NOTUN_TGT $NOTUN_FWD 2>/dev/null || true

header "19. half-close propagation and --max-streams"
python3 - >/tmp/ww_test_half.log 2>&1 <<'PY' &
import socket
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1',8096)); srv.listen(5)
c,_=srv.accept()
data=b''
while True:
    b=c.recv(4096)
    if not b: break
    data+=b
c.sendall(b'AFTER-EOF\n')
c.close()
PY
HALF_PID=$!
sleep 1
ww -s "$TUN_SOCK" forward "$LIVE_ID" -L 127.0.0.1:8185:127.0.0.1:8096 >/tmp/ww_test_half_fwd.log 2>&1 &
HALF_FWD=$!
sleep 1
OUT=$(python3 - <<'PY'
import socket
s=socket.create_connection(('127.0.0.1',8185),timeout=8)
s.sendall(b'PING\n')
s.shutdown(socket.SHUT_WR)
s.settimeout(8)
data=b''
try:
    while True:
        c=s.recv(4096)
        if not c: break
        data+=c
except Exception:
    pass
print(data.decode(errors='replace').strip())
PY
)
if echo "$OUT" | grep -q "AFTER-EOF"; then
    pass "half-close propagated (read-to-EOF then reply)"
else
    fail "half-close was not propagated"
    echo "  Got: $OUT"
fi

python3 - >/tmp/ww_test_maxhold.log 2>&1 <<'PY' &
import socket
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1',8095)); srv.listen(5)
conns=[]
while True:
    c,_=srv.accept(); conns.append(c)
PY
MAX_HOLD=$!
ww-server -p 4494 -P 4496 -s /tmp/ww_test_max.sock >/tmp/ww_test_max_srv.log 2>&1 &
MAX_SRV=$!
sleep 1
ww-target 127.0.0.1 -p 4496 --max-streams 2 --no-reconnect >/tmp/ww_test_max_tgt.log 2>&1 &
MAX_TGT=$!
sleep 2
ww -s /tmp/ww_test_max.sock socks 1 --listen 127.0.0.1:18085 >/tmp/ww_test_max_socks.log 2>&1 &
MAX_SOCK=$!
sleep 1
OUT=$(python3 - <<'PY'
import socket
holds=[]
for _ in range(3):
    s=socket.create_connection(('127.0.0.1',18085),timeout=5)
    s.sendall(b'\x05\x01\x00'); s.recv(2)
    s.sendall(b'\x05\x01\x00\x03\x09' + b'127.0.0.1' + b'\x1f\x9f')
    holds.append(s.recv(10).hex())
print(' '.join(holds))
PY
)
if echo "$OUT" | grep -q "05000001000000000000 05000001000000000000 0501"; then
    pass "--max-streams 2 refuses the third tunnel with 0x01"
else
    fail "max-streams enforcement failed"
    echo "  Got: $OUT"
fi
kill $MAX_SRV $MAX_TGT $MAX_SOCK $MAX_HOLD 2>/dev/null || true

header "20. idle SOCKS client is dropped by the handshake timeout"
OUT=$(python3 - <<'PY'
import socket
s=socket.create_connection(('127.0.0.1',18080),timeout=5)
s.settimeout(15)
try:
    d=s.recv(1)
    print('closed' if d==b'' else 'open')
except Exception:
    print('still-open')
PY
)
if echo "$OUT" | grep -q "closed"; then
    pass "idle client dropped after the handshake timeout"
else
    fail "idle client was not dropped"
    echo "  Got: $OUT"
fi

header "21. SOCKS5 auth is enforced; HTTP CONNECT is refused with it"
ww -s "$TUN_SOCK" socks "$LIVE_ID" --listen 127.0.0.1:18090 \
   --socks-user bob --socks-pass s3cret >/tmp/ww_test_socks_auth.log 2>&1 &
SOCK_AUTH=$!
sleep 1
AUTH_RAW=$(python3 - <<'PY'
import socket

def recvn(s, n):
    b = b''
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            break
        b += c
    return b

def talk(payload, n=10):
    s = socket.create_connection(('127.0.0.1', 18090), timeout=10)
    s.sendall(payload)
    try:
        return recvn(s, n)
    finally:
        s.close()

# Only the no-auth method offered while credentials are configured -> 0xFF.
print('noauth', talk(b'\x05\x01\x00', 2).hex())
# User/pass offered with the wrong password -> RFC 1929 failure (01 01).
print('bad', talk(b'\x05\x01\x02' + b'\x01\x03bob\x05wrong', 4).hex())
# Correct credentials, then a real CONNECT request -> greet 05 02, auth 01 00, reply 05 00.
s = socket.create_connection(('127.0.0.1', 18090), timeout=10)
s.sendall(b'\x05\x01\x02' + b'\x01\x03bob\x06s3cret')
greet = recvn(s, 2)
auth = recvn(s, 2)
s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\xa3')  # 127.0.0.1:8099 (the HTTP server)
try:
    reply = recvn(s, 10)
except Exception:
    reply = b''
s.close()
print('ok', (greet + auth + reply).hex())
# HTTP CONNECT on the authenticated port -> 501 (auth is SOCKS5-only).
http = talk(b'CONNECT 127.0.0.1:8099 HTTP/1.1\r\n\r\n', 32)
print('http', http.decode(errors='replace').splitlines()[0] if http else 'closed')
PY
)
if echo "$AUTH_RAW" | grep -q "noauth 05ff"; then
    pass "client offering only 'no auth' is rejected (0xFF)"
else
    fail "auth was bypassable by offering only method 0x00"
    echo "  $AUTH_RAW"
fi
if echo "$AUTH_RAW" | grep -q "bad 05020101"; then
    pass "wrong password -> RFC 1929 failure"
else
    fail "wrong password was not rejected"
    echo "  $AUTH_RAW"
fi
if echo "$AUTH_RAW" | grep -q "ok 0502010005000001000000000000"; then
    pass "correct credentials tunnel to the destination"
else
    fail "authenticated SOCKS5 request failed"
    echo "  $AUTH_RAW"
fi
if echo "$AUTH_RAW" | grep -q "http HTTP/1.1 501"; then
    pass "HTTP CONNECT refused (501) while SOCKS5 auth is enabled"
else
    fail "HTTP CONNECT bypassed SOCKS5 auth"
    echo "  $AUTH_RAW"
fi
kill $SOCK_AUTH 2>/dev/null || true

header "22. a destination that speaks first is relayed reliably"
python3 - >/tmp/ww_test_banner.log 2>&1 <<'PY' &
import socket
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 8094))
srv.listen(8)
while True:
    c, _ = srv.accept()
    try:
        c.sendall(b'BANNER-FIRST\n')  # speaks before the client says anything
        c.settimeout(5)
        try:
            c.recv(64)
        except Exception:
            pass
    finally:
        c.close()
PY
BANNER_PID=$!
sleep 1
# Bound to the *current* session id (18080 is bound to the pre-restart id).
ww -s "$TUN_SOCK" socks "$LIVE_ID" --listen 127.0.0.1:18091 >/tmp/ww_test_banner_socks.log 2>&1 &
SOCK_BANNER=$!
sleep 1
BANNER_OK=0
for _ in 1 2 3 4 5; do
    OUT=$(python3 - <<'PY'
import socket
s = socket.create_connection(('127.0.0.1', 18091), timeout=10)
s.sendall(b'\x05\x01\x00')
s.recv(2)
s.sendall(b'\x05\x01\x00\x03\x09127.0.0.1\x1f\x9e')  # 127.0.0.1:8094
try:
    print(s.recv(10).hex())
    print(s.recv(64).decode(errors='replace').strip())
except Exception as e:
    print('err', e)
PY
)
    if echo "$OUT" | grep -q "BANNER-FIRST"; then
        BANNER_OK=$((BANNER_OK + 1))
    fi
done
if [ "$BANNER_OK" = 5 ]; then
    pass "5/5 banner-first destinations relayed their banner"
else
    fail "banner-first tunnel lost data ($BANNER_OK/5)"
fi
kill $BANNER_PID $SOCK_BANNER 2>/dev/null || true
tunnel_cleanup

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"
if [ $FAIL -gt 0 ]; then exit 1; fi
