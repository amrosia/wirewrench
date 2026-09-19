#!/usr/bin/env bash
# End-to-end tests for exclusive dumb-shell session locks (v3.5.0).
#
# Tests:
#   1. `ww list` shows the connection identity and no lock when idle
#   2. A second client is refused (with the holder's identity), not interleaved
#   3. `ww list` flags the busy dumb shell; smart sessions are never flagged
#   4. Unrelated clients are not stalled while a dumb send is in flight
#   5. `--force` takes the lock over and runs the command
#   6. `--wait` queues and then succeeds
#   7. A killed interactive client releases the lock automatically (no hardlock)
#   8. Stale output from a previous holder is drained on acquire
#   9. Flags after the command are parsed (not folded into it)
#  10. An authenticated TCP connection shows as authenticated in the banner
#
# Usage: ./tests/e2e_locks.sh
# Requires: ww, ww-server, ww-target on PATH (ssh-keygen for test 10,
#           python3 for the fake dumb shell)

set -u
export PATH=/tmp/ww_bin:$PATH
SOCK=/tmp/ww_lock.sock
rm -f "$SOCK"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; sleep 0.3; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; rm -f "$SOCK"; }
trap cleanup EXIT
PASS=0; FAIL=0
pass(){ PASS=$((PASS+1)); echo "  ✓ $1"; }
fail(){ FAIL=$((FAIL+1)); echo "  ✗ $1"; }
hdr(){ echo ""; echo "━━━ $1 ━━━"; }

ww-server -p 6044 -P 6046 -s "$SOCK" >/tmp/ww_lock_srv.log 2>&1 & PIDS+=($!)
sleep 1
python3 - >/tmp/ww_lock_dumb.log 2>&1 <<'PY' &
import socket, threading, time
s = socket.create_connection(('127.0.0.1', 6044))
send_lock = threading.Lock()
def send(b):
    with send_lock:
        s.sendall(b)
def handle(cmd):
    if cmd == 'HOLD':    time.sleep(5);  send(b'HOLD-DONE\n')
    elif cmd == 'LONG':  time.sleep(30); send(b'LONG-DONE\n')
    elif cmd == 'CMD_A': time.sleep(3);  send(b'FROM-A\n')
    elif cmd == 'CMD_B': send(b'FROM-B\n')
    else:                send(('OK:' + cmd + '\n').encode())
f = s.makefile('rb')
for line in f:
    cmd = line.decode(errors='replace').strip()
    if cmd:
        threading.Thread(target=handle, args=(cmd,), daemon=True).start()
PY
PIDS+=($!)
ww-target 127.0.0.1 -p 6046 --poll 1 --no-reconnect >/tmp/ww_lock_tgt.log 2>&1 & PIDS+=($!)
sleep 2

LIST=$(ww -s "$SOCK" list 2>/dev/null)
SMART=$(echo "$LIST" | awk '/\[ww-target\]/{print $1; exit}')
DUMB=$(echo "$LIST" | awk '!/\[ww-target\]/ && /^[0-9]+/{print $1; exit}')
echo "smart id=$SMART  dumb id=$DUMB"

hdr "1. list shows connection identity and no lock when idle"
echo "$LIST" | sed 's/^/    /'
if echo "$LIST" | grep -q "local unix socket, unauthenticated"; then
  pass "banner identifies the (unauthenticated) unix connection"
else
  fail "missing connection banner"
fi
if echo "$LIST" | grep -q "user (uid="; then
  pass "holder identity resolves the peer uid to a name"
else
  fail "peer uid not resolved"
fi
if echo "$LIST" | awk -v d="$DUMB" '$1==d' | grep -q "🔒"; then
  fail "idle dumb shell wrongly shows a lock"
else
  pass "idle dumb shell shows no lock"
fi

hdr "2. concurrent use of a dumb shell is refused, not interleaved"
( ww -s "$SOCK" send "$DUMB" -t 8 "HOLD" >/tmp/ww_lock_hold.out 2>&1 ) & HOLD=$!
sleep 0.6
BUSY=$(ww -s "$SOCK" send "$DUMB" -t 2 "CMD_B" 2>&1 || true)
echo "    second client: $BUSY"
if echo "$BUSY" | grep -q "locked by"; then
  pass "second client is refused with the holder's identity"
else
  fail "second client was not refused (got: $BUSY)"
fi
if echo "$BUSY" | grep -q -- "--force"; then
  pass "refusal points at --force / --wait"
else
  fail "refusal lacks the override hint"
fi

hdr "3. list marks the busy dumb shell as locked"
L=$(ww -s "$SOCK" list 2>/dev/null)
echo "$L" | sed 's/^/    /'
if echo "$L" | awk -v d="$DUMB" '$1==d' | grep -q "🔒"; then
  pass "busy shell is flagged with a lock"
else
  fail "busy shell not flagged"
fi
if echo "$L" | awk -v s="$SMART" '$1==s' | grep -q "🔒"; then
  fail "smart session wrongly flagged (send is lock-free there)"
else
  pass "smart session is not flagged (per-command routing, no lock needed)"
fi

hdr "4. unrelated clients are not stalled while a dumb send is in flight"
S=$(date +%s%N); ww -s "$SOCK" list >/dev/null 2>&1; E=$(date +%s%N)
awk -v a="$S" -v b="$E" 'BEGIN{printf "    list latency: %.2fs\n",(b-a)/1e9}'
awk -v a="$S" -v b="$E" 'BEGIN{exit !((b-a)/1e9 < 1.5)}' \
  && pass "list is not blocked by the command read (per-session lock, not global)" \
  || fail "list was blocked behind the dumb-shell read"

hdr "5. --force takes over the lock"
F=$(ww -s "$SOCK" send "$DUMB" --force -t 3 "CMD_B" 2>&1 || true)
echo "    force output: $(echo "$F" | tr '\n' ' ')"
if echo "$F" | grep -q "FROM-B"; then
  pass "--force displaced the holder and ran the command"
else
  fail "--force did not run"
fi
wait $HOLD 2>/dev/null || true

hdr "6. --wait queues and then succeeds"
( ww -s "$SOCK" send "$DUMB" -t 8 "HOLD" >/dev/null 2>&1 ) & HOLD2=$!
sleep 0.6
S=$(date +%s%N)
W=$(ww -s "$SOCK" send "$DUMB" --wait 12 -t 3 "CMD_B" 2>&1 || true)
E=$(date +%s%N)
awk -v a="$S" -v b="$E" 'BEGIN{printf "    waited %.1fs: %s\n",(b-a)/1e9,""}' 
echo "    output: $(echo "$W" | tr '\n' ' ')"
if echo "$W" | grep -q "FROM-B"; then
  pass "--wait acquired the lock after the holder finished"
else
  fail "--wait failed"
fi
wait $HOLD2 2>/dev/null || true

hdr "7. a killed client releases its lock (no hardlock)"
export DUMB_ID="$DUMB"
python3 - >/tmp/ww_lock_interact.log 2>&1 <<PY &
import socket, time, os
s = socket.socket(socket.AF_UNIX)
s.connect('/tmp/ww_lock.sock')
s.sendall(('{"action":"interact","id":%s}\n' % os.environ['DUMB_ID']).encode())
time.sleep(60)   # hold the lock, then get SIGKILLed
PY
HOLDPY=$!
sleep 1.2
if ww -s "$SOCK" list 2>/dev/null | awk -v d="$DUMB" '$1==d' | grep -q "🔒"; then
  pass "interactive attach holds the lock"
else
  fail "interactive attach did not take the lock"
fi
kill -9 $HOLDPY 2>/dev/null; wait $HOLDPY 2>/dev/null || true
sleep 1.0
if ww -s "$SOCK" list 2>/dev/null | awk -v d="$DUMB" '$1==d' | grep -q "🔒"; then
  fail "lock survived the killed client (HARDLOCK)"
else
  pass "lock released automatically when the client died"
fi
K=$(ww -s "$SOCK" send "$DUMB" -t 3 "CMD_B" 2>&1 || true)
if echo "$K" | grep -q "FROM-B"; then
  pass "shell is usable again immediately"
else
  fail "shell not usable after client death: $K"
fi

hdr "8. stale output from a previous holder is drained on acquire"
A=$(ww -s "$SOCK" send "$DUMB" -t 1 "CMD_A" 2>&1 || true)
echo "    client A (times out): $(echo "$A" | tr '\n' ' ')"
sleep 3.5   # FROM-A lands in the shared buffer while nobody holds the lock
B=$(ww -s "$SOCK" send "$DUMB" -t 2 "CMD_B" 2>&1 || true)
echo "    client B: $(echo "$B" | tr '\n' ' ')"
if echo "$B" | grep -q "FROM-B" && ! echo "$B" | grep -q "FROM-A"; then
  pass "client B sees only its own output (no leak from A)"
else
  fail "client B saw the previous holder's output"
fi

hdr "9. flags after the command are parsed (previously swallowed)"
F2=$(ww -s "$SOCK" send "$DUMB" "echo hi" -t 5 2>&1 || true)
echo "    output: $(echo "$F2" | tr '\n' ' ')"
if echo "$F2" | grep -q "OK:echo hi" && ! echo "$F2" | grep -q -- "-t 5"; then
  pass "command is exactly 'echo hi'; -t 5 was parsed as the timeout"
else
  fail "flags after the command were folded into it"
fi

hdr "10. authenticated TCP connection shows as authenticated"
if command -v ssh-keygen >/dev/null; then
  KEY=/tmp/ww_lock_key
  [ -f "$KEY" ] || ssh-keygen -t ed25519 -N "" -q -f "$KEY"
  ww-server -p 6144 -P 6146 -c 6145 -k "$KEY.pub" -s /tmp/ww_lock_tcp.sock >/tmp/ww_lock_tcp.log 2>&1 & TS=$!
  sleep 1
  ww-target 127.0.0.1 -p 6146 --poll 1 --no-reconnect >/dev/null 2>&1 & TT=$!
  sleep 2
  TL=$(ww -H 127.0.0.1:6145 -i "$KEY" list 2>&1)
  echo "$TL" | head -1 | sed 's/^/    /'
  if echo "$TL" | grep -q "authenticated over tcp as SHA256:"; then
    pass "green (authenticated) banner with the key fingerprint as identity"
  else
    fail "authenticated banner missing: $(echo "$TL" | head -1)"
  fi
  kill $TS $TT 2>/dev/null || true
else
  echo "  (skipped: no ssh-keygen)"
fi

echo ""
echo "═══════════════════════════════════════"
echo "  Locks: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"
[ "$FAIL" -eq 0 ]
