#!/usr/bin/env bash
# T40's engine-probe check (engine_probe.py, check 6 of check_device_handoff.sh) on stand-in job control sockets: it
# passes only a reply the engine's probe reads (device_query.rs, request_within): `ok <n>` with n at most 1 MiB,
# exactly n bytes of output, every line a device line, and one whose UUID field is the card's (review r2 of #10540).
# Needs no root, card or engine: each stand-in socket answers one request with fixed bytes. Prints
# `## FIXTURE engine-probe-<case> want=<PASS|FAIL> got=<PASS|FAIL|...> RIGHT|WRONG` per case, then `## FIXTURES rc=<n>`
# (0 when every case came out as wanted).
set -u
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
UUID=GPU-00000000-0000-4000-8000-0000000f1x00
LINE="$UUID, NVIDIA GeForce RTX 4090, 24564"
WRONG=0

# A job control socket at <socket> that reads one request line, answers the bytes of <reply file>, and closes. The
# socket is bound and listening under a staging name and renamed into place, so it is there whole once it is there.
serve_once() { # <socket> <reply file>
  python3 - "$1" "$2" << 'EOF' &
import os, socket, sys
path, reply_file = sys.argv[1], sys.argv[2]
with open(reply_file, "rb") as f:
    reply = f.read()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
    listener.bind(path + ".staging")
    listener.listen(1)
    os.rename(path + ".staging", path)
    listener.settimeout(30)
    conn, _ = listener.accept()
    with conn:
        conn.settimeout(30)
        request = b""
        while not request.endswith(b"\n") and len(request) < 64:
            chunk = conn.recv(1)
            if not chunk:
                break
            request += chunk
        conn.sendall(reply)
EOF
}

case_reply() { # <name> <want PASS|FAIL> <reply, as printf's %b reads it>
  local sock=$tmp/$1.sock reply=$tmp/$1.reply got tries=0
  printf '%b' "$3" > "$reply"
  serve_once "$sock" "$reply"
  until [ -S "$sock" ] || [ "$tries" -ge 200 ]; do sleep 0.05; tries=$((tries + 1)); done
  got=$(python3 "$here/engine_probe.py" "$sock" "$UUID" 2>&1 | head -1)
  wait
  if [ "${got%% *}" = "$2" ]; then echo "## FIXTURE engine-probe-$1 want=$2 got=${got%% *} RIGHT ($got)"
  else echo "## FIXTURE engine-probe-$1 want=$2 got=${got%% *} WRONG ($got)"; WRONG=$((WRONG + 1)); fi
}

framed() { # <output, as printf's %b reads it>: `ok <its length>` and the output
  local out=$tmp/framed
  printf '%b' "$1" > "$out"
  printf 'ok %s\\n%s' "$(wc -c < "$out" | tr -d ' ')" "$1"
}

case_reply whole PASS "$(framed "$LINE\\n")"
case_reply two-cards PASS "$(framed "GPU-11111111-1111-4111-8111-111111111111, NVIDIA A100, 81920\\n$LINE\\n")"
# The review's case: the frame names 999 bytes and the body is one short line.
case_reply short-body FAIL "ok 999\\n$LINE\\n"
case_reply long-body FAIL "ok 5\\n$LINE\\n"
case_reply past-the-cap FAIL "ok 1048577\\n$LINE\\n"
case_reply no-length FAIL "ok\\n$LINE\\n"
case_reply length-not-a-number FAIL "ok 12x\\n$LINE\\n"
case_reply refused FAIL "refused query_stuck: an earlier device query has not ended\\n"
case_reply uuid-as-a-prefix FAIL "$(framed "${UUID}0, NVIDIA GeForce RTX 4090, 24564\\n")"
case_reply uuid-in-the-model FAIL "$(framed "GPU-11111111-1111-4111-8111-111111111111, $UUID, 24564\\n")"
case_reply unreadable-line FAIL "$(framed "$LINE\\nnot a device line\\n")"
echo "## FIXTURES rc=$WRONG"
exit "$WRONG"
