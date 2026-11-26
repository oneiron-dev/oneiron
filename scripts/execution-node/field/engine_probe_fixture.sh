#!/usr/bin/env bash
# T40's engine-probe check (engine_probe.py, check 6 of check_device_handoff.sh) on stand-in job control sockets: it
# passes only a reply the engine's probe reads (device_query.rs, request_within): `ok <n>` with n at most 1 MiB,
# exactly n bytes of output, every line a device line, no UUID listed twice, and one whose UUID field is the card's
# (review r2 of #10540), all within the probe's 15 s.
# Needs no root, card or engine: each stand-in socket answers one request with fixed bytes. Prints
# `## FIXTURE engine-probe-<case> want=<PASS|FAIL> got=<PASS|FAIL|...> RIGHT|WRONG` per case, then `## FIXTURES rc=<n>`
# (0 when every case came out as wanted). A FAIL case is RIGHT only when its reason holds the case's words, so a
# transport failure never stands in for the rejection a case is about.
#
# Parity with the Rust readers (the Engine's review of #10540 after its merge), one case each:
#   memory-past-u64 / memory-u64-max / memory-with-plus  device.rs parse_device_lines reads the memory as a u64 with
#                                                        Rust's integer parse (an optional '+', ASCII digits).
#   unit-separator   Rust's str::trim does not remove U+001C-U+001F, which Python's str.strip() does: a device line
#                    ending in U+001F is one the probe does not read.
#   slow-reply       the probe's whole exchange ends 15 s after it starts (GPU_QUERY_TIMEOUT 10 s, ANSWER_MARGIN 5 s).
#   duplicate-uuid   slots.rs refuses a reading that lists one UUID twice (repeated_device_id).
#   held-open        the probe reads the first line and exactly n bytes, and waits neither for more nor for the end.
set -u
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
UUID=GPU-00000000-0000-4000-8000-0000000f1x00
LINE="$UUID, NVIDIA GeForce RTX 4090, 24564"
WRONG=0

# A job control socket at <socket> that reads one request line, waits <delay> seconds, answers the bytes of <reply
# file>, and holds the connection <hold> seconds before it closes. The socket is bound and listening under a staging
# name and renamed into place, so it is there whole once it is there.
serve_once() { # <socket> <reply file> <delay> <hold>
  python3 - "$1" "$2" "$3" "$4" << 'EOF' &
import os, socket, sys, time
path, reply_file, delay, hold = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
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
        time.sleep(delay)
        try:
            conn.sendall(reply)
        except OSError:
            pass  # the probe gave up first (slow-reply)
        time.sleep(hold)
EOF
  server=$!
}

case_reply() { # <name> <want PASS|FAIL> <reply, as printf's %b reads it> [<words a FAIL's reason holds>] [<delay>] [<hold>]
  local sock=$tmp/$1.sock reply=$tmp/$1.reply got verdict tries=0
  printf '%b' "$3" > "$reply"
  serve_once "$sock" "$reply" "${5:-0}" "${6:-0}"
  until [ -S "$sock" ] || [ "$tries" -ge 200 ]; do sleep 0.05; tries=$((tries + 1)); done
  got=$(python3 "$here/engine_probe.py" "$sock" "$UUID" 2>&1 | head -1)
  kill "$server" 2> /dev/null; wait "$server" 2> /dev/null
  verdict=${got%% *}
  if [ "$verdict" = FAIL ] && [ "$2" = FAIL ] && [[ $got != *"${4:-}"* ]]; then verdict="FAIL-for-another-reason"; fi
  if [ "$verdict" = "$2" ]; then echo "## FIXTURE engine-probe-$1 want=$2 got=$verdict RIGHT ($got)"
  else echo "## FIXTURE engine-probe-$1 want=$2 got=$verdict WRONG ($got)"; WRONG=$((WRONG + 1)); fi
}

framed() { # <output, as printf's %b reads it>: `ok <its length>` and the output
  local out=$tmp/framed
  printf '%b' "$1" > "$out"
  printf 'ok %s\\n%s' "$(wc -c < "$out" | tr -d ' ')" "$1"
}

OTHER=GPU-11111111-1111-4111-8111-111111111111
UNREAD="a line the probe does not read"
NOT_OK="is not \`ok <n>\`"
case_reply whole PASS "$(framed "$LINE\\n")"
case_reply two-cards PASS "$(framed "$OTHER, NVIDIA A100, 81920\\n$LINE\\n")"
# The review's case: the frame names 999 bytes and the body is one short line.
case_reply short-body FAIL "ok 999\\n$LINE\\n" "the output ended after"
# The probe reads 5 bytes, `GPU-0`, and stops there.
case_reply long-body FAIL "ok 5\\n$LINE\\n" "$UNREAD: 'GPU-0'"
case_reply past-the-cap FAIL "ok 1048577\\n$LINE\\n" "$NOT_OK"
case_reply no-length FAIL "ok\\n$LINE\\n" "$NOT_OK"
case_reply length-not-a-number FAIL "ok 12x\\n$LINE\\n" "$NOT_OK"
case_reply refused FAIL "refused query_stuck: an earlier device query has not ended\\n" "refused query_stuck"
case_reply uuid-as-a-prefix FAIL "$(framed "${UUID}0, NVIDIA GeForce RTX 4090, 24564\\n")" "no device line has"
case_reply uuid-in-the-model FAIL "$(framed "$OTHER, $UUID, 24564\\n")" "no device line has"
case_reply unreadable-line FAIL "$(framed "$LINE\\nnot a device line\\n")" "$UNREAD"
case_reply memory-past-u64 FAIL "$(framed "$UUID, NVIDIA GeForce RTX 4090, 18446744073709551616\\n")" "$UNREAD"
case_reply memory-u64-max PASS "$(framed "$UUID, NVIDIA GeForce RTX 4090, 18446744073709551615\\n")"
case_reply memory-with-plus PASS "$(framed "$UUID, NVIDIA GeForce RTX 4090, +24564\\n")"
case_reply unit-separator FAIL "$(framed "$LINE\\x1f\\n")" "$UNREAD"
case_reply duplicate-uuid FAIL "$(framed "$LINE\\n$OTHER, NVIDIA A100, 81920\\n$LINE\\n")" "is listed twice"
case_reply slow-reply FAIL "$(framed "$LINE\\n")" "no whole reply within 15 s" 16 0
case_reply held-open PASS "$(framed "$LINE\\n")" "" 0 30
echo "## FIXTURES rc=$WRONG"
exit "$WRONG"
