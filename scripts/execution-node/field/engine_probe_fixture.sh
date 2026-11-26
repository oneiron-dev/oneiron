#!/usr/bin/env bash
# T40's engine-probe check (engine_probe.py, check 6 of check_device_handoff.sh) on stand-in job control sockets: it
# passes only a reply the engine's probe reads (device_query.rs, request_within): `ok <n>` with n at most 1 MiB,
# exactly n bytes of output, every line a device line, no UUID listed twice, and one whose UUID field is the card's
# (review r2 of #10540), all within the probe's 15 s.
# Needs no root, card or engine: each stand-in socket answers one request with fixed bytes. Prints
# `## FIXTURE engine-probe-<case> want=<PASS|FAIL> got=<PASS|FAIL|...> RIGHT|WRONG` per case, then `## FIXTURES rc=<n>`
# (0 when every case came out as wanted). A FAIL case is RIGHT only when its reason holds the case's words, so a
# transport failure never stands in for the rejection a case is about. A case is RIGHT only when the probe's exit
# status agrees with its line, 0 for PASS and 1 for FAIL, as check 6 counts a PASS line only from a probe that exited 0
# (FIX T40-FIXTURE-LISTEN-QUEUE-NO-EAGAIN).
#
# Parity with the Rust readers (the Engine's review of #10540 after its merge), one case each:
#   memory-past-u64 / memory-u64-max / memory-with-plus  device.rs parse_device_lines reads the memory as a u64 with
#                                                        Rust's integer parse (an optional '+', ASCII digits).
#   memory-many-zeros / memory-many-digits  5,000 leading zeros and a 1 is 1 MiB to Rust, and 5,000 digits of 1 is past
#                    a u64: neither may meet CPython's 4300-digit conversion limit (review r1 of #10541).
#   listen-queue-full  the listener's queue is full for the probe's first 2 s (EAGAIN on a connect that does not
#                    block); device_query.rs connect_by tries again until its deadline (review r1 of #10541). The
#                    case passes only when the probe reports at least one connect that met the full queue
#                    (--report-tries), so a probe that starts after the queue has cleared cannot pass it (FIX
#                    T40-FIXTURE-LISTEN-QUEUE-NO-EAGAIN).
#   flag-named-socket  check 6 passes the socket and the UUID and no flag: a socket the probe is given as the
#                    relative path `--report-tries` is still the socket (review r1 of #10557).
#   unit-separator   Rust's str::trim does not remove U+001C-U+001F, which Python's str.strip() does: a device line
#                    ending in U+001F is one the probe does not read.
#   slow-reply       the probe's whole exchange ends 15 s after it starts (GPU_QUERY_TIMEOUT 10 s, ANSWER_MARGIN 5 s).
#   near-cutoff      a whole frame that arrives 0.5 s before that end: the engine reads the first line a byte at a
#                    time and then the output, its deadline checked before each read, and so does the probe (the
#                    Engine's review of #10541 at 8f39ebb9); both read it in time.
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
# name and renamed into place, so it is there whole once it is there. With <queue full> seconds above 0, its listen
# queue holds one connection (backlog 0) and a filler connection takes it before the rename, so every connect that
# does not block meets EAGAIN until the listener takes the filler <queue full> seconds later.
serve_once() { # <socket> <reply file> <delay> <hold> <queue full>
  python3 - "$1" "$2" "$3" "$4" "$5" << 'EOF' &
import os, socket, sys, time
path, reply_file = sys.argv[1], sys.argv[2]
delay, hold, queue_full = float(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5])
with open(reply_file, "rb") as f:
    reply = f.read()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
    listener.bind(path + ".staging")
    filler = None
    if queue_full > 0:
        listener.listen(0)
        filler = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        filler.connect(path + ".staging")
    else:
        listener.listen(1)
    os.rename(path + ".staging", path)
    listener.settimeout(30)
    if filler is not None:
        time.sleep(queue_full)
        taken, _ = listener.accept()
        taken.close()
        filler.close()
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

# The probe runs in the folder the fixture was started in and is given the socket's path, as $tmp names it (relative
# to that folder when TMPDIR is relative). Only a case that names a socket runs the probe in the cases' folder and gives
# it <socket name>, relative to that folder (review r2 of #10557: changing folder for every case broke a relative TMPDIR).
case_reply() { # <name> <want PASS|FAIL> <reply, as printf's %b reads it> [<words a FAIL's reason holds>] [<delay>] [<hold>] [<queue full>] [<socket name>]
  local sock=$tmp/${8:-$1.sock} reply=$tmp/$1.reply out rc got verdict full tries=0 report=() probe_dir=. probe_sock
  probe_sock=$sock
  printf '%b' "$3" > "$reply"
  serve_once "$sock" "$reply" "${5:-0}" "${6:-0}" "${7:-0}"
  until [ -S "$sock" ] || [ "$tries" -ge 200 ]; do sleep 0.05; tries=$((tries + 1)); done
  # A queue-full case asks the probe how many connects met the full queue: a probe that met none proves nothing.
  if [ "${7:-0}" != 0 ]; then report=(--report-tries); fi
  if [ -n "${8:-}" ]; then probe_dir=$tmp probe_sock=$8; fi
  out=$(cd "$probe_dir" && python3 "$here/engine_probe.py" ${report[@]+"${report[@]}"} "$probe_sock" "$UUID" 2>&1)
  rc=$?
  kill "$server" 2> /dev/null; wait "$server" 2> /dev/null
  got=$(head -1 <<< "$out")
  verdict=${got%% *}
  if [ "$verdict" = FAIL ] && [ "$2" = FAIL ] && [[ $got != *"${4:-}"* ]]; then verdict="FAIL-for-another-reason"; fi
  if { [ "$verdict" = PASS ] && [ "$rc" != 0 ]; } || { [ "$verdict" != PASS ] && [ "$rc" != 1 ]; }; then
    verdict="$verdict-with-exit-$rc"
  fi
  if [ ${#report[@]} -gt 0 ]; then
    full=$(sed -n 's/^full-queue-tries //p' <<< "$out")
    got="$got; full-queue-tries ${full:-unreported}"
    if [ "$verdict" = PASS ] && ! [ "${full:-0}" -ge 1 ] 2> /dev/null; then verdict="PASS-without-a-full-queue"; fi
  fi
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
ZEROS=$(printf '%05000d' 0)
ONES=$(printf '%05000d' 0 | tr 0 1)
case_reply memory-many-zeros PASS "$(framed "$UUID, NVIDIA GeForce RTX 4090, ${ZEROS}1\\n")"
case_reply memory-many-digits FAIL "$(framed "$UUID, NVIDIA GeForce RTX 4090, $ONES\\n")" "$UNREAD"
case_reply unit-separator FAIL "$(framed "$LINE\\x1f\\n")" "$UNREAD"
case_reply duplicate-uuid FAIL "$(framed "$LINE\\n$OTHER, NVIDIA A100, 81920\\n$LINE\\n")" "is listed twice"
case_reply slow-reply FAIL "$(framed "$LINE\\n")" "no whole reply within 15 s" 16 0
case_reply near-cutoff PASS "$(framed "$LINE\\n")" "" 14.5 0
case_reply held-open PASS "$(framed "$LINE\\n")" "" 0 30
case_reply listen-queue-full PASS "$(framed "$LINE\\n")" "" 0 0 2
case_reply flag-named-socket PASS "$(framed "$LINE\\n")" "" 0 0 0 --report-tries
echo "## FIXTURES rc=$WRONG"
exit "$WRONG"
