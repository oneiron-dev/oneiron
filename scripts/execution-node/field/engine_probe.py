#!/usr/bin/env python3
"""T40 check 6 (check_device_handoff.sh --engine-account): the engine's GPU probe through the job control socket.

Sends one `device-query nvidia-devices` request to the socket, as the engine's probe does, and reads the reply as the
probe reads it (crates/oneiron-server/src/gpu_execution_node/scope_systemd/device_query.rs, request_within), all
within the probe's own deadline: the first line up to its newline, 1024 bytes or the peer's end, trimmed at its end,
`ok <n>` with n at most 1 MiB, then exactly n bytes of UTF-8 output, and nothing past them; or `refused <why>`. The
output passes only when every line is a device line the probe reads (device.rs, parse_device_lines: UUID, model,
memory in MiB), no UUID is listed twice (the readiness check refuses such a reading: slots.rs, repeated_device_id),
and one line has the card's UUID as its UUID field, exactly. A reply the probe would reject never passes (review r2 of
#10540: `ok 999` and a short body passed T40 before). This is no whole readiness check: it reads the device listing.

Parity with the Rust readers (the Engine's review of #10540 after its merge; one engine_probe_fixture.sh case each):
  - trim: Rust's str::trim removes Unicode White_Space alone (RUST_WHITESPACE); Python's str.strip() also removes
    U+001C-U+001F, and Python's str.isspace() takes them too (case unit-separator);
  - numbers: Rust's integer parse takes an optional '+' and ASCII digits, and the memory must fit a u64 (cases
    memory-past-u64, memory-u64-max, memory-with-plus); a run of leading zeros of any length is still the number
    after them, so the digits are bounded before Python converts them, past its 4300-digit limit too (case
    memory-many-zeros; review r1 of #10541);
  - deadline: GPU_QUERY_TIMEOUT (10 s) and ANSWER_MARGIN (5 s), from before the connection to the last byte (case
    slow-reply);
  - connection: each try connects without blocking, and a full listen queue (EAGAIN) is tried again on a fresh
    socket every 20 ms until the deadline, as device_query.rs connect_by does (case listen-queue-full; review r1 of
    #10541); the request line is written within the deadline and at most 5 s (control.rs REQUEST_WAIT);
  - a UUID listed twice fails (case duplicate-uuid);
  - framing: neither bytes past the n nor the peer's end are waited for (case held-open).

usage: engine_probe.py [--report-tries] <socket> <GPU-uuid>
  check_device_handoff.sh hands this text to `python3 -c` as the engine's account, which may not read this tree.
Prints one line, `PASS <the card's device line>` or `FAIL <why>`, and exits 0 or 1. With --report-tries
(engine_probe_fixture.sh's listen-queue-full case; FIX T40-FIXTURE-LISTEN-QUEUE-NO-EAGAIN), a second line
`full-queue-tries <n>` says how many connects met a full listen queue before one went through (`none` when the
exchange broke off), so the case proves the probe met the full queue rather than a queue already cleared. The flag
counts only before two more arguments: check 6 passes exactly two, so a socket path that reads as the flag is still the
socket (review r1 of #10557; case flag-named-socket).
"""

import re
import socket
import sys
import time

REQUEST = b"device-query nvidia-devices\n"
# device_query.rs REPLY_HEAD_MAX_BYTES: the first line, its newline included.
HEAD_MAX_BYTES = 1024
# device_query.rs DEVICE_QUERY_OUTPUT_MAX_BYTES.
OUTPUT_MAX_BYTES = 1 << 20
# The probe's whole exchange: device.rs GPU_QUERY_TIMEOUT (10 s) and device_query.rs ANSWER_MARGIN (5 s).
WAIT_SECS = 15
# device_query.rs CONNECT_RETRY: the wait before the next try while the listener's queue is full.
CONNECT_RETRY_SECS = 0.02
# control.rs REQUEST_WAIT: the longest the request line's write may take.
REQUEST_WAIT_SECS = 5
# GpuDevice::memory_total_mib is a u64.
U64_MAX = (1 << 64) - 1
U64_MAX_DIGITS = len(str(U64_MAX))
# Rust's char::is_whitespace (Unicode White_Space): what Rust's trim() removes. Not U+001C-U+001F.
RUST_WHITESPACE = (
    "\t\n\x0b\x0c\r \x85\xa0 " + "".join(map(chr, range(0x2000, 0x200B))) + "    　"
)
# What Rust's unsigned integer parse takes: an optional '+', then ASCII digits.
RUST_UNSIGNED = re.compile(r"\+?[0-9]+")


def rust_trim(text):
    """str::trim."""
    return text.strip(RUST_WHITESPACE)


def rust_u64(text):
    """`text.parse::<u64>()`: the number, or None. The optional '+' and the leading zeros go before the digits are
    counted, and only a count a u64 can hold is converted, so no length of input meets CPython's digit limit."""
    if not RUST_UNSIGNED.fullmatch(text):
        return None
    digits = text[1:] if text.startswith("+") else text
    digits = digits.lstrip("0") or "0"
    if len(digits) > U64_MAX_DIGITS:
        return None
    value = int(digits)
    return value if value <= U64_MAX else None


def connect_by(path, deadline):
    """The connection to the socket at `path`, made by the deadline as device_query.rs connect_by makes it: each try
    on a fresh socket that does not block, and a full listen queue (EAGAIN) tried again every 20 ms. Returns the
    connection and the number of tries that met a full queue."""
    full = 0
    while True:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.setblocking(False)
        try:
            conn.connect(path)
            return conn, full
        except BlockingIOError as error:
            conn.close()
            full += 1
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("the handler took no connection within %d s: %s" % (WAIT_SECS, error)) from None
            time.sleep(min(CONNECT_RETRY_SECS, left))
        except BaseException:
            conn.close()
            raise


def recv_by(conn, deadline, most):
    """At most `most` bytes, by the deadline; b"" at the peer's end."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("no whole reply within %d s" % WAIT_SECS)
    conn.settimeout(left)
    try:
        return conn.recv(most)
    except socket.timeout:
        raise TimeoutError("no whole reply within %d s" % WAIT_SECS) from None


def read_head(conn, deadline):
    """The first line as control.rs read_line reads it: one byte at a time, the deadline checked before each read, up
    to its newline, HEAD_MAX_BYTES or the peer's end. No byte past it is read here (the Engine's review of #10541 at
    8f39ebb9: one read of the whole frame left the output's deadline unchecked)."""
    line = b""
    while len(line) < HEAD_MAX_BYTES:
        byte = recv_by(conn, deadline, 1)
        if not byte:
            break
        line += byte
        if byte == b"\n":
            break
    return line


def read_exactly(conn, deadline, length):
    """Exactly `length` bytes as device_query.rs read_exactly reads them: the deadline checked before each read, and
    none for no bytes; whatever follows them, and the peer's end, are not waited for."""
    data = b""
    while len(data) < length:
        chunk = recv_by(conn, deadline, length - len(data))
        if not chunk:
            raise EOFError("the output ended after %d of %d bytes" % (len(data), length))
        data += chunk
    return data[:length]


def plain_device_id(text):
    """The UUID field as the probe reads it (device.rs, plain_device_id): trimmed, not empty, with no whitespace or
    control character (Unicode Cc)."""
    text = rust_trim(text)
    if not text or any(c in RUST_WHITESPACE or ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in text):
        return None
    return text


def device_uuid(line):
    """The UUID of a device line as parse_device_lines reads it (`<uuid>, <model>, <memory>`), or None."""
    uuid, comma, rest = line.partition(",")
    model, comma_2, memory = rest.rpartition(",")
    if not comma or not comma_2 or not rust_trim(model):
        return None
    if rust_u64(rust_trim(memory)) is None:
        return None
    return plain_device_id(uuid)


def exchange(path):
    """The reply's first line, trimmed at its end, the output it frames (None for a refusal or a bad frame), and the
    number of connects that met a full listen queue."""
    deadline = time.monotonic() + WAIT_SECS
    conn, full = connect_by(path, deadline)
    with conn:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("no whole reply within %d s" % WAIT_SECS)
        conn.settimeout(min(left, REQUEST_WAIT_SECS))
        conn.sendall(REQUEST)
        head = read_head(conn, deadline)
        head = head.decode("utf-8", "replace").rstrip(RUST_WHITESPACE)
        length = rust_u64(head[len("ok ") :]) if head.startswith("ok ") else None
        if length is None or length > OUTPUT_MAX_BYTES:
            return head, None, full
        return head, read_exactly(conn, deadline, length), full


def verdict(path, device):
    """(passed, why, full): the card's device line or why the reply fails, and how many connects met a full listen
    queue before one went through (None when the exchange broke off)."""
    try:
        head, body, full = exchange(path)
    except (OSError, EOFError) as error:
        return False, "error %s" % error, None
    passed, why = judge(head, body, device)
    return passed, why, full


def judge(head, body, device):
    """(passed, why): the card's device line in the reply's first line `head` and output `body`, or why the reply
    fails."""
    if head.startswith("refused "):
        return False, head
    if body is None:
        return False, "first line %r is not `ok <n>` with n at most %d" % (head[:80], OUTPUT_MAX_BYTES)
    try:
        output = body.decode("utf-8")
    except UnicodeDecodeError as error:
        return False, "the output is not UTF-8: %s" % error
    found = None
    listed = set()
    for line in output.split("\n"):
        line = rust_trim(line)
        if not line:
            continue
        uuid = device_uuid(line)
        if uuid is None:
            return False, "a line the probe does not read: %r" % line[:120]
        if uuid in listed:
            return False, "%s is listed twice, a reading the readiness check refuses" % uuid
        listed.add(uuid)
        if uuid == device:
            found = line
    if found is None:
        return False, "no device line has %s as its UUID" % device
    return True, found


def main(argv):
    args = argv[1:]
    report = len(args) == 3 and args[0] == "--report-tries"
    if report:
        args = args[1:]
    if len(args) != 2:
        print("FAIL usage: engine_probe.py [--report-tries] <socket> <GPU-uuid>")
        return 1
    passed, why, full = verdict(args[0], args[1])
    print(("PASS " if passed else "FAIL ") + why.replace("\n", " ").replace("\r", " "))
    if report:
        print("full-queue-tries %s" % ("none" if full is None else full))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
