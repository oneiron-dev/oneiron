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
    memory-past-u64, memory-u64-max, memory-with-plus);
  - deadline: GPU_QUERY_TIMEOUT (10 s) and ANSWER_MARGIN (5 s), from before the connection to the last byte (case
    slow-reply);
  - a UUID listed twice fails (case duplicate-uuid);
  - framing: neither bytes past the n nor the peer's end are waited for (case held-open).

usage: engine_probe.py <socket> <GPU-uuid>
  check_device_handoff.sh hands this text to `python3 -c` as the engine's account, which may not read this tree.
Prints one line, `PASS <the card's device line>` or `FAIL <why>`, and exits 0 or 1.
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
# GpuDevice::memory_total_mib is a u64.
U64_MAX = (1 << 64) - 1
# Rust's char::is_whitespace (Unicode White_Space): what Rust's trim() removes. Not U+001C-U+001F.
RUST_WHITESPACE = (
    "\t\n\x0b\x0c\r \x85\xa0 " + "".join(map(chr, range(0x2000, 0x200B))) + "    　"
)
# What Rust's unsigned integer parse takes: an optional '+', then ASCII digits.
RUST_UNSIGNED = re.compile(r"\+?[0-9]+")


def rust_trim(text):
    """str::trim."""
    return text.strip(RUST_WHITESPACE)


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
    """The first line as control.rs read_line reads it (up to its newline, HEAD_MAX_BYTES or the peer's end), and the
    bytes read past it."""
    data = b""
    while True:
        newline = data.find(b"\n", 0, HEAD_MAX_BYTES)
        if newline >= 0:
            return data[: newline + 1], data[newline + 1 :]
        if len(data) >= HEAD_MAX_BYTES:
            return data[:HEAD_MAX_BYTES], data[HEAD_MAX_BYTES:]
        chunk = recv_by(conn, deadline, 65536)
        if not chunk:
            return data, b""
        data += chunk


def read_exactly(conn, deadline, length, data):
    """Exactly `length` bytes, the first of them in `data`, as device_query.rs read_exactly reads them: whatever
    follows them, and the peer's end, are not waited for."""
    while len(data) < length:
        chunk = recv_by(conn, deadline, min(65536, length - len(data)))
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
    memory = rust_trim(memory)
    if not comma or not comma_2 or not rust_trim(model):
        return None
    if not RUST_UNSIGNED.fullmatch(memory) or int(memory) > U64_MAX:
        return None
    return plain_device_id(uuid)


def exchange(path):
    """The reply's first line, trimmed at its end, and the output it frames ('' for a refusal or a bad frame)."""
    deadline = time.monotonic() + WAIT_SECS
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(WAIT_SECS)
        conn.connect(path)
        conn.settimeout(max(deadline - time.monotonic(), 0.001))
        conn.sendall(REQUEST)
        head, rest = read_head(conn, deadline)
        head = head.decode("utf-8", "replace").rstrip(RUST_WHITESPACE)
        length = head[len("ok ") :] if head.startswith("ok ") else ""
        if not RUST_UNSIGNED.fullmatch(length) or int(length) > OUTPUT_MAX_BYTES:
            return head, None
        return head, read_exactly(conn, deadline, int(length), rest)


def verdict(path, device):
    """(passed, why): the card's device line, or why the reply fails."""
    try:
        head, body = exchange(path)
    except (OSError, EOFError) as error:
        return False, "error %s" % error
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
    if len(argv) != 3:
        print("FAIL usage: engine_probe.py <socket> <GPU-uuid>")
        return 1
    passed, why = verdict(argv[1], argv[2])
    print(("PASS " if passed else "FAIL ") + why.replace("\n", " ").replace("\r", " "))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
