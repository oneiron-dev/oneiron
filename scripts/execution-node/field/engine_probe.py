#!/usr/bin/env python3
"""T40 check 6 (check_device_handoff.sh --engine-account): the engine's GPU probe through the job control socket.

Sends one `device-query nvidia-devices` request to the socket, as the engine's probe does, and reads the reply as the
probe reads it (crates/oneiron-server/src/gpu_execution_node/scope_systemd/device_query.rs, request_within): a first
line of at most 1024 bytes, `ok <n>` with n at most 1 MiB, then exactly n bytes of UTF-8 output; or `refused <why>`.
The output passes only when every line is a device line the probe reads (device.rs, parse_device_lines: UUID, model,
memory in MiB) and one of them has the card's UUID as its UUID field, exactly. A reply the probe would reject never
passes (review r2 of #10540: `ok 999` and a short body passed T40 before).

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
# The probe's own wait: GPU_QUERY_TIMEOUT (10 s) and its margin (5 s), with room.
WAIT_SECS = 20
LENGTH = re.compile(r"ok (0|[1-9][0-9]*)")
MEMORY = re.compile(r"[0-9]+")


def read_reply(path):
    """The reply, up to one byte past the longest the probe reads, all within WAIT_SECS of the call."""
    deadline = time.monotonic() + WAIT_SECS
    limit = HEAD_MAX_BYTES + OUTPUT_MAX_BYTES + 1
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(WAIT_SECS)
        conn.connect(path)
        conn.sendall(REQUEST)
        data = b""
        while len(data) < limit:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("no whole reply within %d s" % WAIT_SECS)
            conn.settimeout(left)
            chunk = conn.recv(min(65536, limit - len(data)))
            if not chunk:
                break
            data += chunk
        return data


def plain_device_id(text):
    """The UUID field as the probe reads it (device.rs, plain_device_id): no whitespace or control character."""
    text = text.strip()
    if not text or any(c.isspace() or ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in text):
        return None
    return text


def device_uuid(line):
    """The UUID of a device line as parse_device_lines reads it (`<uuid>, <model>, <memory>`), or None."""
    uuid, comma, rest = line.partition(",")
    model, comma_2, memory = rest.rpartition(",")
    if not comma or not comma_2 or not model.strip() or not MEMORY.fullmatch(memory.strip()):
        return None
    return plain_device_id(uuid)


def verdict(path, device):
    """(passed, why): the card's device line, or why the reply fails."""
    try:
        data = read_reply(path)
    except OSError as error:
        return False, "error %s" % error
    head, newline, body = data.partition(b"\n")
    if not newline or len(head) + 1 > HEAD_MAX_BYTES:
        return False, "no first line within %d bytes: %r" % (HEAD_MAX_BYTES, head[:80])
    head = head.decode("utf-8", "replace")
    if head.startswith("refused "):
        return False, head
    length = LENGTH.fullmatch(head)
    if not length:
        return False, "first line %r is not `ok <n>`" % head[:80]
    length = int(length.group(1))
    if length > OUTPUT_MAX_BYTES:
        return False, "length %d is past the probe's %d-byte cap" % (length, OUTPUT_MAX_BYTES)
    if len(body) != length:
        return False, "length %d, but %d bytes followed" % (length, len(body))
    try:
        output = body.decode("utf-8")
    except UnicodeDecodeError as error:
        return False, "the output is not UTF-8: %s" % error
    found = None
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        uuid = device_uuid(line)
        if uuid is None:
            return False, "a line the probe does not read: %r" % line[:120]
        if uuid == device and found is None:
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
