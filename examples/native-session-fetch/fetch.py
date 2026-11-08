#!/usr/bin/env python3
"""Fetch through the current native session's host-policy relay."""

import json
import os
import socket
import struct
import sys


def fetch(request: dict) -> dict:
    payload = json.dumps(request).encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.connect(os.environ["ONEIRON_NATIVE_EGRESS_SOCKET"])
        channel.sendall(struct.pack(">I", len(payload)) + payload)
        with channel.makefile("rb") as wire:
            length = wire.read(4)
            if len(length) != 4:
                raise EOFError("native relay closed before its reply")
            size = struct.unpack(">I", length)[0]
            payload = wire.read(size)
            if len(payload) != size:
                raise EOFError("native relay closed during its reply")
    reply = json.loads(payload)
    if reply["errno"]:
        raise OSError(reply["errno"], "native fetch refused")
    return json.loads(bytes(reply["bytes"]))


if __name__ == "__main__":
    json.dump(fetch(json.load(sys.stdin)), sys.stdout)
    sys.stdout.write("\n")
