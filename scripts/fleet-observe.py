#!/usr/bin/env python3
"""Run one fleet measurement with an independent exit/resource receipt (POSIX)."""
import argparse
import json
import os
from pathlib import Path
import platform
import sys
import time


def observe(command, destination):
    # Reserve the evidence path before starting work. Never overwrite a receipt.
    with Path(destination).open("x", encoding="utf-8") as output:
        started = time.monotonic()
        try:
            pid = os.posix_spawnp(command[0], command, os.environ)
            _, status, usage = os.wait4(pid, 0)
            code = os.waitstatus_to_exitcode(status)
            record = {
                "schema": "oneiron-fleet-process-v1",
                "terminal": True,
                "command": command,
                "pid": pid,
                "exit_code": code,
                "signal": -code if code < 0 else None,
                "elapsed_seconds": time.monotonic() - started,
                "user_seconds": usage.ru_utime,
                "system_seconds": usage.ru_stime,
                "max_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
                "os": platform.system(),
            }
        except OSError as error:
            code = 127
            record = {"schema": "oneiron-fleet-process-v1", "terminal": True,
                      "command": command, "exit_code": code, "launch_error": str(error)}
        json.dump(record, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    return code if code >= 0 else 128 - code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    return observe(command, args.receipt)


if __name__ == "__main__":
    raise SystemExit(main())
