#!/usr/bin/env python3
"""Run one fleet measurement with an independent exit/resource receipt (POSIX)."""
import argparse
import json
import os
from pathlib import Path
import platform
import sys
import time


def run_observed(command, output):
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


def observe(command, destination):
    # Reserve the evidence path before starting work. Never overwrite a receipt.
    with Path(destination).open("x", encoding="utf-8") as output:
        return run_observed(command, output)


def detach(command, destination, log_path):
    """Keep the measured process outside a caller's disposable process group."""
    admission = Path(str(destination) + ".admission.json")
    with Path(destination).open("x", encoding="utf-8") as output, Path(log_path).open("x") as log, admission.open("x") as record:
        ready_read, ready_write = os.pipe()
        pid = os.fork()
        if pid:
            os.close(ready_write)
            try:
                ready = os.read(ready_read, 1)
            finally:
                os.close(ready_read)
            if ready != b"1":
                raise RuntimeError("observer failed before detaching")
            json.dump({"observer_pid": pid, "session_id": pid, "receipt": str(destination),
                       "log": str(log_path), "terminal": False}, record)
            record.write("\n")
            record.flush()
            os.fsync(record.fileno())
            return 0
        os.close(ready_read)
        os.setsid()
        with open(os.devnull) as null:
            os.dup2(null.fileno(), 0)
        os.dup2(log.fileno(), 1)
        os.dup2(log.fileno(), 2)
        os.write(ready_write, b"1")
        os.close(ready_write)
        code = run_observed(command, output)
        os._exit(code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--detach", action="store_true")
    parser.add_argument("--log")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    if args.detach:
        if not args.log:
            parser.error("--detach requires a new --log path")
        return detach(command, args.receipt, args.log)
    return observe(command, args.receipt)


if __name__ == "__main__":
    raise SystemExit(main())
