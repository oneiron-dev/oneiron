#!/usr/bin/env python3
"""Opt-in macOS plist boot proof with one temporary label and owned paths only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import socket
import subprocess
import sys
import tempfile
import uuid


def run(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, timeout=90, check=check)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("launchd proof requires macOS")
    root = Path(__file__).resolve().parents[2]
    server = args.server.resolve(strict=True)
    if args.out.exists():
        raise SystemExit("receipt already exists")
    reference = root / "deploy/launchd/com.oneiron.server.plist"
    reference_bytes = reference.read_bytes()
    receipt = {
        "reference_sha256": hashlib.sha256(reference_bytes).hexdigest(),
        "binary_sha256": hashlib.sha256(server.read_bytes()).hexdigest(),
        "os_version": run("sw_vers", "-productVersion").stdout.strip(),
        "deviations": ["temporary label", "owned paths", "KeepAlive=false", "loopback port"],
        "passed": False,
    }
    label = "com.oneiron.server.w7proof." + uuid.uuid4().hex
    target = f"gui/{os.getuid()}/{label}"
    (root / ".w7").mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="launchd-proof-", dir=root / ".w7") as temp:
            scratch = Path(temp)
            vault = scratch / "vault"
            config = scratch / "oneiron.toml"
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            run(str(server), "init", str(vault))
            if not (vault / "data.mdb").is_file():
                raise RuntimeError("init did not create a vault")
            config.write_text(f'vault_path = {json.dumps(str(vault))}\nhost = "127.0.0.1"\nport = {port}\nlog_level = "info"\n')
            plist = plistlib.loads(reference_bytes)
            plist["Label"] = label
            plist["KeepAlive"] = False
            substitutions = {
                "__HOME__/.cargo/bin/oneiron-server": str(server),
                "__HOME__/.local/share/oneiron/default": str(vault),
                "__HOME__/.config/oneiron/oneiron.toml": str(config),
            }
            plist["ProgramArguments"] = [substitutions.get(arg, arg) for arg in plist["ProgramArguments"]]
            plist["StandardOutPath"] = str(scratch / "stdout.log")
            plist["StandardErrorPath"] = str(scratch / "stderr.log")
            rendered = plistlib.dumps(plist)
            if b"__HOME__" in rendered:
                raise RuntimeError("unsubstituted reference path")
            fixture = scratch / "fixture.plist"
            fixture.write_bytes(rendered)
            receipt["fixture_sha256"] = hashlib.sha256(rendered).hexdigest()
            run("plutil", "-lint", str(fixture))
            booted = False
            try:
                run("launchctl", "bootstrap", f"gui/{os.getuid()}", str(fixture))
                booted = True
                health = run("curl", "--silent", "--show-error", "--fail", "--retry", "10", "--retry-connrefused", "--retry-delay", "1", "--max-time", "5", f"http://127.0.0.1:{port}/api/health")
                receipt["health"] = json.loads(health.stdout)
                if receipt["health"].get("status") != "ok":
                    raise RuntimeError("health did not report ok")
                job = run("launchctl", "print", target).stdout
                receipt["job_running"] = "state = running" in job
                if not receipt["job_running"]:
                    raise RuntimeError("launchd did not retain a running job")
                receipt["passed"] = True
            finally:
                receipt["logs"] = {p.name: p.read_text(errors="replace")[-16000:] for p in [scratch / "stdout.log", scratch / "stderr.log"] if p.exists()}
                if booted:
                    run("launchctl", "bootout", target)
                    absent = run("launchctl", "print", target, check=False)
                    receipt["label_removed"] = absent.returncode != 0
                    if not receipt["label_removed"]:
                        raise RuntimeError("temporary label survived teardown")
        receipt["scratch_removed"] = not scratch.exists()
        if reference.read_bytes() != reference_bytes:
            raise RuntimeError("reference plist changed")
    except Exception as error:
        receipt["passed"] = False
        receipt["error"] = str(error)
    with args.out.open("x") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
