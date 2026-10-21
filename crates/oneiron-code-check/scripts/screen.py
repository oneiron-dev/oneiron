#!/usr/bin/env python3
"""Fleet-only backend direction screen. Fetch the pinned native oracle; no tests."""

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[3]
CRATE = ROOT / "crates" / "oneiron-code-check"
PACKAGE = "@typescript/typescript-linux-x64"
# Independent byte pin for MICROSOFT_TS_VERSION, not just mutable registry metadata.
SRI_VERSION = "7.1.0-dev.20261010.1"
SRI = "sha512-/O2ofLSO/VmT45ly/Zw1oHii2U5dxs+7zs4Fjg/qkpR9FWjyfidGhOptYX769l4yMw+MrHA5Fmv9pczayomo1A=="


def capture(*command):
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def read_if_present(path):
    return Path(path).read_text() if Path(path).is_file() else None


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def acquire(work):
    source = (CRATE / "src" / "microsoft.rs").read_text()
    match = re.search(r'pub const MICROSOFT_TS_VERSION: &str = "([^"]+)";', source)
    if not match:
        raise RuntimeError("MICROSOFT_TS_VERSION not found in microsoft.rs")
    version = match[1]
    if version != SRI_VERSION:
        raise RuntimeError("MICROSOFT_TS_VERSION changed; update the independent SRI pin explicitly")
    url = f"https://registry.npmjs.org/{urllib.parse.quote(PACKAGE, safe='')}/{version}"
    with urllib.request.urlopen(url, timeout=60) as response:
        metadata = json.load(response)
    if metadata.get("name") != PACKAGE or metadata.get("version") != version:
        raise RuntimeError("registry metadata names another package/version")
    dist = metadata["dist"]
    if dist.get("integrity") != SRI:
        raise RuntimeError("registry SRI differs from the pinned Microsoft package")
    tarball_url = dist["tarball"]
    if urllib.parse.urlparse(tarball_url).scheme != "https":
        raise RuntimeError("registry tarball must use HTTPS")
    tarball = work / "typescript.tgz"
    digest = hashlib.sha512()
    with urllib.request.urlopen(tarball_url, timeout=60) as response, tarball.open("wb") as target:
        while chunk := response.read(1024 * 1024):
            target.write(chunk)
            digest.update(chunk)
    measured_sri = "sha512-" + base64.b64encode(digest.digest()).decode()
    if measured_sri != SRI:
        raise RuntimeError("Microsoft tarball failed SRI verification")
    # Copy regular members only; never execute package scripts or follow archive links.
    seen = set()
    with tarfile.open(tarball, "r:gz") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != "package":
                raise RuntimeError(f"unexpected tarball path: {member.name}")
            target = work.joinpath(*name.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.name in seen:
                raise RuntimeError(f"tarball member is not a unique regular file: {member.name}")
            seen.add(member.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as incoming, target.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            target.chmod(member.mode & 0o755)
    package = json.loads((work / "package" / "package.json").read_text())
    if package.get("name") != PACKAGE or package.get("version") != version:
        raise RuntimeError("unpacked package names another package/version")
    tsc = work / "package" / "lib" / "tsc"
    if not tsc.is_file() or not os.access(tsc, os.X_OK):
        raise RuntimeError("native package lacks executable package/lib/tsc")
    pin = {"package": PACKAGE, "version": version, "metadata_url": url,
           "tarball": tarball_url, "integrity": measured_sri, "git_head": metadata.get("gitHead"),
           "executable_sha256": hashlib.sha256(tsc.read_bytes()).hexdigest(),
           "executable_bytes": tsc.stat().st_size, "executable": str(tsc)}
    return tsc, pin


def tail(path, lines=80):
    if path.exists():
        print("\n".join(path.read_text(errors="replace").splitlines()[-lines:]), flush=True)


def run(args, output):
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise RuntimeError("screen.py requires a Linux x64 fleet host; never build on the coordinator Mac")
    environment = {
        "host": socket.gethostname(), "cpu": read_if_present("/proc/cpuinfo"),
        "os": platform.platform(), "os_release": read_if_present("/etc/os-release"),
        "rustc": capture("rustc", "--version", "--verbose"),
        "git_head": capture("git", "rev-parse", "HEAD"),
        "git_status": capture("git", "status", "--porcelain"),
        "profile": "release", "started_unix_s": time.time(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)), "loadavg": os.getloadavg(),
        "rounds": args.rounds, "warmup": args.warmup,
        "build_environment": {key: value for key, value in os.environ.items()
                              if key.startswith(("RUST", "CARGO_PROFILE_"))},
    }
    save_json(output / "environment.json", environment)
    work_parent = output / "work"
    work_parent.mkdir()
    work = Path(tempfile.mkdtemp(prefix="microsoft-", dir=work_parent))
    tsc, pin = acquire(work)
    environment["microsoft_package"] = pin
    save_json(output / "environment.json", environment)
    save_json(output / "microsoft-package.json", pin)
    # A clone-local target never shares a runner's cache and goes with the clone.
    target = ROOT / "target" / "backend-screen"
    build = ["cargo", "build", "--locked", "--release", "-p", "oneiron-code-check",
             "--example", "backend_screen"]
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="4",
               CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never")
    print(f"screen host={environment['host']} head={environment['git_head']} output={output}", flush=True)
    print("building: " + " ".join(build), flush=True)
    with (output / "build.log").open("w") as log:
        rc = subprocess.run(build, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
    tail(output / "build.log")
    if rc:
        return rc
    command = [str(target / "release" / "examples" / "backend_screen"),
               "--rounds", str(args.rounds), "--warmup", str(args.warmup),
               "--microsoft-tsc", str(tsc), "--programs", str(args.programs.resolve()),
               "--output", str(output)]
    environment["measurement_launch_loadavg"] = os.getloadavg()
    environment["build_command"] = build
    environment["example_command"] = command
    save_json(output / "environment.json", environment)
    env["ONEIRON_SCREEN_ENV_JSON"] = json.dumps(environment)
    with (output / "run.log").open("w") as log:
        rc = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
    tail(output / "run.log")
    if rc == 0 and not all((output / name).is_file() for name in ("screen.json", "screen.md", "diffs.json")):
        raise RuntimeError("example returned success without its evidence files")
    return rc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=50)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--programs", type=Path, default=CRATE / "examples" / "screen-programs")
    args = parser.parse_args()
    if args.rounds < 1 or args.warmup < 0:
        parser.error("rounds must be positive; warmup must be nonnegative")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output must be empty, so stale evidence cannot be reported")
    rc, head = 1, "unknown"
    try:
        head = capture("git", "rev-parse", "HEAD")
        rc = run(args, output)
    except Exception as error:
        (output / "failure.txt").write_text(f"{type(error).__name__}: {error}\n")
        print(f"screen failed: {error}", file=sys.stderr, flush=True)
    finally:
        print("## SCREEN BEGIN", flush=True)
        page = output / "screen.md"
        if page.exists():
            print(page.read_text(), end="", flush=True)
        else:
            print(f"Screen incomplete (rc={rc}); measurements and Engine decision: pending.", flush=True)
        print("## SCREEN END", flush=True)
        print(f"## SCREEN rc={rc} head={head}", flush=True)
        print(f"## SCREEN output={output}", flush=True)
    return rc if rc >= 0 else 128 - rc


if __name__ == "__main__":
    sys.exit(main())
