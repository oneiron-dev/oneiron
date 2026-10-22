"""Small shared helpers: typed errors, hashing, subprocess and HTTP fetches."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

HEX64 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
CHUNK = 1 << 20


class BuildError(Exception):
    """A refusal with a stable kind, printed as `error[<kind>]: <message>`."""

    kind = "build"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class MissingPin(BuildError):
    kind = "missing-pin"


class BadPin(BuildError):
    kind = "bad-pin"


class PinMismatch(BuildError):
    kind = "pin-mismatch"


class NotYetSupported(BuildError):
    kind = "not-yet-supported"


class HostRefusal(BuildError):
    kind = "host"


class StepFailed(BuildError):
    kind = "step-failed"


def log(message: str) -> None:
    print(f"[images] {message}", file=sys.stderr, flush=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while block := stream.read(CHUNK):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def host_env(**extra: str) -> dict:
    """The environment of every host-side tool the builder runs (git, tar, unshare, mount).

    PATH and the locale only: no HOME, so no ~/.gitconfig, ~/.cargo, ~/.config
    or user site-packages reaches a tool, and no git system config or
    attributes, TAR_OPTIONS, CARGO_*, RUST* or PYTHON* variable either."""
    env = {k: os.environ[k] for k in ("PATH", "LANG") if k in os.environ}
    env.setdefault("PATH", "/usr/bin:/bin")
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_ATTR_NOSYSTEM="1",
               PYTHONNOUSERSITE="1")
    env.update(extra)
    return env


def run(argv, *, cwd=None, env=None, check=True, capture=False, stdin=None) -> subprocess.CompletedProcess:
    """Runs argv; with no env given it gets host_env(), never this process's environment.
    Uncaptured output goes to stderr, so build.py's stdout holds its record alone."""
    shown = " ".join(str(a) for a in argv)
    log(f"$ {shown}")
    result = subprocess.run(
        [str(a) for a in argv],
        cwd=cwd,
        env=host_env() if env is None else env,
        stdin=stdin,
        stdout=subprocess.PIPE if capture else sys.stderr,
        text=capture,
    )
    if check and result.returncode != 0:
        raise StepFailed(f"`{shown}` exited {result.returncode}")
    return result


def fetch_url(url: str, dest: Path, *, headers: dict | None = None) -> None:
    """Downloads url to dest through a .part file; the caller verifies the hash."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "oneiron-images/1", **(headers or {})})
    log(f"GET {url}")
    with urllib.request.urlopen(request, timeout=120) as response, open(part, "wb") as out:
        shutil.copyfileobj(response, out, CHUNK)
    part.rename(dest)


def fetch_json(url: str, *, headers: dict | None = None):
    request = urllib.request.Request(url, headers={"User-Agent": "oneiron-images/1", **(headers or {})})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def require_hex64(value, where: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise BadPin(f"{where} must be 64 lowercase hex characters, got {value!r}")
    return value


def require_digest(value, where: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise BadPin(f"{where} must be sha256:<64 hex>, got {value!r}")
    return value


def userns_root() -> bool:
    """True when this process is root inside a single-uid user namespace (our unshare)."""
    return os.getuid() == 0 and os.environ.get("ONEIRON_IMAGES_USERNS") == "1"


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
