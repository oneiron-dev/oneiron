"""Private, redacted evidence for each check run, and the redaction every printed line passes.

The contract's stdout is one fixed line. Everything a check learns goes to a
JSON file of mode 0600 in a 0700 directory on the box's own disk. A
directory on a network mount is refused, because evidence never goes into a
shared tree. The check is made on the directory the file goes into: the run
directory (`<evidence root>/<run id>`) is opened without following a link, a
link there is refused, and it must be on the evidence root's own filesystem
(a mount at the run directory is refused). The file is written through that
open directory, so no path is looked up again. The evidence and any printed
text (the one stderr reason line) pass `redact` first, so they carry no key,
fingerprint, token or address.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
from pathlib import Path
from typing import Any

# Filesystem types that are shared trees, never a home for evidence.
SHARED_FS_TYPES = ("fuse.sshfs", "nfs", "nfs4", "cifs", "smb3", "9p", "fuse.rclone")

_REDACTIONS = (
    # An OpenSSH key fingerprint.
    (re.compile(r"SHA256:[A-Za-z0-9+/]{20,}={0,2}"), "<fingerprint>"),
    (re.compile(r"MD5:(?:[0-9a-f]{2}:){15}[0-9a-f]{2}"), "<fingerprint>"),
    # A public or private key body.
    (re.compile(r"(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-\S+|sk-\S+)\s+AAAA[A-Za-z0-9+/=]+"), "<key>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "<key>"),
    # A bearer or other long token: mixed case and digits. A lower-case hex
    # name (a commit, a digest, an order id) is no secret and stays.
    (re.compile(r"(?i)bearer\s+\S+"), "<token>"),
    (
        re.compile(r"\b(?=[A-Za-z0-9_\-]*[A-Z])(?=[A-Za-z0-9_\-]*[a-z])(?=[A-Za-z0-9_\-]*\d)[A-Za-z0-9_\-]{32,}\b"),
        "<token>",
    ),
    # A v4 address.
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<address>"),
)

_V6_CANDIDATE = re.compile(r"(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?![\w:])")


def _v6(match: re.Match[str]) -> str:
    try:
        ipaddress.IPv6Address(match.group(0))
    except ValueError:
        return match.group(0)
    return "<address>"


def redact(text: str) -> str:
    """`text` with every key, fingerprint, token and address replaced."""
    for pattern, mark in _REDACTIONS:
        text = pattern.sub(mark, text)
    return _V6_CANDIDATE.sub(_v6, text)


def redact_value(value: Any) -> Any:
    """`value` with `redact` applied to every string inside it."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {redact(str(k)): redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [redact_value(v) for v in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))


class EvidenceError(Exception):
    """The evidence directory cannot be used; the entry exits 2."""


def filesystem_type(path: Path) -> str:
    """The filesystem type holding `path` (its nearest existing parent)."""
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        done = subprocess.run(
            ["findmnt", "-n", "-o", "FSTYPE", "-T", str(probe)],
            capture_output=True,
            text=True,
            timeout=15,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceError(f"the evidence directory's filesystem is not known: {error}") from None
    if done.returncode != 0:
        raise EvidenceError("the evidence directory's filesystem is not known")
    return done.stdout.strip()


class Evidence:
    """One check run's private record."""

    def __init__(self, root: Path, run_id: str, host: str, phase: str, check: str):
        self.root = root
        self.run_id = run_id
        self.name = f"{host}-{phase}-{check}"
        self.facts: dict[str, Any] = {
            "run": run_id,
            "host": host,
            "phase": phase,
            "check": check,
        }

    def add(self, key: str, value: Any) -> None:
        self.facts[key] = value

    def _open_run_directory(self) -> int:
        """The run directory, opened (O_NOFOLLOW) after its checks; EvidenceError when it cannot be used."""
        fs_type = filesystem_type(self.root)
        if fs_type in SHARED_FS_TYPES:
            raise EvidenceError(f"the evidence directory is on a shared filesystem ({fs_type})")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        fs_type = filesystem_type(self.root)
        if fs_type in SHARED_FS_TYPES:
            raise EvidenceError(f"the evidence directory is on a shared filesystem ({fs_type})")
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            _private(root_fd)
            try:
                os.mkdir(self.run_id, 0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
            try:
                run_fd = os.open(self.run_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
            except OSError as error:
                if os.path.islink(self.root / self.run_id):
                    raise EvidenceError("the run directory is a link") from None
                raise EvidenceError(f"the run directory cannot be opened: {error.strerror}") from None
            try:
                _private(run_fd)
                if _device(run_fd) != _device(root_fd):
                    raise EvidenceError("the run directory is on another filesystem than the evidence directory")
            except BaseException:
                os.close(run_fd)
                raise
            return run_fd
        finally:
            os.close(root_fd)

    def write(self, outcome: str, reason: str) -> Path:
        """Writes the record once, atomically, with mode 0600, through the checked run directory."""
        self.facts["outcome"] = outcome
        self.facts["reason"] = reason
        run_fd = self._open_run_directory()
        try:
            target = f"{self.name}.json"
            temp = f".{self.name}.{secrets.token_hex(8)}"
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=run_fd)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as out:
                    json.dump(redact_value(self.facts), out, indent=2, sort_keys=True)
                    out.write("\n")
                os.replace(temp, target, src_dir_fd=run_fd, dst_dir_fd=run_fd)
            except BaseException:
                try:
                    os.unlink(temp, dir_fd=run_fd)
                except FileNotFoundError:
                    pass
                raise
        finally:
            os.close(run_fd)
        return self.root / self.run_id / target


def _device(fd: int) -> int:
    return os.fstat(fd).st_dev


def _private(fd: int) -> None:
    """EvidenceError unless the open directory is open to its owner alone."""
    mode = stat.S_IMODE(os.fstat(fd).st_mode)
    if mode & 0o077:
        raise EvidenceError(f"the evidence directory is open to others (mode {mode:o})")
