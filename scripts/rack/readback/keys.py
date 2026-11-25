"""The key readback (pass 34 15.1, gate C; row K1 part c), one box's part of it.

It reads, and changes nothing. A rack key is the client key of another rack
machine that is not one of the owner's own devices (13: the owner's access
from his device stays). Each box exports its client keys' fingerprints into
a private file (`export_client_keys`); the Orchestrator collects those files
into one directory, `keys.rack_client_keys_dir`, for every box to read.

The box passes when no rack key was accepted by its sshd since the freeze
time and no live inbound session was opened with one. At phase `after` (the
keys removed) no authorized_keys file may list a rack key either. A file that
cannot be read, a missing freeze time, a missing rack list or a live session
with no accept record is no proof: the readback fails.

The sshd journal must cover the whole time since the freeze: a read that
starts after it (`keys.journal_since_unix`) fails, and so does a system
journal with no record from before the freeze (rotated, volatile, or not
readable by the running user). In a privileged run `~` is root's home, so
every authorized_keys file must be named by its absolute path, one for each
account the rack logs in as.
"""

from __future__ import annotations

import base64
import binascii
import glob
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from rack.commands import CommandError, read_output
from rack.rack_config import expand
from rack.readback.drain import parse_peer

KEY_TYPES = re.compile(r"^(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-\S+|sk-\S+@openssh\.com)$")
ACCEPTED = re.compile(
    r"Accepted publickey for (?P<user>\S+) from (?P<addr>\S+) port (?P<port>\d+) \S+: \S+ (?P<fp>SHA256:\S+)"
)


@dataclass
class AuthorizedKey:
    fingerprint: str
    comment: str
    restricted: bool


@dataclass
class Accept:
    when: float
    user: str
    addr: str
    port: int
    fingerprint: str


@dataclass
class KeyReading:
    authorized: dict[str, list[AuthorizedKey]] = field(default_factory=dict)
    unread_files: list[str] = field(default_factory=list)
    rack_keys: dict[str, str] = field(default_factory=dict)
    accepts: list[Accept] = field(default_factory=list)
    live_sessions: list[tuple[str, int]] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)
    # The configured files a run of this privilege cannot use as named.
    path_problems: list[str] = field(default_factory=list)
    # The system journal holds a record from at or before the freeze.
    journal_before_freeze: bool = False


def fingerprint(blob_b64: str) -> str | None:
    """The OpenSSH SHA256 fingerprint of a base64 key body."""
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def _split_options(line: str) -> tuple[str, str]:
    """(options, rest) of an authorized_keys line; quoted commas stay in options."""
    if KEY_TYPES.match(line.split(None, 1)[0]):
        return "", line
    quoted = False
    for index, char in enumerate(line):
        if char == '"':
            quoted = not quoted
        elif char in " \t" and not quoted:
            return line[:index], line[index:].strip()
    return line, ""


def parse_authorized_keys(text: str) -> list[AuthorizedKey]:
    keys = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        options, rest = _split_options(line)
        parts = rest.split(None, 2)
        if len(parts) < 2 or not KEY_TYPES.match(parts[0]):
            continue
        fp = fingerprint(parts[1])
        if fp is None:
            continue
        keys.append(
            AuthorizedKey(
                fingerprint=fp,
                comment=parts[2] if len(parts) > 2 else "",
                restricted="restrict" in options or "command=" in options,
            )
        )
    return keys


def read_client_keys(globs: list[str]) -> list[str]:
    """Fingerprints of this box's own client public keys (.pub files only)."""
    found = []
    for pattern in globs:
        for name in sorted(glob.glob(str(expand(pattern)))):
            if not name.endswith(".pub"):
                continue
            try:
                parts = Path(name).read_text(encoding="utf-8").split()
            except OSError:
                continue
            if len(parts) >= 2 and KEY_TYPES.match(parts[0]):
                fp = fingerprint(parts[1])
                if fp:
                    found.append(fp)
    return sorted(set(found))


def export_client_keys(section: dict, host: str, out_dir: Path) -> Path:
    """Writes `<host>.keys` (one fingerprint and the host per line), mode 0600."""
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = out_dir / f"{host}.keys"
    lines = [f"{fp} {host}\n" for fp in read_client_keys(section["client_key_globs"])]
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.writelines(lines)
    return target


def load_rack_keys(directory: Path, owner_devices: list[str]) -> dict[str, str]:
    """fingerprint -> machine, for every rack machine that is not an owner's device."""
    keys: dict[str, str] = {}
    for name in sorted(directory.glob("*.keys")):
        for line in name.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) != 2 or parts[1] in owner_devices:
                continue
            keys[parts[0]] = parts[1]
    return keys


def _unix_time(word: str) -> float | None:
    try:
        return float(word)
    except ValueError:
        return None


def parse_accepts(text: str) -> list[Accept]:
    """Accept records from `journalctl -o short-unix` lines."""
    accepts = []
    for line in text.splitlines():
        match = ACCEPTED.search(line)
        if not match:
            continue
        try:
            when = float(line.split(None, 1)[0])
        except ValueError:
            continue
        accepts.append(
            Accept(
                when=when,
                user=match["user"],
                addr=match["addr"],
                port=int(match["port"]),
                fingerprint=match["fp"],
            )
        )
    return accepts


def authorized_keys_paths(files: list[str], privileged: bool) -> tuple[list[Path], list[str]]:
    """(paths to read, problems) for the configured authorized_keys files.

    Every path must be absolute once `~` is expanded. In a privileged run `~`
    is root's home, so a `~` entry would read root's file in place of the rack
    login account's: there every entry must be absolute as written.
    """
    paths: list[Path] = []
    problems: list[str] = []
    for name in files:
        if privileged and name.startswith("~"):
            problems.append(
                "a privileged run reads ~ as root's home: name each login account's authorized_keys file "
                "by its absolute path (keys.authorized_keys_files)"
            )
            continue
        path = expand(name)
        if not path.is_absolute():
            problems.append("keys.authorized_keys_files names a relative path")
            continue
        if path not in paths:
            paths.append(path)
    return paths, sorted(set(problems))


def read_keys(section: dict, timeout: int, privileged: bool | None = None) -> KeyReading:
    reading = KeyReading()
    privileged = os.geteuid() == 0 if privileged is None else privileged
    paths, reading.path_problems = authorized_keys_paths(section["authorized_keys_files"], privileged)
    for path in paths:
        try:
            reading.authorized[str(path)] = parse_authorized_keys(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            reading.authorized[str(path)] = []
        except OSError:
            reading.unread_files.append(str(path))

    rack_dir = section["rack_client_keys_dir"]
    if rack_dir:
        try:
            reading.rack_keys = load_rack_keys(expand(rack_dir), section["owner_devices"])
        except OSError:
            reading.unread.append("rack client keys")

    argv = ["journalctl", "--no-pager", "-q", "-o", "short-unix"]
    since = section["journal_since_unix"]
    if since:
        argv += ["--since", f"@{since}"]
    for unit in section["sshd_units"]:
        argv += ["-u", unit]
    try:
        reading.accepts = parse_accepts(read_output(argv, timeout))
    except CommandError:
        reading.unread.append("sshd journal")

    freeze = section["freeze_unix"]
    if freeze:
        # The newest system record at or before the freeze: none means the journal does not reach back to it.
        probe = ["journalctl", "--no-pager", "-q", "-o", "short-unix", "--system", "-r", "-n", "1", "--until", f"@{freeze}"]
        try:
            first = read_output(probe, timeout).split(None, 1)
            reading.journal_before_freeze = bool(first) and _unix_time(first[0]) is not None
        except CommandError:
            reading.unread.append("journal coverage")

    try:
        out = read_output(["ss", "-tnH", "state", "established", "( sport = :22 )"], timeout)
        for line in out.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            peer = cols[3]
            port = peer.rsplit(":", 1)[-1]
            if port.isdigit():
                reading.live_sessions.append((parse_peer(peer), int(port)))
    except CommandError:
        reading.unread.append("live sessions")
    return reading


def judge(reading: KeyReading, section: dict, phase: str) -> tuple[bool, str, dict]:
    """(passed, reason, facts) for one box."""
    freeze = section["freeze_unix"]
    since = section["journal_since_unix"]
    facts: dict = {}
    problems = list(reading.path_problems)
    if reading.unread_files:
        problems.append(f"{len(reading.unread_files)} authorized_keys files not read (root's needs the Orchestrator's run)")
    if reading.unread:
        problems.append("not read: " + ", ".join(reading.unread))
    if not freeze:
        problems.append("no freeze time (keys.freeze_unix)")
    elif since > freeze:
        problems.append("keys.journal_since_unix is later than the freeze: logins in between are not read")
    elif "journal coverage" not in reading.unread and not reading.journal_before_freeze:
        problems.append(
            "the system journal holds no record from before the freeze (rotated, volatile, or not readable by this user)"
        )
    if not reading.rack_keys:
        problems.append("no rack client key list (keys.rack_client_keys_dir)")
    if problems:
        return False, "; ".join(problems), facts

    rack = reading.rack_keys
    used = [a for a in reading.accepts if a.when >= freeze and a.fingerprint in rack]
    facts["rack_key_accepts_since_freeze"] = [
        {"machine": rack[a.fingerprint], "user": a.user, "when": a.when} for a in used
    ]
    latest: dict[tuple[str, int], Accept] = {}
    for accept in sorted(reading.accepts, key=lambda a: a.when):
        latest[(accept.addr, accept.port)] = accept
    live_rack = []
    live_unknown = 0
    for session in reading.live_sessions:
        accept = latest.get(session)
        if accept is None:
            live_unknown += 1
        elif accept.fingerprint in rack:
            live_rack.append(rack[accept.fingerprint])
    facts["live_sessions"] = len(reading.live_sessions)
    facts["live_rack_key_sessions"] = live_rack
    authorized_rack = {
        path: [rack[k.fingerprint] for k in keys if k.fingerprint in rack]
        for path, keys in reading.authorized.items()
    }
    facts["authorized_rack_keys"] = authorized_rack
    listed = sum(len(machines) for machines in authorized_rack.values())

    if used:
        problems.append(f"{len(used)} rack key logins since the freeze")
    if live_rack:
        problems.append(f"{len(live_rack)} live sessions on a rack key")
    if live_unknown:
        problems.append(f"{live_unknown} live sessions with no accept record")
    if phase == "after" and listed:
        problems.append(f"{listed} rack keys still authorized")
    if problems:
        return False, "; ".join(problems), facts
    return True, "", facts
