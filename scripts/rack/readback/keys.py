"""The key readback (pass 34 15.1, gate C; row K1 part c), one box's part of it.

It reads, and changes nothing. A rack key is the client key of another rack
machine that is not one of the owner's own devices (13: the owner's access
from the owner's own devices stays). Each box exports its client keys' fingerprints into
a private file (`export_client_keys`); the Orchestrator collects those files
into one directory, `keys.rack_client_keys_dir`, for every box to read.

The box passes when no rack key was accepted by its sshd since the freeze
time and no live inbound session was opened with one. At phase `after` (the
keys removed) no authorized_keys file may list a rack key either. A file that
cannot be read, a missing freeze time, a missing rack list or a live session
with no accept record is no proof: the readback fails.

The files read are sshd's AuthorizedKeysFile (`keys.authorized_keys_file_patterns`)
for root and for every account the rack logs in as (`keys.login_accounts`),
each account's home and uid from the password database (`getent passwd`),
plus any further absolute files (`keys.authorized_keys_files`). A run with no
login account, or an account the database does not know, is no proof. In a
privileged run `~` is root's home, so a further file named with `~` is
refused.

The sshd journal must cover the whole time since the freeze: a read that
starts after it (`keys.journal_since_unix`) fails, and so does an sshd
journal (`keys.sshd_units`, the units the accepts are read from) with no
record from before the freeze (rotated, volatile, or not readable by the
running user). The units must be where sshd logs: every running sshd
listener (an sshd whose parent is not one) must run in one of them, by its
cgroup; a listener elsewhere, none found, or a process table not read in
full is no proof.

sshd must run as the readback reads it. For each running listener's own
`-f` and `-o` options, for root and every login account, and from every rack
machine's connection (`keys.rack_connections`, as this box's sshd sees it:
`sshd -T -C` applies only the Match blocks whose fields the test names),
`sshd -T` must log an accepted key (LogLevel INFO or more), read no
AuthorizedKeysFile outside `keys.authorized_keys_file_patterns`, and take no
key from an AuthorizedKeysCommand or a TrustedUserCAKeys authority, whose
keys no authorized_keys file lists. The program run is `keys.sshd_program`,
never a path read from a process. No rack connection, one sshd's test cannot
take, a listener command line that cannot be read as sshd reads it, or an
sshd that does not print its settings (a run that is not root) is no proof.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import glob
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from rack.commands import CommandError, read_output
from rack.rack_config import expand
from rack.readback.drain import Process, parse_peer, read_processes

KEY_TYPES = re.compile(r"^(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-\S+|sk-\S+@openssh\.com)$")
ACCEPTED = re.compile(
    r"Accepted publickey for (?P<user>\S+) from (?P<addr>\S+) port (?P<port>\d+) \S+: \S+ (?P<fp>SHA256:\S+)"
)

# The `sshd -T` keywords the readback judges (sshd prints each, lower case, with its value).
SSHD_SETTINGS = ("loglevel", "authorizedkeysfile", "authorizedkeyscommand", "trustedusercakeys")
# sshd logs an accepted key at INFO (auth.c auth_log): these levels keep that line.
ACCEPT_LOG_LEVELS = frozenset({"INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"})
# The fields of sshd's connection test besides user= (sshd.c parse_server_match_testspec).
CONNECTION_FIELDS = ("addr", "host", "laddr", "lport", "rdomain")
# A field value or an account name in that test: no comma, `=` or space, which would add or end a field.
TEST_WORD = re.compile(r"^[A-Za-z0-9._:%\[\]-]+$")
ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*\$?$")
# sshd's command-line options (sshd.c getopt): the letters that take an argument, and the flags.
SSHD_OPTION_ARGS = frozenset("CEbcfghkopu")
SSHD_FLAGS = frozenset("46DGQRTdeiqrtV")


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
class SshdView:
    """sshd's settings for one rack login: `sshd -T -C user=<account>,<connection>`."""

    account: str
    connection: str
    # The listener's own -f and -o options, as `sshd -T` was given them.
    options: tuple[str, ...]
    settings: dict[str, list[str]]


@dataclass
class KeyReading:
    authorized: dict[str, list[AuthorizedKey]] = field(default_factory=dict)
    unread_files: list[str] = field(default_factory=list)
    rack_keys: dict[str, str] = field(default_factory=dict)
    accepts: list[Accept] = field(default_factory=list)
    live_sessions: list[tuple[str, int]] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)
    # The configured files a run of this privilege cannot use as named, and the
    # login accounts whose files cannot be named.
    path_problems: list[str] = field(default_factory=list)
    # The sshd journal (keys.sshd_units) holds a record from at or before the freeze.
    journal_before_freeze: bool = False
    # The systemd unit of each running sshd listener, and why that could not be told.
    sshd_listener_units: list[str] = field(default_factory=list)
    sshd_source_problems: list[str] = field(default_factory=list)
    # sshd's settings for each rack login, and why a login could not be asked about.
    sshd_views: list[SshdView] = field(default_factory=list)
    sshd_view_problems: list[str] = field(default_factory=list)


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
    """(paths to read, problems) for the further authorized_keys files (keys.authorized_keys_files).

    Every path must be absolute once `~` is expanded. In a privileged run `~`
    is root's home, so a `~` entry would read root's file in place of the rack
    login account's: there every entry must be absolute as written.
    """
    paths: list[Path] = []
    problems: list[str] = []
    for name in files:
        if privileged and name.startswith("~"):
            problems.append(
                "a privileged run reads ~ as root's home: name a further authorized_keys file "
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


@dataclass
class Account:
    name: str
    uid: int
    home: Path


def lookup_account(name: str, timeout: int) -> Account | None:
    """The account's uid and home from the password database (`getent passwd`); None when it has none.

    CommandError when the database cannot be asked.
    """
    out = read_output(["getent", "passwd", name], timeout, ok_codes=(0, 2))
    for line in out.splitlines():
        fields = line.split(":")
        if len(fields) >= 7 and fields[0] == name and fields[2].isdigit() and fields[5].startswith("/"):
            return Account(name=name, uid=int(fields[2]), home=Path(fields[5]))
    return None


def expand_authorized_keys_file(pattern: str, account: Account) -> Path | None:
    """sshd's expansion of one AuthorizedKeysFile entry (auth.c expand_authorized_keys); None for `none`.

    %h is the home, %u the name, %U the uid, %% a percent sign; a relative
    result is under the home. ValueError for any other token.
    """
    if pattern.lower() == "none":
        return None
    tokens = {"h": str(account.home), "u": account.name, "U": str(account.uid), "%": "%"}
    out: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char != "%":
            out.append(char)
            index += 1
            continue
        token = pattern[index + 1 : index + 2]
        if token not in tokens:
            raise ValueError(f"AuthorizedKeysFile token %{token}")
        out.append(tokens[token])
        index += 2
    path = Path("".join(out))
    return path if path.is_absolute() else account.home / path


def login_account_files(section: dict, timeout: int) -> tuple[list[Path], list[str], list[str], list[str]]:
    """(files, accounts, problems, unread) for root and every rack login account, as sshd names their files.

    `accounts` are the names the password database knows.
    """
    files: list[Path] = []
    accounts: list[str] = []
    problems: list[str] = []
    unread: list[str] = []
    if not section["login_accounts"]:
        problems.append("no rack login accounts (keys.login_accounts)")
    for name in dict.fromkeys(["root", *section["login_accounts"]]):
        try:
            account = lookup_account(name, timeout)
        except CommandError:
            unread.append("password database")
            continue
        if account is None:
            problems.append("a login account the password database does not know (keys.login_accounts)")
            continue
        accounts.append(name)
        for pattern in section["authorized_keys_file_patterns"]:
            try:
                path = expand_authorized_keys_file(pattern, account)
            except ValueError as error:
                problems.append(f"keys.authorized_keys_file_patterns: {error}")
                continue
            if path is not None and path not in files:
                files.append(path)
    return files, accounts, sorted(set(problems)), sorted(set(unread))


def _connection_field_ok(name: str, sep: str, value: str) -> bool:
    if not sep or name not in CONNECTION_FIELDS or not TEST_WORD.match(value):
        return False
    return name != "lport" or value.isdigit()


def rack_connection_problems(connections: list[str]) -> list[str]:
    """Why `keys.rack_connections` cannot be handed to sshd's connection test."""
    if not connections:
        return ["no rack connections (keys.rack_connections)"]
    for connection in connections:
        fields = [part.partition("=") for part in connection.split(",")]
        names = [name for name, _, _ in fields]
        if "addr" not in names or len(set(names)) != len(names) or not all(_connection_field_ok(*f) for f in fields):
            return [
                "keys.rack_connections: each is addr=<address>, then host=, laddr=, lport= or rdomain= "
                "as this box's sshd sees the login"
            ]
    return []


def parse_sshd_settings(text: str) -> dict[str, list[str]]:
    """The judged keywords of `sshd -T` output: keyword -> its value's words."""
    settings: dict[str, list[str]] = {}
    for line in text.splitlines():
        words = line.split()
        if words and words[0] in SSHD_SETTINGS:
            settings.setdefault(words[0], words[1:])
    return settings


def listener_words(proc: Process) -> list[str] | None:
    """A listener's command line as words: its argv, or the title sshd gives a listener; None for a cut title."""
    if len(proc.argv) == 1 and proc.argv[0].startswith("sshd: "):
        title, listener, _ = proc.argv[0][len("sshd: ") :].partition(" [listener]")
        return title.split() if listener else None
    return proc.argv


def sshd_test_options(words: list[str]) -> list[str] | None:
    """The -f and -o options of an sshd command line, for `sshd -T`; None when it is not read as sshd reads it.

    sshd takes no operand, so a word that is neither an option nor its argument
    (a title split inside a spaced value, say) means the line is not known.
    """
    options: list[str] = []
    index = 1
    while index < len(words):
        word = words[index]
        if word == "--":
            return options if index == len(words) - 1 else None
        if not word.startswith("-") or word == "-":
            return None
        for at, letter in enumerate(word[1:], start=1):
            if letter in SSHD_FLAGS:
                continue
            if letter not in SSHD_OPTION_ARGS:
                return None
            value = word[at + 1 :]
            if not value:
                index += 1
                if index == len(words):
                    return None
                value = words[index]
            if letter in "fo":
                options += [f"-{letter}", value]
            break
        index += 1
    return options


def read_sshd_views(
    section: dict, accounts: list[str], listeners: list[Process], timeout: int
) -> tuple[list[SshdView], list[str], list[str]]:
    """(views, problems, unread): sshd's settings for each listener's options, account and rack connection."""
    problems = rack_connection_problems(section["rack_connections"])
    if problems:
        return [], problems, []
    option_sets: list[tuple[str, ...]] = []
    for proc in listeners:
        words = listener_words(proc)
        options = sshd_test_options(words) if words else None
        if options is None:
            problems.append("an sshd listener's command line cannot be read as sshd reads it, so its -f and -o are unknown")
        elif tuple(options) not in option_sets:
            option_sets.append(tuple(options))
    views: list[SshdView] = []
    for account in accounts:
        if not ACCOUNT_NAME.match(account):
            problems.append("a login account name sshd's connection test cannot carry (keys.login_accounts)")
            continue
        for options in option_sets:
            for connection in section["rack_connections"]:
                argv = [section["sshd_program"], "-T", *options, "-C", f"user={account},{connection}"]
                try:
                    settings = parse_sshd_settings(read_output(argv, timeout))
                except CommandError:
                    return views, sorted(set(problems)), ["sshd effective configuration"]
                views.append(SshdView(account=account, connection=connection, options=options, settings=settings))
    return views, sorted(set(problems)), []


def cgroup_unit(text: str) -> str | None:
    """The systemd service of a process, from its /proc/<pid>/cgroup (the v2 line, else name=systemd)."""
    paths = {}
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            paths[parts[1]] = parts[2]
    path = paths.get("", paths.get("name=systemd"))
    if path is None:
        return None
    services = [part for part in path.split("/") if part.endswith(".service")]
    return services[-1] if services else None


def sshd_listeners(processes: list[Process]) -> list[Process]:
    """The running sshd listeners: an sshd whose parent is not one."""
    names = {proc.pid: proc.name for proc in processes}
    return [proc for proc in processes if proc.name == "sshd" and names.get(proc.ppid) != "sshd"]


def sshd_listener_units(processes: list[Process], proc_root: Path) -> tuple[list[str], list[str]]:
    """(units, problems): the systemd service each running sshd listener runs in."""
    units: list[str] = []
    problems: list[str] = []
    for proc in sshd_listeners(processes):
        try:
            text = (proc_root / str(proc.pid) / "cgroup").read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue
        except OSError:
            problems.append("an sshd listener's cgroup not read")
            continue
        unit = cgroup_unit(text)
        if unit is None:
            problems.append("an sshd listener runs in no systemd service")
            continue
        units.append(unit)
    return sorted(set(units)), sorted(set(problems))


def read_keys(section: dict, proc_root: Path, timeout: int, privileged: bool | None = None) -> KeyReading:
    reading = KeyReading()
    privileged = os.geteuid() == 0 if privileged is None else privileged
    paths, reading.path_problems = authorized_keys_paths(section["authorized_keys_files"], privileged)
    account_paths, accounts, account_problems, account_unread = login_account_files(section, timeout)
    reading.path_problems = sorted(set(reading.path_problems + account_problems))
    reading.unread += account_unread
    for path in account_paths + [p for p in paths if p not in account_paths]:
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

    units: list[str] = []
    for unit in section["sshd_units"]:
        units += ["-u", unit]
    argv = ["journalctl", "--no-pager", "-q", "-o", "short-unix"]
    since = section["journal_since_unix"]
    if since:
        argv += ["--since", f"@{since}"]
    try:
        reading.accepts = parse_accepts(read_output(argv + units, timeout))
    except CommandError:
        reading.unread.append("sshd journal")

    freeze = section["freeze_unix"]
    if freeze:
        # The sshd units' newest record at or before the freeze: none means their journal does not reach back to it.
        probe = ["journalctl", "--no-pager", "-q", "-o", "short-unix", "-r", "-n", "1", "--until", f"@{freeze}"]
        try:
            first = read_output(probe + units, timeout).split(None, 1)
            reading.journal_before_freeze = bool(first) and _unix_time(first[0]) is not None
        except CommandError:
            reading.unread.append("journal coverage")

    try:
        processes, complete = read_processes(proc_root)
    except OSError:
        processes, complete = [], False
    if not complete:
        reading.unread.append("processes")
    else:
        reading.sshd_listener_units, reading.sshd_source_problems = sshd_listener_units(processes, proc_root)
        reading.sshd_views, reading.sshd_view_problems, sshd_unread = read_sshd_views(
            section, accounts, sshd_listeners(processes), timeout
        )
        reading.unread += sshd_unread

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


def sshd_source_problems(reading: KeyReading, section: dict) -> list[str]:
    """Why keys.sshd_units cannot be taken as the journal sshd logs its accepts to."""
    if "processes" in reading.unread:
        return []
    units = section["sshd_units"]
    if not units:
        return ["no sshd units (keys.sshd_units)"]
    problems = list(reading.sshd_source_problems)
    if not reading.sshd_listener_units and not problems:
        problems.append("no sshd listener found, so keys.sshd_units is not shown to be sshd's journal")
    outside = [
        unit for unit in reading.sshd_listener_units if not any(fnmatch.fnmatchcase(unit, pattern) for pattern in units)
    ]
    if outside:
        problems.append(f"an sshd listener runs in {', '.join(outside)}, outside keys.sshd_units")
    return problems


def sshd_config_problems(reading: KeyReading, section: dict) -> list[str]:
    """Why sshd, as it runs for a rack login, is not the sshd this readback reads."""
    found: dict[str, list[str]] = {}
    declared = set(section["authorized_keys_file_patterns"])
    for view in reading.sshd_views:
        login = f"user={view.account},{view.connection}" + (f" with {' '.join(view.options)}" if view.options else "")
        settings = view.settings
        missing = [name for name in SSHD_SETTINGS if not settings.get(name)]
        if missing:
            found.setdefault(f"sshd -T printed no {', '.join(missing)}", []).append(login)
            continue
        level = settings["loglevel"][0].upper()
        if level not in ACCEPT_LOG_LEVELS:
            found.setdefault(f"sshd logs at LogLevel {level}, so an accepted key leaves no record", []).append(login)
        unlisted = [p for p in settings["authorizedkeysfile"] if p.lower() != "none" and p not in declared]
        if unlisted:
            text = f"sshd reads AuthorizedKeysFile {' '.join(unlisted)}, not in keys.authorized_keys_file_patterns"
            found.setdefault(text, []).append(login)
        for name, label in (("authorizedkeyscommand", "AuthorizedKeysCommand"), ("trustedusercakeys", "TrustedUserCAKeys")):
            if [word.lower() for word in settings[name]] != ["none"]:
                found.setdefault(f"sshd takes keys from {label}, which no authorized_keys file lists", []).append(login)
    problems = list(reading.sshd_view_problems)
    for text, logins in found.items():
        more = f" and {len(logins) - 1} more" if len(logins) > 1 else ""
        problems.append(f"{text} ({logins[0]}{more})")
    return problems


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
            "the sshd journal (keys.sshd_units) holds no record from before the freeze "
            "(rotated, volatile, or not readable by this user)"
        )
    problems += sshd_source_problems(reading, section)
    problems += sshd_config_problems(reading, section)
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
