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
`-f` (absolute) and `-o` options, for root and every login account, and from
every rack machine's connection (`keys.rack_connections`, as this box's sshd
sees it: `sshd -T -C` applies only the Match blocks whose fields the test
names), `sshd -T` must log an accepted key (LogLevel INFO or more), read no
AuthorizedKeysFile outside `keys.authorized_keys_file_patterns` (a run of
words of that line is read too, since a pattern holding a space prints as
words), take keys from no AuthorizedKeysCommand but one of
`keys.authorized_keys_commands` run as root (the readback runs it for each
account as sshd does: only when the program and every directory above it
are root's alone, from /, with PATH and root's USER, LOGNAME and HOME; its
answer counts as an authorized_keys file), and trust no TrustedUserCAKeys
authority. After those reads, `sshd -T -dd` names the files sshd reads:
none of them, their directories, the Include directories or a symbolic link
on the way to any of them may have changed after the listener started (a
reload re-executes it in place, keeping its start), since sshd -T reads
what it would load now. A listener that started after the freeze is no
proof: the one it replaced may have logged nothing. The program run is
`keys.sshd_program`, never a path read from a process, and a reason names a
listener by its pid, never by its option values. An authorized_keys file is
opened without blocking and read only when it is a regular file.

No proof: no rack connection or one sshd's test cannot take; a listener
whose title hides where its arguments end (only flags are read back from
one, and a title holding `[listener]` before sshd's own suffix is not read),
or whose command line has -q, -e, -E, -d, a relative -f, an operand or an
option sshd's listener does not take; a configuration file sshd does not
name, or names by a relative path; an sshd that does not print its settings
(a run that is not root).
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import glob
import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from rack.commands import CommandError, read_output, read_streams
from rack.rack_config import expand
from rack.readback.drain import Process, argv_split, parse_peer, read_processes

KEY_TYPES = re.compile(r"^(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-\S+|sk-\S+@openssh\.com)$")
ACCEPTED = re.compile(
    r"Accepted publickey for (?P<user>\S+) from (?P<addr>\S+) port (?P<port>\d+) \S+: \S+ (?P<fp>SHA256:\S+)"
)

# The `sshd -T` keywords the readback judges (sshd prints each, lower case, then its value).
SSHD_SETTINGS = (
    "loglevel",
    "authorizedkeysfile",
    "authorizedkeyscommand",
    "authorizedkeyscommanduser",
    "trustedusercakeys",
)
# sshd logs an accepted key at INFO (auth.c auth_log): these levels keep that line.
ACCEPT_LOG_LEVELS = frozenset({"INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"})
# The fields of sshd's connection test besides user= (sshd.c parse_server_match_testspec).
CONNECTION_FIELDS = ("addr", "host", "laddr", "lport", "rdomain")
# A field value or an account name in that test: no comma, `=` or space, which would add or end a field.
TEST_WORD = re.compile(r"^[A-Za-z0-9._:%\[\]-]+$")
ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*\$?$")
# A listener's command line, read as sshd.c's getopt reads it: -f (an absolute path) and -o are
# replayed to `sshd -T`; these options and flags change neither what -T prints nor where sshd
# logs. Every other letter is refused: -q, -e, -E and -d quiet sshd's log or move it off the
# journal, and the rest (-i, -t, -T, -G, -V, -r, -R, -Q, -C) are not a listener's.
SSHD_REPLAYED = frozenset("fo")
SSHD_KEPT_OPTIONS = frozenset("bcghkpu")
SSHD_KEPT_FLAGS = frozenset("46D")
# `sshd -T -dd` names each configuration file it reads and each Include pattern (servconf.c).
LOADED_FILE = re.compile(r"^debug2: load_server_config: filename (?P<path>.+)$")
NEW_INCLUDE = re.compile(r"^debug2: .* line \d+: new include (?P<pattern>.+)$")
GLOB_CHARS = frozenset("*?[")
# The title sshd gives a listener (sshd.c): its argv joined by spaces, then this suffix.
LISTENER_TITLE = re.compile(r"^sshd: (?P<argv>.+) \[listener\] \d+ of \d+-\d+ startups$")
# The environment sshd gives an AuthorizedKeysCommand (misc.c subprocess): _PATH_STDPATH and the
# run-as user's USER, LOGNAME and HOME; it is run from /.
COMMAND_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


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
    """sshd's settings for one rack login: `sshd -T <listener options> -C user=<account>,<connection>`."""

    account: str
    connection: str
    # The listener (its pid) whose -f and -o options were replayed.
    listener: int
    options: tuple[str, ...]
    # keyword -> its value as sshd printed it.
    settings: dict[str, str]


@dataclass
class SshdReading:
    """What the sshd probes read: the views, why a probe gave no proof, and the further key sources."""

    views: list[SshdView] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)
    # Files an AuthorizedKeysFile line can name beyond its words (a pattern holding a space).
    files: list[Path] = field(default_factory=list)
    # The keys each allowed AuthorizedKeysCommand answers for an account, by label.
    command_keys: dict[str, list[AuthorizedKey]] = field(default_factory=dict)


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
    path = Path(percent_expand(pattern, account, "AuthorizedKeysFile"))
    return path if path.is_absolute() else account.home / path


def percent_expand(text: str, account: Account, where: str) -> str:
    """sshd's %h (home), %u (name), %U (uid) and %% in `text`; ValueError for any other token."""
    tokens = {"h": str(account.home), "u": account.name, "U": str(account.uid), "%": "%"}
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "%":
            out.append(char)
            index += 1
            continue
        token = text[index + 1 : index + 2]
        if token not in tokens:
            raise ValueError(f"{where} token %{token}")
        out.append(tokens[token])
        index += 2
    return "".join(out)


def login_account_files(section: dict, timeout: int) -> tuple[list[Path], list[Account], list[str], list[str]]:
    """(files, accounts, problems, unread) for root and every rack login account, as sshd names their files.

    `accounts` are those the password database knows.
    """
    files: list[Path] = []
    accounts: list[Account] = []
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
        accounts.append(account)
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


def parse_sshd_settings(text: str) -> dict[str, str]:
    """The judged keywords of `sshd -T` output: keyword -> its value as printed."""
    settings: dict[str, str] = {}
    for line in text.splitlines():
        keyword, _, value = line.partition(" ")
        if keyword in SSHD_SETTINGS:
            settings.setdefault(keyword, value)
    return settings


def sshd_test_options(words: list[str]) -> tuple[list[str], str]:
    """(the -f and -o options to replay, why the command line cannot be replayed: "" when it can).

    sshd takes no operand, so a word that is neither an option nor its argument means the line is not known.
    """
    options: list[str] = []
    index = 1
    while index < len(words):
        word = words[index]
        if word == "--":
            return (options, "") if index == len(words) - 1 else ([], "an operand")
        if not word.startswith("-") or word == "-":
            return [], "an operand"
        for at, letter in enumerate(word[1:], start=1):
            if letter in SSHD_KEPT_FLAGS:
                continue
            if letter not in SSHD_REPLAYED and letter not in SSHD_KEPT_OPTIONS:
                return [], f"-{letter}"
            value = word[at + 1 :]
            if not value:
                index += 1
                if index == len(words):
                    return [], f"-{letter} with no argument"
                value = words[index]
            if letter == "f" and not value.startswith("/"):
                return [], "a relative -f"
            if letter in SSHD_REPLAYED:
                options += [f"-{letter}", value]
            break
        index += 1
    return options, ""


def listener_options(proc: Process) -> tuple[list[str], str]:
    """A listener's -f and -o options, and why they cannot be known ("" when they can).

    sshd retitles a listener `sshd: <argv joined by spaces> [listener] N of B-M startups`, which
    loses where an argument ends: from a title only flags that take no argument are read back,
    and a title whose argv holds the marker itself is not read at all.
    """
    if len(proc.argv) == 1 and proc.argv[0].startswith("sshd: "):
        title = LISTENER_TITLE.match(proc.argv[0])
        words = title["argv"].split() if title else []
        flags_only = all(
            word.startswith("-") and len(word) > 1 and set(word[1:]) <= SSHD_KEPT_FLAGS for word in words[1:]
        )
        if not title or "[listener]" in title["argv"] or not words or not flags_only:
            return [], "its title hides where its arguments end"
        return [], ""
    return sshd_test_options(proc.argv)


def configuration_paths(stderr: str) -> tuple[list[Path], str]:
    """The files `sshd -T -dd` read, their directories and its Include directories; why not, "" when known."""
    paths: list[Path] = []
    loaded = False
    for line in stderr.splitlines():
        found = LOADED_FILE.match(line)
        if found:
            path = Path(found["path"])
            if not path.is_absolute():
                return [], "sshd read a configuration file by a relative path"
            loaded = True
            paths += [p for p in (path, path.parent) if p not in paths]
            continue
        found = NEW_INCLUDE.match(line)
        if found:
            pattern = Path(found["pattern"])
            if not pattern.is_absolute():
                return [], "an Include sshd names by a relative path"
            if any(GLOB_CHARS & set(part) for part in pattern.parts[:-1]):
                return [], "an Include whose directory is a pattern"
            if pattern.parent not in paths:
                paths.append(pattern.parent)
    if not loaded:
        return [], "sshd -T named no configuration file it read"
    return paths, ""


def process_started(proc_root: Path, pid: int) -> float | None:
    """A process's start (unix seconds): /proc/<pid>/stat starttime after boot (/proc/stat btime)."""
    try:
        fields = (proc_root / str(pid) / "stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
        table = (proc_root / "stat").read_text(encoding="utf-8").splitlines()
        boot = [line.split()[1] for line in table if line.startswith("btime ")]
        return int(boot[0]) + int(fields[19]) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return None


def lookup_chain(path: Path) -> list[tuple[Path, bool]]:
    """Each entry the kernel reads to resolve absolute `path`, in order, with whether it is a symbolic
    link; the last is the file reached. OSError when an entry is missing or links nest past 40."""
    chain: list[tuple[Path, bool]] = []
    pending = list(path.parts[1:])
    current = Path("/")
    hops = 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            current = current.parent
            continue
        entry = current / part
        if stat.S_ISLNK(os.lstat(entry).st_mode):
            chain.append((entry, True))
            hops += 1
            if hops > 40:
                raise OSError("symbolic links nest past 40")
            target = Path(os.readlink(entry))
            if target.is_absolute():
                current = Path("/")
                pending = list(target.parts[1:]) + pending
            else:
                pending = list(target.parts) + pending
            continue
        chain.append((entry, False))
        current = entry
    return chain


def listener_problems(proc_root: Path, pid: int, paths: list[Path], freeze: int) -> list[str]:
    """Why listener `pid` may not have run, since the freeze, the configuration sshd -T read.

    A listener loads its configuration when it starts (a reload re-executes it in place, keeping
    its start). A configuration file, its directory or an Include directory changed after that
    start may not be in force. Each is followed as the kernel resolves it, and every symbolic
    link on the way counts too, since re-pointing a link changes the link and not the files it
    leads to. A listener that started after the freeze replaced one whose logging is not known,
    so a login before it may have left no record.
    """
    started = process_started(proc_root, pid)
    if started is None:
        return [f"the start of sshd listener {pid} is not read"]
    problems = []
    if freeze and started > freeze:
        problems.append(f"sshd listener {pid} started after the freeze, so how sshd logged before it is not known")
    for path in paths:
        try:
            chain = lookup_chain(path)
            reached = chain[-1][0]
            checked = [entry for entry, is_link in chain if is_link] + [reached, reached.parent]
            changed = max(max(os.lstat(entry).st_ctime, os.lstat(entry).st_mtime) for entry in checked)
        except (OSError, IndexError):
            problems.append(f"a configuration path of sshd listener {pid} cannot be resolved")
            break
        if changed > started:
            problems.append(
                f"sshd listener {pid} started before its configuration last changed, so it may not run it (restart sshd)"
            )
            break
    return problems


def unsafe_program(path: str) -> bool:
    """Whether sshd would refuse to run `path` (auth_secure_path): the file and every directory up to /
    must be owned by root and writable by no group or other user. A run that is not root also takes
    its own user as owner; such a run is no proof anyway, since sshd -T needs root."""
    owners = {0, os.geteuid()}
    try:
        real = Path(os.path.realpath(path))
        if not stat.S_ISREG(real.stat().st_mode):
            return True
        for part in (real, *real.parents):
            info = part.stat()
            if info.st_uid not in owners or info.st_mode & 0o022:
                return True
    except OSError:
        return True
    return False


def spanned_files(value: str, account: Account) -> list[Path]:
    """The files an AuthorizedKeysFile line can name beyond its words.

    sshd prints the list joined by single spaces, so a pattern that holds a space prints as several
    words: every run of two or more of them is read too.
    """
    words = value.split(" ")
    files: list[Path] = []
    for first in range(len(words)):
        for last in range(first + 2, len(words) + 1):
            try:
                path = expand_authorized_keys_file(" ".join(words[first:last]), account)
            except ValueError:
                continue
            if path is not None and path not in files:
                files.append(path)
    return files


def command_argv(command: str, account: Account) -> list[str] | None:
    """The argv sshd runs for an AuthorizedKeysCommand (auth2-pubkey.c), or None when it cannot be built.

    The command is split as argv_split splits it, and each argument's %u %U %h %% is filled; with no
    argument sshd passes the account's name. None for any other token (they need the offered key) or
    for a program that is not an absolute path.
    """
    if "#" in command:
        # sshd splits the command with no comment rule; the splitter here ends a line at one.
        return None
    try:
        words = argv_split(command)
        argv = [percent_expand(word, account, "AuthorizedKeysCommand") for word in words[1:]]
    except ValueError:
        return None
    if not words or not words[0].startswith("/"):
        return None
    return [words[0], *(argv or [account.name])]


def read_sshd(
    section: dict, accounts: list[Account], listeners: list[Process], proc_root: Path, timeout: int
) -> SshdReading:
    """sshd's settings for each listener's options, account and rack connection, and the key sources they name.

    The files the configuration is read from are named and checked after every settings probe, so
    a change during the probes is a change after the listener started and fails.
    """
    out = SshdReading(problems=rack_connection_problems(section["rack_connections"]))
    if out.problems:
        return out
    program = section["sshd_program"]
    option_sets: dict[tuple[str, ...], list[int]] = {}
    for proc in listeners:
        options, why = listener_options(proc)
        if why:
            out.problems.append(f"sshd listener {proc.pid}: {why}, so the settings it runs are not known")
            continue
        option_sets.setdefault(tuple(options), []).append(proc.pid)
    allowed = section["authorized_keys_commands"]
    root = next((account for account in accounts if account.name == "root"), None)
    for account in accounts:
        if not ACCOUNT_NAME.match(account.name):
            out.problems.append("a login account name sshd's connection test cannot carry (keys.login_accounts)")
            continue
        for options, pids in option_sets.items():
            for connection in section["rack_connections"]:
                argv = [program, "-T", *options, "-C", f"user={account.name},{connection}"]
                try:
                    settings = parse_sshd_settings(read_output(argv, timeout))
                except CommandError:
                    out.unread.append("sshd effective configuration")
                    return out
                out.views.append(SshdView(account.name, connection, pids[0], options, settings))
                out.files += [f for f in spanned_files(settings.get("authorizedkeysfile", ""), account) if f not in out.files]
                command = settings.get("authorizedkeyscommand", "").strip()
                if command in allowed and settings.get("authorizedkeyscommanduser", "").strip() == "root":
                    label = f"AuthorizedKeysCommand {allowed.index(command) + 1} for {account.name}"
                    if label not in out.command_keys:
                        read_command_keys(out, label, command, account, root, timeout)
    for options, pids in option_sets.items():
        try:
            _, stderr = read_streams([program, "-T", "-dd", *options], timeout)
        except CommandError:
            out.unread.append("sshd effective configuration")
            return out
        paths, why = configuration_paths(stderr)
        if why:
            out.problems.append(f"sshd listener {pids[0]}: {why}")
            continue
        for pid in pids:
            out.problems += listener_problems(proc_root, pid, paths, section["freeze_unix"])
    out.problems = sorted(set(out.problems))
    out.unread = sorted(set(out.unread))
    return out


def read_command_keys(
    out: SshdReading, label: str, command: str, account: Account, root: Account | None, timeout: int
) -> None:
    """Run one allowed AuthorizedKeysCommand for `account` as sshd runs it, and keep its keys under `label`."""
    run = command_argv(command, account)
    if run is None:
        out.problems.append("an allowed AuthorizedKeysCommand needs the offered key, so its keys cannot be listed")
        return
    if unsafe_program(run[0]):
        out.problems.append(
            "an allowed AuthorizedKeysCommand program is not root's alone (owner, or a group or other "
            "user that can write it or a directory above it), so sshd refuses it and the readback does not run it"
        )
        return
    if root is None:
        out.unread.append("an AuthorizedKeysCommand")
        return
    env = {"PATH": COMMAND_PATH, "USER": "root", "LOGNAME": "root", "HOME": str(root.home)}
    try:
        out.command_keys[label] = parse_authorized_keys(read_output(run, timeout, env=env, cwd="/"))
    except CommandError:
        out.unread.append("an AuthorizedKeysCommand")


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


def read_authorized_file(reading: KeyReading, path: Path) -> None:
    """One authorized_keys file into `reading`: its keys, none when it does not exist, or unread.

    It is opened without blocking and read only when it is a regular file, so a FIFO or a device
    on a guessed path cannot hold the readback.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
    except FileNotFoundError:
        reading.authorized[str(path)] = []
        return
    except OSError:
        reading.unread_files.append(str(path))
        return
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            reading.unread_files.append(str(path))
            return
        with os.fdopen(fd, "rb", closefd=False) as handle:
            text = handle.read().decode("utf-8", errors="replace")
    except OSError:
        reading.unread_files.append(str(path))
        return
    finally:
        os.close(fd)
    reading.authorized[str(path)] = parse_authorized_keys(text)


def read_keys(section: dict, proc_root: Path, timeout: int, privileged: bool | None = None) -> KeyReading:
    reading = KeyReading()
    privileged = os.geteuid() == 0 if privileged is None else privileged
    paths, reading.path_problems = authorized_keys_paths(section["authorized_keys_files"], privileged)
    account_paths, accounts, account_problems, account_unread = login_account_files(section, timeout)
    reading.path_problems = sorted(set(reading.path_problems + account_problems))
    reading.unread += account_unread
    for path in account_paths + [p for p in paths if p not in account_paths]:
        read_authorized_file(reading, path)

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
        sshd = read_sshd(section, accounts, sshd_listeners(processes), proc_root, timeout)
        reading.sshd_views, reading.sshd_view_problems = sshd.views, sshd.problems
        reading.unread += sshd.unread
        for path in sshd.files:
            if str(path) not in reading.authorized and str(path) not in reading.unread_files:
                read_authorized_file(reading, path)
        reading.authorized.update(sshd.command_keys)

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
    """Why sshd, as it runs for a rack login, is not the sshd this readback reads.

    A login is named by its account, its connection and the listener's pid, never by the
    listener's option values (an -o value can carry a secret).
    """
    found: dict[str, list[str]] = {}
    declared = set(section["authorized_keys_file_patterns"])
    allowed = section["authorized_keys_commands"]
    for view in reading.sshd_views:
        login = f"user={view.account},{view.connection} at sshd listener {view.listener}"
        settings = view.settings
        missing = [name for name in SSHD_SETTINGS if not settings.get(name, "").strip()]
        if missing:
            found.setdefault(f"sshd -T printed no {', '.join(missing)}", []).append(login)
            continue
        level = settings["loglevel"].split()[0].upper()
        if level not in ACCEPT_LOG_LEVELS:
            found.setdefault(f"sshd logs at LogLevel {level}, so an accepted key leaves no record", []).append(login)
        unlisted = [p for p in settings["authorizedkeysfile"].split(" ") if p and p.lower() != "none" and p not in declared]
        if unlisted:
            text = f"sshd reads AuthorizedKeysFile {' '.join(unlisted)}, not in keys.authorized_keys_file_patterns"
            found.setdefault(text, []).append(login)
        command = settings["authorizedkeyscommand"].strip()
        if command.lower() != "none":
            if command not in allowed:
                text = "sshd takes keys from an AuthorizedKeysCommand not in keys.authorized_keys_commands"
                found.setdefault(text, []).append(login)
            elif settings["authorizedkeyscommanduser"].strip() != "root":
                text = "sshd runs its AuthorizedKeysCommand as a user other than root, whose answer the readback does not read"
                found.setdefault(text, []).append(login)
        if settings["trustedusercakeys"].strip().lower() != "none":
            text = "sshd takes keys certified by TrustedUserCAKeys, which no authorized_keys file lists"
            found.setdefault(text, []).append(login)
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
