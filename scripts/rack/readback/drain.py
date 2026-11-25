"""The drain readback (pass 34 15.1, gate B; row K1 part b), run at the box.

It reads, and changes nothing. A machine is drained when none of these is
left: a process of the fleet tool, an sshfs mount, a unit or timer of the
tool, an established ssh transport to a rack machine, an ssh control socket,
an ssh forward, or a file transfer program running (the audit's quiet-hour
inventory, lane-hosts-keys PLAN.md:78-82, and its `old-channels-drained` and
`other-rsync` checks). The tool's process and unit names, the mounts kept by
choice and the rack's addresses come from the configuration. A source that
cannot be read is no proof of absence: the readback then fails.

An ssh forward is found three ways, because a command line alone does not
show one: a forward flag or `-o` option in its argv; a forward directive in
the ssh configuration that process reads (its `-F` file, else its owner's
~/.ssh/config and the system file, with their Includes; any Host block
counts, unless its argv clears every forwarding); and a listening socket the
process holds (a local or dynamic forward, one added later through `-O
forward`, or a control master that can take one). Another user's ssh process
can be read only by root: a run that cannot read its sockets or its
configuration fails.
"""

from __future__ import annotations

import fnmatch
import glob
import ipaddress
import os
import pwd
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from rack.commands import CommandError, read_output
from rack.rack_config import expand

# ssh's forward flags, its flags that take a value, and its forward options.
FORWARD_FLAGS = frozenset("LRDWw")
SSH_FLAGS_WITH_VALUE = frozenset("BbcDEeFIiJLlmOoPpQRSWw")
FORWARD_OPTIONS = frozenset(("localforward", "remoteforward", "dynamicforward"))
SSH_PROGRAMS = ("ssh", "autossh")
LIVE_UNIT_STATES = ("active", "activating", "reloading", "deactivating", "refreshing")
# ssh's own bound on nested Includes (readconf.c READCONF_MAX_DEPTH).
INCLUDE_DEPTH = 16
# How `systemctl --user` finds the user's manager; no other variable reaches it.
USER_BUS_ENV = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
# The readback's sources whose absence leaves a forward unproven (forward-policy reads these).
FORWARD_SOURCES = ("processes", "ssh process sockets", "ssh configuration")
# /proc/<pid>/net/tcp state LISTEN, and a unix socket's __SO_ACCEPTCON flag.
TCP_LISTEN = "0A"
UNIX_ACCEPTCON = 0x10000
OPTION_WORDS = re.compile(r"^\s*([A-Za-z0-9]+)\s*(?:=\s*|\s+|$)(.*)$")


@dataclass
class Process:
    pid: int
    ppid: int
    argv: list[str]


@dataclass
class DrainReading:
    """What is still live on the box, by kind."""

    tool_processes: list[str] = field(default_factory=list)
    mounts: list[str] = field(default_factory=list)
    units: list[str] = field(default_factory=list)
    transports: list[str] = field(default_factory=list)
    control_sockets: list[str] = field(default_factory=list)
    forwards: list[str] = field(default_factory=list)
    transfers: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "tool processes": len(self.tool_processes),
            "sshfs mounts": len(self.mounts),
            "tool units": len(self.units),
            "ssh transports": len(self.transports),
            "ssh control sockets": len(self.control_sockets),
            "ssh forwards": len(self.forwards),
            "transfers": len(self.transfers),
            "sources not read": len(self.unread),
        }

    def not_read(self, source: str) -> None:
        if source not in self.unread:
            self.unread.append(source)

    def summary(self, kinds: tuple[str, ...] | None = None) -> str:
        parts = [
            f"{count} {name}"
            for name, count in self.counts().items()
            if count and (kinds is None or name in kinds)
        ]
        return ", ".join(parts)


def read_processes(proc_root: Path) -> list[Process]:
    """Every process whose command line can be read."""
    found = []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
            status = (entry / "status").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        argv = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
        if not argv:
            continue
        ppid = 0
        for line in status.splitlines():
            if line.startswith("PPid:"):
                ppid = int(line.split()[1])
                break
        found.append(Process(pid=int(entry.name), ppid=ppid, argv=argv))
    return found


def own_lineage(processes: list[Process], me: int) -> set[int]:
    """This process and its ancestors: the readback never counts itself."""
    parents = {p.pid: p.ppid for p in processes}
    lineage = {me}
    pid = me
    while pid in parents and parents[pid] not in lineage and parents[pid] > 1:
        pid = parents[pid]
        lineage.add(pid)
    return lineage


def option_words(text: str) -> tuple[str, str]:
    """(keyword in lower case, its argument) of `Key value` or `Key=value`; ("", "") for a blank or comment."""
    line = text.strip()
    if not line or line.startswith("#"):
        return "", ""
    match = OPTION_WORDS.match(line)
    if not match:
        return "", ""
    return match[1].lower(), match[2].strip()


def ssh_options(argv: list[str]) -> list[tuple[str, str]]:
    """The (flag, value) options of an ssh or autossh command line, read as ssh reads them.

    A cluster such as `-fNR` is three flags; a flag that takes a value takes
    the rest of its word or the next word. ssh reads options on both sides of
    the destination (ssh.c parses again after it), so scanning stops only at
    the word after the destination, which starts the remote command, or at
    `--`.
    """
    program = os.path.basename(argv[0])
    if program not in SSH_PROGRAMS:
        return []
    with_value = SSH_FLAGS_WITH_VALUE | ({"M"} if program == "autossh" else set())
    args = argv[1:]
    options: list[tuple[str, str]] = []
    destination = False
    index = 0
    while index < len(args):
        word = args[index]
        if word == "--":
            break
        if not word.startswith("-") or word == "-":
            if destination:
                break
            destination = True
            index += 1
            continue
        for position in range(1, len(word)):
            flag = word[position]
            if flag in with_value:
                rest = word[position + 1 :]
                if not rest:
                    index += 1
                    rest = args[index] if index < len(args) else ""
                options.append((flag, rest))
                break
            options.append((flag, ""))
        index += 1
    return options


def is_forward(argv: list[str]) -> bool:
    """Whether an ssh (or autossh) command line asks for a forward: a flag, or `-o LocalForward=...`."""
    for flag, value in ssh_options(argv):
        if flag in FORWARD_FLAGS:
            return True
        if flag == "o" and option_words(value)[0] in FORWARD_OPTIONS:
            return True
    return False


def clears_forwards(options: list[tuple[str, str]]) -> bool:
    """`-o ClearAllForwardings=yes` on the command line (its first value counts, as in ssh)."""
    for flag, value in options:
        if flag != "o":
            continue
        name, argument = option_words(value)
        if name == "clearallforwardings":
            return argument.lower() == "yes"
    return False


class SshConfigUnread(Exception):
    """An ssh configuration file (or an Include) that exists but cannot be read."""


def forward_in_ssh_config(path: Path, user_conf: bool, home: Path, system_dir: Path, depth: int = 0) -> Path | None:
    """The file, `path` or one it Includes, that names a forward; None when none does.

    A relative Include is under the owner's ~/.ssh for a user file (and a -F
    file) and under the system file's directory otherwise, as in ssh.
    """
    if depth > INCLUDE_DEPTH:
        raise SshConfigUnread(f"Includes nested past {INCLUDE_DEPTH}")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None
    except OSError:
        raise SshConfigUnread(str(path)) from None
    for raw in text.splitlines():
        name, argument = option_words(raw)
        if name in FORWARD_OPTIONS:
            return path
        if name != "include":
            continue
        for word in argument.split():
            word = word.strip('"')
            if word.startswith("~/"):
                pattern = home / word[2:]
            elif os.path.isabs(word):
                pattern = Path(word)
            else:
                pattern = (home / ".ssh" if user_conf else system_dir) / word
            parent = pattern.parent
            if parent.exists() and not os.access(parent, os.R_OK | os.X_OK):
                raise SshConfigUnread(str(parent))
            for match in sorted(glob.glob(str(pattern))):
                found = forward_in_ssh_config(Path(match), user_conf, home, system_dir, depth + 1)
                if found is not None:
                    return found
    return None


def owner_home(pid_dir: Path) -> Path:
    """The home of the process's owner: $HOME for this user, else the password database."""
    uid = os.stat(pid_dir).st_uid
    if uid == os.getuid():
        return expand("~")
    try:
        return Path(pwd.getpwuid(uid).pw_dir)
    except KeyError:
        raise SshConfigUnread(f"no home for uid {uid}") from None


def config_forward(pid_dir: Path, options: list[tuple[str, str]], system_config: Path) -> Path | None:
    """The configuration file that gives this ssh process a forward, if any."""
    if clears_forwards(options):
        return None
    try:
        home = owner_home(pid_dir)
        named = [value for flag, value in options if flag == "F"]
        if named:
            config = named[-1]
            if config == "none":
                return None
            path = Path(config)
            if not path.is_absolute():
                path = Path(os.readlink(pid_dir / "cwd")) / path
            files = [(path, True)]
        else:
            files = [(home / ".ssh" / "config", True), (system_config, False)]
    except FileNotFoundError:
        raise
    except OSError:
        raise SshConfigUnread(str(pid_dir)) from None
    for path, user_conf in files:
        found = forward_in_ssh_config(path, user_conf, home, system_config.parent)
        if found is not None:
            return found
    return None


def socket_inodes(pid_dir: Path) -> set[int]:
    """The socket inodes the process holds open (OSError when its fds cannot be read)."""
    inodes = set()
    fd_dir = pid_dir / "fd"
    for name in os.listdir(fd_dir):
        try:
            target = os.readlink(fd_dir / name)
        except FileNotFoundError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(int(target[len("socket:[") : -1]))
    return inodes


def listening_inodes(pid_dir: Path) -> set[int]:
    """Inodes of the listening TCP and unix sockets in the process's network namespace."""
    found = set()
    for table in ("tcp", "tcp6"):
        try:
            lines = (pid_dir / "net" / table).read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        for line in lines[1:]:
            cols = line.split()
            if len(cols) > 9 and cols[3] == TCP_LISTEN:
                found.add(int(cols[9]))
    for line in (pid_dir / "net" / "unix").read_text(encoding="utf-8").splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 7 and int(cols[3], 16) & UNIX_ACCEPTCON:
            found.add(int(cols[6]))
    return found


def user_bus_env() -> dict[str, str]:
    """The caller's user bus variables, which `systemctl --user` needs to reach its manager."""
    return {name: os.environ[name] for name in USER_BUS_ENV if os.environ.get(name)}


def parse_peer(column: str) -> str:
    """The address part of an `ss` peer column (`addr:port`, `[v6]:port`)."""
    host = column.rsplit(":", 1)[0]
    host = host.strip("[]").split("%", 1)[0]
    # A v4 peer of a dual-stack socket reads ::ffff:a.b.c.d; sshd logs a.b.c.d.
    if host.lower().startswith("::ffff:") and "." in host:
        host = host[len("::ffff:") :]
    return host


def in_rack(address: str, rack: list[str]) -> bool:
    if not rack:
        return True
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address in rack
    for entry in rack:
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def ssh_forward(pid_dir: Path, argv: list[str], system_config: Path, reading: DrainReading) -> str:
    """Why this ssh process is a forward ("" when it is none); a source it cannot read goes to `unread`.

    A process that ended since /proc was listed (its entry is gone) is no forward.
    """
    if is_forward(argv):
        return "a forward on its command line"
    try:
        held = socket_inodes(pid_dir)
        if held and held & listening_inodes(pid_dir):
            return "a listening socket: a forward or a control master"
    except FileNotFoundError:
        return ""
    except (OSError, ValueError):
        reading.not_read("ssh process sockets")
    try:
        if config_forward(pid_dir, ssh_options(argv), system_config) is not None:
            return "a forward in its ssh configuration"
    except FileNotFoundError:
        return ""
    except SshConfigUnread:
        reading.not_read("ssh configuration")
    return ""


def read_drain(section: dict, timeout: int, me: int | None = None) -> DrainReading:
    """What of the old channels is still live on this box."""
    reading = DrainReading()
    me = os.getpid() if me is None else me

    proc_root = expand(section["proc_root"])
    try:
        processes = read_processes(proc_root)
    except OSError:
        processes = []
        reading.not_read("processes")
    lineage = own_lineage(processes, me)
    patterns = section["tool_process_patterns"]
    transfer_programs = set(section["transfer_programs"])
    system_config = expand(section["ssh_system_config"])
    for proc in processes:
        if proc.pid in lineage:
            continue
        line = " ".join(proc.argv)
        if any(pattern and pattern in line for pattern in patterns):
            reading.tool_processes.append(line)
        if os.path.basename(proc.argv[0]) in SSH_PROGRAMS:
            forward = ssh_forward(proc_root / str(proc.pid), proc.argv, system_config, reading)
            if forward:
                reading.forwards.append(f"{line} ({forward})")
        if os.path.basename(proc.argv[0]) in transfer_programs:
            reading.transfers.append(line)

    try:
        out = read_output(["findmnt", "-rn", "-t", "fuse.sshfs", "-o", "TARGET"], timeout, ok_codes=(0, 1))
        ignored = set(section["ignore_mounts"])
        reading.mounts = [m for m in out.split() if m and m not in ignored]
    except CommandError:
        reading.not_read("mounts")

    try:
        out = read_output(
            ["systemctl", "--user", "list-units", "--all", "--plain", "--no-legend", "--no-pager"],
            timeout,
            extra_env=user_bus_env(),
        )
        for line in out.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            unit, active = cols[0], cols[2]
            if active not in LIVE_UNIT_STATES:
                continue
            if any(fnmatch.fnmatch(unit, pattern) for pattern in section["tool_unit_patterns"]):
                reading.units.append(unit)
    except CommandError:
        reading.not_read("units")

    try:
        out = read_output(["ss", "-tnH", "state", "established", "( dport = :22 )"], timeout)
        for line in out.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            peer = parse_peer(cols[3])
            if in_rack(peer, section["rack_addresses"]):
                reading.transports.append(cols[3])
    except CommandError:
        reading.not_read("transports")

    for pattern in section["control_socket_globs"]:
        for name in glob.glob(str(expand(pattern))):
            try:
                if stat.S_ISSOCK(os.lstat(name).st_mode):
                    reading.control_sockets.append(name)
            except OSError:
                continue
    return reading
