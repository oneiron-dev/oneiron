"""The drain readback (pass 34 15.1, gate B; row K1 part b), run at the box.

It reads, and changes nothing. A machine is drained when none of these is
left: a process of the fleet tool, an sshfs mount, a unit or timer of the
tool, an established ssh transport to a rack machine, an ssh control socket,
an ssh forward, or a file transfer program running (the audit's quiet-hour
inventory, lane-hosts-keys PLAN.md:78-82, and its `old-channels-drained` and
`other-rsync` checks). The tool's process and unit names, the mounts kept by
choice and the rack's addresses come from the configuration. A source that
cannot be read is no proof of absence: the readback then fails.
"""

from __future__ import annotations

import fnmatch
import glob
import ipaddress
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from rack.commands import CommandError, read_output
from rack.rack_config import expand

# ssh's forward flags, its flags that take a value, and its forward options.
FORWARD_FLAGS = frozenset("LRDWw")
SSH_FLAGS_WITH_VALUE = frozenset("BbcDEeFIiJLlmOoPpQRSWw")
FORWARD_OPTIONS = frozenset(("localforward", "remoteforward", "dynamicforward"))
LIVE_UNIT_STATES = ("active", "activating", "reloading", "deactivating", "refreshing")


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


def is_forward(argv: list[str]) -> bool:
    """Whether an ssh (or autossh) command line asks for a forward.

    It reads the options as ssh's getopt does: a cluster such as `-fNR` is
    three flags, a flag that takes a value takes the rest of its word or the
    next word, and `-o LocalForward=...` is a forward too. Scanning stops at
    the destination.
    """
    program = os.path.basename(argv[0])
    if program not in ("ssh", "autossh"):
        return False
    with_value = SSH_FLAGS_WITH_VALUE | ({"M"} if program == "autossh" else set())
    args = argv[1:]
    index = 0
    while index < len(args):
        word = args[index]
        if word == "--" or not word.startswith("-") or word == "-":
            return False
        for position in range(1, len(word)):
            flag = word[position]
            if flag in FORWARD_FLAGS:
                return True
            if flag in with_value:
                rest = word[position + 1 :]
                if not rest:
                    index += 1
                    rest = args[index] if index < len(args) else ""
                if flag == "o":
                    name = rest.split("=", 1)[0].split()
                    if name and name[0].lower() in FORWARD_OPTIONS:
                        return True
                break
        index += 1
    return False


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


def read_drain(section: dict, timeout: int, me: int | None = None) -> DrainReading:
    """What of the old channels is still live on this box."""
    reading = DrainReading()
    me = os.getpid() if me is None else me

    proc_root = expand(section["proc_root"])
    try:
        processes = read_processes(proc_root)
    except OSError:
        processes = []
        reading.unread.append("processes")
    lineage = own_lineage(processes, me)
    patterns = section["tool_process_patterns"]
    transfer_programs = set(section["transfer_programs"])
    for proc in processes:
        if proc.pid in lineage:
            continue
        line = " ".join(proc.argv)
        if any(pattern and pattern in line for pattern in patterns):
            reading.tool_processes.append(line)
        if is_forward(proc.argv):
            reading.forwards.append(line)
        if os.path.basename(proc.argv[0]) in transfer_programs:
            reading.transfers.append(line)

    try:
        out = read_output(["findmnt", "-rn", "-t", "fuse.sshfs", "-o", "TARGET"], timeout, ok_codes=(0, 1))
        ignored = set(section["ignore_mounts"])
        reading.mounts = [m for m in out.split() if m and m not in ignored]
    except CommandError:
        reading.unread.append("mounts")

    try:
        out = read_output(
            ["systemctl", "--user", "list-units", "--all", "--plain", "--no-legend", "--no-pager"],
            timeout,
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
        reading.unread.append("units")

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
        reading.unread.append("transports")

    for pattern in section["control_socket_globs"]:
        for name in glob.glob(str(expand(pattern))):
            try:
                if stat.S_ISSOCK(os.lstat(name).st_mode):
                    reading.control_sockets.append(name)
            except OSError:
                continue
    return reading
