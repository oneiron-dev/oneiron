"""The ownership rule the exporter writes into the deterministic tar.

mkosi runs in a single-uid user namespace, so its chown() calls are made
no-ops and the assembled tree is all root on disk. The exporter therefore
states every owner explicitly, from records rather than from the disk:

1. every path defaults to 0:0 with the tree's mode;
2. a path an installed package's data.tar ships with a non-root owner, or
   with a setuid/setgid bit, takes that owner (by name through the image's
   own /etc/passwd and /etc/group, else the numeric id) and keeps those bits;
3. a dpkg statoverride entry (var/lib/dpkg/statoverride) wins over 2;
4. an explicit packages.toml `owners` rule wins over 3: maintainer-script
   ownership dpkg does not record, and the guest user's own paths.

Ownership a maintainer script sets and no rule names stays root; the receipt
lists every non-root entry and its source so a gap is visible.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import stat
import tarfile
from pathlib import Path

from .util import BuildError, PinMismatch

SPECIAL_BITS = stat.S_ISUID | stat.S_ISGID


class OwnerError(BuildError):
    kind = "owner"


def _ids(path: Path) -> dict[str, int]:
    ids = {}
    if path.exists():
        for line in path.read_text().splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2].isdigit():
                ids[parts[0]] = int(parts[2])
    return ids


def installed(tree: Path) -> list[tuple[str, str, str]]:
    """(name, version, arch) for every package dpkg's status file says is installed."""
    status = tree / "var" / "lib" / "dpkg" / "status"
    packages = []
    for stanza in status.read_text().split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line and not line[0].isspace() and ":" in line:
                key, _, value = line.partition(":")
                fields[key] = value.strip()
        if fields.get("Status", "").endswith(" installed") and "Package" in fields:
            packages.append((fields["Package"], fields["Version"], fields["Architecture"]))
    return sorted(packages)


class _Window:
    """A read-only view of [start, start+size) of an open file (one ar member)."""

    def __init__(self, stream, start: int, size: int):
        self.stream, self.left = stream, size
        stream.seek(start)

    def read(self, n: int = -1) -> bytes:
        if self.left <= 0:
            return b""
        n = self.left if n < 0 or n > self.left else n
        data = self.stream.read(n)
        self.left -= len(data)
        return data


def _data_member(deb: Path):
    with open(deb, "rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            raise OwnerError(f"{deb.name} is not an ar archive")
        offset = 8
        while True:
            header = stream.read(60)
            if len(header) < 60:
                raise OwnerError(f"{deb.name} has no data.tar member")
            name = header[:16].decode().strip().rstrip("/")
            size = int(header[48:58].decode().strip())
            if name.startswith("data.tar"):
                return name, offset + 60, size
            offset += 60 + size + (size % 2)
            stream.seek(offset)


def deb_members(deb: Path, zstd_to_tar) -> list[tarfile.TarInfo]:
    """The data.tar entries of a .deb that carry a non-root owner or a set-id bit."""
    name, start, size = _data_member(deb)
    with open(deb, "rb") as stream:
        window = _Window(stream, start, size)
        if name.endswith(".zst"):
            raw = zstd_to_tar(deb, start, size)
            source = open(raw, "rb")
        elif name.endswith(".xz"):
            source = lzma.LZMAFile(window)
        elif name.endswith(".gz"):
            source = gzip.GzipFile(fileobj=window)
        elif name.endswith(".bz2"):
            source = bz2.BZ2File(window)
        elif name == "data.tar":
            source = window
        else:
            raise OwnerError(f"{deb.name}: unknown data member {name}")
        found = []
        with tarfile.open(fileobj=source, mode="r|") as tar:
            for info in tar:
                if info.uid or info.gid or (info.mode & SPECIAL_BITS) or info.uname not in ("", "root") \
                        or info.gname not in ("", "root"):
                    found.append(info)
        if hasattr(source, "close"):
            source.close()
    return found


def canonical(tree: Path, rel: str) -> str:
    """Resolves a merged-usr first component (bin -> usr/bin) the way dpkg's writes did."""
    rel = rel.removeprefix("./").rstrip("/")
    head, _, rest = rel.partition("/")
    link = tree / head
    if rest and link.is_symlink():
        target = os.readlink(link).lstrip("/")
        return f"{target}/{rest}"
    return rel


def resolve(tree: Path, packages: list[tuple[str, str, str]], deb_for, rules: list[dict], zstd_to_tar):
    """Returns {relpath: (uid, gid, mode_or_None, source)} for paths present in the tree."""
    users = _ids(tree / "etc" / "passwd")
    groups = _ids(tree / "etc" / "group")

    def uid_of(name: str, number: int, where: str) -> int:
        if name.startswith("#"):
            return int(name[1:])
        if name in ("", None):
            return number
        if name not in users:
            raise OwnerError(f"{where}: owner {name!r} is not in the image's /etc/passwd")
        return users[name]

    def gid_of(name: str, number: int, where: str) -> int:
        if name.startswith("#"):
            return int(name[1:])
        if name in ("", None):
            return number
        if name not in groups:
            raise OwnerError(f"{where}: group {name!r} is not in the image's /etc/group")
        return groups[name]

    owners: dict[str, tuple[int, int, int | None, str]] = {}
    for name, version, arch in packages:
        deb = deb_for(name, version, arch)
        if deb is None:
            raise PinMismatch(f"installed package {name} {version} {arch} has no locked .deb")
        for info in deb_members(deb, zstd_to_tar):
            rel = canonical(tree, info.name)
            if not rel or not os.path.lexists(tree / rel):
                continue
            where = f"{name}:{info.name}"
            uid = uid_of(info.uname, info.uid, where)
            gid = gid_of(info.gname, info.gid, where)
            bits = info.mode & SPECIAL_BITS
            mode = None
            if bits:
                mode = stat.S_IMODE(os.lstat(tree / rel).st_mode) | bits
            if uid or gid or mode is not None:
                owners[rel] = (uid, gid, mode, f"data.tar {name}")
    overrides = tree / "var" / "lib" / "dpkg" / "statoverride"
    if overrides.exists():
        for line in overrides.read_text().splitlines():
            parts = line.split(None, 3)
            if len(parts) != 4:
                continue
            user, group, mode, path = parts
            rel = canonical(tree, path.lstrip("/"))
            if os.path.lexists(tree / rel):
                owners[rel] = (uid_of(user, 0, path), gid_of(group, 0, path), int(mode, 8), "dpkg statoverride")
    for rule in rules:
        rel = canonical(tree, rule["path"].lstrip("/"))
        if not os.path.lexists(tree / rel):
            if rule.get("required", False):
                raise OwnerError(f"owners rule names {rule['path']}, which the image does not have")
            continue
        mode = int(rule["mode"], 8) if "mode" in rule else None
        owners[rel] = (uid_of(rule["user"], 0, rule["path"]), gid_of(rule["group"], 0, rule["path"]),
                       mode, f"packages.toml: {rule.get('why', 'owners rule')}")
    return owners
