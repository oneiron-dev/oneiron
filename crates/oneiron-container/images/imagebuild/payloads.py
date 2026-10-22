"""Installing the pinned downloads that are not one plain file: a member of a
zip archive, an npm package tarball, and the two-line launchers that run a
pinned entry file under a pinned runtime. Everything is staged in the plan
directory; mkosi.postinst places it. Nothing here reaches the network: each
input is a mirror blob its fetch already checked.

An npm package is unpacked without npm and without its lifecycle scripts:
`package/package.json` must name the pinned package and version, the
`package/` prefix goes, and only regular files and directories are taken
(a link, an absolute path or a `..` member refuses the payload). Modes are
normalized (NPM_MODES); times come from the build epoch at export.
"""

from __future__ import annotations

import json
import shutil
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from .util import PinMismatch, StepFailed

# Directory, data file, and a file the tarball marks executable (the native
# tsrs binary, the JS entry stubs).
NPM_MODES = (0o755, 0o644, 0o555)
# A launcher's whole content: the pinned runtime on the pinned entry, every
# argument passed through and the exit status kept (exec).
LAUNCHER = '#!/bin/sh\nexec {runtime} {entry} "$@"\n'


def archive_member(archive: Path, member: str, out: Path, *, what: str) -> Path:
    """The one declared regular member of a zip archive, written to out."""
    with zipfile.ZipFile(archive) as zf:
        try:
            info = zf.getinfo(member)
        except KeyError:
            raise PinMismatch(f"{what}: the archive has no member {member!r}") from None
        if info.is_dir() or (info.external_attr >> 16) & 0o170000 not in (0, 0o100000):
            raise PinMismatch(f"{what}: {member!r} is not a regular file")
        with zf.open(info) as src, open(out, "wb") as dst:
            shutil.copyfileobj(src, dst)
    return out


def npm_package(tarball: Path, dest: Path, *, package: str, version: str, what: str) -> Path:
    """Unpacks an npm tarball's package/ into dest, checked against its pin."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    dir_mode, file_mode, exec_mode = NPM_MODES
    seen_manifest = False
    with tarfile.open(tarball, "r:gz") as tar:
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if member.name.startswith("/") or ".." in parts or not parts or parts[0] != "package":
                raise StepFailed(f"{what}: member {member.name!r} is outside package/")
            rel = PurePosixPath(*parts[1:]) if len(parts) > 1 else None
            if member.isdir():
                if rel is not None:
                    (dest / rel).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isreg() or rel is None:
                raise StepFailed(f"{what}: member {member.name!r} is not a regular file")
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            target.chmod(exec_mode if member.mode & 0o111 else file_mode)
            seen_manifest |= str(rel) == "package.json"
    if not seen_manifest:
        raise PinMismatch(f"{what}: the tarball has no package/package.json")
    manifest = json.loads((dest / "package.json").read_text())
    if manifest.get("name") != package or manifest.get("version") != version:
        raise PinMismatch(f"{what}: package.json names {manifest.get('name')}@{manifest.get('version')}, "
                          f"release.toml pins {package}@{version}")
    for path in [dest, *sorted(p for p in dest.rglob("*") if p.is_dir())]:
        path.chmod(dir_mode)
    return dest


def launcher(entry: dict) -> bytes:
    """The launcher bytes for one packages.toml `launchers` row."""
    return LAUNCHER.format(runtime=entry["runtime"], entry=entry["entry"]).encode()
