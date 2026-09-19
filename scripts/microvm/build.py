#!/usr/bin/env python3
"""Build pinned microVM artifacts with preinstalled tools. Never downloads or installs."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DIRECTORIES = ("sbin", "lib", "lib64", "usr", "usr/lib", "proc", "sys", "dev", "run", "tmp", "mnt", "mnt/workspace")


def run(*args, cwd=None, env=None, stdin=None):
    completed = subprocess.run([str(arg) for arg in args], cwd=cwd, env=env,
                               input=stdin, text=True, capture_output=True, check=True)
    return completed.stdout


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pin(path, expected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or sha256(path) != expected:
        raise ValueError("artifact SHA256 pin mismatch")


def new_output(path):
    path = Path(path).absolute()
    path.mkdir(parents=True, exist_ok=False)
    return path


def json_write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def config_values(text):
    values = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2:-11]] = "n"
    return values


def verify_config(actual, fragment):
    wanted = config_values(fragment)
    got = config_values(actual)
    missing = sorted(key for key, value in wanted.items() if got.get(key, "n") != value)
    if missing:
        raise ValueError("kernel configuration did not retain: " + ", ".join(missing))


def unpack_kernel(archive, destination):
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        tops = set()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError("unsafe kernel archive path")
            if member.issym() or member.islnk():
                link = PurePosixPath(member.linkname)
                target = posixpath.normpath(str(path.parent / link) if member.issym() else str(link))
                if link.is_absolute() or not target.startswith(path.parts[0] + "/"):
                    raise ValueError("kernel archive link escapes its source root")
            elif not (member.isdir() or member.isfile()):
                raise ValueError("kernel archive contains a special file")
            tops.add(path.parts[0])
        if len(tops) != 1:
            raise ValueError("kernel archive must have one root directory")
        tar.extractall(destination, members=members, filter="data")
    source = destination / tops.pop()
    if not (source / "Makefile").is_file():
        raise ValueError("kernel source Makefile missing")
    return source


def build_kernel(args):
    archive = Path(args.archive).resolve(strict=True)
    pin(archive, args.sha256)
    output = new_output(args.output)
    source = unpack_kernel(archive, output)
    build = output / "build"
    build.mkdir()
    env = os.environ.copy()
    env.update(SOURCE_DATE_EPOCH=str(args.epoch), KBUILD_BUILD_USER="builder",
               KBUILD_BUILD_HOST="guest", KBUILD_BUILD_VERSION="1", TZ="UTC",
               KBUILD_BUILD_TIMESTAMP=datetime.datetime.fromtimestamp(args.epoch, datetime.timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y"))
    make = ["make", "-C", source, f"O={build}", "ARCH=x86"]
    run(*make, "x86_64_defconfig", env=env)
    run("bash", source / "scripts/kconfig/merge_config.sh", "-m", build / ".config", HERE / "kernel.config", cwd=build, env=env)
    run(*make, "olddefconfig", env=env)
    verify_config((build / ".config").read_text(), (HERE / "kernel.config").read_text())
    run(*make, f"-j{args.jobs}", "vmlinux", env=env)
    artifact = output / "kernel.elf"
    shutil.copyfile(build / "vmlinux", artifact)
    artifact.chmod(0o444)
    json_write(output / "kernel-receipt.json", {
        "schema": 1, "architecture": "x86_64", "source_sha256": args.sha256,
        "fragment_sha256": sha256(HERE / "kernel.config"),
        "config_sha256": sha256(build / ".config"), "kernel_sha256": sha256(artifact),
        "source_date_epoch": args.epoch, "make": run("make", "--version").splitlines()[0],
        "compiler": run(os.environ.get("CC", "cc"), "--version").splitlines()[0],
    })


def library_spec(value):
    destination, separator, source = value.partition("=")
    path = PurePosixPath(destination)
    if (not separator or path.is_absolute() or ".." in path.parts or
            not re.fullmatch(r"(?:lib64|lib|usr/lib)/[A-Za-z0-9_.+-]+", destination)):
        raise ValueError("library must be lib[/64]/NAME=HOST_FILE or usr/lib/NAME=HOST_FILE")
    return destination, Path(source).resolve(strict=True)


def elf_details(path):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
    # Linux x86-64 ELF only. A Mach-O produced on a macOS build host is not an image.
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01" or int.from_bytes(header[18:20], "little") != 62:
        raise ValueError("artifact is not a little-endian x86-64 ELF")
    info = run("readelf", "--wide", "--program-headers", "--dynamic", path)
    if not re.search(r"^\s*LOAD\s", info, re.M):
        raise ValueError("ELF has no loadable segments")
    interpreter = re.findall(r"Requesting program interpreter:\s*([^\]]+)\]", info)
    needed = re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", info)
    return interpreter[0] if interpreter else None, needed


def validate_libraries(agent, libraries):
    names = {PurePosixPath(path).name for path in libraries}
    for path in [agent, *libraries.values()]:
        interpreter, needed = elf_details(path)
        if path == agent and interpreter and interpreter.lstrip("/") not in libraries:
            raise ValueError("ELF interpreter was not explicitly supplied: " + interpreter)
        for name in needed:
            if "/" in name or name not in names:
                raise ValueError("ELF dependency was not explicitly supplied: " + name)


def build_rootfs(args):
    agent = Path(args.agent).resolve(strict=True)
    pin(agent, args.sha256)
    libraries = {}
    for item in args.library:
        destination, source = library_spec(item)
        if destination in libraries:
            raise ValueError("duplicate library destination")
        libraries[destination] = source
    validate_libraries(agent, libraries)
    output = new_output(args.output)
    stage = output / "tree"
    stage.mkdir()
    for directory in DIRECTORIES:
        (stage / directory).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(agent, stage / "sbin/oneiron-guest")
    for destination, source in libraries.items():
        dest = stage / destination
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
    entries = [stage, *sorted(stage.rglob("*"))]
    for path in entries:
        path.chmod(0o755 if path.is_dir() or path.name == "oneiron-guest" else 0o644)
        os.utime(path, (args.epoch, args.epoch))
    inventory = {str(path.relative_to(stage)): sha256(path) for path in entries if path.is_file()}
    seed = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
    fs_uuid = str(uuid.UUID(seed[:32]))
    image = output / "rootfs.ext4"
    with image.open("xb") as stream:
        stream.truncate(args.size_mib * 1024 * 1024)
    env = os.environ.copy()
    env.update(E2FSPROGS_FAKE_TIME=str(args.epoch), SOURCE_DATE_EPOCH=str(args.epoch))
    run("mke2fs", "-q", "-F", "-t", "ext4", "-d", stage, "-U", fs_uuid,
        "-E", f"root_owner=0:0,hash_seed={fs_uuid},lazy_itable_init=0,lazy_journal_init=0", image, env=env)
    commands = []
    for path in entries:
        name = "/" + path.relative_to(stage).as_posix() if path != stage else "/"
        for field, value in [("uid", 0), ("gid", 0), ("atime", args.epoch),
                             ("ctime", args.epoch), ("mtime", args.epoch), ("crtime", args.epoch)]:
            commands.append(f"set_inode_field {name} {field} {value}")
    # No mounts, loop devices, root privileges, or host package installation.
    run("debugfs", "-w", "-f", "/dev/stdin", image, stdin="\n".join(commands) + "\n", env=env)
    image.chmod(0o444)
    json_write(output / "rootfs-receipt.json", {
        "schema": 1, "architecture": "x86_64", "agent_sha256": args.sha256,
        "files": inventory, "rootfs_sha256": sha256(image), "uuid": fs_uuid,
        "source_date_epoch": args.epoch, "size_mib": args.size_mib,
    })


def make_manifest(args):
    artifacts = {}
    for kind in ("kernel", "rootfs", "component"):
        path = Path(getattr(args, kind)).resolve(strict=True)
        digest = run(args.digest_tool, "--artifact-digest", path).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid BLAKE3 artifact digest")
        artifacts[kind] = {"path": str(path), "bytes": path.stat().st_size,
                           "sha256": sha256(path), "blake3": digest}
    output = Path(args.output)
    with output.open("x") as stream:
        json.dump({"schema": 1, "protocol": 1, "world": "oneiron:code-run/guest@1.0.0",
                   "wit_sha256": sha256(ROOT / "crates/oneiron/wit/code-run.wit"),
                   "artifacts": artifacts}, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    kernel = commands.add_parser("kernel", help="build an explicitly SHA256-pinned Linux source archive")
    kernel.add_argument("--archive", required=True)
    kernel.add_argument("--sha256", required=True)
    kernel.add_argument("--jobs", type=int, choices=range(1, 17), default=2)
    kernel.add_argument("--epoch", type=int, required=True)
    kernel.add_argument("--output", required=True)
    kernel.set_defaults(action=build_kernel)
    rootfs = commands.add_parser("rootfs", help="stage a pinned Linux ELF and explicit libraries into read-only ext4")
    rootfs.add_argument("--agent", required=True)
    rootfs.add_argument("--sha256", required=True)
    rootfs.add_argument("--library", action="append", default=[])
    rootfs.add_argument("--size-mib", type=int, choices=range(32, 4097), default=256)
    rootfs.add_argument("--epoch", type=int, required=True)
    rootfs.add_argument("--output", required=True)
    rootfs.set_defaults(action=build_rootfs)
    manifest = commands.add_parser("manifest", help="record exact kernel/rootfs/component hashes for host pinning")
    for name in ("kernel", "rootfs", "component", "digest-tool", "output"):
        manifest.add_argument("--" + name, required=True)
    manifest.set_defaults(action=make_manifest)
    args = parser.parse_args()
    if hasattr(args, "epoch") and args.epoch < 0:
        parser.error("epoch must be nonnegative")
    try:
        args.action(args)
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"artifact build refused: {error}\n")


if __name__ == "__main__":
    main()
