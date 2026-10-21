#!/usr/bin/env python3
"""Build a vault VM's pinned kernel, read-only engine image and fresh vault disk.

Uses preinstalled tools only: never downloads, installs, mounts or uses a loop
device. The code-run guest's recipe (scripts/microvm/build.py) is untouched;
this one reuses its pinning, ELF and kernel-archive checks.

  kernel      the vault kernel from a SHA256-pinned Linux source archive and
              this directory's kernel.config (fscrypt v2, keyring, vsock)
  rootfs      /sbin/oneiron-vault-init, the same-build /usr/bin/oneiron-server,
              /usr/bin/oneiron-broker, /usr/bin/oneiron-vm-init and
              /usr/bin/oneiron-vm-outbox (the outbox carrier's companion), the
              shell tools the init runs and their explicit library closure
  vault-disk  an empty ext4 vault disk with its encrypt feature and a fixed
              UUID: the vault_disk_uuid of the VM profile's provision binding
  manifest    every artifact's SHA256 and the engine revision, for the host's
              image pin (the provision prelude's, the outbox carrier's with its
              backup-label registration, and the restore channel's build floor)
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
_SPEC = importlib.util.spec_from_file_location("microvm_build", ROOT / "scripts/microvm/build.py")
microvm = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(microvm)

# The image's mountpoints and tool directories. /vault takes the vault disk,
# /config the optional settings drive, /restore a cold restore's optional
# source drive, /etc/oneiron the UID table's tmpfs.
DIRECTORIES = ("bin", "sbin", "usr/bin", "lib", "lib64", "usr/lib", "proc", "sys",
               "dev", "run", "tmp", "vault", "config", "restore", "etc/oneiron")
BINARIES = ("oneiron-server", "oneiron-broker", "oneiron-vm-init", "oneiron-vm-outbox")
# What /sbin/oneiron-vault-init runs besides the engine's binaries.
TOOLS = ("sh", "mount", "umount", "cat", "head", "sync", "reboot")
PROVISION_REVISION = 1
# The outbox carrier's wire revision (oneiron_vault_contract::vm_outbox): 2
# makes the guest's backup-label registration required (FIX 7046), and each
# end refuses the other's revision 1, so a host pairs only with an image whose
# manifest names 2.
OUTBOX_WIRE_REVISION = 2
# The restore channel's wire revision (oneiron_vault_contract::vm_restore):
# every cold boot of this image dials it first, so a host pairs only with an
# image whose manifest names it.
RESTORE_WIRE_REVISION = 1


def build_kernel(args):
    archive = Path(args.archive).resolve(strict=True)
    microvm.pin(archive, args.sha256)
    output = microvm.new_output(args.output)
    source = microvm.unpack_kernel(archive, output)
    build = output / "build"
    build.mkdir()
    fragment = HERE / "kernel.config"
    env = os.environ.copy()
    env.update(SOURCE_DATE_EPOCH=str(args.epoch), KBUILD_BUILD_USER="builder",
               KBUILD_BUILD_HOST="vault", KBUILD_BUILD_VERSION="1", TZ="UTC",
               KBUILD_BUILD_TIMESTAMP=datetime.datetime.fromtimestamp(args.epoch, datetime.timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y"))
    make = ["make", "-C", source, f"O={build}", "ARCH=x86"]
    microvm.run(*make, "x86_64_defconfig", env=env)
    microvm.run("bash", source / "scripts/kconfig/merge_config.sh", "-m", build / ".config", fragment, cwd=build, env=env)
    microvm.run(*make, "olddefconfig", env=env)
    microvm.verify_config((build / ".config").read_text(), fragment.read_text())
    microvm.run(*make, f"-j{args.jobs}", "vmlinux", env=env)
    artifact = output / "vmlinux"
    shutil.copyfile(build / "vmlinux", artifact)
    artifact.chmod(0o444)
    microvm.json_write(output / "kernel-receipt.json", {
        "schema": 1, "architecture": "x86_64", "source_sha256": args.sha256,
        "fragment_sha256": microvm.sha256(fragment),
        "config_sha256": microvm.sha256(build / ".config"), "kernel_sha256": microvm.sha256(artifact),
        "source_date_epoch": args.epoch, "make": microvm.run("make", "--version").splitlines()[0],
        "compiler": microvm.run(os.environ.get("CC", "cc"), "--version").splitlines()[0],
    })


def pinned(value, kinds):
    """NAME=SHA256=HOST_FILE for one of `kinds`, its pin checked."""
    name, separator, rest = value.partition("=")
    digest, separator2, source = rest.partition("=")
    if not separator or not separator2 or name not in kinds:
        raise ValueError("expected NAME=SHA256=HOST_FILE with NAME one of " + ", ".join(kinds))
    path = Path(source).resolve(strict=True)
    microvm.pin(path, digest)
    return name, path


def validate_closure(executables, libraries):
    names = {PurePosixPath(path).name for path in libraries}
    for path in [*executables, *libraries.values()]:
        interpreter, needed = microvm.elf_details(path)
        if path in executables and interpreter and interpreter.lstrip("/") not in libraries:
            raise ValueError("ELF interpreter was not explicitly supplied: " + interpreter)
        for name in needed:
            if "/" in name or name not in names:
                raise ValueError("ELF dependency was not explicitly supplied: " + name)


def build_rootfs(args):
    binaries = dict(pinned(item, BINARIES) for item in args.binary)
    tools = dict(pinned(item, TOOLS) for item in args.tool)
    for kind, wanted, got in (("binary", BINARIES, binaries), ("tool", TOOLS, tools)):
        missing = sorted(set(wanted) - set(got))
        if missing:
            raise ValueError(f"no --{kind} for: " + ", ".join(missing))
    libraries = {}
    for item in args.library:
        destination, source = microvm.library_spec(item)
        if destination in libraries:
            raise ValueError("duplicate library destination")
        libraries[destination] = source
    validate_closure({*binaries.values(), *tools.values()}, libraries)
    output = microvm.new_output(args.output)
    stage = output / "tree"
    stage.mkdir()
    for directory in DIRECTORIES:
        (stage / directory).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(HERE / "oneiron-vault-init", stage / "sbin/oneiron-vault-init")
    for name, source in binaries.items():
        shutil.copyfile(source, stage / "usr/bin" / name)
    for name, source in tools.items():
        shutil.copyfile(source, stage / "bin" / name)
    for destination, source in libraries.items():
        shutil.copyfile(source, stage / destination)
    entries = [stage, *sorted(stage.rglob("*"))]
    for path in entries:
        # Directories, ELF files and the init script all need search or exec.
        path.chmod(0o755)
        os.utime(path, (args.epoch, args.epoch))
    inventory = {str(path.relative_to(stage)): microvm.sha256(path) for path in entries if path.is_file()}
    seed = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
    fs_uuid = str(uuid.UUID(seed[:32]))
    image = output / "engine.ext4"
    with image.open("xb") as stream:
        stream.truncate(args.size_mib * 1024 * 1024)
    env = os.environ.copy()
    env.update(E2FSPROGS_FAKE_TIME=str(args.epoch), SOURCE_DATE_EPOCH=str(args.epoch))
    microvm.run("mke2fs", "-q", "-F", "-t", "ext4", "-d", stage, "-U", fs_uuid,
                "-E", f"root_owner=0:0,hash_seed={fs_uuid},lazy_itable_init=0,lazy_journal_init=0", image, env=env)
    commands = []
    for path in entries:
        name = "/" + path.relative_to(stage).as_posix() if path != stage else "/"
        for field, value in [("uid", 0), ("gid", 0), ("atime", args.epoch),
                             ("ctime", args.epoch), ("mtime", args.epoch), ("crtime", args.epoch)]:
            commands.append(f"set_inode_field {name} {field} {value}")
    microvm.run("debugfs", "-w", "-f", "/dev/stdin", image, stdin="\n".join(commands) + "\n", env=env)
    image.chmod(0o444)
    microvm.json_write(output / "rootfs-receipt.json", {
        "schema": 1, "architecture": "x86_64", "files": inventory,
        "rootfs_sha256": microvm.sha256(image), "uuid": fs_uuid,
        "source_date_epoch": args.epoch, "size_mib": args.size_mib,
    })


def build_vault_disk(args):
    disk_uuid = str(uuid.UUID(args.uuid)) if args.uuid else str(uuid.uuid4())
    if args.uuid and disk_uuid != args.uuid:
        raise ValueError("the vault disk UUID must be 8-4-4-4-12 lowercase hex")
    output = microvm.new_output(args.output)
    image = output / "vault.ext4"
    with image.open("xb") as stream:
        stream.truncate(args.size_mib * 1024 * 1024)
    # Root-owned and empty: oneiron-vm-init lays out its encrypted storage on
    # the first cold boot, under the provisioned key. No plaintext tree.
    microvm.run("mke2fs", "-q", "-F", "-t", "ext4", "-O", "encrypt", "-U", disk_uuid,
                "-E", "root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0", image)
    image.chmod(0o600)
    microvm.json_write(output / "vault-disk-receipt.json", {
        "schema": 1, "uuid": disk_uuid, "size_mib": args.size_mib, "features": ["encrypt"],
    })


def make_manifest(args):
    if not re.fullmatch(r"[0-9a-f]{40}", args.engine_revision):
        raise ValueError("the engine revision is a full 40-hex commit")
    artifacts = {}
    for kind in ("kernel", "rootfs"):
        path = Path(getattr(args, kind)).resolve(strict=True)
        artifacts[kind] = {"path": str(path), "bytes": path.stat().st_size, "sha256": microvm.sha256(path)}
    receipt = json.loads(Path(args.rootfs_receipt).read_text())
    output = Path(args.output)
    with output.open("x") as stream:
        json.dump({"schema": 1, "engine_revision": args.engine_revision,
                   "contract_version": 3, "provision_revision": PROVISION_REVISION,
                   "outbox_wire_revision": OUTBOX_WIRE_REVISION,
                   "restore_wire_revision": RESTORE_WIRE_REVISION,
                   "artifacts": artifacts, "rootfs_files": receipt["files"]},
                  stream, indent=2, sort_keys=True)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    kernel = commands.add_parser("kernel", help="build the vault kernel from an explicitly SHA256-pinned Linux source archive")
    kernel.add_argument("--archive", required=True)
    kernel.add_argument("--sha256", required=True)
    kernel.add_argument("--jobs", type=int, choices=range(1, 17), default=2)
    kernel.add_argument("--epoch", type=int, required=True)
    kernel.add_argument("--output", required=True)
    kernel.set_defaults(action=build_kernel)
    rootfs = commands.add_parser("rootfs", help="stage the vault init, engine binaries, tools and libraries into read-only ext4")
    rootfs.add_argument("--binary", action="append", default=[], help="NAME=SHA256=HOST_FILE for " + ", ".join(BINARIES))
    rootfs.add_argument("--tool", action="append", default=[], help="NAME=SHA256=HOST_FILE for " + ", ".join(TOOLS))
    rootfs.add_argument("--library", action="append", default=[])
    rootfs.add_argument("--size-mib", type=int, choices=range(64, 4097), default=512)
    rootfs.add_argument("--epoch", type=int, required=True)
    rootfs.add_argument("--output", required=True)
    rootfs.set_defaults(action=build_rootfs)
    disk = commands.add_parser("vault-disk", help="make an empty ext4 vault disk with its encrypt feature")
    disk.add_argument("--uuid", help="the binding's vault_disk_uuid; a fresh one when absent")
    disk.add_argument("--size-mib", type=int, required=True)
    disk.add_argument("--output", required=True)
    disk.set_defaults(action=build_vault_disk)
    manifest = commands.add_parser("manifest", help="record the kernel and rootfs hashes and the engine revision for host pinning")
    for name in ("kernel", "rootfs", "rootfs-receipt", "engine-revision", "output"):
        manifest.add_argument("--" + name, required=True)
    manifest.set_defaults(action=make_manifest)
    args = parser.parse_args()
    if getattr(args, "epoch", 0) < 0:
        parser.error("epoch must be nonnegative")
    if getattr(args, "size_mib", 1) <= 0:
        parser.error("size must be positive")
    try:
        args.action(args)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"artifact build refused: {error}\n")


if __name__ == "__main__":
    main()
