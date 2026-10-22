#!/usr/bin/env python3
"""Build a vault VM's pinned kernel, read-only engine image and fresh vault disk.

Uses preinstalled tools only: never downloads, installs, mounts or uses a loop
device. The code-run guest's recipe (scripts/microvm/build.py) is untouched;
this one reuses its pinning, ELF and kernel-archive checks.

  kernel      the vault kernel from a SHA256-pinned Linux source archive and
              this directory's kernel.config (fscrypt v2, keyring, vsock,
              virtio-net)
  rootfs      /sbin/oneiron-vault-init, the same-build /usr/bin/oneiron-server,
              /usr/bin/oneiron-broker, /usr/bin/oneiron-vm-init and
              /usr/bin/oneiron-vm-outbox (the outbox carrier's companion), the
              shell tools the init runs and their explicit library closure, and
              the empty /etc/resolv.conf the guest network's resolver covers;
              with the three guest runtime inputs, the guests' rootless
              container runtime too (FIX 7671): its pinned closure, each file
              with its own mode, both guests' image archives, the descriptor
              naming them and the empty /etc/subuid and /etc/subgid the
              bootstrap's rows cover
  vault-disk  an empty ext4 vault disk with its encrypt feature and a fixed
              UUID: the vault_disk_uuid of the VM profile's provision binding
  config-disk a fresh read-only ext4 config drive holding an operator's tree
              as it is, its trusted-organ-builds list among the files (FIX
              7889): the VM profile's config_disk
  manifest    every artifact's SHA256 and the engine revision, for the host's
              image pin (the provision prelude's, the outbox carrier's with its
              backup-label registration, the restore channel's, the custody
              anchor channels' and the guest network's build floors), the
              guest runtime's revision and descriptor, and the trusted organ
              builds file's revision
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
# The custody anchor exchange's and proxy's wire revisions
# (oneiron_vault_contract::vm_anchor, FIX 6517), published together: every
# serving cold boot of this image dials the exchange, so a host delivers the
# anchor's credential only to an image whose manifest names both.
ANCHOR_WIRE_REVISION = 1
ANCHOR_PROXY_REVISION = 1
# The guest network's revision (oneiron_vault_contract::vm::VM_NETWORK_REVISION,
# FIX 6808): this image sets up the one NIC a host attaches, IPv4 only, from
# the config drive's network.json, so a host attaches one only to an image
# whose manifest names it.
VM_NETWORK_REVISION = 1
# The managed profile's revision
# (oneiron_vault_contract::vm::VM_MANAGED_PROFILE_REVISION, FIX 6809): this
# image's oneiron-vm-init reads the config drive's five typed profile files and
# passes the engine their flags, so a host stages them only for an image whose
# manifest names it.
VM_MANAGED_PROFILE_REVISION = 1
# The trusted organ builds file's revision
# (oneiron_vault_contract::vm::VM_TRUSTED_ORGAN_BUILDS_REVISION, FIX 7889):
# this image's init passes each line of the config drive's trusted-organ-builds
# to the engine as its own --trusted-organ-build, so an operator's list is
# applied only by an image whose manifest names it. It never says a list was
# staged or an organ started.
VM_TRUSTED_ORGAN_BUILDS_REVISION = 1
# The resolver file's mountpoint: empty and 0644 in the image, and covered by
# oneiron-vm-init's bind mount when the guest's network plan names nameservers.
RESOLV_CONF = "etc/resolv.conf"
# The guest runtime's revision
# (oneiron_vault_contract::vm::VM_GUEST_RUNTIME_REVISION, FIX 7671): an image
# that stages the whole guest runtime, its descriptor beside it, names it; one
# built without names 0 and a null descriptor. It never says a guest started.
VM_GUEST_RUNTIME_REVISION = 1
# The guest runtime's fixed paths (oneiron_vault_contract::vm): its
# directory, the descriptor in it, and each guest's image archive.
GUEST_RUNTIMES = "usr/lib/oneiron/guest-runtimes"
GUEST_RUNTIME_DESCRIPTOR = GUEST_RUNTIMES + "/manifest.json"
IMAGE_ARCHIVES = {"browser": GUEST_RUNTIMES + "/images/browser.tar",
                  "desktop": GUEST_RUNTIMES + "/images/desktop.tar"}
# The subordinate ID files' mountpoints: empty and 0644 in the image, covered
# by oneiron-vm-init's bind mounts of the vault UID's rows.
SUBID_FILES = ("etc/subuid", "etc/subgid")
# The mapping helpers the container CLI runs from its PATH (/usr/bin:/bin),
# the distro's own, set-user-ID root.
MAPPING_HELPERS = ("newuidmap", "newgidmap")
# The most a staged runtime file's mode holds: set-user-ID and 0755, never a
# group's or others' write (oneiron_vault_contract::vm::VmGuestRuntimeFile).
RUNTIME_MODE_BITS = 0o4755
# Where no runtime file goes: a mountpoint a boot covers, the UID table's
# directory, and the guest runtime's own directory.
RESERVED = ("proc", "sys", "dev", "run", "tmp", "vault", "config", "restore", "etc/oneiron",
            GUEST_RUNTIMES)
# Where the image's dynamic loader finds a library (microvm.library_spec).
LIBRARY_DESTINATION = re.compile(r"(?:lib64|lib|usr/lib)/[A-Za-z0-9_.+-]+")


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


def guest_path(value):
    """An absolute guest path, as its path below the image's root."""
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError("a guest runtime path must be absolute")
    parts = value[1:].split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("a guest runtime path must have no empty, . or .. part")
    return "/".join(parts)


def archive_image(path):
    """The image id a `docker save` archive's own manifest names: its config's
    SHA256, checked against the config's bytes. Nothing is pulled."""
    with tarfile.open(path) as tar:
        listed = tar.extractfile("manifest.json")
        manifest = json.load(listed) if listed else None
        if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
            raise ValueError("an image archive's manifest must name exactly one image")
        config = manifest[0].get("Config")
        member = tar.extractfile(config) if isinstance(config, str) else None
        if member is None:
            raise ValueError("an image archive holds no config its manifest names")
        digest = hashlib.file_digest(member, "sha256").hexdigest()
    if PurePosixPath(config).name.removesuffix(".json") != digest:
        raise ValueError("an image archive's config is not the bytes its name says")
    return "sha256:" + digest


def guest_runtime_inputs(args, staged, libraries):
    """The pinned closure and both archives, all three or none: each closure
    file's guest path, source, mode and SHA256, the CLI and the fence among
    them, the mapping helpers set-user-ID root on the CLI's PATH, every ELF's
    libraries supplied; and each archive's source, SHA256 and image id."""
    given = (args.guest_runtime_closure, args.browser_image_archive, args.desktop_image_archive)
    if not any(given):
        return None
    if not all(given):
        raise ValueError("a guest runtime needs --guest-runtime-closure, --browser-image-archive "
                         "and --desktop-image-archive together")
    closure = json.loads(Path(args.guest_runtime_closure).read_text())
    if (not isinstance(closure, dict) or set(closure) != {"cli", "fence", "members"}
            or not isinstance(closure["members"], list)):
        raise ValueError("the guest runtime closure is exactly cli, fence and members")
    members = {}
    for member in closure["members"]:
        if not isinstance(member, dict) or set(member) != {"src", "guest_path", "mode", "sha256"}:
            raise ValueError("each closure member is exactly src, guest_path, mode and sha256")
        destination = guest_path(member["guest_path"])
        mode = member["mode"]
        if type(mode) is not int or mode < 0 or mode & ~RUNTIME_MODE_BITS:
            raise ValueError("a closure member's mode is beyond set-user-ID and 0755: " + destination)
        if destination in members or destination in staged or any(
                destination == reserved or destination.startswith(reserved + "/") for reserved in RESERVED):
            raise ValueError("a closure member's guest path is taken or reserved: " + destination)
        source = Path(member["src"]).resolve(strict=True)
        if not source.is_file():
            raise ValueError("a closure member is not a regular file: " + destination)
        microvm.pin(source, member["sha256"])
        members[destination] = (source, mode, member["sha256"])
    cli, fence = guest_path(closure["cli"]), guest_path(closure["fence"])
    for program in (cli, fence):
        if program not in members or not members[program][1] & 0o001:
            raise ValueError("the CLI and the fence must be closure members every UID may run")
    for helper in MAPPING_HELPERS:
        found = [path for path in ("usr/bin/" + helper, "bin/" + helper) if path in members]
        if not found or members[found[0]][1] != 0o4755:
            raise ValueError(f"the closure needs {helper} in usr/bin or bin, mode 04755")
    elves = {}
    for destination, (source, _, _) in members.items():
        with source.open("rb") as stream:
            if stream.read(4) == b"\x7fELF":
                elves[destination] = source
    runtime_libraries = {**libraries, **{destination: source for destination, source in elves.items()
                                         if LIBRARY_DESTINATION.fullmatch(destination)}}
    validate_closure({source for destination, source in elves.items() if destination not in runtime_libraries},
                     runtime_libraries)
    archives = {}
    for name in IMAGE_ARCHIVES:
        source = Path(getattr(args, name + "_image_archive")).resolve(strict=True)
        archives[name] = (source, microvm.sha256(source), archive_image(source))
    return {"cli": cli, "fence": fence, "members": members, "archives": archives}


def guest_runtime_descriptor(runtime):
    """The descriptor oneiron_vault_contract::vm::VmGuestRuntimeDescriptor reads."""
    return {
        "cli": "/" + runtime["cli"], "fence": "/" + runtime["fence"],
        "closure": [{"guest_path": "/" + destination, "sha256": digest, "mode": mode}
                    for destination, (_, mode, digest) in sorted(runtime["members"].items())],
        **{name + "_image": {"guest_path": "/" + IMAGE_ARCHIVES[name], "sha256": digest, "image_id": image_id}
           for name, (_, digest, image_id) in runtime["archives"].items()},
    }


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
    staged = {"sbin/oneiron-vault-init", RESOLV_CONF, *SUBID_FILES, *libraries,
              *("usr/bin/" + name for name in BINARIES), *("bin/" + name for name in TOOLS)}
    runtime = guest_runtime_inputs(args, staged, libraries)
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
    (stage / RESOLV_CONF).write_bytes(b"")
    # The resolver mountpoint is read, never run.
    modes = {stage / RESOLV_CONF: 0o644}
    descriptor = None
    if runtime:
        for destination, (source, mode, _) in runtime["members"].items():
            (stage / destination).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, stage / destination)
            modes[stage / destination] = mode
        for name, (source, _, _) in runtime["archives"].items():
            (stage / IMAGE_ARCHIVES[name]).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, stage / IMAGE_ARCHIVES[name])
            modes[stage / IMAGE_ARCHIVES[name]] = 0o444
        descriptor = guest_runtime_descriptor(runtime)
        (stage / GUEST_RUNTIME_DESCRIPTOR).write_text(json.dumps(descriptor, indent=2, sort_keys=True) + "\n")
        modes[stage / GUEST_RUNTIME_DESCRIPTOR] = 0o444
        for mountpoint in SUBID_FILES:
            (stage / mountpoint).write_bytes(b"")
            modes[stage / mountpoint] = 0o644
    entries = [stage, *sorted(stage.rglob("*"))]
    for path in entries:
        # Directories, ELF files and the init script all need search or exec;
        # the files above take the modes their rows name.
        path.chmod(modes.get(path, 0o755))
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
        "vm_guest_runtime_revision": VM_GUEST_RUNTIME_REVISION if descriptor else 0,
        "guest_runtime": descriptor,
        # The init copied above reads the config drive's trusted-organ-builds.
        "vm_trusted_organ_builds_revision": VM_TRUSTED_ORGAN_BUILDS_REVISION,
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


def build_config_disk(args):
    """A fresh config drive from the operator's tree, offline: every file in it
    lands at the drive's root as it is, so <tree>/trusted-organ-builds is the
    guest's /config/trusted-organ-builds (FIX 7889). No list is derived or
    checked here: the engine's --trusted-organ-build parser judges each line on
    boot. Never writes to a drive a VM has attached."""
    source = Path(args.source_dir).resolve(strict=True)
    if not source.is_dir():
        raise ValueError("the config drive's source is not a directory")
    output = microvm.new_output(args.output)
    image = output / "config.ext4"
    with image.open("xb") as stream:
        stream.truncate(args.size_mib * 1024 * 1024)
    microvm.run("mke2fs", "-q", "-F", "-t", "ext4", "-d", source,
                "-E", "root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0", image)
    image.chmod(0o444)
    microvm.json_write(output / "config-disk-receipt.json", {
        "schema": 1, "size_mib": args.size_mib, "config_sha256": microvm.sha256(image),
    })


def make_manifest(args):
    if not re.fullmatch(r"[0-9a-f]{40}", args.engine_revision):
        raise ValueError("the engine revision is a full 40-hex commit")
    artifacts = {}
    for kind in ("kernel", "rootfs"):
        path = Path(getattr(args, kind)).resolve(strict=True)
        artifacts[kind] = {"path": str(path), "bytes": path.stat().st_size, "sha256": microvm.sha256(path)}
    receipt = json.loads(Path(args.rootfs_receipt).read_text())
    runtime_revision, descriptor = receipt["vm_guest_runtime_revision"], receipt["guest_runtime"]
    if type(runtime_revision) is not int or not (
            (runtime_revision == 0 and descriptor is None)
            or (runtime_revision == VM_GUEST_RUNTIME_REVISION and isinstance(descriptor, dict))):
        raise ValueError("the rootfs receipt's guest runtime revision and descriptor disagree")
    trusted_revision = receipt["vm_trusted_organ_builds_revision"]
    if type(trusted_revision) is not int or trusted_revision != VM_TRUSTED_ORGAN_BUILDS_REVISION:
        raise ValueError("the rootfs receipt names another trusted organ builds revision")
    output = Path(args.output)
    with output.open("x") as stream:
        json.dump({"schema": 1, "engine_revision": args.engine_revision,
                   "contract_version": 3, "provision_revision": PROVISION_REVISION,
                   "outbox_wire_revision": OUTBOX_WIRE_REVISION,
                   "restore_wire_revision": RESTORE_WIRE_REVISION,
                   "anchor_wire_revision": ANCHOR_WIRE_REVISION,
                   "anchor_proxy_revision": ANCHOR_PROXY_REVISION,
                   "vm_network_revision": VM_NETWORK_REVISION,
                   "vm_managed_profile_revision": VM_MANAGED_PROFILE_REVISION,
                   "vm_guest_runtime_revision": runtime_revision, "guest_runtime": descriptor,
                   "vm_trusted_organ_builds_revision": trusted_revision,
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
    rootfs.add_argument("--guest-runtime-closure",
                        help="JSON {cli, fence, members: [{src, guest_path, mode, sha256}]}: the guests' pinned "
                             "rootless container runtime (FIX 7671), with both image archives")
    rootfs.add_argument("--browser-image-archive", help="the browser guest's `docker save` archive")
    rootfs.add_argument("--desktop-image-archive", help="the desktop guest's `docker save` archive")
    rootfs.add_argument("--size-mib", type=int, choices=range(64, 16385), default=512)
    rootfs.add_argument("--epoch", type=int, required=True)
    rootfs.add_argument("--output", required=True)
    rootfs.set_defaults(action=build_rootfs)
    disk = commands.add_parser("vault-disk", help="make an empty ext4 vault disk with its encrypt feature")
    disk.add_argument("--uuid", help="the binding's vault_disk_uuid; a fresh one when absent")
    disk.add_argument("--size-mib", type=int, required=True)
    disk.add_argument("--output", required=True)
    disk.set_defaults(action=build_vault_disk)
    config = commands.add_parser("config-disk", help="make a fresh read-only ext4 config drive from an operator's tree")
    config.add_argument("--source-dir", required=True,
                        help="the operator's tree: settings.toml, seal/, trusted-organ-builds and the other files")
    config.add_argument("--size-mib", type=int, required=True)
    config.add_argument("--output", required=True)
    config.set_defaults(action=build_config_disk)
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
