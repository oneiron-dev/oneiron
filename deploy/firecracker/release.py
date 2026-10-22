#!/usr/bin/env python3
"""Emit the OS-IMAGE release document of a standalone Firecracker vault image (FIX 9352).

Offline, over a kernel and a read-only engine image `build.py kernel` and
`build.py rootfs` already built, with their receipts: it builds nothing, runs
no mkosi and no OCI conversion, reaches no network, and makes no vault or
config disk. It writes, into a new output directory:

  vmlinux, rootfs.ext4  copies of the kernel and the engine image, each
                        measured again (SHA-256 and BLAKE3) and checked
                        against its receipt
  receipt.json          the provenance it was emitted from: both receipts and
                        the release inputs, as given
  image-release.json    the release manifest, in the guest image family's
                        wire (crates/oneiron-container/images/manifest.md)
  image-release.sig.json  only when --signer-cmd names a real signer

The manifest names no OCI form (`artifacts.oci: null`): this image has none,
and no OCI digest is made up. It binds the image's own bytes instead, the
rootfs and kernel digests a host's Firecracker pins compare. A snapshot of it
is not qualified. With no signer no envelope is written, and a reader
records the signature's typed absence.

What the receipts do not hold comes from --release-inputs, a JSON file pinned
for this build: the engine commit and workspace version the binaries were
built from, the SHA-256 of each engine binary that build made (checked
against the rootfs receipt's inventory), and the contract revisions and
source pins at that commit. Nothing is read from the current checkout. The
two VM capability facts come from the rootfs receipt's measured inventory.

BLAKE3 comes from b3sum (--b3sum, or the one on PATH); without one nothing is
emitted.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "crates/oneiron-container/images"))
from imagebuild import release_manifest  # noqa: E402
from imagebuild.util import BadPin, BuildError, MissingPin, PinMismatch, StepFailed, sha256_bytes  # noqa: E402

# The engine binaries build.py stages under usr/bin.
ENGINE_BINARIES = ("oneiron-server", "oneiron-broker", "oneiron-vm-init", "oneiron-vm-outbox")
# The vault init build.py stages, which reads the config drive's
# trusted-organ-builds.
VAULT_INIT = "sbin/oneiron-vault-init"
# The kernel config fragment the kernel receipt pins.
KERNEL_CONFIG = "deploy/firecracker/kernel.config"
RECEIPT_KIND = "oneiron-firecracker-vault-receipt"
RECEIPT_MEDIA_TYPE = "application/vnd.oneiron.firecracker-vault-receipt.v1+json"


def blake3_hasher(b3sum: str | None):
    """BLAKE3 of a file through b3sum; refused without one."""
    tool = b3sum or shutil.which("b3sum")
    if not tool:
        raise MissingPin("no b3sum: pass --b3sum; a release without BLAKE3 is not emitted")

    def digest(path: Path) -> str:
        out = subprocess.run([tool, "--no-names", str(path)], stdout=subprocess.PIPE, check=True, text=True).stdout.strip()
        if not release_manifest.HEX64.fullmatch(out):
            raise StepFailed(f"b3sum printed {out[:80]!r} for {path}")
        return out
    return digest


def read_json(path: str) -> dict:
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict):
        raise BadPin(f"{path} is not one JSON object")
    return value


def staged(source: str, output: Path, name: str) -> Path:
    """A read-only copy of `source` at output/name: what ships beside the manifest."""
    path = Path(source).resolve(strict=True)
    if not path.is_file():
        raise MissingPin(f"{path} is not a regular file")
    copy = output / name
    shutil.copyfile(path, copy)
    copy.chmod(0o444)
    return copy


def capabilities(receipt: dict) -> dict:
    """The two VM capability facts from the rootfs receipt's measured inventory (FIX 9344).

    The runtime's revision only when every file its descriptor names is in the
    inventory at its sha256, the descriptor too; 0 when the image staged none.
    The trusted organ builds revision only when the image holds the vault init.
    """
    files = receipt["files"]
    revision, descriptor = receipt["vm_guest_runtime_revision"], receipt["guest_runtime"]
    if descriptor is None:
        if revision != 0:
            raise PinMismatch("the rootfs receipt names a guest runtime revision and no descriptor")
        runtime = 0
    else:
        if revision != release_manifest.GUEST_RUNTIME_REVISION or not descriptor.get("closure"):
            raise PinMismatch("the rootfs receipt's guest runtime revision and descriptor disagree")
        if release_manifest.GUEST_RUNTIME_DESCRIPTOR not in files:
            raise PinMismatch("the rootfs receipt names a guest runtime but its inventory has no descriptor")
        for item in [*descriptor["closure"], descriptor["browser_image"], descriptor["desktop_image"]]:
            path = str(item["guest_path"]).lstrip("/")
            if files.get(path) != release_manifest._bare(str(item["sha256"])):
                raise PinMismatch(f"the rootfs receipt's inventory does not hold {item['guest_path']} as its descriptor names it")
        runtime = release_manifest.GUEST_RUNTIME_REVISION
    trusted = receipt["vm_trusted_organ_builds_revision"] if VAULT_INIT in files else 0
    return {
        "vm_trusted_organ_builds_revision": release_manifest._u32(trusted, "vm_trusted_organ_builds_revision"),
        "vm_guest_runtime_revision": runtime,
    }


def contracts(inputs: dict, measured: dict) -> dict:
    """The release inputs' contract revisions and source pins, with the measured capability facts."""
    pinned = dict(inputs["contracts"])
    vault = pinned.get("vault")
    if not isinstance(vault, dict) or set(vault) != set(release_manifest.VAULT_KEYS):
        raise BadPin("release inputs' contracts.vault must name exactly " + ", ".join(release_manifest.VAULT_KEYS))
    if pinned.get("storage") is None:
        raise BadPin("release inputs' contracts.storage is required: the vault keeps vault storage")
    pinned["vault"] = {**vault, **measured}
    return pinned


def emit(args) -> None:
    kernel_receipt = read_json(args.kernel_receipt)
    rootfs_receipt = read_json(args.rootfs_receipt)
    inputs = read_json(args.release_inputs)
    for name, receipt in (("kernel", kernel_receipt), ("rootfs", rootfs_receipt)):
        if receipt.get("schema") != 1 or receipt.get("architecture") != "x86_64":
            raise PinMismatch(f"the {name} receipt is not a schema 1 x86_64 build.py receipt")
    engine = inputs.get("engine")
    schema = release_manifest._schema()
    release_manifest._check(engine, {"$ref": "#/$defs/engine"}, schema, "release-inputs.engine")
    built = inputs.get("engine_binaries")
    if not isinstance(built, dict) or set(built) != set(ENGINE_BINARIES):
        raise BadPin("release inputs' engine_binaries must name the sha256 of exactly " + ", ".join(ENGINE_BINARIES))
    for name in ENGINE_BINARIES:
        held = rootfs_receipt["files"].get(f"usr/bin/{name}")
        if held is None or held != release_manifest._bare(str(built[name])):
            raise PinMismatch(f"usr/bin/{name} in the rootfs is not the binary the release inputs' build made")
    blake3 = blake3_hasher(args.b3sum)

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise BadPin(f"{output} is not empty: a release is emitted into a new directory")
    kernel = release_manifest._file(staged(args.kernel, output, "vmlinux"), blake3)
    release_manifest._expect(kernel["sha256"], kernel_receipt.get("kernel_sha256"), "the kernel")
    rootfs = release_manifest._file(staged(args.rootfs, output, "rootfs.ext4"), blake3)
    release_manifest._expect(rootfs["sha256"], rootfs_receipt.get("rootfs_sha256"), "the engine image")
    fragment = kernel_receipt.get("fragment_sha256")
    if not isinstance(fragment, str) or not release_manifest.HEX64.fullmatch(fragment):
        raise PinMismatch("the kernel receipt pins no kernel config fragment")

    receipt_bytes = (json.dumps({
        "schema": 1, "kind": RECEIPT_KIND, "kernel_receipt": kernel_receipt,
        "rootfs_receipt": rootfs_receipt, "release_inputs": inputs,
    }, indent=2, sort_keys=True) + "\n").encode()
    (output / "receipt.json").write_bytes(receipt_bytes)
    receipt_sha = sha256_bytes(receipt_bytes)
    bundle = contracts(inputs, capabilities(rootfs_receipt))

    payload = {
        "schema": 1,
        "kind": "oneiron-image-release",
        "variant": "vault",
        "arch": release_manifest.ARCH,
        "generation": f"{engine['commit'][:12]}-{receipt_sha[:16]}",
        "engine": engine,
        "contracts": bundle,
        "artifacts": {
            # No OCI form exists for this image, and none is made up.
            "oci": None,
            "rootfs_ext4": rootfs,
            "kernel": {"config": {"path": KERNEL_CONFIG, "sha256": "sha256:" + fragment}, "image": kernel},
        },
        # The code-run guest's binaries; the vault image holds none of them.
        "binaries": {"guest": None, "fence": None, "relay": None},
        "sbom": None,
        "provenance": {"media_type": RECEIPT_MEDIA_TYPE, "path": "receipt.json", "sha256": "sha256:" + receipt_sha},
        "host": {"kvm": True, "kernel_floor": None, "landlock_abi_floor": None, "seccomp_user_notify": False},
        "snapshot": {
            "qualified": False,
            "rootfs_ext4_blake3": rootfs["blake3"],
            "kernel_blake3": kernel["blake3"],
            "guest_protocol": bundle["guest_protocol"],
            "storage_abi": bundle["storage"]["abi_version"],
        },
        "facts": [],
    }
    path, sha = release_manifest.write_release(output, payload, args.signer_cmd)
    print(f"{path} sha256:{sha}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kernel", required=True, help="the vmlinux `build.py kernel` built")
    parser.add_argument("--kernel-receipt", required=True, help="its kernel-receipt.json")
    parser.add_argument("--rootfs", required=True, help="the engine.ext4 `build.py rootfs` built")
    parser.add_argument("--rootfs-receipt", required=True, help="its rootfs-receipt.json")
    parser.add_argument("--release-inputs", required=True,
                        help="JSON pinned for this build: engine {commit, version}, engine_binaries "
                             "{name: sha256}, contracts {guest_protocol, checker_helper, wit_world, vault, "
                             "storage, unversioned}")
    parser.add_argument("--output", required=True, help="a new, empty directory")
    parser.add_argument("--signer-cmd", help="a real signer: reads the manifest bytes, writes one envelope")
    parser.add_argument("--b3sum", help="the b3sum to measure BLAKE3 with; else the one on PATH")
    args = parser.parse_args()
    try:
        emit(args)
    except (BuildError, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"release emission refused: {error}\n")


if __name__ == "__main__":
    main()
