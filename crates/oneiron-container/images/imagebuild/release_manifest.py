"""image-release.json: the release manifest of one built variant (FIX 8253).

The manifest is the payload a release signature covers, byte for byte: a
detached envelope (image-release.sig.json) signs the exact file bytes, so no
canonical JSON form exists. Every artifact digest here is measured from the
built files themselves (rootfs.tar, the OCI archive and each blob in it,
rootfs.ext4, the engine binaries inside the rootfs) and cross-checked against
the build receipt; none is copied from release.toml. BLAKE3, the digest the
Firecracker host pins compare, comes from the tools tree's b3sum. The wire is
release-manifest.schema.json; the reader is oneiron_container::image_release
(manifest.md).

No signing key exists. Without --signer-cmd no envelope is written, and the
engine reports the image as image_signature_unavailable.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
import tarfile
from pathlib import Path

from . import mkosi_run, pipeline
from .model import ARCH, HERE, Model
from .util import CHUNK, HEX64, BadPin, BuildError, MissingPin, PinMismatch, StepFailed, log, sha256_bytes, sha256_file

SCHEMA_FILE = HERE / "release-manifest.schema.json"
MANIFEST = "image-release.json"
ENVELOPE = "image-release.sig.json"
RECEIPT = "receipt.json"
RECEIPT_MEDIA_TYPE = "application/vnd.oneiron.image-receipt.v1+json"
BINARIES = {
    "guest": "/usr/local/bin/oneiron-guest",
    "fence": "/usr/local/bin/oneiron-fence",
    "relay": "/usr/local/bin/oneiron-browser-relay",
}
VAULT_KEYS = (
    "contract_version", "vm_provision_revision", "vm_outbox_wire_revision", "vm_restore_wire_revision",
    "vm_anchor_wire_revision", "vm_anchor_proxy_revision", "vm_network_revision", "vm_managed_profile_revision",
)
# The first Linux release that offers each Landlock ABI (kernel
# Documentation/userspace-api/landlock.rst). The fence runs on the host
# kernel in the OCI form, so its floor is the host's kernel floor.
LANDLOCK_KERNEL = {1: "5.13", 2: "5.19", 3: "6.2", 4: "6.7", 5: "6.10", 6: "6.12"}


class MissingTool(BuildError):
    kind = "missing-tool"


def tools_tree(work: Path) -> Path:
    return work / "out-build" / "tools" / "tools"


def in_builder(work: Path) -> bool:
    """A builder work dir holds the tools tree its builds ran in."""
    return tools_tree(work).is_dir()


def _blake3(work: Path, variant: str):
    """BLAKE3 of a file through the tools tree's b3sum, or None outside a builder."""
    if not in_builder(work):
        log("note: no builder tools tree under --work, so BLAKE3 is not measured; "
            "the manifest carries the fact blake3_unmeasured")
        return None
    if not (tools_tree(work) / "usr" / "bin" / "b3sum").exists():
        raise MissingTool(f"the tools tree {tools_tree(work)} has no b3sum: rebuild it "
                          "(packages.toml [tools] lists b3sum)")
    cfg = work / "cfg" / f"build-{variant}"
    sources = sorted(p for p in (work / "mkosi-src").glob("*") if (p / "mkosi" / "__main__.py").exists())
    if not (cfg / "mkosi.conf").exists() or len(sources) != 1:
        raise MissingPin(f"{work} holds a tools tree but not the {variant} build config and mkosi source: "
                         f"rerun `build.py build --variant {variant}`")

    def digest(path: Path) -> str:
        out = mkosi_run.box(sources[0], cfg, work, ["b3sum", "--no-names", str(path)], capture=True).stdout.strip()
        if not HEX64.fullmatch(out):
            raise StepFailed(f"b3sum printed {out[:80]!r} for {path}")
        return out
    return digest


def _bare(value: str) -> str:
    return value.removeprefix("sha256:")


def _expect(measured: str, recorded, what: str) -> None:
    if recorded is None or _bare(str(recorded)) != _bare(measured):
        raise PinMismatch(f"{what}: measured {measured}, the build receipt records {recorded}")


def _stream_sha256(stream) -> str:
    digest = hashlib.sha256()
    while block := stream.read(CHUNK):
        digest.update(block)
    return digest.hexdigest()


def _file(path: Path, blake3) -> dict:
    if not path.is_file() or path.is_symlink():
        raise MissingPin(f"{path} is not a regular file")
    return {
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": "sha256:" + sha256_file(path),
        "blake3": None if blake3 is None else "blake3:" + blake3(path),
    }


def _blob(tar: tarfile.TarFile, digest: str, *, keep: bool) -> bytes | None:
    algorithm, _, hexd = str(digest).partition(":")
    if algorithm != "sha256" or not HEX64.fullmatch(hexd):
        raise PinMismatch(f"OCI descriptor digest {digest!r} is not sha256:<64 hex>")
    try:
        stream = tar.extractfile(f"blobs/sha256/{hexd}")
    except KeyError:
        stream = None
    if stream is None:
        raise PinMismatch(f"the OCI archive has no regular blob {digest}")
    hasher = hashlib.sha256()
    data = bytearray()
    while block := stream.read(CHUNK):
        hasher.update(block)
        if keep:
            data.extend(block)
    if hasher.hexdigest() != hexd:
        raise PinMismatch(f"OCI blob {digest} does not hash to its name")
    return bytes(data) if keep else None


def _oci(archive: Path) -> dict:
    """The OCI identities, measured from the archive's own index and blobs."""
    with tarfile.open(archive) as tar:
        try:
            index_stream = tar.extractfile("index.json")
        except KeyError:
            index_stream = None
        if index_stream is None:
            raise PinMismatch(f"{archive.name} has no index.json")
        index_bytes = index_stream.read()
        manifests = json.loads(index_bytes).get("manifests", [])
        if len(manifests) != 1:
            raise PinMismatch(f"{archive.name} index lists {len(manifests)} manifests, not one")
        manifest_digest = manifests[0]["digest"]
        manifest = json.loads(_blob(tar, manifest_digest, keep=True))
        config_digest = manifest["config"]["digest"]
        config = json.loads(_blob(tar, config_digest, keep=True))
        layers = manifest.get("layers", [])
        if len(layers) != 1:
            raise PinMismatch(f"{archive.name} manifest lists {len(layers)} layers, not one")
        _blob(tar, layers[0]["digest"], keep=False)
        diff_ids = config.get("rootfs", {}).get("diff_ids", [])
        if len(diff_ids) != 1:
            raise PinMismatch(f"{archive.name} config lists {len(diff_ids)} diff_ids, not one")
    return {
        "index_digest": "sha256:" + sha256_bytes(index_bytes),
        "manifest_digest": manifest_digest,
        "config_digest": config_digest,
        "layer_digest": layers[0]["digest"],
        "layer_diff_id": diff_ids[0],
    }


def _binaries(rootfs_tar: Path, recorded: dict) -> dict:
    """The engine binaries as the image holds them, hashed from rootfs.tar."""
    out = {}
    with tarfile.open(rootfs_tar) as tar:
        names = set(tar.getnames())
        for role, dest in BINARIES.items():
            name = dest.lstrip("/")
            if name not in names:
                if dest in recorded:
                    raise PinMismatch(f"the build receipt lists {dest}, rootfs.tar lacks it")
                out[role] = None
                continue
            info = tar.getmember(name)
            if not info.isreg():
                raise PinMismatch(f"{dest} in rootfs.tar is not a regular file")
            sha = _stream_sha256(tar.extractfile(info))
            if dest in recorded:
                _expect(sha, recorded[dest], dest)
            out[role] = {"path": dest, "sha256": "sha256:" + sha}
    return out


def _u32(value, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise BadPin(f"{what} must be an unsigned 32-bit integer, got {value!r}")
    return value


def _contracts(receipt: dict, variant: str) -> dict:
    inputs = receipt["inputs"]
    contracts, files = inputs["contracts"], inputs["files"]

    def source(key: str) -> dict:
        pin = files[key]
        return {"path": pin["path"], "sha256": "sha256:" + pin["sha256"]}

    fence_sources = contracts["fence"]["sources"]
    for key in ("fence-wire-src", "fence-supervisor-src"):
        if key not in fence_sources:
            raise BadPin(f"contracts.fence.sources no longer names {key}")
    storage = contracts["storage"]
    return {
        "guest_protocol": _u32(contracts["code_guest_protocol"]["version"], "code_guest_protocol.version"),
        "checker_helper": _u32(contracts["checker_helper"]["header_version"], "checker_helper.header_version"),
        "wit_world": contracts["wit"]["world"],
        "vault": {key: _u32(contracts["vault"][key], f"contracts.vault.{key}") for key in VAULT_KEYS},
        # Only the vault's engine keeps vault storage.
        "storage": {
            "abi_version": _u32(storage["abi_version"], "storage.abi_version"),
            "schema_version": _u32(storage["schema_version"], "storage.schema_version"),
        } if variant == "vault" else None,
        "unversioned": {
            "native_session": source(contracts["native_session"]["source"]),
            "fence_wire": source("fence-wire-src"),
            "fence_supervisor": source("fence-supervisor-src"),
            "relay": source(contracts["relay"]["source"]),
        },
    }


# -- the closed wire description, checked before anything is written ----------


def _check(value, schema: dict, root: dict, where: str) -> None:
    """The subset of JSON Schema release-manifest.schema.json uses."""
    if "$ref" in schema:
        schema = root["$defs"][schema["$ref"].removeprefix("#/$defs/")]
    if "oneOf" in schema:
        passed = 0
        for option in schema["oneOf"]:
            try:
                _check(value, option, root, where)
                passed += 1
            except BadPin:
                pass
        if passed != 1:
            raise BadPin(f"{where}: {value!r} matches {passed} of the allowed shapes, not one")
        return
    if "const" in schema and value != schema["const"]:
        raise BadPin(f"{where}: must be {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise BadPin(f"{where}: {value!r} is not one of {schema['enum']}")
    kind = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise BadPin(f"{where}: must be an integer")
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise BadPin(f"{where}: {value} is out of range")
    elif kind is not None and not isinstance(value, types[kind]):
        raise BadPin(f"{where}: must be {kind}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or ("pattern" in schema and not re.search(schema["pattern"], value)):
            raise BadPin(f"{where}: {value!r} has the wrong form")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        extra = sorted(set(value) - set(props)) if schema.get("additionalProperties") is False else []
        missing = sorted(set(schema.get("required", [])) - set(value))
        if extra or missing:
            raise BadPin(f"{where}: unknown keys {extra}, missing keys {missing}")
        for key, item in value.items():
            _check(item, props[key], root, f"{where}.{key}")
    if isinstance(value, list):
        if schema.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            raise BadPin(f"{where}: repeats an item")
        for index, item in enumerate(value):
            _check(item, schema.get("items", {}), root, f"{where}[{index}]")


def _schema() -> dict:
    return json.loads(SCHEMA_FILE.read_text())


def _sign(command: str, payload: bytes, schema: dict) -> bytes:
    """The signing seam: the command reads the manifest bytes on stdin and
    writes one envelope on stdout. Unused today: no signing key exists."""
    argv = shlex.split(command)
    if not argv:
        raise BadPin("--signer-cmd is empty")
    log(f"$ {command} < {MANIFEST}")
    result = subprocess.run(argv, input=payload, stdout=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise StepFailed(f"--signer-cmd exited {result.returncode}")
    try:
        envelope = json.loads(result.stdout)
    except ValueError:
        raise StepFailed("--signer-cmd did not print one JSON envelope") from None
    _check(envelope, {"$ref": "#/$defs/signature_envelope"}, schema, "envelope")
    return (json.dumps(envelope, indent=2) + "\n").encode()


def emit(model: Model, work: Path, variant: str, *, kernel: Path | None, signer_cmd: str | None) -> tuple[Path, str]:
    """Writes <work>/artifacts/<variant>/image-release.json; returns its path and sha256."""
    record = pipeline.load_record(work, variant)
    pipeline.check_record_inputs(model, record)
    artifacts = Path(record["artifacts"])
    receipt_path = artifacts / RECEIPT
    if not receipt_path.is_file():
        raise MissingPin(f"no {receipt_path}: run `build.py receipt --work {work} --variant {variant}` first")
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    if (receipt.get("kind"), receipt.get("variant"), receipt.get("platform")) != ("oneiron-image-receipt", variant, ARCH):
        raise PinMismatch(f"{receipt_path} is not the {variant} {ARCH} build receipt")
    commit = model.engine_commit()
    if receipt.get("source_commit") != commit:
        raise PinMismatch("the build receipt names a different engine commit than release.toml")
    outputs = receipt["outputs"]
    blake3 = _blake3(work, variant)

    rootfs_tar = artifacts / "rootfs.tar"
    tar_sha = sha256_file(rootfs_tar)
    _expect(tar_sha, outputs.get("rootfs_tar_sha256"), "rootfs.tar")
    oci_archive = artifacts / f"{variant}.oci.tar"
    oci = _oci(oci_archive)
    for key in ("index_digest", "manifest_digest", "config_digest", "layer_digest", "layer_diff_id"):
        _expect(oci[key], outputs.get(f"oci_{key}"), f"OCI {key}")
    _expect(oci["layer_diff_id"], tar_sha, "OCI layer diff_id against rootfs.tar")
    archive = _file(oci_archive, blake3)
    _expect(archive["sha256"], outputs.get("oci_archive_sha256"), oci_archive.name)
    ext4 = _file(artifacts / "rootfs.ext4", blake3)
    _expect(ext4["sha256"], outputs.get("ext4_sha256"), "rootfs.ext4")
    kernel_image = _file(kernel.resolve(), blake3) if kernel else None
    config_pin = receipt["inputs"]["files"]["kernel-config-vault" if variant == "vault" else "kernel-config-foreign"]
    binaries = _binaries(rootfs_tar, receipt.get("native") or {})
    contracts = _contracts(receipt, variant)
    fenced = binaries["fence"] is not None
    floor = None
    if fenced:
        floor = _u32(receipt["inputs"]["contracts"]["fence"]["landlock_abi_floor"], "fence.landlock_abi_floor")
    if floor is not None and floor not in LANDLOCK_KERNEL:
        raise BadPin(f"no kernel release is known for Landlock ABI {floor}")
    receipt_sha = sha256_bytes(receipt_bytes)

    payload = {
        "schema": 1,
        "kind": "oneiron-image-release",
        "variant": variant,
        "arch": ARCH,
        "generation": f"{commit[:12]}-{receipt_sha[:16]}",
        "engine": {"commit": commit, "version": receipt["inputs"]["engine"]["workspace_version"]},
        "contracts": contracts,
        "artifacts": {
            "oci": {"reference": outputs["oci_ref"], **oci, "archive": archive},
            "rootfs_ext4": ext4,
            "kernel": {
                "config": {"path": config_pin["path"], "sha256": "sha256:" + config_pin["sha256"]},
                "image": kernel_image,
            },
        },
        "binaries": binaries,
        "sbom": None,
        "provenance": {"media_type": RECEIPT_MEDIA_TYPE, "path": RECEIPT, "sha256": "sha256:" + receipt_sha},
        "host": {
            # The vault boots only as a microVM; every other variant's OCI form runs without KVM.
            "kvm": variant == "vault",
            "kernel_floor": LANDLOCK_KERNEL[floor] if floor is not None else None,
            "landlock_abi_floor": floor,
            "seccomp_user_notify": fenced,
        },
        "snapshot": {
            "qualified": False,
            "rootfs_ext4_blake3": ext4["blake3"],
            "kernel_blake3": kernel_image["blake3"] if kernel_image else None,
            "guest_protocol": contracts["guest_protocol"],
            "storage_abi": contracts["storage"]["abi_version"] if contracts["storage"] else None,
        },
        "facts": [] if blake3 is not None else ["blake3_unmeasured"],
    }
    schema = _schema()
    _check(payload, schema, schema, "manifest")
    data = (json.dumps(payload, indent=2) + "\n").encode()
    path = artifacts / MANIFEST
    path.write_bytes(data)
    envelope_path = artifacts / ENVELOPE
    if signer_cmd:
        envelope_path.write_bytes(_sign(signer_cmd, data, schema))
        log(f"envelope {envelope_path}")
    elif envelope_path.exists():
        # No signer ran for these bytes; an older envelope would read as an
        # invalid signature, never as this manifest's.
        envelope_path.unlink()
        log(f"removed {envelope_path}: no --signer-cmd ran for these manifest bytes")
    if kernel_image:
        log(f"the kernel is listed as {kernel_image['path']}: ship it beside {MANIFEST}")
    return path, sha256_bytes(data)
