"""The JSON receipt of one build, and the release.toml output block it fills.

A receipt is a provenance record, not a signature (signing is a later pack)
and not a boot proof. It names every input pin the build read, the builder's
identity (tools tree content hash), every output digest and the measured
bytes. Fields keep the checker receipt's names where they overlap
(source_commit, cargo_lock_sha256, rustc, cargo, fence_sha256, guest_sha256).
"""

from __future__ import annotations

import json
from pathlib import Path

from .model import ARCH, Model
from .util import sha256_bytes


def receipt(model: Model, record: dict) -> dict:
    inputs = model.release["inputs"]
    bins = record["native"].get("bins", {})
    body = {
        "schema": 1,
        "kind": "oneiron-image-receipt",
        "variant": record["variant"],
        "platform": ARCH,
        "builder": {
            "commit": record["builder_commit"],
            "tools_tree_sha256": record["tools_tree_sha256"],
            "mkosi": inputs["mkosi"],
            "host": record["host"],
        },
        "source_commit": record["engine_commit"],
        "cargo_lock_sha256": inputs["engine"]["cargo_lock_sha256"],
        "rustc": record["native"].get("rustc"),
        "cargo": record["native"].get("cargo"),
        "fence_sha256": bins.get("/usr/local/bin/oneiron-fence"),
        "guest_sha256": bins.get("/usr/local/bin/oneiron-guest"),
        "native": bins,
        "inputs": {
            "base": inputs["base"],
            "debian": inputs["debian"],
            "rust": {k: v for k, v in inputs["rust"].items() if k != "components"},
            "rust_components": inputs["rust"]["components"],
            "engine": inputs["engine"],
            "files": inputs["files"],
            "contracts": inputs["contracts"],
            "build": inputs["build"],
            "packages_lock_sha256": record["packages_lock_sha256"],
        },
        "packages": [{"name": n, "version": v, "arch": a} for n, v, a in record["packages"]],
        "ownership": record["ownership"],
        "outputs": {
            "rootfs_tar_sha256": record["tar"]["sha256"],
            "oci_index_digest": record["oci_index_digest"],
            "oci_manifest_digest": record["oci_manifest_digest"],
            "oci_config_digest": record["oci_config_digest"],
            "oci_layer_digest": record["oci_layer_digest"],
            "oci_layer_diff_id": record["oci_layer_diff_id"],
            "oci_archive_sha256": record["oci_archive_sha256"],
            "oci_ref": record["oci_ref"],
            "ext4_sha256": record["ext4_sha256"],
            "ext4_uuid": record["ext4_uuid"],
        },
        "bytes": {
            "compressed_bytes": record["compressed_bytes"],
            "oci_layer_bytes": record["oci_layer_bytes"],
            "unpacked_bytes": record["unpacked_bytes"],
            "rootfs_tar_bytes": record["tar"]["bytes"],
            "sparse_capacity_bytes": record["sparse_capacity_bytes"],
            "ext4_allocated_bytes": record["ext4_allocated_bytes"],
        },
        "not_measured": ["writable_bytes", "peak_ram_bytes", "cold_boot"],
        "not_produced": ["sbom", "provenance_attestation", "signature", "boot_proof"],
    }
    return body


def write(model: Model, record: dict, artifacts: Path) -> tuple[Path, str]:
    body = receipt(model, record)
    data = json.dumps(body, indent=2, sort_keys=True) + "\n"
    path = artifacts / "receipt.json"
    path.write_text(data)
    return path, sha256_bytes(data.encode())


def release_block(record: dict, receipt_sha: str) -> str:
    """The [variants.<v>.outputs."linux/amd64"] table to paste into release.toml."""
    fields = [
        ("state", "built-candidate"),
        ("builder_commit", record["builder_commit"]),
        ("engine_commit", record["engine_commit"]),
        ("host", record["host"]),
        ("tools_tree_sha256", record["tools_tree_sha256"]),
        ("packages_lock_sha256", record["packages_lock_sha256"]),
        ("oci_index_digest", record["oci_index_digest"]),
        ("oci_manifest_digest", record["oci_manifest_digest"]),
        ("oci_config_digest", record["oci_config_digest"]),
        ("oci_layer_digest", record["oci_layer_digest"]),
        ("oci_layer_diff_id", record["oci_layer_diff_id"]),
        ("oci_archive_sha256", record["oci_archive_sha256"]),
        ("ext4_sha256", record["ext4_sha256"]),
        ("ext4_uuid", record["ext4_uuid"]),
        ("compressed_bytes", record["compressed_bytes"]),
        ("oci_layer_bytes", record["oci_layer_bytes"]),
        ("unpacked_bytes", record["unpacked_bytes"]),
        ("rootfs_tar_bytes", record["tar"]["bytes"]),
        ("sparse_capacity_bytes", record["sparse_capacity_bytes"]),
        ("ext4_allocated_bytes", record["ext4_allocated_bytes"]),
        ("receipt_sha256", receipt_sha),
    ]
    lines = [f'[variants.{record["variant"]}.outputs."{ARCH}"]']
    for key, value in fields:
        lines.append(f"{key} = {value}" if isinstance(value, int) else f'{key} = "{value}"')
    return "\n".join(lines)
