"""The JSON receipt of one build, and the release.toml output block it fills.

A receipt is a provenance record, not a signature (signing is a later pack)
and not a boot proof. It names every input pin the build read, the builder's
identity (tools tree content hash), every output digest, the measured bytes
against the variant's proposed budget, and the build's SBOM and provenance
statement by digest (attest.py). The payloads and external source builds the
variant used are named by their pins, and what each put in the image is
measured there (installed: a file's sha256 or a tree's content digest); a
source build adds its own toolchain's versions and its binary's hash. Fields keep the checker receipt's names
where they overlap (source_commit, cargo_lock_sha256, rustc, cargo,
fence_sha256, guest_sha256).
"""

from __future__ import annotations

import json
from pathlib import Path

from .model import ARCH, Model
from .util import sha256_bytes


def budget(model: Model, record: dict) -> dict:
    """The measured bytes against release.toml's proposed budget and the Firecracker cap."""
    proposed = model.release["variants"][record["variant"]]["budget"]
    cap = model.release["limits"]["firecracker_rootfs_max_bytes"]
    unpacked = record["unpacked_bytes"]
    out = {"status": proposed["status"], "unpacked_bytes": unpacked,
           "payload_max_bytes": proposed["payload_max_bytes"],
           "within_payload_max": unpacked <= proposed["payload_max_bytes"],
           "firecracker_rootfs_max_bytes": cap}
    if "payload_min_bytes" in proposed:
        out["payload_min_bytes"] = proposed["payload_min_bytes"]
        out["at_or_above_payload_min"] = unpacked >= proposed["payload_min_bytes"]
    if record.get("sparse_capacity_bytes"):
        out["sparse_capacity_bytes"] = record["sparse_capacity_bytes"]
        out["fits_firecracker_cap"] = record["sparse_capacity_bytes"] <= cap
    else:
        out["ext4_needed_bytes"] = record.get("ext4_needed_bytes")
        out["fits_firecracker_cap"] = False
        out["ext4_refused"] = record.get("ext4_refused")
    return out


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
            "payloads": record.get("payloads", {}),
        },
        "installed": record.get("installed", {}),
        "source_builds": {
            pin: {"repository": pin_["repository"], "rev": pin_["rev"], "archive_sha256": pin_["archive_sha256"],
                  "cargo_lock_sha256": pin_["cargo_lock_sha256"], "store": f"cargo-home-{pin}",
                  "rustc": record["native"].get(f"rustc-{pin}"), "cargo": record["native"].get(f"cargo-{pin}")}
            for pin, pin_ in record.get("payloads", {}).items() if pin_.get("kind") == "source-build"
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
            "ext4_sha256": record.get("ext4_sha256"),
            "ext4_uuid": record.get("ext4_uuid"),
            "ext4_refused": record.get("ext4_refused"),
            "rootfs_members_sha256": record["tar"]["members_sha256"],
        },
        "bytes": {
            "compressed_bytes": record["compressed_bytes"],
            "oci_layer_bytes": record["oci_layer_bytes"],
            "unpacked_bytes": record["unpacked_bytes"],
            "rootfs_tar_bytes": record["tar"]["bytes"],
            "sparse_capacity_bytes": record.get("sparse_capacity_bytes"),
            "ext4_allocated_bytes": record.get("ext4_allocated_bytes"),
            "files": record["tar"]["files"],
            "entries": record["tar"]["entries"],
            "builder_peak_rss_bytes": record["builder_peak_rss_bytes"],
        },
        "budget": budget(model, record),
        "sbom": record["sbom"],
        "provenance_statement": record["provenance"],
        "not_measured": {
            "writable_bytes": "the rootfs is read-only in both forms; run-time writes land in the session's "
                              "tmpfs, which only a boot measures",
            "guest_peak_ram_bytes": "unmeasured: needs the acceptance smoke (a boot)",
            "cold_boot": "unmeasured: needs the acceptance smoke (a boot)",
        },
        "not_produced": ["signature", "boot_proof"],
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
        ("ext4_sha256", record.get("ext4_sha256")),
        ("ext4_uuid", record.get("ext4_uuid")),
        ("ext4_refused", record.get("ext4_refused")),
        ("ext4_needed_bytes", record.get("ext4_needed_bytes") if record.get("ext4_refused") else None),
        ("rootfs_tar_sha256", record["tar"]["sha256"]),
        ("rootfs_members_sha256", record["tar"]["members_sha256"]),
        ("compressed_bytes", record["compressed_bytes"]),
        ("oci_layer_bytes", record["oci_layer_bytes"]),
        ("unpacked_bytes", record["unpacked_bytes"]),
        ("rootfs_tar_bytes", record["tar"]["bytes"]),
        ("sparse_capacity_bytes", record.get("sparse_capacity_bytes")),
        ("ext4_allocated_bytes", record.get("ext4_allocated_bytes")),
        ("builder_peak_rss_bytes", record["builder_peak_rss_bytes"]),
        ("sbom_sha256", record["sbom"]["sha256"]),
        ("provenance_sha256", record["provenance"]["sha256"]),
        ("receipt_sha256", receipt_sha),
    ]
    lines = [f'[variants.{record["variant"]}.outputs."{ARCH}"]']
    for key, value in fields:
        if value is None:
            continue
        lines.append(f"{key} = {value}" if isinstance(value, int) else f'{key} = "{value}"')
    return "\n".join(lines)
