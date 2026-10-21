"""The SBOM and the provenance statement of one build. Both are unsigned: a
release signature (manifest.md) covers the release manifest, which names the
SBOM by digest; signing is its own seam.

sbom.spdx.json is an SPDX 2.3 JSON document. Its packages are:
- the image itself (its OCI manifest digest and archive sha256);
- every Debian package dpkg says is installed, with the .deb sha256 from
  packages.lock.toml;
- every native binary the build placed, and the Cargo packages each one links
  (`cargo tree -e normal` in the build chroot, so the features are the ones
  this build resolved), plus the crates its build also compiled
  (`-e normal,build`), joined with Cargo.lock for source and checksum;
- for a variant that ships the offline Cargo store, every crate archive and
  git source in that store;
- every pinned payload (an upstream binary, the Rust components) and pinned
  repo file placed in the image.
Licences are what Cargo declares for a crate; a Debian package's licence is
not machine-read here, so it is NOASSERTION, never a guess.

provenance.json is an in-toto Statement v1 with a SLSA provenance v1
predicate: the builder identity (the tools tree's content hash, mkosi's pin,
the builder commit), every input pin the build read, the build epoch and
seed, and the output digests as subjects.
"""

from __future__ import annotations

import json
import re
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from .model import ARCH, LOCK, PACKAGES, RELEASE, Model, Plan
from .util import MissingPin, sha256_bytes, sha256_file

SBOM = "sbom.spdx.json"
PROVENANCE = "provenance.json"
SBOM_MEDIA_TYPE = "application/spdx+json"
PROVENANCE_MEDIA_TYPE = "application/vnd.in-toto+json"
REPO = "https://github.com/oneiron-dev/oneiron"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
NOASSERTION = "NOASSERTION"
DISTRO = "debian-13"


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _spdx_id(kind: str, index: int, name: str) -> str:
    return f"SPDXRef-{kind}-{index}-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def _cargo_lock(engine: Path) -> dict[tuple[str, str], dict]:
    with open(engine / "Cargo.lock", "rb") as stream:
        lock = tomllib.load(stream)
    return {(p["name"], p["version"]): p for p in lock.get("package", [])}


def _cargo_tree(path: Path) -> dict[tuple[str, str], str]:
    """{(name, version): licence} from `cargo tree --prefix none --format '{p}|{l}'`."""
    found = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        package, _, licence = line.partition("|")
        licence = licence.removesuffix("(*)").strip()
        parts = package.split()
        if len(parts) < 2 or not parts[1].startswith("v"):
            continue
        found[(parts[0], parts[1][1:])] = licence
    return found


def cargo_closures(build_dir: Path, plan: Plan) -> dict[str, dict]:
    """{package: {"normal": {...}, "build": {...}}} for every package the plan built natively."""
    out = {}
    for package in dict.fromkeys(n["package"] for n in plan.native):
        trees = {}
        for edges, key in (("normal", "normal"), ("normal+build", "build")):
            hits = sorted(build_dir.rglob(f"sbom-cargo-{package}-{edges}.txt"))
            if not hits:
                raise MissingPin(f"no cargo tree for {package} ({edges}) under {build_dir}: the build script writes it")
            trees[key] = _cargo_tree(hits[0])
        trees["build"] = {k: v for k, v in trees["build"].items() if k not in trees["normal"]}
        out[package] = trees
    return out


def store_crates(cargo_home: Path, lock: dict[tuple[str, str], dict]) -> list[dict]:
    """The lock entries the offline Cargo store holds: crate archives and git sources."""
    by_file = {f"{name}-{version}.crate": entry for (name, version), entry in lock.items()}
    held = []
    for crate in sorted((cargo_home / "registry" / "cache").glob("*/*.crate")):
        entry = by_file.get(crate.name)
        if entry is not None:
            held.append(entry)
    if any((cargo_home / "git" / "db").glob("*")):
        held += [e for e in lock.values() if str(e.get("source", "")).startswith("git+")]
    return held


def _cargo_package(index: int, name: str, version: str, entry: dict | None, licence: str | None,
                   commit: str) -> dict:
    source = (entry or {}).get("source", "")
    pkg = {
        "SPDXID": _spdx_id("cargo", index, f"{name}-{version}"),
        "name": name,
        "versionInfo": version,
        "supplier": NOASSERTION,
        "filesAnalyzed": False,
        "licenseConcluded": NOASSERTION,
        "licenseDeclared": licence or NOASSERTION,
        "copyrightText": NOASSERTION,
    }
    if source == CRATES_IO:
        pkg["downloadLocation"] = f"https://crates.io/api/v1/crates/{name}/{version}/download"
        pkg["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                "referenceLocator": f"pkg:cargo/{name}@{version}"}]
        if entry.get("checksum"):
            pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": entry["checksum"]}]
    elif source.startswith("git+"):
        url, _, rev = source.removeprefix("git+").partition("#")
        pkg["downloadLocation"] = f"git+{url.split('?')[0]}@{rev}"
        pkg["sourceInfo"] = f"git source pinned by Cargo.lock at {rev}"
    else:
        # A path package: a workspace crate or a vendored snapshot in the engine tree.
        pkg["downloadLocation"] = f"git+{REPO}@{commit}"
        pkg["sourceInfo"] = f"path package in the engine tree at {commit}"
    return pkg


def sbom(model: Model, record: dict, plan: Plan, *, closures: dict, store: list[dict],
         lock: dict[tuple[str, str], dict]) -> dict:
    variant = record["variant"]
    commit = record["engine_commit"]
    epoch = model.epoch()
    manifest_hex = record["oci_manifest_digest"].removeprefix("sha256:")
    image_id = "SPDXRef-image"
    packages = [{
        "SPDXID": image_id,
        "name": f"oneiron-image-{variant}",
        "versionInfo": record["oci_manifest_digest"],
        "supplier": "Organization: Oneiron",
        "downloadLocation": NOASSERTION,
        "filesAnalyzed": False,
        "licenseConcluded": NOASSERTION,
        "licenseDeclared": NOASSERTION,
        "copyrightText": NOASSERTION,
        "primaryPackagePurpose": "CONTAINER",
        "checksums": [{"algorithm": "SHA256", "checksumValue": record["oci_archive_sha256"]}],
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                          "referenceLocator": f"pkg:oci/oneiron-image-{variant}@sha256%3A{manifest_hex}?arch=amd64"}],
        "comment": f"built from engine commit {commit}; rootfs.tar sha256 {record['tar']['sha256']}"
                   + (f"; rootfs.ext4 sha256 {record['ext4_sha256']}" if record.get("ext4_sha256") else ""),
    }]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                      "relatedSpdxElement": image_id}]

    def contains(parent: str, child: str, kind: str = "CONTAINS") -> None:
        relationships.append({"spdxElementId": parent, "relationshipType": kind, "relatedSpdxElement": child})

    debs = {(e["name"], e["version"], e["arch"]): e for e in model.lock_entries()}
    for index, (name, version, arch) in enumerate(record["packages"]):
        entry = debs.get((name, version, arch), {})
        pkg = {
            "SPDXID": _spdx_id("deb", index, name),
            "name": name,
            "versionInfo": version,
            "supplier": "Organization: Debian",
            "downloadLocation": NOASSERTION,
            "filesAnalyzed": False,
            "licenseConcluded": NOASSERTION,
            "licenseDeclared": NOASSERTION,
            "copyrightText": NOASSERTION,
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": f"pkg:deb/debian/{name}@{version}?arch={arch}&distro={DISTRO}"}],
            "comment": f"{entry.get('filename', '?')} from snapshot {model.inputs('debian', 'snapshot')}",
        }
        if entry.get("sha256"):
            pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": entry["sha256"]}]
        packages.append(pkg)
        contains(image_id, pkg["SPDXID"])

    cargo_ids: dict[tuple[str, str], str] = {}

    def cargo_id(name: str, version: str, licence: str | None) -> str:
        key = (name, version)
        if key not in cargo_ids:
            pkg = _cargo_package(len(cargo_ids), name, version, lock.get(key), licence, commit)
            packages.append(pkg)
            cargo_ids[key] = pkg["SPDXID"]
        return cargo_ids[key]

    bins = record["native"].get("bins", {})
    for index, entry in enumerate(plan.native):
        dest = entry["dest"]
        bin_id = _spdx_id("bin", index, entry["bin"])
        pkg = {
            "SPDXID": bin_id,
            "name": entry["bin"],
            "versionInfo": commit,
            "supplier": "Organization: Oneiron",
            "downloadLocation": f"git+{REPO}@{commit}",
            "filesAnalyzed": False,
            "licenseConcluded": NOASSERTION,
            "licenseDeclared": NOASSERTION,
            "copyrightText": NOASSERTION,
            "primaryPackagePurpose": "APPLICATION",
            "comment": f"{dest}: cargo package {entry['package']}, built in the image's userspace "
                       f"({record['native'].get('rustc', '?')})",
        }
        if bins.get(dest):
            pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": bins[dest]}]
        packages.append(pkg)
        contains(image_id, bin_id)
        closure = closures[entry["package"]]
        for (name, version), licence in sorted(closure["normal"].items()):
            contains(bin_id, cargo_id(name, version, licence))
        for (name, version), licence in sorted(closure["build"].items()):
            relationships.append({"spdxElementId": cargo_id(name, version, licence),
                                  "relationshipType": "BUILD_DEPENDENCY_OF", "relatedSpdxElement": bin_id})

    if store:
        dest = next(t["dest"] for t in plan.trees if t["kind"] == "cargo-store")
        for entry in store:
            child = cargo_id(entry["name"], entry["version"], None)
            relationships.append({"spdxElementId": image_id, "relationshipType": "CONTAINS",
                                  "relatedSpdxElement": child, "comment": f"source archive in {dest}"})

    for index, entry in enumerate(plan.payloads):
        payload = model.payload(entry["pin"])
        if payload["kind"] == "rust-toolchain":
            comps = model.inputs("rust", "components")
            for comp in payload["components"]:
                pkg = {
                    "SPDXID": _spdx_id("rust", index, comp),
                    "name": f"rust-{comp}",
                    "versionInfo": model.inputs("rust", "version"),
                    "supplier": "Organization: The Rust Project",
                    "downloadLocation": comps[comp]["url"],
                    "filesAnalyzed": False,
                    "licenseConcluded": NOASSERTION,
                    "licenseDeclared": "MIT OR Apache-2.0",
                    "copyrightText": NOASSERTION,
                    "checksums": [{"algorithm": "SHA256", "checksumValue": comps[comp]["sha256"]}],
                    "comment": f"installed under {entry['dest']}",
                }
                packages.append(pkg)
                contains(image_id, pkg["SPDXID"])
            continue
        pkg = {
            "SPDXID": _spdx_id("payload", index, entry["pin"]),
            "name": entry["pin"],
            "versionInfo": str(payload.get("version", NOASSERTION)),
            "supplier": NOASSERTION,
            "downloadLocation": payload.get("url", NOASSERTION),
            "filesAnalyzed": False,
            "licenseConcluded": NOASSERTION,
            "licenseDeclared": NOASSERTION,
            "copyrightText": NOASSERTION,
            "comment": f"installed at {entry['dest']}",
        }
        if payload.get("sha256"):
            pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": payload["sha256"]}]
        packages.append(pkg)
        contains(image_id, pkg["SPDXID"])

    for index, entry in enumerate(plan.files):
        pin = model.pinned_file(entry["pin"])
        pkg = {
            "SPDXID": _spdx_id("file", index, entry["pin"]),
            "name": entry["pin"],
            "versionInfo": commit,
            "supplier": "Organization: Oneiron",
            "downloadLocation": f"git+{REPO}@{commit}#{pin['path']}",
            "filesAnalyzed": False,
            "licenseConcluded": NOASSERTION,
            "licenseDeclared": NOASSERTION,
            "copyrightText": NOASSERTION,
            "checksums": [{"algorithm": "SHA256", "checksumValue": pin["sha256"]}],
            "comment": f"repo file {pin['path']} installed at {entry['dest']}",
        }
        packages.append(pkg)
        contains(image_id, pkg["SPDXID"])

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"oneiron-image-{variant}-{ARCH.replace('/', '-')}",
        "documentNamespace": f"{REPO}/images/{variant}/{record['oci_manifest_digest']}",
        "creationInfo": {
            # The build epoch, not the wall clock: the document describes that build.
            "created": _iso(epoch),
            "creators": [f"Tool: oneiron-images-build.py-{record['builder_commit'][:12]}",
                         "Organization: Oneiron"],
            "comment": "Unsigned. Debian licences are NOASSERTION (not machine-read); "
                       "Cargo licences are as each crate declares.",
        },
        "documentDescribes": [image_id],
        "packages": packages,
        "relationships": relationships,
    }


def provenance(model: Model, record: dict, plan: Plan, *, sbom_sha: str) -> dict:
    inputs = model.inputs()
    commit = record["engine_commit"]
    subjects = [
        {"name": Path(record["oci_archive"]).name, "digest": {"sha256": record["oci_archive_sha256"]}},
        {"name": "oci-manifest", "digest": {"sha256": record["oci_manifest_digest"].removeprefix("sha256:")}},
        {"name": "oci-config", "digest": {"sha256": record["oci_config_digest"].removeprefix("sha256:")}},
        {"name": "rootfs.tar", "digest": {"sha256": record["tar"]["sha256"]}},
    ]
    if record.get("ext4_sha256"):
        subjects.append({"name": "rootfs.ext4", "digest": {"sha256": record["ext4_sha256"]}})
    base = inputs["base"]
    deps = [
        {"name": "engine", "uri": f"git+{REPO}@{commit}", "digest": {"gitCommit": commit}},
        {"name": "builder", "uri": f"git+{REPO}@{record['builder_commit']}",
         "digest": {"gitCommit": record["builder_commit"]}},
        {"name": "Cargo.lock", "digest": {"sha256": inputs["engine"]["cargo_lock_sha256"]}},
        {"name": "base-layer", "uri": f"oci://{base['image']}@{base['index_digest']}",
         "digest": {"sha256": base["layer_digest"].removeprefix("sha256:")},
         "annotations": {"platform": base["platform"], "manifest_digest": base["manifest_digest"],
                         "use": "bootstrap tree for the tools tree only; not in the image"}},
        {"name": "mkosi", "uri": inputs["mkosi"]["archive_url"],
         "digest": {"sha256": inputs["mkosi"]["archive_sha256"], "gitCommit": inputs["mkosi"]["commit"]}},
        {"name": "packages.lock.toml", "digest": {"sha256": record["packages_lock_sha256"]},
         "annotations": {"snapshot": inputs["debian"]["snapshot"]}},
    ]
    for source in inputs["debian"]["sources"]:
        deps.append({"name": f"debian-{source['name']}", "uri": source["uri"],
                     "annotations": {"suite": source["suite"], "components": " ".join(source["components"]),
                                     "signed_by": inputs["debian"]["keyring"]}})
    for name, comp in sorted(inputs["rust"]["components"].items()):
        deps.append({"name": f"rust-{name}", "uri": comp["url"], "digest": {"sha256": comp["sha256"]}})
    for name, dep in sorted(inputs["engine"].get("git_dependencies", {}).items()):
        deps.append({"name": f"git-dependency-{name}", "uri": f"git+{dep['url']}", "digest": {"gitCommit": dep["rev"]}})
    for entry in plan.payloads:
        payload = model.payload(entry["pin"])
        if payload.get("sha256"):
            deps.append({"name": f"payload-{entry['pin']}", "uri": payload["url"], "digest": {"sha256": payload["sha256"]}})
    for key, pin in sorted(inputs["files"].items()):
        deps.append({"name": f"file-{key}", "uri": f"git+{REPO}@{commit}#{pin['path']}",
                     "digest": {"sha256": pin["sha256"]}})
    byproducts = [{"name": SBOM, "mediaType": SBOM_MEDIA_TYPE, "digest": {"sha256": sbom_sha}}]
    if record["tar"].get("members_sha256"):
        byproducts.append({"name": "rootfs.members.tsv", "digest": {"sha256": record["tar"]["members_sha256"]}})
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": f"{REPO}/tree/main/crates/oneiron-container/images#build.py-mkosi-v1",
                "externalParameters": {
                    "variant": record["variant"],
                    "platform": ARCH,
                    "release_toml_sha256": sha256_file(RELEASE),
                    "packages_toml_sha256": sha256_file(PACKAGES),
                    "packages_lock_sha256": sha256_file(LOCK),
                },
                "internalParameters": {
                    "source_date_epoch": model.epoch(),
                    "seed": str(model.seed()),
                    "rootfs_uuid": str(model.rootfs_uuid(record["variant"])),
                    "network": "none in the build phase (a user namespace with no network)",
                    "privilege": "unprivileged: one uid mapped to root in a user namespace",
                },
                "resolvedDependencies": deps,
            },
            "runDetails": {
                "builder": {
                    "id": f"{REPO}/crates/oneiron-container/images/build.py@{record['builder_commit']}",
                    "version": {"mkosi": inputs["mkosi"]["version"],
                                "tools_tree_sha256": record["tools_tree_sha256"]},
                    "builderDependencies": [
                        {"name": "tools-tree", "digest": {"sha256": record["tools_tree_sha256"]}},
                        {"name": "rustc", "annotations": {"version": str(record["native"].get("rustc"))}},
                    ],
                },
                "metadata": {
                    "invocationId": f"{record['host']}/{record.get('started', '')}",
                    "startedOn": record.get("started"),
                    "finishedOn": record.get("finished"),
                },
                "byproducts": byproducts,
            },
        },
    }


def _write(path: Path, value: dict) -> str:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(data)
    return sha256_bytes(data)


def write(model: Model, record: dict, plan: Plan, *, build_dir: Path, engine: Path, cargo_home: Path) -> dict:
    """Writes sbom.spdx.json and provenance.json beside the artifacts; returns their refs."""
    artifacts = Path(record["artifacts"])
    lock = _cargo_lock(engine)
    closures = cargo_closures(build_dir, plan)
    store = store_crates(cargo_home, lock) if any(t["kind"] == "cargo-store" for t in plan.trees) else []
    document = sbom(model, record, plan, closures=closures, store=store, lock=lock)
    sbom_sha = _write(artifacts / SBOM, document)
    statement = provenance(model, record, plan, sbom_sha=sbom_sha)
    provenance_sha = _write(artifacts / PROVENANCE, statement)
    return {
        "sbom": {"media_type": SBOM_MEDIA_TYPE, "path": SBOM, "sha256": sbom_sha,
                 "packages": len(document["packages"])},
        "provenance": {"media_type": PROVENANCE_MEDIA_TYPE, "path": PROVENANCE, "sha256": provenance_sha},
    }
