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
Licences are what Cargo declares for a crate. A Debian package's declared
licence is read from its own /usr/share/doc/<package>/copyright in the built
image when that file is machine-readable (DEP-5, copyright-format 1.0); its
short names map to SPDX ids through DEBIAN_TO_SPDX alone, an unmapped name
with its text becomes a LicenseRef with that text extracted, and anything
else stays NOASSERTION with the reason in licenseComments. licenseConcluded
stays NOASSERTION throughout: this is the packager's declaration, not a
legal conclusion.

provenance.json is an in-toto Statement v1 with a SLSA provenance v1
predicate: the builder identity (the tools tree's content hash, mkosi's pin,
the builder commit), every input pin the build read, the build epoch and
seed, and the output digests as subjects.
"""

from __future__ import annotations

import hashlib
import json
import os
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
DEP5_FORMAT = "copyright-format/1.0"
# Debian copyright-format short names (and SPDX ids used as names) that are
# exactly one SPDX licence; matched case-insensitively. Names that are vague
# in Debian's own list (MIT, BSD, Artistic, Apache, GPL without a version,
# public-domain, ...) are left out on purpose: they become a LicenseRef
# carrying the package's own text. This table is the one place the mapping
# is decided (FIX 9356).
DEBIAN_TO_SPDX = {
    "agpl-3": "AGPL-3.0-only",
    "agpl-3+": "AGPL-3.0-or-later",
    "agpl-3.0-only": "AGPL-3.0-only",
    "agpl-3.0-or-later": "AGPL-3.0-or-later",
    "apache-2.0": "Apache-2.0",
    "artistic-2.0": "Artistic-2.0",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd-4-clause": "BSD-4-Clause",
    "cc0-1.0": "CC0-1.0",
    "expat": "MIT",
    "gpl-1": "GPL-1.0-only",
    "gpl-1+": "GPL-1.0-or-later",
    "gpl-2": "GPL-2.0-only",
    "gpl-2+": "GPL-2.0-or-later",
    "gpl-2.0-only": "GPL-2.0-only",
    "gpl-2.0-or-later": "GPL-2.0-or-later",
    "gpl-3": "GPL-3.0-only",
    "gpl-3+": "GPL-3.0-or-later",
    "gpl-3.0-only": "GPL-3.0-only",
    "gpl-3.0-or-later": "GPL-3.0-or-later",
    "isc": "ISC",
    "lgpl-2": "LGPL-2.0-only",
    "lgpl-2+": "LGPL-2.0-or-later",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-2.1+": "LGPL-2.1-or-later",
    "lgpl-2.1-only": "LGPL-2.1-only",
    "lgpl-2.1-or-later": "LGPL-2.1-or-later",
    "lgpl-3": "LGPL-3.0-only",
    "lgpl-3+": "LGPL-3.0-or-later",
    "lgpl-3.0-only": "LGPL-3.0-only",
    "lgpl-3.0-or-later": "LGPL-3.0-or-later",
    "mpl-1.1": "MPL-1.1",
    "mpl-2.0": "MPL-2.0",
    "ofl-1.1": "OFL-1.1",
    "python-2.0": "Python-2.0",
    "zlib": "Zlib",
}


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _spdx_id(kind: str, index: int, name: str) -> str:
    return f"SPDXRef-{kind}-{index}-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def _in_root(root: Path, rel: str) -> Path | None:
    """rel inside root, every symlink resolved against root (never the host's
    own /usr); None when it is missing or not a regular file."""
    parts = [p for p in rel.split("/") if p]
    held: list[str] = []
    hops = 0
    while parts:
        part = parts.pop(0)
        if part == ".":
            continue
        if part == "..":
            if held:
                held.pop()
            continue
        path = root.joinpath(*held, part)
        if path.is_symlink():
            hops += 1
            if hops > 40:
                return None
            target = os.readlink(path)
            if target.startswith("/"):
                held = []
            parts = [p for p in target.split("/") if p] + parts
            continue
        held.append(part)
    path = root.joinpath(*held)
    return path if path.is_file() and not path.is_symlink() else None


def _paragraphs(text: str) -> list[dict[str, str]] | None:
    """Control-file paragraphs, {lowercased field: raw value with its
    continuation lines}; None when a line fits no field."""
    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key = None
    for line in text.splitlines():
        if not line.strip():
            if current:
                paragraphs.append(current)
            current, key = {}, None
        elif line.startswith("#"):
            continue
        elif line[0] in " \t":
            if key is None:
                return None
            current[key] += "\n" + line
        else:
            name, sep, value = line.partition(":")
            if not sep or not name.strip():
                return None
            key = name.strip().lower()
            current[key] = value.strip()
    if current:
        paragraphs.append(current)
    return paragraphs


def _field(value: str) -> tuple[str, str]:
    """(first line, continuation text): one leading space dropped, ` .` a blank line."""
    first, _, rest = value.partition("\n")
    lines = []
    for line in rest.split("\n") if rest else []:
        line = line[1:] if line[:1] in (" ", "\t") else line
        lines.append("" if line.strip() == "." else line)
    return first.strip(), "\n".join(lines).strip("\n")


def _licence_ref(name: str, body: str, extracted: dict[str, dict]) -> str:
    licence_id = (f"LicenseRef-Debian-{re.sub(r'[^A-Za-z0-9.-]', '-', name)}-"
                  f"{hashlib.sha256(body.encode()).hexdigest()[:12]}")
    extracted.setdefault(licence_id, {"licenseId": licence_id, "name": name, "extractedText": body})
    return licence_id


def _expression(field: str, standalone: dict[str, str], extracted: dict[str, dict]) -> tuple[str | None, str]:
    """One Files paragraph's License field as an SPDX expression, or (None, why).
    Only a plain list joined by one operator (all `or` or all `and`) is read:
    commas, `with ... exception` and mixed operators are not written out."""
    first, text = _field(field)
    tokens = first.split()
    names, ops = tokens[0::2], [op.lower() for op in tokens[1::2]]
    if not tokens or len(tokens) % 2 == 0 or any(c in first for c in ",()"):
        return None, f"License {first!r} is not a plain list of short names"
    if any(op not in ("and", "or") for op in ops) or len(set(ops)) > 1:
        return None, f"License {first!r} uses an exception or mixes and/or"
    ids = []
    for name in names:
        spdx = DEBIAN_TO_SPDX.get(name.lower())
        if spdx is None:
            body = text if len(names) == 1 and text else standalone.get(name.lower(), "")
            if not body.strip():
                return None, f"{name} has no SPDX id and no licence text"
            spdx = _licence_ref(name, body, extracted)
        ids.append(spdx)
    return (" OR " if ops and ops[0] == "or" else " AND ").join(ids), ""


def debian_licence(rootfs: Path, package: str, extracted: dict[str, dict]) -> tuple[str, str]:
    """(licenseDeclared, licenseComments) for one installed package, from its
    copyright file in the built image. Every Files paragraph's expression
    applies to some of the package's files, so they are joined with AND."""
    rel = f"usr/share/doc/{package}/copyright"
    path = _in_root(rootfs, rel)
    if path is None:
        return NOASSERTION, f"no /{rel} in the image"
    try:
        paragraphs = _paragraphs(path.read_bytes().decode("utf-8"))
    except UnicodeDecodeError:
        paragraphs = None
    if not paragraphs or DEP5_FORMAT not in paragraphs[0].get("format", ""):
        return NOASSERTION, f"/{rel} is not machine-readable (no DEP-5 {DEP5_FORMAT} Format)"
    standalone = {}
    for paragraph in paragraphs[1:]:
        if "files" not in paragraph and "license" in paragraph:
            name, text = _field(paragraph["license"])
            standalone.setdefault(name.lower(), text)
    found = []
    scratch: dict[str, dict] = {}
    for paragraph in paragraphs[1:]:
        if "files" not in paragraph:
            continue
        if "license" not in paragraph:
            return NOASSERTION, f"/{rel}: a Files paragraph has no License"
        expression, why = _expression(paragraph["license"], standalone, scratch)
        if expression is None:
            return NOASSERTION, f"/{rel}: {why}"
        if expression not in found:
            found.append(expression)
    if not found:
        return NOASSERTION, f"/{rel} has no Files paragraph"
    extracted.update({k: v for k, v in scratch.items() if k not in extracted})
    declared = found[0] if len(found) == 1 else " AND ".join(f"({e})" if " " in e else e for e in found)
    return declared, f"declared in /{rel} (DEP-5): its distinct Files licences, joined with AND"


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
        # Cargo's old `MIT/Apache-2.0` form is not an SPDX expression; it means OR.
        licence = " OR ".join(part.strip() for part in licence.split("/")) if "/" in licence else licence
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
         lock: dict[tuple[str, str], dict], rootfs: Path) -> dict:
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
    extracted: dict[str, dict] = {}
    for index, (name, version, arch) in enumerate(record["packages"]):
        entry = debs.get((name, version, arch), {})
        declared, why = debian_licence(rootfs, name, extracted)
        pkg = {
            "SPDXID": _spdx_id("deb", index, name),
            "name": name,
            "versionInfo": version,
            "supplier": "Organization: Debian",
            "downloadLocation": NOASSERTION,
            "filesAnalyzed": False,
            "licenseConcluded": NOASSERTION,
            "licenseDeclared": declared,
            "licenseComments": why,
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

    document = {
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
            "comment": "Unsigned. A Debian package's licenseDeclared is read from its DEP-5 copyright "
                       "file in the image (NOASSERTION, with the reason, where that file is absent, not "
                       "DEP-5 or not representable); Cargo licences are as each crate declares; "
                       "licenseConcluded is NOASSERTION throughout.",
        },
        "documentDescribes": [image_id],
        "packages": packages,
        "relationships": relationships,
    }
    if extracted:
        document["hasExtractedLicensingInfos"] = [extracted[k] for k in sorted(extracted)]
    return document


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


def write(model: Model, record: dict, plan: Plan, *, build_dir: Path, engine: Path, cargo_home: Path,
          rootfs: Path) -> dict:
    """Writes sbom.spdx.json and provenance.json beside the artifacts; returns their refs.
    rootfs is the assembled image tree the licences are read from."""
    artifacts = Path(record["artifacts"])
    lock = _cargo_lock(engine)
    closures = cargo_closures(build_dir, plan)
    store = store_crates(cargo_home, lock) if any(t["kind"] == "cargo-store" for t in plan.trees) else []
    document = sbom(model, record, plan, closures=closures, store=store, lock=lock, rootfs=rootfs)
    sbom_sha = _write(artifacts / SBOM, document)
    statement = provenance(model, record, plan, sbom_sha=sbom_sha)
    provenance_sha = _write(artifacts / PROVENANCE, statement)
    return {
        "sbom": {"media_type": SBOM_MEDIA_TYPE, "path": SBOM, "sha256": sbom_sha,
                 "packages": len(document["packages"])},
        "provenance": {"media_type": PROVENANCE_MEDIA_TYPE, "path": PROVENANCE, "sha256": provenance_sha},
    }
