"""release.toml, packages.toml and packages.lock.toml: loading, validation, overlay resolution.

release.toml is the one release list (frozen inputs, built outputs, budgets).
packages.toml holds requests only: the tools tree, [base] and the five variant
overlays. packages.lock.toml is the resolved closure the first fetch writes.
Nothing here downloads or builds.
"""

from __future__ import annotations

import re
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .util import (
    BadPin,
    MissingPin,
    PinMismatch,
    canonical_json,
    require_digest,
    require_hex64,
    sha256_bytes,
)

HERE = Path(__file__).resolve().parent.parent
RELEASE = HERE / "release.toml"
PACKAGES = HERE / "packages.toml"
LOCK = HERE / "packages.lock.toml"

VARIANTS = ("vault", "browser", "desktop-cua", "checker", "generic-agent")
BUILDABLE = ("tools", "base", *VARIANTS)
ARCH = "linux/amd64"
OUTPUT_STATES = ("unbuilt", "built-candidate", "boot-proved", "released")
# What a built-candidate output must carry; anything else stays absent until measured.
BUILT_FIELDS = (
    "builder_commit", "engine_commit", "host", "tools_tree_sha256", "packages_lock_sha256",
    "oci_index_digest", "oci_manifest_digest", "oci_config_digest", "oci_layer_digest",
    "oci_layer_diff_id", "oci_archive_sha256", "compressed_bytes", "unpacked_bytes",
    "sbom_sha256", "provenance_sha256", "receipt_sha256",
)
# The Firecracker rootfs: present, or refused at the engine's cap (ext4_refused names why).
EXT4_FIELDS = ("ext4_sha256", "ext4_uuid", "sparse_capacity_bytes")
DEB_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")
SNAPSHOT = re.compile(r"\d{8}T\d{6}Z")
MODE = re.compile(r"0[0-7]{3,4}")
# An npm tarball's pin: its registry SRI integrity, sha512 only.
SRI_SHA512 = re.compile(r"sha512-[A-Za-z0-9+/]{86}==")


def load_toml(path: Path) -> dict:
    try:
        with open(path, "rb") as stream:
            return tomllib.load(stream)
    except FileNotFoundError:
        raise MissingPin(f"{path.name} is missing") from None


@dataclass
class Plan:
    """One build's resolved requests: what goes in, where, and how it is entered."""

    name: str
    phase: int
    packages: list[str]
    build_packages: list[str]
    native: list[dict] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    payloads: list[dict] = field(default_factory=list)
    trees: list[dict] = field(default_factory=list)
    source_builds: list[dict] = field(default_factory=list)
    launchers: list[dict] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)
    dirs: list[dict] = field(default_factory=list)
    user: dict | None = None
    image: dict = field(default_factory=dict)

    def requests_sha256(self) -> str:
        return sha256_bytes(canonical_json({
            "packages": sorted(self.packages),
            "build_packages": sorted(self.build_packages),
        }))


class Model:
    def __init__(self, release: dict, packages: dict, lock: dict | None):
        self.release = release
        self.packages = packages
        self.lock = lock

    @classmethod
    def load(cls) -> "Model":
        lock = load_toml(LOCK) if LOCK.exists() else None
        return cls(load_toml(RELEASE), load_toml(PACKAGES), lock)

    # -- inputs ------------------------------------------------------------

    def inputs(self, *path: str):
        node = self.release.get("inputs", {})
        for key in path:
            if not isinstance(node, dict) or key not in node:
                raise MissingPin("release.toml has no [inputs." + ".".join(path) + "]")
            node = node[key]
        return node

    def engine_commit(self) -> str:
        commit = self.inputs("engine", "commit")
        if not COMMIT.fullmatch(commit):
            raise BadPin(f"inputs.engine.commit must be a full 40-hex commit, got {commit!r}")
        return commit

    def pinned_file(self, key: str) -> dict:
        files = self.inputs("files")
        if key not in files:
            raise MissingPin(f"no [inputs.files.{key}] pin in release.toml")
        return files[key]

    def payload(self, key: str) -> dict:
        payloads = self.inputs("payloads")
        if key not in payloads:
            raise MissingPin(f"no [inputs.payloads.{key}] pin in release.toml")
        return payloads[key]

    def epoch(self) -> int:
        value = self.inputs("build", "source_date_epoch")
        if not isinstance(value, int) or value <= 0:
            raise BadPin("inputs.build.source_date_epoch must be a positive integer")
        return value

    def seed(self) -> uuid.UUID:
        return uuid.UUID(self.inputs("build", "seed"))

    def rootfs_uuid(self, variant: str) -> uuid.UUID:
        return uuid.uuid5(self.seed(), f"{variant}/x86_64")

    # -- requests ----------------------------------------------------------

    def plan(self, name: str) -> Plan:
        if name not in BUILDABLE:
            raise BadPin(f"unknown variant {name!r}; one of: {', '.join(BUILDABLE)}")
        doc = self.packages
        if name == "tools":
            tools = doc["tools"]
            return Plan("tools", 1, list(tools["packages"]), [])
        base = doc["base"]
        plumbing_doc = base.get("plumbing", {})
        overlay = {} if name == "base" else doc["variants"][name]
        plumbing = overlay.get("plumbing", True)
        image = dict(plumbing_doc.get("image", {})) if plumbing else {}
        env = {e.split("=", 1)[0]: e for e in image.get("env", [])}
        for entry in overlay.get("image", {}).get("env", []):
            env[entry.split("=", 1)[0]] = entry
        image.update({k: v for k, v in overlay.get("image", {}).items() if k != "env"})
        image["env"] = sorted(env.values())

        def both(key: str, base_part: dict) -> list:
            return list(base_part.get(key, [])) + list(overlay.get(key, []))

        return Plan(
            name=name,
            phase=self.release.get("variants", {}).get(name, {}).get("phase", 1),
            packages=both("packages", base),
            build_packages=both("build_packages", base),
            native=(list(plumbing_doc.get("native", [])) if plumbing else []) + list(overlay.get("native", [])),
            files=both("files", base),
            payloads=both("payloads", base),
            trees=both("trees", base),
            source_builds=both("source_builds", base),
            launchers=both("launchers", base),
            links=(list(plumbing_doc.get("links", [])) if plumbing else []) + list(overlay.get("links", [])),
            dirs=both("dirs", base),
            user=plumbing_doc.get("user") if plumbing else overlay.get("user"),
            image=image,
        )

    # -- lock --------------------------------------------------------------

    def lock_entries(self) -> list[dict]:
        if self.lock is None:
            raise MissingPin("packages.lock.toml is missing: run `build.py fetch --learn` once, commit the lock")
        return self.lock.get("package", [])

    def check_lock_covers(self, plan: Plan) -> None:
        if self.lock is None:
            raise MissingPin("packages.lock.toml is missing: run `build.py fetch --learn` once, commit the lock")
        scope = self.lock.get("scopes", {}).get(plan.name)
        if scope is None:
            raise MissingPin(f"packages.lock.toml has no [scopes.{plan.name}]: run `build.py fetch --learn`")
        if scope.get("requests_sha256") != plan.requests_sha256():
            raise PinMismatch(
                f"packages.toml requests for {plan.name} changed since packages.lock.toml was "
                "learned: rerun `build.py fetch --learn` and commit the new lock"
            )


# -- validation --------------------------------------------------------------


def _walk(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, f"{path}.{key}" if path else key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")
    else:
        yield path, node


def _check_values(doc: dict, name: str, problems: list[str]) -> None:
    for path, value in _walk(doc):
        key = path.rsplit(".", 1)[-1].split("[", 1)[0]
        if isinstance(value, str) and re.search(r"(^|[/:@=\s])latest($|[/\s])", value.lower()):
            problems.append(f"{name}: {path} names a moving 'latest' reference: {value!r}")
        try:
            if key == "sha256" or key.endswith("_sha256"):
                require_hex64(value, f"{name}: {path}")
            elif key == "digest" or key.endswith("_digest") or key.endswith("_diff_id"):
                require_digest(value, f"{name}: {path}")
            elif (key in ("commit", "rev") or key.endswith("_commit")) and not COMMIT.fullmatch(str(value)):
                problems.append(f"{name}: {path} must be a full 40-hex commit, got {value!r}")
            elif key == "mode" and not MODE.fullmatch(str(value)):
                problems.append(f"{name}: {path} must be an octal mode string like \"0555\"")
            elif key == "integrity" and not SRI_SHA512.fullmatch(str(value)):
                problems.append(f"{name}: {path} must be an npm sha512 SRI integrity, got {value!r}")
        except BadPin as error:
            problems.append(error.message)


def _check_outputs(name: str, outputs: dict, problems: list[str]) -> None:
    if set(outputs) != {ARCH}:
        problems.append(f"release.toml: variants.{name}.outputs must hold exactly \"{ARCH}\"")
        return
    out = outputs[ARCH]
    state = out.get("state")
    if state not in OUTPUT_STATES:
        problems.append(f"release.toml: variants.{name} output state {state!r} not in {OUTPUT_STATES}")
    elif state == "unbuilt":
        extra = sorted(k for k in out if k not in ("state", "note"))
        if extra:
            problems.append(f"release.toml: variants.{name} is unbuilt but carries {extra}; unbuilt fields stay absent")
    else:
        refused = "ext4_refused" in out
        missing = [k for k in BUILT_FIELDS + (() if refused else EXT4_FIELDS) if k not in out]
        if missing:
            problems.append(f"release.toml: variants.{name} is {state} but lacks {missing}")
        if refused and any(k in out for k in EXT4_FIELDS):
            problems.append(f"release.toml: variants.{name} names ext4_refused and an ext4 output at once")
    for key, value in out.items():
        if isinstance(value, int) and value <= 0:
            problems.append(f"release.toml: variants.{name}.{key} is {value}; a zero is never a measurement")


def _check_requests(model: Model, problems: list[str]) -> None:
    doc = model.packages
    if doc.get("schema") != 1:
        problems.append("packages.toml: schema must be 1")
    for section in ("tools", "base", "variants"):
        if section not in doc:
            problems.append(f"packages.toml: [{section}] is missing")
    if problems:
        return
    missing = [v for v in VARIANTS if v not in doc["variants"]]
    if missing:
        problems.append(f"packages.toml: overlay sections missing for {missing}")
    files = model.release.get("inputs", {}).get("files", {})
    payloads = model.release.get("inputs", {}).get("payloads", {})
    for name in BUILDABLE:
        if name in missing:
            continue
        plan = model.plan(name)
        for kind, names in (("packages", plan.packages), ("build_packages", plan.build_packages)):
            seen = set()
            for pkg in names:
                if not DEB_NAME.fullmatch(pkg):
                    problems.append(f"packages.toml: {name}.{kind} entry {pkg!r} is not a bare Debian package name")
                if pkg in seen:
                    problems.append(f"packages.toml: {name}.{kind} lists {pkg!r} twice")
                seen.add(pkg)
        for entry in plan.files:
            if entry.get("pin") not in files:
                problems.append(f"packages.toml: {name} file pin {entry.get('pin')!r} has no [inputs.files] entry")
        for entry in [*plan.payloads, *plan.source_builds]:
            if entry.get("pin") not in payloads:
                problems.append(f"packages.toml: {name} payload pin {entry.get('pin')!r} has no [inputs.payloads] entry")
        for entry in [*plan.native, *plan.files, *plan.payloads, *plan.trees, *plan.links, *plan.source_builds,
                      *plan.launchers]:
            dest = entry.get("dest", entry.get("path", ""))
            if not str(dest).startswith("/usr/") and not str(dest).startswith("/opt/"):
                problems.append(f"packages.toml: {name} places {dest!r} outside /usr or /opt (merged-usr image)")
        for entry in plan.launchers:
            for key in ("runtime", "entry"):
                value = str(entry.get(key, ""))
                if not value.startswith("/") or any(c in value for c in "\"'$`\\ \n"):
                    problems.append(f"packages.toml: {name} launcher {entry.get('path')!r} {key} {value!r} "
                                    "must be an absolute path with no shell metacharacters")


def _check_lock(model: Model, problems: list[str], notes: list[str]) -> None:
    lock = model.lock
    if lock is None:
        notes.append("packages.lock.toml absent: the first `fetch --learn` writes it")
        return
    if lock.get("schema") != 1:
        problems.append("packages.lock.toml: schema must be 1")
    if lock.get("snapshot") != model.release["inputs"]["debian"]["snapshot"]:
        problems.append("packages.lock.toml: snapshot differs from release.toml inputs.debian.snapshot")
    for scope, entry in lock.get("scopes", {}).items():
        if scope not in BUILDABLE:
            problems.append(f"packages.lock.toml: unknown scope {scope!r}")
        elif entry.get("requests_sha256") != model.plan(scope).requests_sha256():
            problems.append(f"packages.lock.toml: scope {scope} is stale against packages.toml (rerun fetch --learn)")
    names = set()
    for entry in lock.get("package", []):
        for key in ("name", "version", "arch", "filename", "size", "sha256"):
            if key not in entry:
                problems.append(f"packages.lock.toml: a package entry lacks {key}: {entry}")
        if entry.get("filename") in names:
            problems.append(f"packages.lock.toml: {entry.get('filename')} appears twice")
        names.add(entry.get("filename"))
    scopes = sorted(lock.get("scopes", {}))
    notes.append(f"packages.lock.toml: {len(names)} packages, scopes {scopes}")


def validate(model: Model) -> list[str]:
    """Returns notes; raises BadPin listing every problem found."""
    problems: list[str] = []
    notes: list[str] = []
    rel = model.release
    if rel.get("schema") != 1:
        problems.append("release.toml: schema must be 1")
    _check_values(rel, "release.toml", problems)
    _check_values(model.packages, "packages.toml", problems)
    if model.lock is not None:
        _check_values(model.lock, "packages.lock.toml", problems)
    if set(rel.get("arch", {})) != {ARCH}:
        problems.append(f"release.toml: [arch] must name exactly \"{ARCH}\" (x86_64 only in this release)")
    variants = rel.get("variants", {})
    for name in ("base", *VARIANTS):
        if name not in variants:
            problems.append(f"release.toml: [variants.{name}] is missing")
            continue
        budget = variants[name].get("budget", {})
        if budget.get("status") != "proposed":
            problems.append(f"release.toml: variants.{name}.budget.status must be \"proposed\"")
        _check_outputs(name, variants[name].get("outputs", {}), problems)
    extra = sorted(set(variants) - {"base", *VARIANTS})
    if extra:
        problems.append(f"release.toml: unknown variants {extra}")
    debian = rel.get("inputs", {}).get("debian", {})
    snapshot = debian.get("snapshot", "")
    if not SNAPSHOT.fullmatch(snapshot):
        problems.append(f"release.toml: inputs.debian.snapshot {snapshot!r} is not YYYYMMDDTHHMMSSZ")
    names = {s.get("name") for s in debian.get("sources", [])}
    if names != {"main", "updates", "security"}:
        problems.append("release.toml: inputs.debian.sources must be exactly main, updates and security")
    for source in debian.get("sources", []):
        if snapshot not in source.get("uri", ""):
            problems.append(f"release.toml: debian source {source.get('name')} is not pinned to the snapshot")
    if debian.get("signature_check") is not True:
        problems.append("release.toml: inputs.debian.signature_check must stay true")
    rust = rel.get("inputs", {}).get("rust", {})
    for comp in rust.get("builder_components", []):
        if comp not in rust.get("components", {}):
            problems.append(f"release.toml: rust builder component {comp} has no pin")
    try:
        model.engine_commit()
        model.epoch()
        model.seed()
    except (BadPin, MissingPin, ValueError) as error:
        problems.append(f"release.toml: {error}")
    _check_requests(model, problems)
    _check_lock(model, problems, notes)
    if problems:
        raise BadPin("\n  ".join(["release inputs are inconsistent:", *problems]))
    return notes
