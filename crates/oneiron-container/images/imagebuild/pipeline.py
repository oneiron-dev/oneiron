"""fetch (online) and build (offline): the two phases build.py runs."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

from . import export, mkosi_run, owners
from .fetch import (
    Mirror,
    bootstrap_tree,
    cargo_fetch,
    closure,
    deb_files,
    engine_tree,
    fetch_blob,
    install_rust,
    lock_text,
    mkosi_source,
    verify_closure,
)
from .model import LOCK, Model, Plan
from .util import BuildError, HostRefusal, MissingPin, PinMismatch, log, run, sha256_file, write_json

TOOLS_MARK = ".oneiron-tools-sha256"


def _payload_blobs(model: Model, mirror: Mirror, plans: list[Plan]) -> None:
    for plan in plans:
        for entry in plan.payloads:
            payload = model.payload(entry["pin"])
            if payload["kind"] in ("file", "archive"):
                fetch_blob(mirror, payload["url"], payload["sha256"], learn=False, what=f"payload {entry['pin']}")


def _sources(engine: Path, rust: Path, mirror: Mirror, plan_dir: Path) -> dict[str, Path]:
    return {"engine": engine, "rust": rust, "cargo-home": mirror.cargo_home, "plan": plan_dir}


def fetch(model: Model, *, repo: Path, mirror: Mirror, work: Path, variants: list[str], learn: bool) -> None:
    mirror.prepare()
    before = set(deb_files(mirror))
    if learn and before:
        raise HostRefusal(
            f"fetch --learn needs an empty package cache, {mirror.archives} holds {len(before)} .deb files: "
            "point --mirror at a fresh directory, or drop --learn to verify against the committed lock"
        )
    plans = [model.plan(v) for v in variants]
    bootstrap = bootstrap_tree(model, mirror, work)
    mkosi_src = mkosi_source(model, mirror, work, learn=learn)
    rust = install_rust(model, mirror, model.inputs("rust", "builder_components"), work / "rust")
    engine = engine_tree(model, repo, work)
    cargo_fetch(mirror, engine, rust)
    _payload_blobs(model, mirror, plans)
    mkosi_run.sandbox_tree(model, work)
    tools = model.plan("tools")
    cfg, out = mkosi_run.write_config(model, tools, work=work, mirror=mirror, tools_tree=bootstrap, phase="fetch")
    mkosi_run.build(mkosi_src, cfg, work)
    fetched_tools = mkosi_run.finish_tools_tree(out)
    for plan in plans:
        plan_dir = mkosi_run.write_plan(model, plan, engine=engine, mirror=mirror, work=work)
        cfg, _ = mkosi_run.write_config(model, plan, work=work, mirror=mirror, tools_tree=fetched_tools,
                                        phase="fetch", sources=_sources(engine, rust, mirror, plan_dir))
        mkosi_run.build(mkosi_src, cfg, work)
    new = set(deb_files(mirror)) - before
    if learn:
        text = lock_text(model, closure(mirror), ["tools", *variants])
        LOCK.write_text(text)
        (work / "packages.lock.toml").write_text(text)
        log(f"LEARNED packages.lock.toml: {len(new)} packages, written to {LOCK}")
    else:
        for plan in [tools, *plans]:
            model.check_lock_covers(plan)
        for warning in verify_closure(model, mirror, new=new):
            log(f"warning: {warning}")
    log(f"fetch done: mirror {mirror.root}")


def _tools_tree(model: Model, mirror: Mirror, work: Path, mkosi_src: Path, bootstrap: Path) -> tuple[Path, str]:
    out = work / "out-build" / "tools"
    mark = out / "tools" / TOOLS_MARK
    if mark.exists():
        recorded = mark.read_text().strip()
        mark.unlink()
        if export.tree_digest(out / "tools") == recorded:
            mark.write_text(recorded + "\n")
            log(f"tools tree reused: {recorded}")
            return out / "tools", recorded
    tools = model.plan("tools")
    model.check_lock_covers(tools)
    cfg, out = mkosi_run.write_config(model, tools, work=work, mirror=mirror, tools_tree=bootstrap, phase="build")
    mkosi_run.build(mkosi_src, cfg, work)
    tree = mkosi_run.finish_tools_tree(out)
    digest = export.tree_digest(tree)
    (tree / TOOLS_MARK).write_text(digest + "\n")
    log(f"tools tree (builder identity) sha256 {digest}")
    return tree, digest


def _deb_lookup(model: Model, mirror: Mirror):
    by_key = {(e["name"], e["version"], e["arch"]): mirror.archives / e["filename"] for e in model.lock_entries()}
    return lambda name, version, arch: by_key.get((name, version, arch))


def _zstd(cfg: Path, work: Path, mkosi_src: Path):
    def to_tar(deb: Path, start: int, size: int) -> Path:
        member = work / "tmp" / (deb.name + ".data.tar.zst")
        with open(deb, "rb") as src, open(member, "wb") as dst:
            src.seek(start)
            dst.write(src.read(size))
        mkosi_run.box(mkosi_src, cfg, work, ["zstd", "-q", "-d", "-f", str(member)])
        return member.with_suffix("")
    return to_tar


def _native_record(build_dir: Path) -> dict:
    record = {"bins": {}}
    for path in sorted(build_dir.rglob("native-record.tsv")):
        for line in path.read_text().splitlines():
            parts = line.split("\t")
            if parts[0] == "bin":
                record["bins"][parts[1]] = parts[2]
            else:
                record[parts[0]] = parts[1]
    return record


def build(model: Model, *, repo: Path, mirror: Mirror, work: Path, variant: str) -> dict:
    if os.environ.get("ONEIRON_IMAGES_OFFLINE") != "1":
        raise HostRefusal("build runs only inside its network-less namespace (build.py enters it itself)")
    plan = model.plan(variant)
    if plan.phase > 1 and variant != "tools":
        log(f"note: {variant} is a phase-{plan.phase} variant")
    for warning in verify_closure(model, mirror):
        log(f"warning: {warning}")
    bootstrap = bootstrap_tree(model, mirror, work)
    mkosi_src = mkosi_source(model, mirror, work, learn=False)
    rust = install_rust(model, mirror, model.inputs("rust", "builder_components"), work / "rust")
    engine = engine_tree(model, repo, work)
    mkosi_run.sandbox_tree(model, work)
    tools, tools_sha = _tools_tree(model, mirror, work, mkosi_src, bootstrap)
    if variant == "tools":
        return {"variant": "tools", "tools_tree_sha256": tools_sha, "tools_tree": str(tools)}
    model.check_lock_covers(plan)
    plan_dir = mkosi_run.write_plan(model, plan, engine=engine, mirror=mirror, work=work)
    cfg, out = mkosi_run.write_config(model, plan, work=work, mirror=mirror, tools_tree=tools, phase="build",
                                      sources=_sources(engine, rust, mirror, plan_dir))
    mkosi_run.build(mkosi_src, cfg, work)
    tree = out / variant
    if not tree.is_dir():
        raise BuildError(f"mkosi left no {variant} tree at {tree}")
    removed = export.clean_apivfs(tree)
    needles = [str(work.resolve()), str(mirror.root.resolve()), str(repo.resolve()), "/work/src/", "/work/build/"]
    home = os.path.expanduser("~")
    if home not in ("/", "/root"):
        needles.append(home + "/")
    export.leak_scan(tree, needles)
    packages = owners.installed(tree)
    rules = owners.resolve(tree, packages, _deb_lookup(model, mirror), plan_owner_rules(model, plan),
                           _zstd(cfg, work, mkosi_src))
    epoch = model.epoch()
    artifacts = work / "artifacts" / variant
    artifacts.mkdir(parents=True, exist_ok=True)
    tar = export.rootfs_tar(tree, artifacts / "rootfs.tar", epoch, rules)
    commit = model.engine_commit()
    builder = run(["git", "-C", repo, "rev-parse", "HEAD"], capture=True).stdout.strip()
    annotations = {"org.opencontainers.image.revision": commit,
                   "org.opencontainers.image.source": model.inputs("engine", "repository"),
                   "dev.oneiron.image.variant": variant,
                   "dev.oneiron.image.builder-commit": builder}
    oci = export.oci(tar, variant=variant, image=plan.image, epoch=epoch, out=artifacts, annotations=annotations)

    def in_tools(argv, env):
        mkosi_run.box(mkosi_src, cfg, work, argv, env_extra=env)

    ext4 = export.ext4(tar, uuid=str(model.rootfs_uuid(variant)), epoch=epoch, out=artifacts,
                       cap=model.release["limits"]["firecracker_rootfs_max_bytes"], run_in_tools=in_tools)
    native = _native_record(work / "cargo-build" / variant)
    record = {
        "variant": variant, "builder_commit": builder, "engine_commit": commit,
        "host": socket.gethostname(), "tools_tree_sha256": tools_sha,
        "packages_lock_sha256": sha256_file(LOCK), "mkosi": model.inputs("mkosi", "version"),
        "apivfs_removed": removed, "packages": [list(p) for p in packages],
        "ownership": {
            "rule": owners.__doc__.strip(),
            "non_root": {path: {"uid": u, "gid": g, "mode": None if m is None else f"{m:04o}", "source": s}
                         for path, (u, g, m, s) in sorted(rules.items())},
        },
        "native": native, "tar": tar, **oci, **ext4,
        "compressed_bytes": oci["oci_archive_bytes"], "unpacked_bytes": tar["file_bytes"],
        "artifacts": str(artifacts),
    }
    write_json(artifacts / "build-record.json", record)
    return record


def plan_owner_rules(model: Model, plan: Plan) -> list[dict]:
    base = model.packages["base"]
    overlay = {} if plan.name == "base" else model.packages["variants"].get(plan.name, {})
    return list(base.get("owners", [])) + list(overlay.get("owners", []))


def load_record(work: Path, variant: str) -> dict:
    path = work / "artifacts" / variant / "build-record.json"
    if not path.exists():
        raise MissingPin(f"no build record at {path}: run `build.py build --variant {variant}` first")
    return json.loads(path.read_text())


def check_record_inputs(model: Model, record: dict) -> None:
    if record["engine_commit"] != model.engine_commit():
        raise PinMismatch("the build record names a different engine commit than release.toml")
