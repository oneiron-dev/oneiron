"""mkosi: the generated per-build config, the plan the hooks read, and the runs.

The repo's mkosi.conf / mkosi.tools.conf hold the fixed defaults; each build
gets a generated config directory in the work dir that includes one of them
and adds what comes from the TOMLs: packages, the tools tree, the mirror
paths, the epoch and seed. The hooks read their per-variant work from the
plan directory (tab-separated files), so no package or path list is
duplicated in a .conf file.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from . import payloads
from .fetch import Mirror, install_rust
from .model import HERE, Model, Plan
from .util import NotYetSupported, StepFailed, host_env, run

IMAGES = HERE
HOOKS = {
    "build": IMAGES / "mkosi.build.chroot",
    "postinst": IMAGES / "mkosi.postinst",
    "finalize": IMAGES / "mkosi.finalize",
}
# The snapshot sources sandbox_tree() writes, relative to its root; the
# finished tools tree carries the same file and no other source list.
SNAPSHOT_SOURCES = Path("etc/apt/sources.list.d/mkosi.sources")
# What write_plan() can install today, one installer per kind (INSTALLERS
# below); anything else is refused before a fetch.
SUPPORTED_PAYLOADS = ("file", "rust-toolchain", "archive", "npm")
SUPPORTED_TREES = ("cargo-store",)
# An external source build: a pinned archive compiled by Cargo in the build
# overlay, offline, from its own lock and store. These pin fields must be set.
SOURCE_BUILD_KIND = "source-build"
SOURCE_BUILD_FIELDS = ("archive_url", "archive_sha256", "extract", "workdir", "cargo_lock_sha256", "package",
                       "bin", "rust", "licence_files", "licence_dest")


def sandbox_tree(model: Model, work: Path) -> Path:
    """Our own apt sources: every source pinned to the snapshot, signatures checked."""
    debian = model.inputs("debian")
    root = work / "sandbox"
    if root.exists():
        shutil.rmtree(root)
    sources = root / SNAPSHOT_SOURCES
    sources.parent.mkdir(parents=True)
    stanzas = []
    for source in debian["sources"]:
        stanzas.append("\n".join([
            "Types: deb",
            f"URIs: {source['uri']}",
            f"Suites: {source['suite']}",
            f"Components: {' '.join(source['components'])}",
            f"Signed-By: {debian['keyring']}",
            # Snapshot Release files carry a Valid-Until that has passed; this source is frozen.
            "Check-Valid-Until: no",
        ]))
    sources.write_text("\n\n".join(stanzas) + "\n")
    conf = root / "etc" / "apt" / "apt.conf.d" / "50oneiron-images.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text('Acquire::Retries "8";\nAcquire::Languages "none";\nAcquire::http::Timeout "120";\n')
    return root


def _tsv(path: Path, rows) -> None:
    path.write_text("".join("\t".join(str(c) for c in row) + "\n" for row in rows))


def check_supported(model: Model, plan: Plan) -> None:
    """Refuses a plan write_plan() cannot install. Side-effect free: build.py
    calls it for every requested plan before its namespace or any download."""
    for entry in plan.source_builds:
        payload = model.payload(entry["pin"])
        missing = [k for k in SOURCE_BUILD_FIELDS if k not in payload]
        if payload["kind"] != SOURCE_BUILD_KIND or missing:
            raise NotYetSupported(f"source build {entry['pin']} has kind {payload['kind']!r} and lacks {missing}; "
                                  f"only a pinned {SOURCE_BUILD_KIND} archive with its own Cargo.lock is built")
    for entry in plan.payloads:
        kind = model.payload(entry["pin"])["kind"]
        if kind not in SUPPORTED_PAYLOADS:
            raise NotYetSupported(f"payload {entry['pin']} has kind {kind!r}, which no installer handles")
    for entry in plan.trees:
        if entry["kind"] not in SUPPORTED_TREES:
            raise NotYetSupported(f"tree kind {entry['kind']!r} is not supported")


def write_plan(model: Model, plan: Plan, *, engine: Path, mirror: Mirror, work: Path) -> Path:
    """The plan directory the hooks read (mounted at /work/src/plan)."""
    check_supported(model, plan)
    root = work / "plan" / plan.name
    if root.exists():
        shutil.rmtree(root)
    (root / "files").mkdir(parents=True)
    (root / "trees").mkdir()
    _tsv(root / "native.tsv", [(n["package"], n["bin"], n["dest"], n.get("mode", "0555")) for n in plan.native])
    files = []
    for entry in plan.files:
        pin = model.pinned_file(entry["pin"])
        shutil.copyfile(engine / pin["path"], root / "files" / entry["pin"])
        files.append((f"files/{entry['pin']}", entry["dest"], entry.get("mode", "0644")))
    trees = []
    for entry in plan.payloads:
        payload = model.payload(entry["pin"])
        INSTALLERS[payload["kind"]](model, mirror, entry, payload, root, files, trees)
    for entry in plan.launchers:
        name = "launcher-" + entry["path"].rsplit("/", 1)[-1]
        (root / "files" / name).write_bytes(payloads.launcher(entry))
        files.append((f"files/{name}", entry["path"], "0555"))
    sources = []
    for entry in plan.source_builds:
        sb = model.payload(entry["pin"])
        if any("\t" in e or " " in e for e in sb.get("build_env", [])):
            raise StepFailed(f"source build {entry['pin']}: a build_env entry holds a space or tab")
        sources.append((entry["pin"], sb["workdir"], sb["package"], sb["bin"], entry["dest"],
                        entry.get("mode", "0555"), " ".join(sb.get("build_env", [])) or "-"))
        # Its licence texts, from the mounted source tree (/work/src/source-<pin>).
        for rel in sb["licence_files"]:
            files.append((f"../source-{entry['pin']}/{rel}", f"{sb['licence_dest']}/{rel.rsplit('/', 1)[-1]}", "0644"))
    for entry in plan.trees:
        trees.append(("cargo-home", entry["dest"]))
    _tsv(root / "files.tsv", files)
    _tsv(root / "trees.tsv", trees)
    _tsv(root / "sources.tsv", sources)
    _tsv(root / "links.tsv", [(link["path"], link["target"]) for link in plan.links])
    _tsv(root / "dirs.tsv", [(d["path"], d.get("mode", "0755")) for d in plan.dirs])
    _tsv(root / "empty-files.tsv", [(e["path"], e.get("mode", "0644")) for e in plan.empty_files])
    user = plan.user
    _tsv(root / "user.tsv", [(user["name"], user["uid"], user["gid"], user["home"], user["shell"])] if user else [])
    return root


def _install_file(model, mirror, entry, payload, root, files, trees) -> None:
    shutil.copyfile(mirror.blob(payload["sha256"]), root / "files" / entry["pin"])
    files.append((f"files/{entry['pin']}", entry["dest"], entry.get("mode", "0555")))


def _install_rust_toolchain(model, mirror, entry, payload, root, files, trees) -> None:
    install_rust(model, mirror, payload["components"], root / "trees" / entry["pin"])
    trees.append((f"plan/trees/{entry['pin']}", entry["dest"]))


def _install_archive_member(model, mirror, entry, payload, root, files, trees) -> None:
    payloads.archive_member(mirror.blob(payload["sha256"]), payload["member"], root / "files" / entry["pin"],
                            what=f"payload {entry['pin']}")
    files.append((f"files/{entry['pin']}", entry["dest"], entry.get("mode", "0555")))


def _install_npm(model, mirror, entry, payload, root, files, trees) -> None:
    payloads.npm_package(mirror.sri_blob(payload["integrity"]), root / "trees" / entry["pin"],
                         package=payload["package"], version=payload["version"], what=f"payload {entry['pin']}")
    trees.append((f"plan/trees/{entry['pin']}", entry["dest"]))


# The one dispatch from a payload's kind to its installer (SUPPORTED_PAYLOADS).
INSTALLERS = {
    "file": _install_file,
    "rust-toolchain": _install_rust_toolchain,
    "archive": _install_archive_member,
    "npm": _install_npm,
}
assert set(INSTALLERS) == set(SUPPORTED_PAYLOADS)


def _setting(key: str, values) -> list[str]:
    values = [str(v) for v in values]
    if not values:
        return []
    return [f"{key}=", *[f"        {v}" for v in values]]


def write_config(
    model: Model,
    plan: Plan,
    *,
    work: Path,
    mirror: Mirror,
    tools_tree: Path,
    phase: str,
    sources: dict[str, Path] | None = None,
) -> tuple[Path, Path]:
    """Writes cfg/<phase>-<name>/mkosi.conf; returns (config dir, output dir)."""
    is_tools = plan.name == "tools"
    cfg = work / "cfg" / f"{phase}-{plan.name}"
    out = work / f"out-{phase}" / plan.name
    for path in (cfg, out):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)
    fmt = "none" if phase == "fetch" and not is_tools else "directory"
    lines = [
        "# Generated by build.py; the fixed defaults are in the included file.",
        "[Include]",
        f"Include={IMAGES / ('mkosi.tools.conf' if is_tools else 'mkosi.conf')}",
        "",
        "[Output]",
        f"Format={fmt}",
        f"Output={plan.name}",
        f"OutputDirectory={out}",
        f"Seed={model.seed()}",
        "",
        "[Content]",
        *_setting("Packages", plan.packages),
        *_setting("BuildPackages", [] if is_tools else plan.build_packages),
        f"SourceDateEpoch={model.epoch()}",
    ]
    if not is_tools:
        lines += [
            f"BuildScripts={HOOKS['build']}",
            f"PostInstallationScripts={HOOKS['postinst']}",
            f"FinalizeScripts={HOOKS['finalize']}",
        ]
    lines += [
        "",
        "[Build]",
        f"ToolsTree={tools_tree}",
        f"CacheOnly={'never' if phase == 'fetch' else 'always'}",
        f"CacheDirectory={mirror.mkosi_cache}",
        f"PackageCacheDirectory={mirror.pkgcache}",
        f"WorkspaceDirectory={work / 'workspace'}",
        f"SandboxTrees={work / 'sandbox'}",
        "Incremental=no",
        "History=no",
        "WithNetwork=no",
        f"Environment=ONEIRON_IMAGES_PHASE={phase} ONEIRON_IMAGE_VARIANT={plan.name}",
    ]
    if not is_tools:
        build_dir = work / "cargo-build" / plan.name
        if build_dir.exists():
            shutil.rmtree(build_dir)
        build_dir.mkdir(parents=True)
        lines += [f"BuildDirectory={build_dir}", "BuildSourcesEphemeral=yes",
                  *_setting("BuildSources", [f"{src}:{dst}" for dst, src in sorted((sources or {}).items())])]
    (work / "workspace").mkdir(parents=True, exist_ok=True)
    (cfg / "mkosi.conf").write_text("\n".join(lines) + "\n")
    return cfg, out


def _env(mkosi_src: Path, work: Path) -> dict:
    """mkosi's environment: host_env() plus its source, a scratch TMPDIR and an
    empty HOME in the work dir, so no user configuration of the host reaches it."""
    tmp = work / "tmp"
    home = work / "home"
    for path in (tmp, home):
        path.mkdir(parents=True, exist_ok=True)
    env = host_env(PYTHONPATH=str(mkosi_src), TMPDIR=str(tmp), HOME=str(home), MKOSI_FORCE_USERNS_FALLBACK="1")
    for key in ("TERM", "ONEIRON_IMAGES_USERNS"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def _as_user() -> list[str]:
    """mkosi runs as the invoking uid, in a user namespace below the builder's.

    The builder is root of its own single-uid namespace. mkosi 27.1 takes uid 0
    with CAP_SYS_ADMIN for real root: it then skips its own unprivileged setup,
    and its tar extraction (`--same-owner` when getuid() is 0) chowns to ids no
    single-uid namespace maps. Run as a regular uid, mkosi does what it does
    for any unprivileged user: every tool in a sandbox that maps that uid to
    root, package managers with chown() made a no-op. MKOSI_FORCE_USERNS_FALLBACK
    keeps it on plain unshare(CLONE_NEWUSER), never systemd-nsresourced's
    foreign uid range (files the builder could not read back)."""
    uid = os.environ.get("ONEIRON_IMAGES_UID", "1000")
    gid = os.environ.get("ONEIRON_IMAGES_GID", uid)
    if uid == "0":
        uid = gid = "1000"
    return ["unshare", "--user", f"--map-user={uid}", f"--map-group={gid}", "--"]


def mkosi(mkosi_src: Path, cfg: Path, work: Path, *args) -> None:
    run([*_as_user(), sys.executable, "-B", "-m", "mkosi", "-C", cfg, *args], env=_env(mkosi_src, work))


def build(mkosi_src: Path, cfg: Path, work: Path) -> None:
    mkosi(mkosi_src, cfg, work, "--force", "build")


def box(mkosi_src: Path, cfg: Path, work: Path, argv, *, env_extra: dict | None = None, capture=False):
    """Runs argv with /usr from the tools tree (`mkosi box`), the host's other dirs in place."""
    prefix = ["env", *[f"{k}={v}" for k, v in (env_extra or {}).items()]] if env_extra else []
    cmd = [*_as_user(), sys.executable, "-B", "-m", "mkosi", "-C", cfg, "box", "--", *prefix, *argv]
    result = run(cmd, env=_env(mkosi_src, work), capture=capture, check=False)
    if result.returncode != 0:
        raise StepFailed(f"tools-tree command {argv[0]} exited {result.returncode}")
    return result


def finish_tools_tree(out: Path, work: Path) -> Path:
    """Normalizes the tools tree mkosi left in out; idempotent."""
    tree = out / "tools"
    if not tree.is_dir():
        raise StepFailed(f"mkosi left no tools tree at {tree}")
    # apt in the tree reads the frozen snapshot only. mkosi writes the tree's
    # own trixie.sources for deb.debian.org (its for_image repositories drop
    # the snapshot); that and any other enabled list go, and sandbox_tree()'s
    # snapshot file takes their place (FIX 9355).
    apt = tree / "etc" / "apt"
    (apt / "sources.list").unlink(missing_ok=True)
    parts = apt / "sources.list.d"
    parts.mkdir(parents=True, exist_ok=True)
    for path in sorted(parts.iterdir()):
        if path.suffix in (".list", ".sources"):
            path.unlink()
    shutil.copyfile(work / "sandbox" / SNAPSHOT_SOURCES, tree / SNAPSHOT_SOURCES)
    os.chmod(tree / SNAPSHOT_SOURCES, 0o644)
    resolv = tree / "etc" / "resolv.conf"
    if not resolv.exists() and not resolv.is_symlink():
        # mkosi refuses a tools tree without one; its own default tools tree ships an empty file.
        resolv.touch()
    # Host-dependent state no tool reads back: ldconfig's aux cache records each
    # library's inode and ctime, and the logs carry wall-clock times. Two hosts'
    # tools trees differed in exactly these two files (runs b4 and b5), so they
    # go before the tree is hashed as the builder identity.
    (tree / "var" / "cache" / "ldconfig" / "aux-cache").unlink(missing_ok=True)
    logs = tree / "var" / "log"
    if logs.is_dir() and not logs.is_symlink():
        for path in sorted(logs.rglob("*"), reverse=True):
            if path.is_symlink() or path.is_file():
                path.unlink()
    return tree
