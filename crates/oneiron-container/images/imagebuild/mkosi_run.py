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

from .fetch import Mirror, install_rust
from .model import HERE, Model, Plan
from .util import NotYetSupported, StepFailed, host_env, run

IMAGES = HERE
HOOKS = {
    "build": IMAGES / "mkosi.build.chroot",
    "postinst": IMAGES / "mkosi.postinst",
    "finalize": IMAGES / "mkosi.finalize",
}


def sandbox_tree(model: Model, work: Path) -> Path:
    """Our own apt sources: every source pinned to the snapshot, signatures checked."""
    debian = model.inputs("debian")
    root = work / "sandbox"
    if root.exists():
        shutil.rmtree(root)
    sources = root / "etc" / "apt" / "sources.list.d" / "mkosi.sources"
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


def write_plan(model: Model, plan: Plan, *, engine: Path, mirror: Mirror, work: Path) -> Path:
    """The plan directory the hooks read (mounted at /work/src/plan)."""
    root = work / "plan" / plan.name
    if root.exists():
        shutil.rmtree(root)
    (root / "files").mkdir(parents=True)
    (root / "trees").mkdir()
    if plan.source_builds:
        names = ", ".join(sb["pin"] for sb in plan.source_builds)
        raise NotYetSupported(f"{plan.name} needs an external source build ({names}); the CUA build lands with its phase")
    _tsv(root / "native.tsv", [(n["package"], n["bin"], n["dest"], n.get("mode", "0555")) for n in plan.native])
    files = []
    for entry in plan.files:
        pin = model.pinned_file(entry["pin"])
        shutil.copyfile(engine / pin["path"], root / "files" / entry["pin"])
        files.append((f"files/{entry['pin']}", entry["dest"], entry.get("mode", "0644")))
    trees = []
    for entry in plan.payloads:
        payload = model.payload(entry["pin"])
        kind = payload["kind"]
        if kind == "file":
            shutil.copyfile(mirror.blob(payload["sha256"]), root / "files" / entry["pin"])
            files.append((f"files/{entry['pin']}", entry["dest"], entry.get("mode", "0555")))
        elif kind == "rust-toolchain":
            install_rust(model, mirror, payload["components"], root / "trees" / entry["pin"])
            trees.append((f"plan/trees/{entry['pin']}", entry["dest"]))
        else:
            raise NotYetSupported(f"payload {entry['pin']} has kind {kind!r}; its install lands with phase {plan.phase}")
    for entry in plan.trees:
        if entry["kind"] != "cargo-store":
            raise NotYetSupported(f"tree kind {entry['kind']!r} is not supported")
        trees.append(("cargo-home", entry["dest"]))
    _tsv(root / "files.tsv", files)
    _tsv(root / "trees.tsv", trees)
    _tsv(root / "links.tsv", [(link["path"], link["target"]) for link in plan.links])
    _tsv(root / "dirs.tsv", [(d["path"], d.get("mode", "0755")) for d in plan.dirs])
    user = plan.user
    _tsv(root / "user.tsv", [(user["name"], user["uid"], user["gid"], user["home"], user["shell"])] if user else [])
    return root


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
    env = host_env(PYTHONPATH=str(mkosi_src), TMPDIR=str(tmp), HOME=str(home))
    for key in ("TERM", "ONEIRON_IMAGES_USERNS"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def mkosi(mkosi_src: Path, cfg: Path, work: Path, *args) -> None:
    run([sys.executable, "-B", "-m", "mkosi", "-C", cfg, *args], env=_env(mkosi_src, work))


def build(mkosi_src: Path, cfg: Path, work: Path) -> None:
    mkosi(mkosi_src, cfg, work, "--force", "build")


def box(mkosi_src: Path, cfg: Path, work: Path, argv, *, env_extra: dict | None = None, capture=False):
    """Runs argv with /usr from the tools tree (`mkosi box`), the host's other dirs in place."""
    prefix = ["env", *[f"{k}={v}" for k, v in (env_extra or {}).items()]] if env_extra else []
    cmd = [sys.executable, "-B", "-m", "mkosi", "-C", cfg, "box", "--", *prefix, *argv]
    result = run(cmd, env=_env(mkosi_src, work), capture=capture, check=False)
    if result.returncode != 0:
        raise StepFailed(f"tools-tree command {argv[0]} exited {result.returncode}")
    return result


def finish_tools_tree(out: Path) -> Path:
    tree = out / "tools"
    if not tree.is_dir():
        raise StepFailed(f"mkosi left no tools tree at {tree}")
    resolv = tree / "etc" / "resolv.conf"
    if not resolv.exists() and not resolv.is_symlink():
        # mkosi refuses a tools tree without one; its own default tools tree ships an empty file.
        resolv.touch()
    return tree
