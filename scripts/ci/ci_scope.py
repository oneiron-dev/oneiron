#!/usr/bin/env python3
"""Decide what a CI run builds and tests (owner ruling 2026-09-26: test only what changed).

PR and main-push runs are scoped to the diff: clippy for touched workspace
packages and their reverse dependents, tests for touched packages, and for the
`oneiron` crate only the touched top-level modules. The nightly schedule and
manual dispatch run everything (`full`).

Usage: ci_scope.py [--base REV] [--head REV] [--full]. Writes key=value lines
to $GITHUB_OUTPUT when set, and always prints them.

Outputs:
  rust      true when anything Rust-relevant changed
  full      true when the whole suite must run (schedule, dispatch, build files)
  packages  space-separated touched workspace packages (clippy and tests)
  dependents space-separated transitive workspace reverse dependents (clippy only)
  oneiron   true when crates/oneiron changed
  modules   touched top-level oneiron modules, or ALL
  it        true when oneiron's integration tests or their support changed
  deny      true when the dependency policy inputs changed
  pytools   true when CI or tooling scripts changed
  stemma_fork true when the vendored stemma fork, or the script that runs its unit tests, changed
"""
import argparse
import json
import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Changes here can break any crate: run everything.
FULL_PATHS = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "clippy.toml", "rustfmt.toml", ".config/nextest.toml")
FULL_PREFIXES = (".cargo/",)
RUST_PREFIXES = ("crates/", "docs/ops/", "packages/prompts/")
RUST_PATHS = FULL_PATHS + ("deny.toml", "oneiron.skills.md", ".github/workflows/ci.yml")
# Files at the crate root that every module sees.
ONEIRON_ROOT_FILES = {"lib.rs", "error.rs", "prelude.rs"}
MAX_MODULES = 12
# The vendored stemma fork: two packages outside the workspace (root Cargo.toml `exclude`). No workspace run
# compiles their own unit tests; STEMMA_FORK_RUNNER does.
STEMMA_FORK_PREFIXES = ("crates/oneiron-docedit/vendor/stemma-engine/", "crates/oneiron-docedit/vendor/stemma-diff/")
STEMMA_FORK_RUNNER = "scripts/docedit/run_stemma_fork_unit_tests.sh"


def changed_files(base, head):
    """The paths the diff touches, each as it is.

    -z: git quotes a path that holds a non-ASCII byte unless the names end in NUL. --no-renames: a moved file is
    listed at the path it left and at its new path, so the place it left counts as changed too.
    """
    out = subprocess.run(["git", "diff", "--no-renames", "--name-only", "-z", base, head], cwd=ROOT,
                         capture_output=True, encoding="utf-8", errors="surrogateescape", check=True)
    return [path for path in out.stdout.split("\0") if path]


def package_of(crate_dir):
    manifest = ROOT / "crates" / crate_dir / "Cargo.toml"
    if not manifest.exists():
        return None
    in_package = False
    for line in manifest.read_text().splitlines():
        if line.strip() == "[package]":
            in_package = True
        elif line.startswith("["):
            in_package = False
        elif in_package:
            m = re.match(r'name\s*=\s*"([^"]+)"', line.strip())
            if m:
                return m.group(1)
    return None


def workspace_excluded(crate_dir):
    return crate_dir in ("heed", "paste")


@lru_cache(maxsize=1)
def workspace_reverse_dependencies():
    """Map each workspace package to its direct dependents, including dev dependencies."""
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    metadata = json.loads(result.stdout)
    members = set(metadata["workspace_members"])
    packages = [p for p in metadata["packages"] if p["id"] in members]
    by_path = {str(Path(p["manifest_path"]).parent): p["name"] for p in packages}
    reverse = {p["name"]: set() for p in packages}
    for package in packages:
        for dependency in package["dependencies"]:
            name = by_path.get(dependency.get("path"))
            if name and name != package["name"]:
                reverse[name].add(package["name"])
    return reverse


def reverse_dependents(touched):
    if not touched:
        return []
    reverse = workspace_reverse_dependencies()
    seen = set(touched)
    pending = list(touched)
    while pending:
        for dependent in reverse.get(pending.pop(), set()) - seen:
            seen.add(dependent)
            pending.append(dependent)
    return sorted(seen - set(touched))


def scope(files, force_full):
    out = {"rust": False, "full": force_full, "packages": [], "dependents": [], "oneiron": False,
           "modules": set(), "it": False, "deny": False, "pytools": False, "stemma_fork": False}
    for f in files:
        if f in FULL_PATHS or f.startswith(FULL_PREFIXES):
            out["full"] = True
        if f in RUST_PATHS or f.startswith(RUST_PREFIXES):
            out["rust"] = True
        if f in ("Cargo.lock", "deny.toml"):
            out["deny"] = True
        if f.startswith(("scripts/", ".github/")):
            out["pytools"] = True
        if f.startswith(STEMMA_FORK_PREFIXES) or f == STEMMA_FORK_RUNNER:
            out["stemma_fork"] = True
            out["rust"] = True  # the runner is a cargo test step: the test job must reach it
        parts = f.split("/")
        if parts[0] == "crates" and len(parts) > 2 and not workspace_excluded(parts[1]):
            pkg = package_of(parts[1])
            if pkg and pkg not in out["packages"]:
                out["packages"].append(pkg)
            if parts[1] == "oneiron":
                out["oneiron"] = True
                if parts[2] == "src" and len(parts) > 3:
                    top = parts[3]
                    if len(parts) == 4 and top in ONEIRON_ROOT_FILES:
                        out["modules"].add("ALL")
                    else:
                        out["modules"].add(top.removesuffix(".rs"))
                elif parts[2] == "tests":
                    out["it"] = True
                elif parts[2] in ("Cargo.toml", "build.rs"):
                    out["modules"].add("ALL")
    if out["full"]:
        out["rust"] = True
    else:
        out["dependents"] = reverse_dependents(out["packages"])
    if "ALL" in out["modules"] or len(out["modules"]) > MAX_MODULES:
        out["modules"] = {"ALL"}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    files = []
    force_full = a.full
    if not force_full:
        try:
            files = changed_files(a.base or "HEAD^1", a.head)
        except subprocess.CalledProcessError:
            force_full = True  # no usable diff base: run everything rather than nothing
    s = scope(files, force_full)
    lines = [
        f"rust={str(s['rust']).lower()}",
        f"full={str(s['full']).lower()}",
        f"packages={' '.join(s['packages'])}",
        f"dependents={' '.join(s['dependents'])}",
        f"oneiron={str(s['oneiron']).lower()}",
        f"modules={' '.join(sorted(s['modules']))}",
        f"it={str(s['it']).lower()}",
        f"deny={str(s['deny']).lower()}",
        f"pytools={str(s['pytools']).lower()}",
        f"stemma_fork={str(s['stemma_fork']).lower()}",
    ]
    for line in lines:
        print(line)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
