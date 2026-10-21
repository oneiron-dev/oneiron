"""The fetch phase: every input lands in the mirror, checked against its pin.

The mirror is content-addressed where the input has a single file
(blobs/sha256/<hex>: the base layer, the mkosi archive, the Rust components,
payloads). Debian packages stay in mkosi's package cache layout
(pkgcache/cache/apt/archives) and are content-addressed through
packages.lock.toml; the signed apt metadata they were verified against stays
in mkosi-cache. The Cargo closure is a clean CARGO_HOME (cargo-home/) that
`cargo fetch --locked` filled; Cargo.lock's checksums pin it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import urllib.parse
from pathlib import Path

from .model import Model
from .util import (
    HostRefusal,
    MissingPin,
    PinMismatch,
    StepFailed,
    fetch_json,
    fetch_url,
    log,
    run,
    sha256_file,
)

RUST_TARGET = "x86_64-unknown-linux-gnu"


class Mirror:
    def __init__(self, root: Path):
        self.root = root

    @property
    def blobs(self) -> Path:
        return self.root / "blobs" / "sha256"

    def blob(self, sha: str) -> Path:
        return self.blobs / sha

    @property
    def pkgcache(self) -> Path:
        return self.root / "pkgcache"

    @property
    def archives(self) -> Path:
        return self.pkgcache / "cache" / "apt" / "archives"

    @property
    def mkosi_cache(self) -> Path:
        return self.root / "mkosi-cache"

    @property
    def cargo_home(self) -> Path:
        return self.root / "cargo-home"

    def prepare(self) -> None:
        for path in (self.blobs, self.pkgcache, self.mkosi_cache, self.cargo_home):
            path.mkdir(parents=True, exist_ok=True)


def fetch_blob(mirror: Mirror, url: str, sha: str | None, *, learn: bool, what: str, headers=None) -> str:
    """Puts url's bytes at blobs/sha256/<hex>. Without a pin only --learn may proceed."""
    if sha is not None and mirror.blob(sha).exists():
        if sha256_file(mirror.blob(sha)) == sha:
            log(f"{what}: mirror hit {sha[:12]}")
            return sha
        mirror.blob(sha).unlink()
    if sha is None and not learn:
        raise MissingPin(f"{what} has no sha256 pin in release.toml (a first run may learn it with --learn)")
    temp = mirror.root / "incoming" / Path(urllib.parse.urlparse(url).path).name
    fetch_url(url, temp, headers=headers)
    got = sha256_file(temp)
    if sha is not None and got != sha:
        temp.unlink()
        raise PinMismatch(f"{what}: {url} has sha256 {got}, release.toml pins {sha}")
    if sha is None:
        log(f"LEARNED {what} sha256 = {got}")
    mirror.blobs.mkdir(parents=True, exist_ok=True)
    temp.replace(mirror.blob(got))
    return got


def fetch_base_layer(model: Model, mirror: Mirror) -> Path:
    base = model.inputs("base")
    digest = base["layer_digest"].removeprefix("sha256:")
    if mirror.blob(digest).exists() and sha256_file(mirror.blob(digest)) == digest:
        return mirror.blob(digest)
    token = fetch_json(base["token_url"])["token"]
    repo = base["repository"]
    url = f"{base['registry']}/v2/{repo}/blobs/sha256:{digest}"
    fetch_blob(mirror, url, digest, learn=False, what="base layer",
               headers={"Authorization": f"Bearer {token}"})
    size = mirror.blob(digest).stat().st_size
    if size != base["layer_bytes"]:
        raise PinMismatch(f"base layer is {size} bytes, release.toml pins {base['layer_bytes']}")
    return mirror.blob(digest)


def unpack_tar(archive: Path, dest: Path) -> None:
    """Unpacks with the host's tar inside our user namespace (root-mapped, so owners stay 0)."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    run(["tar", "--extract", "--file", archive, "--directory", dest, "--numeric-owner",
         "--no-same-owner", "--delay-directory-restore"])


def bootstrap_tree(model: Model, mirror: Mirror, work: Path) -> Path:
    layer = fetch_base_layer(model, mirror)
    tree = work / "bootstrap"
    marker = tree / ".oneiron-layer"
    digest = model.inputs("base", "layer_digest")
    if marker.exists() and marker.read_text().strip() == digest:
        return tree
    unpack_tar(layer, tree)
    resolv = tree / "etc" / "resolv.conf"
    if not resolv.exists() and not resolv.is_symlink():
        resolv.touch()
    marker.write_text(digest + "\n")
    return tree


def mkosi_source(model: Model, mirror: Mirror, work: Path, *, learn: bool) -> Path:
    pin = model.inputs("mkosi")
    sha = fetch_blob(mirror, pin["archive_url"], pin.get("archive_sha256"), learn=learn, what="mkosi source archive")
    dest = work / "mkosi-src"
    unpack_tar(mirror.blob(sha), dest)
    tops = [p for p in dest.iterdir() if p.is_dir()]
    if len(tops) != 1 or not (tops[0] / "mkosi" / "__main__.py").exists():
        raise StepFailed("the mkosi archive does not hold one mkosi source tree")
    version = (tops[0] / "pyproject.toml").read_text()
    if f'version = "{pin["version"]}"' not in version:
        raise PinMismatch(f"the mkosi archive is not version {pin['version']}")
    return tops[0]


def fetch_rust(model: Model, mirror: Mirror, names) -> dict[str, Path]:
    comps = model.inputs("rust", "components")
    out = {}
    for name in names:
        if name not in comps:
            raise MissingPin(f"no [inputs.rust.components.{name}] pin")
        sha = fetch_blob(mirror, comps[name]["url"], comps[name]["sha256"], learn=False, what=f"rust {name}")
        out[name] = mirror.blob(sha)
    return out


def install_rust(model: Model, mirror: Mirror, names, prefix: Path) -> Path:
    """Installs dist components the way their install.sh does (manifest.in), without running it."""
    archives = fetch_rust(model, mirror, names)
    if prefix.exists():
        shutil.rmtree(prefix)
    prefix.mkdir(parents=True)
    stage = prefix.parent / (prefix.name + ".stage")
    for name, archive in archives.items():
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir()
        with tarfile.open(archive, "r:xz") as tar:
            tar.extractall(stage, filter="tar")
        (top,) = [p for p in stage.iterdir() if p.is_dir()]
        for comp in (top / "components").read_text().split():
            for line in (top / comp / "manifest.in").read_text().splitlines():
                kind, _, rel = line.partition(":")
                src, dst = top / comp / rel, prefix / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                if kind == "file":
                    shutil.copy2(src, dst)
                elif kind == "dir":
                    shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
                else:
                    raise StepFailed(f"rust {name}: unknown manifest.in entry {line!r}")
        shutil.rmtree(stage)
    for tool in ("rustc", "cargo"):
        if (prefix / "bin" / tool).exists():
            (prefix / "bin" / tool).chmod(0o755)
    return prefix


def engine_tree(model: Model, repo: Path, work: Path) -> Path:
    """The engine source at the pinned commit, checked against every file pin."""
    commit = model.engine_commit()
    probe = run(["git", "-C", repo, "cat-file", "-e", f"{commit}^{{commit}}"], check=False)
    if probe.returncode != 0:
        raise MissingPin(f"engine commit {commit} is not in {repo}: `git fetch --depth 1 origin {commit}` first")
    dest = work / "engine"
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    archive = work / "engine.tar"
    with open(archive, "wb") as out:
        result = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", commit], stdout=out)
    if result.returncode != 0:
        raise StepFailed("git archive of the engine commit failed")
    run(["tar", "--extract", "--file", archive, "--directory", dest, "--no-same-owner"])
    archive.unlink()
    lock = model.inputs("engine", "cargo_lock_sha256")
    got = sha256_file(dest / "Cargo.lock")
    if got != lock:
        raise PinMismatch(f"Cargo.lock at {commit} has sha256 {got}, release.toml pins {lock}")
    for key, pin in model.inputs("files").items():
        path = dest / pin["path"]
        if not path.exists():
            raise PinMismatch(f"pinned file {key} ({pin['path']}) is absent at {commit}")
        got = sha256_file(path)
        if got != pin["sha256"]:
            raise PinMismatch(f"pinned file {key} ({pin['path']}) has sha256 {got}, release.toml pins {pin['sha256']}")
    toolchain = model.inputs("rust")
    if sha256_file(dest / toolchain["toolchain_file"]) != toolchain["toolchain_file_sha256"]:
        raise PinMismatch("rust-toolchain.toml changed since release.toml pinned the toolchain")
    return dest


def _refuse_host_cargo_config(tree: Path) -> None:
    for parent in tree.resolve().parents:
        for name in ("config", "config.toml"):
            if (parent / ".cargo" / name).exists():
                raise HostRefusal(f"{parent / '.cargo' / name} would leak host Cargo config into the fetch")


def cargo_fetch(mirror: Mirror, engine: Path, rust: Path) -> None:
    _refuse_host_cargo_config(engine)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CARGO_", "RUSTUP_", "RUSTC"))}
    env.update(CARGO_HOME=str(mirror.cargo_home), PATH=f"{rust / 'bin'}:/usr/bin:/bin",
               CARGO_TERM_COLOR="never", CARGO_NET_RETRY="6")
    for leaked in ("config", "config.toml", "credentials", "credentials.toml"):
        if (mirror.cargo_home / leaked).exists():
            raise HostRefusal(f"the mirror CARGO_HOME holds {leaked}; it must stay clean")
    run(["cargo", "fetch", "--locked", "--target", RUST_TARGET], cwd=engine, env=env)


# -- the Debian closure ---------------------------------------------------------


def deb_files(mirror: Mirror) -> dict[str, Path]:
    if not mirror.archives.exists():
        return {}
    return {p.name: p for p in sorted(mirror.archives.glob("*.deb"))}


def parse_deb_name(filename: str) -> tuple[str, str, str]:
    stem = urllib.parse.unquote(filename.removesuffix(".deb"))
    name, version, arch = stem.split("_")
    return name, version, arch


def closure(mirror: Mirror) -> list[dict]:
    entries = []
    for filename, path in deb_files(mirror).items():
        name, version, arch = parse_deb_name(filename)
        entries.append({"name": name, "version": version, "arch": arch, "filename": filename,
                        "size": path.stat().st_size, "sha256": sha256_file(path)})
    return entries


def verify_closure(model: Model, mirror: Mirror, *, new: set[str] | None = None) -> list[str]:
    """Every locked .deb is present with its hash; returns warnings for extra files."""
    locked = {e["filename"]: e for e in model.lock_entries()}
    files = deb_files(mirror)
    problems, warnings = [], []
    for filename, entry in locked.items():
        path = files.get(filename)
        if path is None:
            problems.append(f"{filename} (locked) is not in the mirror")
        elif path.stat().st_size != entry["size"] or sha256_file(path) != entry["sha256"]:
            problems.append(f"{filename} in the mirror does not match its lock hash")
    for filename in sorted(set(files) - set(locked)):
        if new is not None and filename in new:
            problems.append(f"{filename} was downloaded this run but is not in packages.lock.toml")
        else:
            warnings.append(f"{filename} is in the mirror but not in packages.lock.toml (another scope?)")
    if problems:
        raise PinMismatch("the package closure drifted from packages.lock.toml:\n  " + "\n  ".join(problems))
    return warnings


def lock_text(model: Model, entries: list[dict], scopes: list[str]) -> str:
    debian = model.inputs("debian")
    lines = [
        "# Generated by `build.py fetch --learn`: the resolved Debian closure for the",
        "# scopes below, one entry per .deb the frozen snapshot served. The requests",
        "# live in packages.toml; edit that, never this file. build.py build refuses",
        "# a mirror whose .deb bytes differ from these hashes.",
        "schema = 1",
        f'snapshot = "{debian["snapshot"]}"',
        f'suite = "{debian["suite"]}"',
        'architecture = "amd64"',
        "",
    ]
    for scope in scopes:
        lines += [f"[scopes.{scope}]", f'requests_sha256 = "{model.plan(scope).requests_sha256()}"', ""]
    for entry in sorted(entries, key=lambda e: (e["name"], e["arch"], e["version"])):
        lines += [
            "[[package]]",
            f'name = "{entry["name"]}"',
            f'version = "{entry["version"]}"',
            f'arch = "{entry["arch"]}"',
            f'filename = "{entry["filename"]}"',
            f"size = {entry['size']}",
            f'sha256 = "{entry["sha256"]}"',
            "",
        ]
    return "\n".join(lines)
