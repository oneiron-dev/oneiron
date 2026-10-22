"""The fetch phase: every input lands in the mirror, checked against its pin.

The mirror is content-addressed where the input has a single file
(blobs/sha256/<hex>: the base layer, the mkosi archive, the Rust components,
payloads). Debian packages stay in mkosi's package cache layout
(pkgcache/cache/apt/archives) and are content-addressed through
packages.lock.toml; the signed apt metadata they were verified against stays
in mkosi-cache. The Cargo closure is a clean CARGO_HOME (cargo-home/) that
`cargo fetch --locked` filled; Cargo.lock's checksums pin it.

The fetch runs the pinned cargo in a root of its own (fetch_root): a tmpfs
holding the pinned base layer's userspace, the engine source at /src and the
store's CARGO_HOME at /cargo-home. Cargo reads `.cargo/config.toml` in every
parent of its working directory, so a work dir under a home directory would
pick up that home's Cargo config; in this root the walk is /src (the pinned
repo config) and an empty /.
"""

from __future__ import annotations

import shlex
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
    host_env,
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
        result = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", commit], stdout=out,
                                env=host_env())
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


# Where a host keeps its CA roots; cargo's TLS needs one bundle, nothing else of the host's /etc.
CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
)
# The device nodes the fetch root binds one by one (no other host device); /proc
# is the only other host mount in it.
FETCH_DEVICES = ("null", "zero", "full", "random", "urandom")
# Inside the fetch root.
FETCH_SRC, FETCH_CARGO_HOME, FETCH_RUST = "/src", "/cargo-home", "/rust"
FETCH_CA = "/etc/ssl/certs/ca-certificates.crt"

# Runs as root of the build's user namespace, in a mount namespace of its own
# (unshare --mount), so every mount below ends with the command. $1 is the
# empty mount point, $2 the bootstrap tree, $3-$5 the engine source, the
# store's CARGO_HOME and the pinned Rust, $6 the host CA bundle, $7 the host
# resolver file; the rest is the command run in the root.
FETCH_ROOT_SH = r"""
set -eu
root=$1 boot=$2 engine=$3 cargo_home=$4 rust=$5 ca=$6 resolv=$7
shift 7
mount -t tmpfs -o mode=0755 oneiron-fetch-root "$root"
for top in "$boot"/*; do
  name=${top##*/}
  if [ -L "$top" ]; then ln -s "$(readlink "$top")" "$root/$name"; fi
done
mkdir -p "$root/usr" "$root/dev" "$root/proc" "$root/tmp" "$root/src" "$root/cargo-home" "$root/rust"
chmod 1777 "$root/tmp"
mount --bind "$boot/usr" "$root/usr"
# ld.so expands rustc's $ORIGIN/../lib RUNPATH through /proc/self/exe.
mount --rbind /proc "$root/proc"
cp -a "$boot/etc" "$root/etc"
rm -f "$root/etc/resolv.conf"
cat "$resolv" > "$root/etc/resolv.conf"
mkdir -p "$root/etc/ssl/certs"
cat "$ca" > "$root/etc/ssl/certs/ca-certificates.crt"
for dev in null zero full random urandom; do
  : > "$root/dev/$dev"
  mount --bind "/dev/$dev" "$root/dev/$dev"
done
mount --bind "$engine" "$root/src"
mount --bind "$cargo_home" "$root/cargo-home"
mount --bind "$rust" "$root/rust"
exec chroot "$root" "$@"
"""


def _host_file(candidates, what: str) -> Path:
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return path.resolve()
    raise HostRefusal(f"the host has no {what} (looked at {', '.join(candidates)})")


def fetch_root(work: Path, bootstrap: Path, *, engine: Path, cargo_home: Path, rust: Path, command: list[str],
               cwd: str = FETCH_SRC) -> None:
    """Runs command (an argv inside the root) with the pinned base layer's
    userspace, the engine at /src, CARGO_HOME at /cargo-home, the pinned Rust
    at /rust, and nothing of the host's but its CA roots and resolver.

    No HOME is set and no host directory but those three is visible, so no
    Cargo or git configuration of the host reaches the command."""
    ca = _host_file(CA_BUNDLES, "CA certificate bundle")
    resolv = _host_file(("/etc/resolv.conf",), "/etc/resolv.conf")
    mount_point = work / "fetch-root"
    mount_point.mkdir(parents=True, exist_ok=True)
    env = [
        f"PATH={FETCH_RUST}/bin:/usr/bin:/bin",
        f"CARGO_HOME={FETCH_CARGO_HOME}",
        f"CARGO_HTTP_CAINFO={FETCH_CA}",
        f"SSL_CERT_FILE={FETCH_CA}",
        "CARGO_TERM_COLOR=never",
        "CARGO_NET_RETRY=6",
        "CARGO_HTTP_TIMEOUT=120",
        "CARGO_NET_GIT_FETCH_WITH_CLI=false",
    ]
    inner = f"cd {shlex.quote(cwd)} && exec " + " ".join(shlex.quote(a) for a in command)
    run(["unshare", "--mount", "--propagation", "private", "--", "/bin/sh", "-c", FETCH_ROOT_SH, "fetch-root",
         mount_point, bootstrap, engine, cargo_home, rust, ca, resolv,
         "/usr/bin/env", "-i", *env, "/bin/sh", "-c", inner])


def cargo_fetch(mirror: Mirror, engine: Path, rust: Path, *, bootstrap: Path, work: Path) -> None:
    for leaked in ("config", "config.toml", "credentials", "credentials.toml"):
        if (mirror.cargo_home / leaked).exists():
            raise HostRefusal(f"the mirror CARGO_HOME holds {leaked}; it must stay clean")
    if (bootstrap / ".cargo").exists() or (bootstrap / "root" / ".cargo").exists():
        raise HostRefusal("the bootstrap tree holds a .cargo directory; the pinned base layer has none")
    log(f"cargo config walk: {FETCH_SRC}/.cargo/config.toml (inputs.files.cargo-config), then an empty /")
    fetch_root(work, bootstrap, engine=engine, cargo_home=mirror.cargo_home, rust=rust,
               command=["cargo", "fetch", "--locked", "--target", RUST_TARGET])


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
