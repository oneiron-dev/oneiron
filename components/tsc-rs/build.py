#!/usr/bin/env python3
"""Build/check the pinned tsc-rs type checker module. No tool installation.

Build: Rust 1.96 with the wasm32-wasip1 target, git, and an owned
CARGO_TARGET_DIR. Run from the repository root. `--source` names a checkout
of the pinned commit; otherwise the build clones it into the target directory.
`--check` verifies the artifact, notices and host pins without building.
"""
import argparse
import glob
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ARTIFACTS = HERE / "artifacts"
REPO = "https://github.com/pingdotgg/ts-rust.git"
COMMIT = "80f9944aab296595c4c9aa4d9d1ad65d1e5f76f6"
# The TypeScript (typescript-go) commit the port follows, from its UPSTREAM.md.
TYPESCRIPT_COMMIT = "673a5f17d713bdc8c7185f18a9c11e3c4ac5d781"
TARGET = "wasm32-wasip1"
PROFILE = "wasm"
# Upstream's `wasm` profile is opt-level "z" (smallest). See README.md for the
# measured trade against "s".
OPT_LEVEL = "z"
NOTICES = ("LICENSE", "NOTICE.md", "licenses/Go-LICENSE.txt", "licenses/TypeScript-LICENSE.txt",
           "licenses/TypeScript-NOTICE.txt", "licenses/Unicode-LICENSE.txt",
           "licenses/vscode-languageserver-node-LICENSE.txt")
HOST = ROOT / "crates/oneiron-code-check/src/tsc_rs.rs"
EXPORTS = {"memory", "ts_input", "ts_run", "ts_output", "ts_output_len"}
# The host links exactly these modules: the file system the checker reads
# (`ts_host`) and the WASI calls of crates/ts_wasm, answered in memory.
IMPORT_MODULES = {"ts_host", "wasi_snapshot_preview1"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def leb(data, at):
    value = shift = 0
    while True:
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return value, at


def inventory(data):
    """The module's (imports, exports), read from its import and export sections."""
    if data[:8] != b"\0asm\x01\0\0\0":
        raise SystemExit("tsc-rs artifact is not a core Wasm module")
    imports, exports, at = set(), set(), 8
    while at < len(data):
        section = data[at]
        size, at = leb(data, at + 1)
        end = at + size
        if section in (2, 7):
            count, cursor = leb(data, at)
            for _ in range(count):
                names = []
                for _ in range(1 if section == 7 else 2):
                    length, cursor = leb(data, cursor)
                    names.append(data[cursor:cursor + length].decode())
                    cursor += length
                kind = data[cursor]
                if section == 7:
                    _, cursor = leb(data, cursor + 1)
                    exports.add(names[0])
                    continue
                if kind != 0:
                    raise SystemExit(f"tsc-rs artifact imports a non-function: {names}")
                _, cursor = leb(data, cursor + 1)
                imports.add(tuple(names))
        at = end
    return imports, exports


def build(source, out_dir):
    if source is None:
        source = out_dir / f"tsc-rs-{COMMIT}"
        if not source.exists():
            subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", REPO, str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "checkout", "--detach", COMMIT], check=True)
    head = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], text=True, capture_output=True, check=True)
    dirty = subprocess.run(["git", "-C", str(source), "status", "--porcelain"], text=True, capture_output=True, check=True)
    if head.stdout.strip() != COMMIT or dirty.stdout.strip():
        raise SystemExit(f"{source} is not a clean checkout of {COMMIT}")
    # Map every build path out of the module, as upstream's scripts/wasm/build.sh
    # does: the checkout, the registry sources and the toolchain's library source.
    sysroot = subprocess.run(["rustc", "--print", "sysroot"], text=True, capture_output=True, check=True).stdout.strip()
    version = subprocess.run(["rustc", "-vV"], text=True, capture_output=True, check=True).stdout
    rustc_commit = next(line.split(": ", 1)[1] for line in version.splitlines() if line.startswith("commit-hash: "))
    cargo_home = os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))
    remaps = [(str(source.resolve()) + "/", ""), (f"{sysroot}/lib/rustlib/src/rust", f"/rustc/{rustc_commit}")]
    remaps += [(registry, "") for registry in sorted(glob.glob(f"{cargo_home}/registry/src/*/"))]
    rustflags = " ".join(f"--remap-path-prefix={before}={after}" for before, after in remaps)
    env = dict(os.environ, RUSTFLAGS=rustflags, CARGO_PROFILE_WASM_OPT_LEVEL=OPT_LEVEL)
    subprocess.run(["cargo", "rustc", "--locked", "--profile", PROFILE, "-p", "ts_wasm", "--lib", "--target", TARGET],
                   cwd=source, env=env, check=True)
    built = Path(env["CARGO_TARGET_DIR"]) / TARGET / PROFILE / "ts_wasm.wasm"
    data = built.read_bytes()
    for before, _ in remaps:
        if before.rstrip("/").encode() in data:
            raise SystemExit(f"the module holds the build path {before}")
    ARTIFACTS.mkdir(exist_ok=True)
    (ARTIFACTS / "ts_rust.wasm").write_bytes(data)
    for name in NOTICES:
        target = ARTIFACTS / "notices" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    manifest = {"schema_version": 1, "repository": REPO, "commit": COMMIT, "typescript_commit": TYPESCRIPT_COMMIT,
                "crate": "ts_wasm", "target": TARGET, "profile": PROFILE, "opt_level": OPT_LEVEL, "wasm_opt": "none",
                "rust_toolchain": version.splitlines()[0], "license": "MIT AND Apache-2.0",
                "sha256": sha(data), "bytes": len(data),
                "notices": {name: sha((ARTIFACTS / "notices" / name).read_bytes()) for name in NOTICES},
                "sources": {"build.py": sha((HERE / "build.py").read_bytes())}}
    (ARTIFACTS / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def check():
    manifest = json.loads((ARTIFACTS / "manifest.json").read_text())
    data = (ARTIFACTS / "ts_rust.wasm").read_bytes()
    if manifest["commit"] != COMMIT or manifest["opt_level"] != OPT_LEVEL:
        raise SystemExit("tsc-rs manifest names another build")
    if manifest["sha256"] != sha(data) or manifest["bytes"] != len(data):
        raise SystemExit("tsc-rs artifact pin mismatch")
    if manifest["sources"] != {"build.py": sha((HERE / "build.py").read_bytes())}:
        raise SystemExit("tsc-rs build script pin mismatch")
    if manifest["notices"] != {name: sha((ARTIFACTS / "notices" / name).read_bytes()) for name in NOTICES}:
        raise SystemExit("tsc-rs notices must travel with the module")
    host = HOST.read_text()
    for literal in (f'const SHA256: &str = "{manifest["sha256"]}";', f'pub const TSC_RS_COMMIT: &str = "{COMMIT}";'):
        if literal not in host:
            raise SystemExit(f"host pin mismatch: {HOST.relative_to(ROOT)} lacks {literal}")
    imports, exports = inventory(data)
    if {module for module, _ in imports} - IMPORT_MODULES or not EXPORTS <= exports:
        raise SystemExit(f"tsc-rs ABI changed: imports {sorted(imports)}, exports {sorted(exports)}")
    print("TSC-RS-OK: artifact, notices, host pins and ABI")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    if not args.check:
        if "CARGO_TARGET_DIR" not in os.environ:
            parser.error("set an owned CARGO_TARGET_DIR")
        build(args.source, Path(os.environ["CARGO_TARGET_DIR"]))
    check()


if __name__ == "__main__":
    main()
