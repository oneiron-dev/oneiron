#!/usr/bin/env python3
"""Build/check the pinned import-free validator guest. No tool installation.

Requires Rust 1.96 with wasm32-unknown-unknown and wasm-tools 1.239.0.
Run from the repository root with an owned CARGO_TARGET_DIR.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ARTIFACTS = HERE / "artifacts"
WASM_NAME = "oneiron_schema_validator_guest.wasm"
SOURCES = ("Cargo.toml", "Cargo.lock", "src/lib.rs", "build.py")
RUSTFLAGS = '--cfg getrandom_backend="custom"'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(path):
    result = subprocess.run(["wasm-tools", "print", str(path)], text=True, capture_output=True, check=True)
    imports = [line for line in result.stdout.splitlines() if line.lstrip().startswith("(import ")]
    if imports:
        raise SystemExit(f"schema validator must have no imports: {imports}")
    for export in ('(export "memory"', '(export "alloc"', '(export "run"'):
        if export not in result.stdout:
            raise SystemExit(f"missing validator ABI {export}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not args.check:
        if "CARGO_TARGET_DIR" not in os.environ:
            parser.error("set an owned CARGO_TARGET_DIR")
        env = dict(os.environ, RUSTFLAGS=RUSTFLAGS)
        subprocess.run(["cargo", "build", "--manifest-path", str(HERE / "Cargo.toml"),
                        "--target", "wasm32-unknown-unknown", "--release", "--locked",
                        "-j", "8"], env=env, check=True)
        source = Path(env["CARGO_TARGET_DIR"]) / "wasm32-unknown-unknown/release" / WASM_NAME
        ARTIFACTS.mkdir(exist_ok=True)
        (ARTIFACTS / "validator.wasm").write_bytes(source.read_bytes())
        manifest = {"schema_version": 1, "target": "wasm32-unknown-unknown",
                    "rust_toolchain": "1.96", "crate": "jsonschema =0.33.0 default-features=false",
                    "rustflags": RUSTFLAGS, "sha256": sha(source), "bytes": source.stat().st_size,
                    "sources": {name: sha(HERE / name) for name in SOURCES}}
        (ARTIFACTS / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    manifest = json.loads((ARTIFACTS / "manifest.json").read_text())
    artifact = ARTIFACTS / "validator.wasm"
    if manifest["sha256"] != sha(artifact) or manifest["bytes"] != artifact.stat().st_size:
        raise SystemExit("validator artifact pin mismatch")
    if manifest["sources"] != {name: sha(HERE / name) for name in SOURCES}:
        raise SystemExit("validator source pin mismatch")
    host = (HERE.parent.parent / "crates/oneiron/src/llm/step/schema_runtime.rs").read_text()
    if f'const SHA256: &str = "{manifest["sha256"]}";' not in host:
        raise SystemExit("host validator artifact pin mismatch")
    inventory(artifact)
    print("SCHEMA-VALIDATOR-OK: sources, artifact, ABI and zero imports pinned")


if __name__ == "__main__":
    main()
