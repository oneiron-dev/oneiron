#!/usr/bin/env python3
"""Vendor/check the pinned tsrs type checker module (@tsrs/wasm). Stdlib only.

Fetch (the default): download the pinned npm tarball into a fresh temporary
directory, verify its npm integrity (SRI sha512), and copy only the Wasm
module, LICENSE and NOTICE.txt into vendor/tsrs/, beside a manifest.json.
Members are read from the archive as bytes; nothing is extracted whole and
nothing in the package runs. Run it as `python3 -I`, from an empty directory.
`--check` verifies the vendored bytes, the manifest and the host pins in
src/tsrs.rs without the network.
"""
import argparse
import base64
import hashlib
import io
import json
import re
import tarfile
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent
VENDOR = CRATE / "vendor" / "tsrs"
HOST = CRATE / "src" / "tsrs.rs"
PACKAGE = "@tsrs/wasm"
VERSION = "0.18.0-ts7.1.0-dev.20260929"
TARBALL = f"https://registry.npmjs.org/{PACKAGE}/-/wasm-{VERSION}.tgz"
INTEGRITY = "sha512-1Wv0GU3OIsY1x37cUykxrDLTeCWb81lWS/BCuw2ZfYcB6E7cno3mgfZvOA/3uV1hKs6fBN94LEntmMjULNaRTw=="
# The release the package is built from: tag v0.18.0, named by the package's
# npm provenance.
REPOSITORY = "https://github.com/oxc-project/tsrs.git"
TAG = "v0.18.0"
COMMIT = "5f92808bc92bb97b06212153ab73d28d551c0b9b"
LICENSE = "Apache-2.0"
MODULE = "tsrs.wasm"
NOTICES = ("LICENSE", "NOTICE.txt")
HOST_MODULE = "tsrs_host"
VALTYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}


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
    """The module's imports with their signatures, and its exports, read from
    its type, import and export sections (components/tsc-rs/build.py)."""
    if data[:8] != b"\0asm\x01\0\0\0":
        raise SystemExit("tsrs artifact is not a core Wasm module")
    types, imports, exports, at = [], {}, set(), 8
    while at < len(data):
        section = data[at]
        size, at = leb(data, at + 1)
        end = at + size
        if section == 1:
            count, cursor = leb(data, at)
            for _ in range(count):
                if data[cursor] != 0x60:
                    raise SystemExit("tsrs artifact has a non-function type")
                cursor += 1
                sides = []
                for _ in range(2):
                    length, cursor = leb(data, cursor)
                    sides.append(",".join(VALTYPES[byte] for byte in data[cursor:cursor + length]))
                    cursor += length
                types.append(f"({sides[0]})->({sides[1]})")
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
                    raise SystemExit(f"tsrs artifact imports a non-function: {names}")
                index, cursor = leb(data, cursor + 1)
                imports[".".join(names)] = types[index]
        at = end
    return imports, exports


def integrity(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def members(tarball):
    """The package's module, notices and package.json, each a regular file
    named once in the archive, as bytes."""
    wanted = {f"package/{name}" for name in (MODULE, "package.json", *NOTICES)}
    found = {}
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        for member in archive.getmembers():
            if member.name not in wanted:
                continue
            if not member.isreg() or member.name in found:
                raise SystemExit(f"the tarball's {member.name} is not one regular file")
            found[member.name] = archive.extractfile(member).read()
    if missing := sorted(wanted - set(found)):
        raise SystemExit(f"the tarball lacks {missing}")
    return {name.removeprefix("package/"): data for name, data in found.items()}


def fetch(work):
    tarball_path = work / f"wasm-{VERSION}.tgz"
    with urllib.request.urlopen(TARBALL) as response:
        tarball_path.write_bytes(response.read())
    tarball = tarball_path.read_bytes()
    if integrity(tarball) != INTEGRITY:
        raise SystemExit("the tarball fails its npm integrity pin")
    files = members(tarball)
    package = json.loads(files["package.json"])
    if package.get("name") != PACKAGE or package.get("version") != VERSION:
        raise SystemExit("the tarball names another package")
    if package.get("license") != LICENSE:
        raise SystemExit(f"the package's licence is {package.get('license')!r}, not {LICENSE}")
    stated = package.get("tsrs", {})
    module = files[MODULE]
    imports, exports = inventory(module)
    VENDOR.mkdir(parents=True, exist_ok=True)
    (VENDOR / MODULE).write_bytes(module)
    for name in NOTICES:
        target = VENDOR / "notices" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(files[name])
    manifest = {"schema_version": 1, "package": PACKAGE, "version": VERSION, "tarball": TARBALL,
                "integrity": INTEGRITY, "shasum": hashlib.sha1(tarball).hexdigest(),
                "repository": REPOSITORY, "tag": TAG, "commit": COMMIT,
                "typescript_version": stated.get("typescriptVersion"),
                "typescript_commit": stated.get("typescriptCommit"),
                "license": LICENSE, "module": MODULE, "sha256": sha(module), "bytes": len(module),
                "notices": {name: sha(files[name]) for name in NOTICES},
                "imports": dict(sorted(imports.items())), "exports": sorted(exports),
                "sources": {"vendor-tsrs.py": sha(Path(__file__).read_bytes())}}
    (VENDOR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def check():
    manifest = json.loads((VENDOR / "manifest.json").read_text())
    module = (VENDOR / MODULE).read_bytes()
    pinned = {"package": PACKAGE, "version": VERSION, "tarball": TARBALL, "integrity": INTEGRITY,
              "commit": COMMIT, "license": LICENSE, "module": MODULE}
    if any(manifest.get(key) != value for key, value in pinned.items()):
        raise SystemExit("the tsrs manifest names another package")
    if manifest["sha256"] != sha(module) or manifest["bytes"] != len(module):
        raise SystemExit("tsrs artifact pin mismatch")
    if manifest["sources"] != {"vendor-tsrs.py": sha(Path(__file__).read_bytes())}:
        raise SystemExit("tsrs vendoring script pin mismatch")
    if manifest["notices"] != {name: sha((VENDOR / "notices" / name).read_bytes()) for name in NOTICES}:
        raise SystemExit("tsrs notices must travel with the module")
    imports, exports = inventory(module)
    if imports != manifest["imports"] or sorted(exports) != manifest["exports"]:
        raise SystemExit("tsrs ABI differs from its manifest")
    host = HOST.read_text()
    for literal in (f'const SHA256: &str = "{manifest["sha256"]}";', f'pub const TSRS_COMMIT: &str = "{COMMIT}";',
                    f'pub const TSRS_VERSION: &str = "{VERSION}";'):
        if literal not in host:
            raise SystemExit(f"host pin mismatch: {HOST.relative_to(CRATE)} lacks {literal}")
    registered = set(re.findall(rf'func_wrap\(\s*"{HOST_MODULE}",\s*"(\w+)"', host))
    custom = {name.split(".", 1)[1] for name in imports if name.startswith(f"{HOST_MODULE}.")}
    if registered != custom:
        raise SystemExit(f"the host registers {sorted(registered)}, the module imports {sorted(custom)}")
    print("TSRS-OK: artifact, notices, host pins and ABI")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not args.check:
        with tempfile.TemporaryDirectory(prefix="vendor-tsrs-") as work:
            fetch(Path(work))
    check()


if __name__ == "__main__":
    main()
