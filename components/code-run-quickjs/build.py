#!/usr/bin/env python3
"""Build two real QuickJS components. Never installs a compiler or fetches tools.

Required: WASI_SDK_PATH (wasi-sdk 27), wit-bindgen 0.46.0, wasm-tools 1.239.0.
The only download is the hash-pinned upstream QuickJS source archive.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
URL = "https://bellard.org/quickjs/quickjs-2025-09-13-2.tar.xz"
SOURCE_SHA256 = "996c6b5018fc955ad4d06426d0e9cb713685a00c825aa5c0418bd53f7df8b0b4"


def run(args, **kwargs):
    return subprocess.run([str(v) for v in args], check=True, **kwargs)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def patch_function(source, name, body):
    start = source.index("{", source.index(name))
    end, depth = start + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[:start] + "{\n" + body + "\n}" + source[end:]


def tool_version_matches(tool, version, reported):
    """Release CLIs may append a commit/date after their exact version token."""
    fields = reported.split()
    return (len(fields) >= 2 and fields[0] in {tool, tool + "-cli"}
            and fields[1] == version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "target/code-run-quickjs")
    parser.add_argument("--source", type=Path, help="existing pinned source archive; disables fetching")
    args = parser.parse_args()
    sdk = os.environ.get("WASI_SDK_PATH")
    if not sdk or not (Path(sdk) / "bin/clang").is_file():
        parser.error("missing WASI_SDK_PATH/bin/clang; host owner must provision wasi-sdk 27")
    versions = {}
    for tool, version in [("wit-bindgen", "0.46.0"), ("wasm-tools", "1.239.0")]:
        if not shutil.which(tool): parser.error(f"missing {tool} {version}; no tools are installed by this script")
        found = run([tool, "--version"], capture_output=True, text=True).stdout.strip()
        if not tool_version_matches(tool, version, found): parser.error(f"expected {tool} {version}, got {found}")
        versions[tool] = found
    versions["clang"] = run([Path(sdk) / "bin/clang", "--version"], capture_output=True, text=True).stdout.strip()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    archive = args.source or out / "quickjs.tar.xz"
    if not archive.exists():
        with urllib.request.urlopen(URL) as response: archive.write_bytes(response.read())
    if sha(archive) != SOURCE_SHA256: parser.error("QuickJS source SHA-256 mismatch")
    upstream = out / "source"
    upstream.mkdir(exist_ok=True)
    with tarfile.open(archive, "r:xz") as tar:
        tar.extractall(upstream, filter="data")
    source = upstream / "quickjs-2025-09-13"
    quickjs = (source / "quickjs.c").read_text()
    quickjs = patch_function(quickjs, "static int getTimezoneOffset(int64_t time)", "    (void)time; return 0; /* host clock, UTC only */")
    # No ambient clocks survive even during JS_NewContext initialization.
    quickjs = quickjs.replace("gettimeofday(", "oneiron_gettimeofday(")
    quickjs = quickjs.replace('#include "quickjs.h"', '#include "quickjs.h"\nextern int oneiron_gettimeofday(struct timeval *, void *);')
    (source / "quickjs.c").write_text(quickjs)
    # This pinned dtoa release includes setjmp.h but never uses its API.
    # WASI intentionally rejects the header without experimental exception
    # support; remove only the unused include, not an error-handling path.
    dtoa = (source / "dtoa.c").read_text()
    if dtoa.count("#include <setjmp.h>") != 1 or re.search(r"\b(?:setjmp|longjmp|jmp_buf)\b", dtoa.replace("#include <setjmp.h>", "")):
        raise SystemExit("unexpected dtoa setjmp dependency")
    (source / "dtoa.c").write_text(dtoa.replace("#include <setjmp.h>", ""))
    wit = (ROOT / "crates/oneiron/wit/code-run.wit").read_text()
    sdk_js = (ROOT / "crates/oneiron/wit/generated/code-run.mjs").read_text()
    bootstrap = "(() => {\n" + sdk_js.replace("export function createHostSdk", "function createHostSdk") + "\nreturn " + (HERE / "bootstrap.js").read_text() + "\n})();"
    artifacts = {}
    for tier in ["first-party", "foreign"]:
        stage = out / tier
        stage.mkdir(exist_ok=True)
        stage_wit = wit
        if tier == "foreign":
            # Same package/world and export types. This is the tier's import
            # projection, not a new world or a second protocol.
            stage_wit = re.sub(r"    // @js self\.[^\n]*\n    import [^\n]*\n", "", wit)
        (stage / "code-run.wit").write_text(stage_wit)
        run(["wit-bindgen", "c", "--world", "guest", "--out-dir", stage, stage / "code-run.wit"])
        run(["python3", HERE / "generate_bridge.py", ROOT / "crates/oneiron/wit/generated/code-run.mjs", stage / "bridge.h"])
        # Numeric C initializer is encoding- and quoting-independent.
        (stage / "bootstrap.h").write_text("static const char bootstrap[] = {" + ",".join(str(v) for v in bootstrap.encode()) + ",0};\n")
        wasm = stage / "guest.core.wasm"
        command = [Path(sdk) / "bin/clang", "--sysroot=" + str(Path(sdk) / "share/wasi-sysroot"),
                   "-O2", "-DNDEBUG", "-DEMSCRIPTEN", '-DCONFIG_VERSION="2025-09-13"',
                   "-fwrapv", "-ffunction-sections", "-fdata-sections", "-mexec-model=reactor",
                   "-Wl,--gc-sections", "-Wl,-z,stack-size=524288", "-Wl,--initial-memory=2097152",
                   "-Wl,--max-memory=33554432", "-I" + str(source), "-I" + str(stage)]
        if tier == "foreign": command.append("-DONEIRON_FOREIGN")
        wrappers = ["fd_write", "fd_read", "fd_close", "fd_seek", "fd_fdstat_get",
                    "environ_sizes_get", "environ_get", "args_sizes_get", "args_get",
                    "clock_time_get", "random_get", "proc_exit"]
        command += ["-Wl,--wrap=__wasi_" + name for name in wrappers]
        command += [HERE / "guest.c", HERE / "libc_denials.c", stage / "guest.c", stage / "guest_component_type.o"]
        command += [source / name for name in ["quickjs.c", "dtoa.c", "libregexp.c", "libunicode.c", "cutils.c"]]
        command += ["-lm", "-o", wasm]
        run(command)
        # No WASI adapter is used. Any ambient import is a build failure.
        wat = run(["wasm-tools", "print", wasm], capture_output=True, text=True).stdout
        modules = set(re.findall(r'\(import "([^"]+)"', wat))
        if modules - {"$root"}: raise SystemExit(f"refusing ambient core imports: {modules}")
        component = out / f"quickjs-{tier}.wasm"
        run(["wasm-tools", "component", "new", wasm, "-o", component])
        run(["wasm-tools", "validate", component])
        artifacts[tier] = {"file":component.name, "sha256":sha(component), "bytes":component.stat().st_size}
    manifest = {"schema_version":1, "component_name":"oneiron.plain-js.quickjs-component", "world":"oneiron:code-run/guest@1.0.0",
                "engine":"quickjs-2025-09-13-2", "upstream_url":URL,
                "upstream_sha256":SOURCE_SHA256, "toolchain":versions, "patched_quickjs_sha256":sha(source / "quickjs.c"),
                "patched_dtoa_sha256":sha(source / "dtoa.c"),
                "wit_sha256":sha(ROOT / "crates/oneiron/wit/code-run.wit"),
                "sources":{p.name:sha(p) for p in [HERE / "guest.c", HERE / "libc_denials.c", HERE / "bootstrap.js", HERE / "generate_bridge.py", HERE / "build.py"]},
                "artifacts":artifacts}
    shutil.copyfile(source / "LICENSE", out / "LICENSE")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(out / "manifest.json")


if __name__ == "__main__": main()
