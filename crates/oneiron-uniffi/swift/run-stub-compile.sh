#!/usr/bin/env bash
# Compile proof for the ONE-1440 UniFFI definition surface.
#
# Pipeline: build the Rust library (cdylib + staticlib), generate Swift
# bindings from the compiled library's UniFFI metadata with the crate-local,
# version-locked bindgen binary, lay out the generated C module and Swift
# target, and `swift build` a never-run consumer against the freshly
# generated API. Successful generation plus compilation is the evidence:
# generated Swift names, memberwise DTO initializers, and the error field
# shape all type-check, or the build fails.
#
# This mirrors the proven pattern of
# `crates/oneiron-ffi/swift/run-consumer-smoke.sh` but stays self-contained:
# it resolves its own roots, never touches the root Swift package, never
# runs the executable, and never packages an XCFramework.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CRATE_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(cd "$CRATE_DIR/../.." && pwd)

cd "$REPO_ROOT"

export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-$(sw_vers -productVersion | awk -F. '{print $1 "." $2}')}
HOST_ARCH=$(uname -m)
SWIFT_TRIPLE=${SWIFT_TRIPLE:-${HOST_ARCH}-apple-macosx${MACOSX_DEPLOYMENT_TARGET}}

# The cdylib carries the UniFFI metadata bindgen reads in library mode; the
# staticlib is what the Swift compile target links. `bindgen-cli` builds the
# crate-local generator so it cannot drift from the compiled library.
cargo build -p oneiron-uniffi --features bindgen-cli

CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-target}
case "$CARGO_TARGET_DIR" in
  /*) TARGET_DIR="$CARGO_TARGET_DIR" ;;
  *) TARGET_DIR="$REPO_ROOT/$CARGO_TARGET_DIR" ;;
esac

BINDGEN="$TARGET_DIR/debug/uniffi-bindgen"
DYLIB="$TARGET_DIR/debug/liboneiron_uniffi.dylib"
RUST_ARCHIVE="$TARGET_DIR/debug/liboneiron_uniffi.a"

if [[ ! -x "$BINDGEN" ]]; then
  echo "missing crate-local bindgen binary: $BINDGEN" >&2
  exit 1
fi
if [[ ! -f "$DYLIB" ]]; then
  echo "missing UniFFI metadata library: $DYLIB" >&2
  exit 1
fi

RAW_DIR="$SCRIPT_DIR/.generated/raw"
C_MODULE_DIR="$SCRIPT_DIR/.generated/OneironUniFFIFFI"
SWIFT_MODULE_DIR="$SCRIPT_DIR/.generated/OneironUniFFI"

rm -rf "$RAW_DIR" "$C_MODULE_DIR" "$SWIFT_MODULE_DIR"
mkdir -p "$RAW_DIR" "$C_MODULE_DIR" "$SWIFT_MODULE_DIR"

# Generate from the compiled library, not a UDL file. The generated files
# are build outputs and are never committed; `--no-format` keeps the output
# independent of whichever Swift formatter a host happens to install.
"$BINDGEN" generate \
  --library "$DYLIB" \
  --language swift \
  --out-dir "$RAW_DIR" \
  --no-format

# Place the generated files into the paths the package manifest names. Only
# the module map file is relocated (renamed to SPM's conventional
# `module.modulemap`); no generated source is rewritten.
cp "$RAW_DIR/OneironUniFFI.swift" "$SWIFT_MODULE_DIR/OneironUniFFI.swift"
cp "$RAW_DIR/OneironUniFFIFFI.h" "$C_MODULE_DIR/OneironUniFFIFFI.h"
cp "$RAW_DIR/OneironUniFFIFFI.modulemap" "$C_MODULE_DIR/module.modulemap"
printf '/* Placeholder translation unit: a C target cannot be header-only. */\n' \
  > "$C_MODULE_DIR/placeholder.c"

if [[ ! -f "$RUST_ARCHIVE" ]]; then
  echo "missing Rust archive: $RUST_ARCHIVE" >&2
  exit 1
fi

# Type-check the committed compile consumer against the freshly generated
# bindings, linked with the static archive. The executable is never run.
swift build \
  --package-path "$SCRIPT_DIR" \
  --scratch-path "$SCRIPT_DIR/.build" \
  --triple "$SWIFT_TRIPLE" \
  -Xlinker "$RUST_ARCHIVE"
