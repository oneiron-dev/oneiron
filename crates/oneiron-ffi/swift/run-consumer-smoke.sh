#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
CONSUMER_DIR="$SCRIPT_DIR/SmokeConsumer"

cd "$REPO_ROOT"

export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-$(sw_vers -productVersion | awk -F. '{print $1 "." $2}')}
HOST_ARCH=$(uname -m)
SWIFT_TRIPLE=${SWIFT_TRIPLE:-${HOST_ARCH}-apple-macosx${MACOSX_DEPLOYMENT_TARGET}}

cargo build -p oneiron-ffi

CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-target}
case "$CARGO_TARGET_DIR" in
  /*) TARGET_DIR="$CARGO_TARGET_DIR" ;;
  *) TARGET_DIR="$REPO_ROOT/$CARGO_TARGET_DIR" ;;
esac

RUST_ARCHIVE="$TARGET_DIR/debug/liboneiron_ffi.a"
if [[ ! -f "$RUST_ARCHIVE" ]]; then
  echo "missing Rust archive: $RUST_ARCHIVE" >&2
  exit 1
fi

swift run \
  --package-path "$CONSUMER_DIR" \
  --scratch-path "$REPO_ROOT/.build/oneiron-storage-smoke" \
  --triple "$SWIFT_TRIPLE" \
  -Xlinker "$RUST_ARCHIVE" \
  OneironStorageSmoke
