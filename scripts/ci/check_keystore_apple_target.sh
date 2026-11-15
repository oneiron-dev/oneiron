#!/usr/bin/env bash
# oneiron-keystore's manifest promises that its Apple adapters check for an
# Apple target from any host: no dependency may need an SDK, a linker or a C
# toolchain at build time. This runs that check: the library and its examples,
# every feature, for one Apple target (`cargo check` never links).
#
# It adds the target's standard library through rustup when it is missing, so
# it needs the network once per toolchain.
#
# Usage: scripts/ci/check_keystore_apple_target.sh [target triple]
set -euo pipefail

target="${1:-aarch64-apple-darwin}"
cd "$(dirname "$0")/../.."
rustup target add "${target}"
cargo check --locked -p oneiron-keystore --all-features --lib --examples --target "${target}"
