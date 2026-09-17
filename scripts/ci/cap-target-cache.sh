#!/bin/bash
# Bound a self-hosted runner's persistent build cache (best effort, never a gate).
#
# usage: scripts/ci/cap-target-cache.sh [cap-gb]   (default 20 GiB)
#
# Cargo owns artifact selection: first remove workspace outputs, preserving
# third-party dependencies. Only reset the whole cache if it still exceeds the
# cap. No hand-written fingerprint/mtime eviction; every retained artifact is
# still validated by Cargo on the next build. Run after the runner's cargo job,
# never alongside another build sharing this target directory.
set -uo pipefail

cap_gb="${1-20}"
dir="${CARGO_TARGET_DIR:-}"

note() { echo "cap-target-cache: $*"; }

# Bound the arithmetic as well as rejecting zero, negative and nonnumeric caps.
if [[ ! "$cap_gb" =~ ^[1-9][0-9]{0,5}$ ]]; then
  note "invalid cap '$cap_gb' (expected a positive GiB integer); nothing removed"
  exit 0
fi
if [ -z "$dir" ]; then
  note "CARGO_TARGET_DIR is unset (no persistent cache on this runner); nothing to do"
  exit 0
fi
if [ ! -d "$dir" ]; then
  note "$dir does not exist; nothing to do"
  exit 0
fi
case "$dir" in
  /*/ci/target) ;;
  *)
    note "refusing to manage $dir (not an absolute .../ci/target path); nothing removed"
    exit 0
    ;;
esac
# Reject symlinks in any component, not just a target symlink. The runner's
# configured path must be its real path (also the macOS TCC/cache contract).
physical_dir="$(cd "$dir" && pwd -P)" || { note "cannot resolve $dir; nothing removed"; exit 0; }
if [ "$physical_dir" != "$dir" ]; then
  note "refusing non-canonical cache path $dir; nothing removed"
  exit 0
fi

measure() {
  local usage
  usage="$(du -sk "$dir")" || return 1
  used_kb="${usage%%[[:space:]]*}"
  [[ "$used_kb" =~ ^[0-9]+$ ]]
}

cap_kb=$((cap_gb * 1024 * 1024))
if ! measure; then
  note "cannot measure $dir; nothing removed"
  exit 0
fi
if [ "$used_kb" -lt "$cap_kb" ]; then
  note "$dir is $((used_kb / 1024 / 1024)) GiB, cap is $cap_gb GiB: kept"
  exit 0
fi

# --workspace respects Cargo.toml's vendor exclusions and removes old feature
# variants. With package selection Cargo defaults to debug only, so explicitly
# clean both standard output profiles (test uses debug). Custom-profile outputs,
# if any, remain subject to the measured full-reset fallback below.
repo="$(cd "$(dirname "$0")/../.." && pwd -P)" || { note "cannot resolve workspace; cache kept"; exit 0; }
note "$dir reached $cap_gb GiB: cleaning workspace outputs, keeping dependencies"
if ! cargo clean --manifest-path "$repo/Cargo.toml" --workspace --profile dev --target-dir "$dir" --locked --offline ||
   ! cargo clean --manifest-path "$repo/Cargo.toml" --workspace --profile release --target-dir "$dir" --locked --offline; then
  note "workspace cleanup failed; cache kept (no full reset)"
  exit 0
fi
if ! measure; then
  note "cannot measure after workspace cleanup; remaining cache kept"
  exit 0
fi
if [ "$used_kb" -lt "$cap_kb" ]; then
  note "$dir is now $((used_kb / 1024 / 1024)) GiB: dependency cache kept"
  exit 0
fi

note "$dir is still $((used_kb / 1024 / 1024)) GiB: resetting the cache"
if ! rm -rf -- "$dir"; then
  note "cache reset failed; maintenance does not change the job verdict"
fi
exit 0
