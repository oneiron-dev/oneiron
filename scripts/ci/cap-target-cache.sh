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

# Cargo expands templates in build.build-dir even in a quoted config value.
# Refuse braces rather than risk cleaning a different path after expansion.
case "$dir" in
  *'{'*|*'}'*)
    note "refusing template braces in cache path $dir; nothing removed"
    exit 0
    ;;
esac

# Check before EACH clean pass: Cargo can follow artifact-directory symlinks
# even when the target root is canonical. Refuse all descendant symlinks,
# including internal, file and dangling links, rather than guess which are safe.
# The caller must own the target, exclude concurrent changes, and ensure there
# are no mounted descendants (including same-device bind/file mounts). Device
# checks below are defense in depth, not a proof of that precondition. Keep the
# namespace stable; this preflight is not a lock or path-swap race protection.
clean_workspace_profile() {
  local build_config
  build_config="$(python3 - "$dir" <<'PY'
import json
import os
import stat
import sys

root = sys.argv[1]
# Diagnostic logical sizes only: no second walk, extra stat, or inode accounting.
components = dict.fromkeys((
    "debug/deps", "debug/build", "debug/incremental", "release", "doc", "tests/trybuild", "other"
), 0)
try:
    root_stat = os.lstat(root)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("cache root is not a real directory")
    pending = [root]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                entry_stat = entry.stat(follow_symlinks=False)
                mode = entry_stat.st_mode
                if stat.S_ISLNK(mode):
                    raise ValueError(f"cache contains a symlink: {entry.path!r}")
                if entry_stat.st_dev != root_stat.st_dev:
                    raise ValueError(f"cache crosses a device boundary: {entry.path!r}")
                if stat.S_ISDIR(mode):
                    pending.append(entry.path)
                elif stat.S_ISREG(mode) and components is not None:
                    # Keep optional accounting separate from stat and all safety
                    # checks above. A metrics failure cannot veto a valid clean.
                    try:
                        relative = entry.path[len(root) + 1:]
                        group = next((name for name in components
                                      if relative.startswith(name + "/")), "other")
                        components[group] += entry_stat.st_size
                    except Exception:
                        components = None
    # JSON basic-string escaping is also valid TOML. Keep non-ASCII characters
    # literal so non-BMP paths do not become JSON-only surrogate-pair escapes.
    print("build.build-dir=" + json.dumps(root, ensure_ascii=False))
except (OSError, ValueError) as error:
    print(f"cap-target-cache: cannot validate cache layout: {error}", file=sys.stderr)
    sys.exit(1)

# Only a complete successful safety scan reaches diagnostics. These values never
# replace du's allocated KiB or feed a cleanup decision. None means unavailable.
try:
    space = os.statvfs(root)
    available_bytes = space.f_bavail * space.f_frsize
except Exception:
    available_bytes = None
try:
    report = {"available_bytes": available_bytes,
              "apparent_file_bytes_non_deduplicated": components}
    # Write directly: a broken stderr must not leave buffered output that makes
    # Python's shutdown fail after a successful scan/config result on stdout.
    os.write(2, ("cap-target-cache: diagnostics " + json.dumps(report) + "\n").encode())
except Exception:
    pass
PY
)" || return 1
  # --target-dir alone does not constrain Cargo 1.96's separate build directory.
  # CLI config wins over file config; do not inherit an external build-dir env.
  env -u CARGO_BUILD_BUILD_DIR cargo clean --manifest-path "$repo/Cargo.toml" \
    --workspace --profile "$1" --target-dir "$dir" --config "$build_config" --locked --offline
}

# --workspace respects Cargo.toml's vendor exclusions and removes old feature
# variants. With package selection Cargo defaults to debug only, so explicitly
# clean both standard output profiles (test uses debug). Custom-profile outputs,
# if any, remain subject to the measured full-reset fallback below.
repo="$(cd "$(dirname "$0")/../.." && pwd -P)" || { note "cannot resolve workspace; cache kept"; exit 0; }
note "$dir reached $cap_gb GiB: cleaning workspace outputs, keeping dependencies"
if ! clean_workspace_profile dev || ! clean_workspace_profile release; then
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
