#!/bin/bash
# Bound a self-hosted runner's persistent build cache.
#
# usage: scripts/ci/cap-target-cache.sh [cap-gb]   (default 20)
#
# Each runner's .env exports a persistent CARGO_TARGET_DIR (install-runner.sh),
# and cargo never evicts stale artifacts from it: every rebuilt crate leaves
# the old one behind, so the dir only grows (58 GB on the Mac mini after two
# days of PR traffic). This runs as the last step of every cargo job. Past the
# cap the whole dir is removed and the next job on this runner builds cold;
# under it nothing happens. It exits 0 either way: the cache is the host's
# concern, never the job's verdict.
#
# It only ever removes a dir named .../ci/target, the shape install-runner.sh
# documents, so a mispointed CARGO_TARGET_DIR is reported, not deleted.
set -euo pipefail

cap_gb="${1:-20}"
dir="${CARGO_TARGET_DIR:-}"

if [ -z "$dir" ]; then
  echo "cap-target-cache: CARGO_TARGET_DIR is unset (no persistent cache on this runner); nothing to do"
  exit 0
fi
if [ ! -d "$dir" ]; then
  echo "cap-target-cache: $dir does not exist; nothing to do"
  exit 0
fi
case "$dir" in
  */ci/target) ;;
  *)
    echo "cap-target-cache: refusing to manage $dir (not a .../ci/target path); nothing removed"
    exit 0
    ;;
esac

used_kb=$(du -sk "$dir" | cut -f1)
used_gb=$((used_kb / 1024 / 1024))
if [ "$used_gb" -ge "$cap_gb" ]; then
  echo "cap-target-cache: $dir is ${used_gb} GB, cap is ${cap_gb} GB: removing it; the next job here builds cold"
  rm -rf "$dir"
else
  echo "cap-target-cache: $dir is ${used_gb} GB, cap is ${cap_gb} GB: kept"
fi
