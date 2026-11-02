#!/usr/bin/env bash
# L15-S loop bench runner (bench only, never merges). Usage: bash l15s-bench.sh <stage>
# Runs on the fleet host inside the synced worktree. Warm target per fleet --who home.
set -u
export PATH=$HOME/.cargo/bin:$PATH CARGO_TERM_COLOR=never CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=1 CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_TARGET_DIR=$HOME/l15s-target
stage=${1:?stage}
head=$(git rev-parse HEAD 2>/dev/null || echo nogit)
start=$(date +%s)
case "$stage" in
  fusion)
    cargo build --locked --release -p oneiron-retrieval --example l15s_fusion_bench || exit 1
    echo "## BUILD rc=0 head=$head secs=$(( $(date +%s) - start ))"
    for i in 1 2 3; do "$CARGO_TARGET_DIR/release/examples/l15s_fusion_bench" l15s-inputs/claims.tsv 60; done
    ;;
  oneiron)
    cargo build --locked --release -p oneiron --bin l15s_bench || exit 1
    echo "## BUILD rc=0 head=$head secs=$(( $(date +%s) - start ))"
    for i in 1 2 3; do "$CARGO_TARGET_DIR/release/l15s_bench" "${2:?substage}"; done
    ;;
  *) echo "unknown stage $stage"; exit 2;;
esac
