#!/usr/bin/env bash
# One distributed verify leg. Select with LEG:
#   LEG=fmt-clippy   code-map pin + fmt (check-mode) + workspace clippy
#   LEG=tests:1/2    nextest full tier, partition hash:1/2, + doctests
#   LEG=tests:2/2    nextest full tier, partition hash:2/2
#
# Markers printed to stdout so they land INSIDE the tee'd log (the only truth):
#   VERIFY-LEG-OK <leg>
#   VERIFY-LEG-FAIL-<stage> <leg>    stage in codemap | fmt | clippy | test | doctest
set -uo pipefail
cd "$(dirname "$0")/.."

LEG="${LEG:?set LEG=fmt-clippy|tests:1/2|tests:2/2}"
# Line-start anchor: unanchored `error:` matches `error::tests::...` module
# paths in nextest output (false-positived the first Phase-0 run).
ERR_RE='^error(\[E[0-9]+\])?:'

run_stage() {
  local stage="$1"; shift
  echo "=== verify-leg ${LEG}: ${stage}: $* ==="
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  printf '%s\n' "$out"
  if [ $rc -ne 0 ] || printf '%s\n' "$out" | grep -qE "$ERR_RE"; then
    echo "VERIFY-LEG-FAIL-${stage} ${LEG}"
    exit 1
  fi
}

run_test_partition() {
  local partition="$1"
  local -a packages=(--workspace)
  # Linux cannot link napi tests off a Node host. Keep the existing macOS
  # coverage, unlike verify.sh's unconditional exclusion for its reference lane.
  if [ "$(uname -s)" = Linux ]; then
    packages+=(--exclude oneiron-napi)
  fi
  run_stage test cargo nextest run --locked "${packages[@]}" --all-features --profile full --partition "$partition"
}

case "$LEG" in
  fmt-clippy)
    run_stage codemap scripts/codemap/check.sh
    # Honor the workspace's heed exclusion; --all also follows local path dependencies.
    run_stage fmt    cargo fmt --check
    run_stage clippy cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
    ;;
  tests:1/2)
    run_test_partition hash:1/2
    # Doctests ride the 1/2 leg (nextest doesn't run them; they're fast).
    run_stage doctest cargo test --locked --doc --workspace --exclude oneiron-bench --all-features
    ;;
  tests:2/2)
    run_test_partition hash:2/2
    ;;
  *)
    echo "VERIFY-LEG-FAIL-badleg ${LEG}"
    exit 2
    ;;
esac

echo "VERIFY-LEG-OK ${LEG}"
