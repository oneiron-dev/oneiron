#!/usr/bin/env bash
# One distributed verify leg. Select with LEG:
#   LEG=fmt-clippy   fmt (check-mode) + workspace clippy
#   LEG=tests:1/2    nextest full tier, partition hash:1/2, + doctests
#   LEG=tests:2/2    nextest full tier, partition hash:2/2
#
# Markers printed to stdout so they land INSIDE the tee'd log (the only truth):
#   VERIFY-LEG-OK <leg>
#   VERIFY-LEG-FAIL-<stage> <leg>    stage in fmt | clippy | test | doctest
set -uo pipefail
cd "$(dirname "$0")/.."

LEG="${LEG:?set LEG=fmt-clippy|tests:1/2|tests:2/2}"
ERR_RE='error(\[E[0-9]+\])?:'

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

case "$LEG" in
  fmt-clippy)
    run_stage fmt    cargo fmt --all --check
    run_stage clippy cargo clippy --workspace --all-targets --all-features -- -D warnings
    ;;
  tests:1/2)
    run_stage test    cargo nextest run --workspace --all-features --profile full --partition hash:1/2
    # Doctests ride the 1/2 leg (nextest doesn't run them; they're fast).
    run_stage doctest cargo test --doc --workspace --exclude oneiron-bench --all-features
    ;;
  tests:2/2)
    run_stage test cargo nextest run --workspace --all-features --profile full --partition hash:2/2
    ;;
  *)
    echo "VERIFY-LEG-FAIL-badleg ${LEG}"
    exit 2
    ;;
esac

echo "VERIFY-LEG-OK ${LEG}"
