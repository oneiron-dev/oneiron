#!/usr/bin/env bash
# Full verify gate: fmt (check-mode) -> workspace clippy -> full nextest tier ->
# doctests -> the two featureless `oneiron` gates.
#
# Markers are printed to stdout so they land INSIDE the tee'd log — the marker in
# the log is the only verify truth; wrapper/ssh exit codes are not evidence.
#   VERIFY-OK             everything green
#   VERIFY-FAIL-<stage>   first red stage
#                         (fmt | clippy | test | doctest |
#                          clippy-featureless | test-featureless)
#
# Mirrors CI's record-of-truth lane (.github/workflows/ci.yml main-push):
# clippy --workspace --all-targets --all-features -D warnings, nextest `full`
# profile, doctests separately (nextest does not run them).
#
# The `oneiron` crate declares NO default features, and its library *and* its
# test targets must compile and run with none (AGENTS.md, Landmines →
# featureless builds). Those two gates run in ADDITION to the all-features
# stages above, never instead of them: a law whose mode is base-mode has to be
# executed featureless, not merely compiled.
set -uo pipefail
cd "$(dirname "$0")/.."

# Coded compiler errors (`error[E0308]:` and bare `error:`) double-checked in
# stage output: a runner that dies without a failing exit still can't pass.
# Anchored to line start — unanchored `error:` matches Rust paths like
# `error::tests::...` in nextest PASS lines (found on the first arch run).
ERR_RE='^error(\[E[0-9]+\])?:'

run_stage() {
  local stage="$1"; shift
  echo "=== verify: ${stage}: $* ==="
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  # Full output into the log (tee'd by the caller) — never grep-consumed.
  printf '%s\n' "$out"
  if [ $rc -ne 0 ] || printf '%s\n' "$out" | grep -qE "$ERR_RE"; then
    echo "VERIFY-FAIL-${stage}"
    exit 1
  fi
}

run_stage fmt     cargo fmt --all --check
run_stage clippy  cargo clippy --workspace --all-targets --all-features -- -D warnings
run_stage test    cargo nextest run --workspace --all-features --profile full
run_stage doctest cargo test --doc --workspace --exclude oneiron-bench --all-features

run_stage clippy-featureless \
  cargo clippy -p oneiron --all-targets --no-default-features -- -D warnings
run_stage test-featureless \
  cargo test -p oneiron --lib --no-default-features

echo "VERIFY-OK"
