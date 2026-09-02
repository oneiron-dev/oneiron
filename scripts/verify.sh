#!/usr/bin/env bash
# Full verify gate: fmt (check-mode) -> all-feature and featureless clippy ->
# full all-feature nextest tier -> featureless oneiron library tests -> doctests.
#
# Markers are printed to stdout so they land INSIDE the tee'd log — the marker in
# the log is the only verify truth; wrapper/ssh exit codes are not evidence.
#   VERIFY-OK             everything green
#   VERIFY-FAIL-<stage>   first red stage
#
# Mirrors CI's record-of-truth all-feature lane (.github/workflows/ci.yml
# main-push) and keeps the unconditional oneiron surface honest with explicit
# no-default-feature clippy and library-test stages. Doctests stay separate
# because nextest does not run them.
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

run_stage fmt                 cargo fmt --all --check
run_stage clippy              cargo clippy --workspace --all-targets --all-features -- -D warnings
run_stage clippy-featureless  cargo clippy -p oneiron --all-targets --no-default-features -- -D warnings
run_stage test                cargo nextest run --workspace --all-features --profile full
run_stage test-featureless    cargo test -p oneiron --lib --no-default-features
run_stage doctest             cargo test --doc --workspace --exclude oneiron-bench --all-features

echo "VERIFY-OK"
