#!/usr/bin/env bash
# Full verify gate: code-map pin -> fmt (check-mode) -> all-feature and
# featureless + server-production clippy -> strict rustdoc -> full all-feature
# nextest tier -> featureless oneiron library tests -> doctests.
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

usage() {
  printf '%s\n' \
    'Usage: scripts/verify.sh [--list | --help]' \
    '  No arguments: run all 9 scripted stages; success prints VERIFY-OK.' \
    '  --list: print stage names and commands without running them.' \
    '  --help: show this help without running any checks.' \
    '  ONEIRON_FEATURELESS_RUNNER may be unset or libtest; other values are rejected.' \
    'The featureless libtest stage is mandatory; nextest is an inner-loop option only.' \
    'The rustdoc stage denies documentation warnings before runtime tests.' \
    'Scoped iteration: see AGENTS.md. Extra narrow-sync policy gate: WORKFLOW.md section 3.'
}

LIST_ONLY=false
case "$#:$*" in
  0:) ;;
  1:--list) LIST_ONLY=true ;;
  1:--help|1:-h) usage; exit 0 ;;
  *) usage >&2; echo 'VERIFY-FAIL-usage' >&2; exit 2 ;;
esac

# Reject the retired replacement rather than silently weaken shared-process coverage.
case "${ONEIRON_FEATURELESS_RUNNER-libtest}" in
  libtest) ;;
  *)
    echo 'ONEIRON_FEATURELESS_RUNNER only accepts libtest; nextest is inner-loop only' >&2
    echo 'VERIFY-FAIL-usage' >&2
    exit 2
    ;;
esac

cd "$(dirname "$0")/.." || { echo 'VERIFY-FAIL-root'; exit 1; }

# Coded compiler errors (`error[E0308]:` and bare `error:`) double-checked in
# stage output: a runner that dies without a failing exit still can't pass.
# Anchored to line start — unanchored `error:` matches Rust paths like
# `error::tests::...` in nextest PASS lines (found on the first arch run).
ERR_RE='^error(\[E[0-9]+\])?:'

run_stage() {
  local stage="$1"; shift
  # Listing and execution share these calls, so discovery cannot omit a gate.
  if [ "$LIST_ONLY" = true ]; then
    printf '%s\t' "$stage"
    printf '%q ' "$@"
    printf '\n'
    return
  fi
  echo "=== verify: ${stage}: $* ==="
  local out rc started finished
  # Bash SECONDS measures elapsed wall time since script start, not CPU time.
  # Emit the start before the command: its output stays buffered until it exits.
  started=$SECONDS
  echo "VERIFY-STAGE-START ${stage} wall_elapsed=${started}s"
  out="$("$@" 2>&1)"; rc=$?
  finished=$SECONDS
  # Full output into the log (tee'd by the caller) — never grep-consumed.
  printf '%s\n' "$out"
  echo "VERIFY-STAGE-END ${stage} wall_elapsed=${finished}s wall_duration=$((finished - started))s"
  if [ $rc -ne 0 ] || printf '%s\n' "$out" | grep -qE "$ERR_RE"; then
    echo "VERIFY-FAIL-${stage}"
    exit 1
  fi
}

# Build commands are --locked so a stale manifest cannot rewrite Cargo.lock during verification.
# Generated code map first: cheap, and a stale map is a docs bug that must not
# hide behind a long compile.
run_stage codemap             scripts/codemap/check.sh
# Honor the workspace's heed exclusion; --all also follows local path dependencies.
run_stage fmt                 cargo fmt --check
run_stage clippy              cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
run_stage clippy-featureless  cargo clippy --locked -p oneiron --all-targets --no-default-features -- -D warnings
# The server's own feature selection of the engine (`sync` without `test-hooks`) is a
# third combination neither row above compiles: `--workspace --all-targets` unifies the
# dev-dependency features in, and `--no-default-features` drops `sync`. No `--all-targets`
# here on purpose — that is what the release binary builds.
run_stage clippy-server       cargo clippy --locked -p oneiron-server --all-features -- -D warnings
# Existing mandatory documentation policy belongs in the gate, not a manual step.
# Encoded flags take precedence even when empty. Unset them for this child only;
# do not change other stages' environments or compiler fingerprints globally.
run_stage rustdoc             env -u CARGO_ENCODED_RUSTDOCFLAGS RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
run_stage test                cargo nextest run --locked --workspace --exclude oneiron-napi --all-features --profile full
run_stage test-featureless    cargo test --locked -p oneiron --lib --no-default-features
run_stage doctest             cargo test --locked --doc --workspace --exclude oneiron-bench --all-features

if [ "$LIST_ONLY" = false ]; then
  echo "VERIFY-OK"
fi
