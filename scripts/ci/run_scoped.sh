#!/usr/bin/env bash
# run_scoped.sh clippy|test|featureless: the cargo work of one CI job, sized by scripts/ci/ci_scope.py.
# Scoped (PRs, main pushes): clippy for touched packages and their reverse dependents; tests for touched
# packages only, and for `oneiron` only the touched top-level modules. Full runs the complete gate.
# Inputs (from the `changes` job): SCOPE_FULL, SCOPE_PACKAGES, SCOPE_DEPENDENTS, SCOPE_ONEIRON,
# SCOPE_MODULES, SCOPE_IT.
set -euo pipefail
mode=${1:?clippy|test|featureless}
full=${SCOPE_FULL:-true}
packages=${SCOPE_PACKAGES:-}
dependents=${SCOPE_DEPENDENTS:-}
oneiron=${SCOPE_ONEIRON:-false}
modules=${SCOPE_MODULES:-ALL}
it=${SCOPE_IT:-false}

# Packages other than the core crate, and the napi addon, which needs a Node host to test.
others=()
for p in $packages; do
  case "$p" in oneiron | oneiron-napi) ;; *) others+=(-p "$p") ;; esac
done
# nextest filter for the touched top-level modules of the core crate.
filter=""
if [ "$modules" != ALL ] && [ -n "$modules" ]; then
  filter="test(/^($(echo "$modules" | tr ' ' '|'))::/)"
fi

# Keep each test command's vault/temp files isolated and clean them even on failure.
run() {
  echo "+ $*"
  if [ "$mode" = test ] || [ "$mode" = featureless ]; then
    RUSTC_WORKSPACE_WRAPPER="$PWD/scripts/ci/rustc-threads.sh" scripts/ci/with-test-tmpdir.sh "$@"
  else
    "$@"
  fi
}

case "$mode" in
clippy)
  if [ "$full" = true ]; then
    run cargo clippy --workspace --all-targets --all-features -- -D warnings
    run cargo clippy -p oneiron --all-targets --no-default-features -- -D warnings
    run cargo clippy -p oneiron-server --all-features -- -D warnings
    run env -u CARGO_ENCODED_RUSTDOCFLAGS RUSTC_WORKSPACE_WRAPPER="$PWD/scripts/ci/rustc-threads.sh" RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
    exit 0
  fi
  pk=(); for p in $packages $dependents; do pk+=(-p "$p"); done
  [ ${#pk[@]} -gt 0 ] && run cargo clippy "${pk[@]}" --all-targets --all-features -- -D warnings
  [ "$oneiron" = true ] && run cargo clippy -p oneiron --all-targets --no-default-features -- -D warnings
  [ ${#pk[@]} -gt 0 ] || [ "$oneiron" = true ] || echo "no Rust package changed: nothing to lint"
  ;;
test)
  if [ "$full" = true ]; then
    run cargo nextest run --workspace --exclude oneiron-napi --all-features --profile full --no-fail-fast
    run cargo test --doc --workspace --exclude oneiron-bench --all-features
    exit 0
  fi
  [ ${#others[@]} -gt 0 ] && run cargo nextest run "${others[@]}" --all-features --no-fail-fast --no-tests=pass
  if [ "$oneiron" = true ]; then
    if [ -n "$filter" ]; then
      run cargo nextest run -p oneiron --lib --all-features --no-fail-fast --no-tests=pass -E "$filter"
    else
      run cargo nextest run -p oneiron --lib --all-features --no-fail-fast
    fi
    [ "$it" = true ] && run cargo nextest run -p oneiron --all-features --no-fail-fast --no-tests=pass -E 'kind(test)'
  fi
  [ ${#others[@]} -gt 0 ] || [ "$oneiron" = true ] || echo "no Rust package changed: nothing to test"
  ;;
featureless)
  if [ "$full" = true ]; then
    # Both process models (W8-T41): libtest threads in one process, then nextest one process per test.
    run cargo test -p oneiron --lib --no-default-features
    run cargo nextest run -p oneiron --lib --no-default-features --profile featureless --no-fail-fast --retries 0
    exit 0
  fi
  if [ "$oneiron" = true ]; then
    # The shared-process lane for the touched modules: libtest runs every test whose path contains a filter.
    if [ "$modules" = ALL ] || [ -z "$modules" ]; then
      run cargo test -p oneiron --lib --no-default-features
    else
      args=(); for m in $modules; do args+=("$m::"); done
      run cargo test -p oneiron --lib --no-default-features -- "${args[@]}"
    fi
  else
    echo "oneiron unchanged: no featureless tests to run"
  fi
  ;;
*) echo "unknown mode $mode" >&2; exit 2 ;;
esac
