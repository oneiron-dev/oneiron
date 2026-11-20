#!/usr/bin/env bash
# run_stemma_fork_unit_tests.sh [--test <target>]: the vendored stemma fork's unit tests or one of stemma's
# integration targets, run from the fork's own manifests.
#
# The fork is two packages that the root Cargo.toml lists under `exclude`: `stemma`
# (crates/oneiron-docedit/vendor/stemma-engine) and `stemma-diff` (crates/oneiron-docedit/vendor/stemma-diff).
# The workspace compiles `stemma` only as a dependency of oneiron-docedit, so no workspace run builds the
# `#[cfg(test)]` modules under the fork's `src`. This script builds and runs them: `cargo test --lib` for each
# package. With no arguments it runs none of the fork's integration targets (`tests/`); `--test <target>` runs
# one of stemma's. crates/oneiron-docedit/PROVENANCE.md says what each of them does today.
#
# Dependency versions come from the workspace's Cargo.lock, so the tests run on the versions the product builds
# the fork with. Neither package has a lock file of its own. The script copies the workspace lock beside the
# manifest of each package it tests and lets cargo resolve from it: cargo keeps every version the copy names and
# drops the entries the package does not use. With `--test` it tests `stemma` alone, so only stemma-engine gets a
# copy: `stemma-diff` is then a path dev-dependency, and cargo reads no lock file beside a path dependency. The
# run is refused when the resolved lock holds a package the workspace lock does not hold (the fork's own two
# packages apart), and the tests then run with --locked. The copies are removed when the script ends. The script
# neither overwrites nor removes a lock file it did not make. One that is already beside the manifest of a
# package it tests refuses the run at the start. Each copy is made only as a new file, when its package's turn
# comes, so a lock file that appears beside that manifest during the run refuses the run then and stays as it is.
# What the script cannot tell apart: a file written over a copy it already made; that file is removed as the copy.
#
# Usage: scripts/docedit/run_stemma_fork_unit_tests.sh [--test <target>]   (from any directory)
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
fork=crates/oneiron-docedit/vendor

usage_error() {
  printf 'error: %s\n' "$1" >&2
  printf 'Usage: scripts/docedit/run_stemma_fork_unit_tests.sh\n' >&2
  printf '       scripts/docedit/run_stemma_fork_unit_tests.sh --test <target>\n' >&2
  exit 2
}

case $# in
  0)
    packages=(stemma-engine stemma-diff)
    test_args=(--lib)
    ;;
  2)
    [ "$1" = --test ] || usage_error "the first argument must be --test"
    target_pattern='^[a-z][a-z0-9_]*$'
    if ! (export LC_ALL=C; shopt -u nocasematch; [[ $2 =~ $target_pattern ]]); then
      usage_error "the target name must match $target_pattern"
    fi
    target_path=$fork/stemma-engine/tests/$2
    if [[ ! -f "$target_path.rs" && ! -f "$target_path/main.rs" ]]; then
      usage_error "no stemma integration target named '$2'"
    fi
    packages=(stemma-engine)
    test_args=(--test "$2")
    ;;
  *)
    usage_error "expected no arguments or --test followed by one target name"
    ;;
esac

# The fork's build output stays apart from the workspace's.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}/stemma-fork"

work=$(mktemp -d)
# The lock copies this run made; only these are removed.
created=()
remove_copies() {
  rm -rf -- "$work"
  for lock in ${created[@]+"${created[@]}"}; do rm -f -- "$lock"; done
}
trap remove_copies EXIT

for package in "${packages[@]}"; do
  if [ -e "$fork/$package/Cargo.lock" ] || [ -L "$fork/$package/Cargo.lock" ]; then
    echo "error: $fork/$package/Cargo.lock exists and this run did not make it. The script writes a copy of the workspace's Cargo.lock at that path and removes it at the end; move the file away and run again." >&2
    exit 2
  fi
done

# One line for each [[package]] table of a lock file: name, version, source, checksum ("-" where it has none).
lock_packages() {
  awk '
    function finish() {
      if (name != "") print name, version, (source == "" ? "-" : source), (checksum == "" ? "-" : checksum)
      name = version = source = checksum = ""
    }
    /^\[/ { finish(); in_package = ($0 == "[[package]]"); next }
    !in_package { next }
    { value = $3; gsub(/"/, "", value) }
    $1 == "name" { name = value }
    $1 == "version" { version = value }
    $1 == "source" { source = value }
    $1 == "checksum" { checksum = value }
    END { finish() }
  ' "$1" | LC_ALL=C sort -u
}

# Makes an empty file at $1 as this run's own. noclobber: the shell creates the file and fails when anything is at
# the path, in one step, so a lock file that appeared after the check above is not written over. The path joins
# `created` only once the file is made, so the cleanup never removes a file this run did not make.
make_own_lock_file() {
  if ! (set -o noclobber; : > "$1"); then
    echo "error: $1 could not be made as a new file (the shell's line above says why). The script writes a copy of the workspace's Cargo.lock at that path and removes it at the end, and it never writes over a file it did not make; if a file is there, move it away and run again." >&2
    exit 2
  fi
  created+=("$1")
}

lock_packages Cargo.lock > "$work/workspace.packages"
for package in "${packages[@]}"; do
  manifest=$fork/$package/Cargo.toml
  make_own_lock_file "$fork/$package/Cargo.lock"
  cp Cargo.lock "$fork/$package/Cargo.lock"
  # Resolve only; nothing is built.
  cargo metadata --manifest-path "$manifest" --format-version 1 > /dev/null
  lock_packages "$fork/$package/Cargo.lock" > "$work/fork.packages"
  # A path package has no source: the fork's own two are the only ones a fork lock may add.
  unpinned=$(LC_ALL=C comm -13 "$work/workspace.packages" "$work/fork.packages" \
    | grep -v -x -E '(stemma|stemma-diff) [^ ]+ - -' || true)
  if [ -n "$unpinned" ]; then
    echo "error: $manifest resolves packages that the workspace's Cargo.lock does not hold (name, version, source, checksum):" >&2
    echo "$unpinned" >&2
    exit 1
  fi
  echo "+ cargo test --locked --manifest-path $manifest ${test_args[*]}"
  cargo test --locked --manifest-path "$manifest" "${test_args[@]}"
done
