#!/usr/bin/env bash
# run_stemma_fork_unit_tests.sh: the unit tests of the vendored stemma fork, run from the fork's own manifests.
#
# The fork is two packages that the root Cargo.toml lists under `exclude`: `stemma`
# (crates/oneiron-docedit/vendor/stemma-engine) and `stemma-diff` (crates/oneiron-docedit/vendor/stemma-diff).
# The workspace compiles `stemma` only as a dependency of oneiron-docedit, so no workspace run builds the
# `#[cfg(test)]` modules under the fork's `src`. This script builds and runs them: `cargo test --lib` for each
# package. It does not run the fork's integration targets (`tests/`); crates/oneiron-docedit/PROVENANCE.md says
# what each of them does today.
#
# Dependency versions come from the workspace's Cargo.lock, so the tests run on the versions the product builds
# the fork with. Neither package has a lock file of its own. The script copies the workspace lock beside each
# manifest and lets cargo resolve from it: cargo keeps every version the copy names and drops the entries the
# package does not use. The run is refused when the resolved lock holds a package the workspace lock does not
# hold (the fork's own two packages apart), and the tests then run with --locked. The copies are removed when
# the script ends. A lock file that is already beside a manifest refuses the run: the script neither overwrites
# nor removes a file it did not make.
#
# Usage: scripts/docedit/run_stemma_fork_unit_tests.sh   (no arguments; from any directory)
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
fork=crates/oneiron-docedit/vendor
packages=(stemma-engine stemma-diff)
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

lock_packages Cargo.lock > "$work/workspace.packages"
for package in "${packages[@]}"; do
  manifest=$fork/$package/Cargo.toml
  created+=("$fork/$package/Cargo.lock")
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
  echo "+ cargo test --locked --manifest-path $manifest --lib"
  cargo test --locked --manifest-path "$manifest" --lib
done
