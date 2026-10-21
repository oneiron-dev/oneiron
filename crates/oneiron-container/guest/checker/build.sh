#!/usr/bin/env bash
# Builds the merge queue checker image on a Linux host, writes its receipt
# and prints its local image id (`sha256:<64 hex>`), the value
# `[merge_queue] image` pins. Nothing is pushed to a registry. See README.md.
#
# It builds oneiron-fence and oneiron-guest from this checkout, then builds
# the Dockerfile here from a context of checker.py, those binaries and a
# `git archive` of HEAD; the image installs Rust 1.96 and fetches the
# lockfile's dependency store. The image id (image-id) and the receipt
# (image.json) land in ONEIRON_CHECKER_OUT. Every other line of output goes
# to stderr, so stdout holds the image id alone.
set -euo pipefail

: "${ONEIRON_CHECKER_DOCKER:=docker}"
: "${ONEIRON_CHECKER_TAG:=oneiron-queue-checker:local}"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)

# The receipt names the commit; a local edit would build an image it does
# not name.
if [ -n "$(git -C "$repo" status --porcelain --untracked-files=no)" ]; then
  echo "$repo has local changes; the image is built only from a commit" >&2
  exit 1
fi
commit=$(git -C "$repo" rev-parse HEAD)

: "${CARGO_TARGET_DIR:=$repo/target}"
export CARGO_TARGET_DIR
: "${ONEIRON_CHECKER_OUT:=$CARGO_TARGET_DIR/checker-image}"
mkdir -p "$ONEIRON_CHECKER_OUT"
rm -f "$ONEIRON_CHECKER_OUT/image-id" "$ONEIRON_CHECKER_OUT/image.json"

(cd "$repo" && cargo build --release --locked -p oneiron-container --bin oneiron-fence) >&2
(cd "$repo" && cargo build --release --locked -p oneiron-guest) >&2

context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
cp "$here/Dockerfile" "$here/checker.py" "$context/"
cp "$CARGO_TARGET_DIR/release/oneiron-fence" "$CARGO_TARGET_DIR/release/oneiron-guest" "$context/"
mkdir "$context/tree"
git -C "$repo" archive --format=tar "$commit" | tar -x -C "$context/tree"
lock_sha256=$(sha256sum "$context/tree/Cargo.lock" | cut -d' ' -f1)

"$ONEIRON_CHECKER_DOCKER" build \
  --iidfile "$ONEIRON_CHECKER_OUT/image-id" \
  --tag "$ONEIRON_CHECKER_TAG" \
  "$context" >&2
image=$(cat "$ONEIRON_CHECKER_OUT/image-id")

# The binaries link against this host's libraries; one built against a newer
# glibc than the image's would fail only when a check starts its guest.
missing=$("$ONEIRON_CHECKER_DOCKER" run --rm --network none --entrypoint ldd "$image" \
  /usr/local/bin/oneiron-fence /usr/local/bin/oneiron-guest 2>&1 \
  | grep 'not found' || true)
if [ -n "$missing" ]; then
  echo "$missing" >&2
  echo "a binary does not load in $image; build on a host whose glibc is no newer than the image's" >&2
  exit 1
fi

# The receipt, written inside the image by its own Python: the toolchain is
# the one the seed plan's RUSTUP_TOOLCHAIN selects, and the helper, fence and
# guest digests are of the files the image holds.
"$ONEIRON_CHECKER_DOCKER" run --rm -i --network none --entrypoint /usr/bin/python3 \
  --env "IMAGE=$image" --env "SOURCE_COMMIT=$commit" --env "CARGO_LOCK_SHA256=$lock_sha256" \
  --env RUSTUP_TOOLCHAIN=1.96 \
  "$image" - > "$ONEIRON_CHECKER_OUT/image.json" <<'PY'
import hashlib
import json
import os
import subprocess


def sha256(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def output(*argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout.strip()


print(json.dumps({
    "image": os.environ["IMAGE"],
    "source_commit": os.environ["SOURCE_COMMIT"],
    "cargo_lock_sha256": os.environ["CARGO_LOCK_SHA256"],
    "rustc": output("/opt/cargo/bin/rustc", "-vV"),
    "cargo": output("/opt/cargo/bin/cargo", "-V"),
    "helper_sha256": sha256("/usr/local/bin/oneiron-queue-check"),
    "fence_sha256": sha256("/usr/local/bin/oneiron-fence"),
    "guest_sha256": sha256("/usr/local/bin/oneiron-guest"),
}, indent=2))
PY
echo "receipt: $ONEIRON_CHECKER_OUT/image.json" >&2

echo "$image"
