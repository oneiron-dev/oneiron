#!/usr/bin/env bash
# Builds the browser guest image on a Linux host and prints its local image
# id (`sha256:<64 hex>`), the value `[browser] image` pins. Nothing is pushed
# to a registry. See README.md.
#
# It builds oneiron-fence, oneiron-browser-relay and oneiron-guest from this
# checkout as it stands, then builds the Dockerfile here, which fetches
# Lightpanda 1.0.0 by its SHA-256. Every other line of output goes to
# stderr, so stdout holds the image id alone.
set -euo pipefail

: "${ONEIRON_BROWSER_DOCKER:=docker}"
: "${ONEIRON_BROWSER_TAG:=oneiron-browser-guest:local}"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)

: "${CARGO_TARGET_DIR:=$repo/target}"
export CARGO_TARGET_DIR
(cd "$repo" && cargo build --release --locked -p oneiron-container \
  --bin oneiron-fence --bin oneiron-browser-relay) >&2
(cd "$repo" && cargo build --release --locked -p oneiron-guest) >&2

context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
cp "$here/Dockerfile" "$here/entrypoint.sh" "$context/"
cp "$CARGO_TARGET_DIR/release/oneiron-fence" "$CARGO_TARGET_DIR/release/oneiron-browser-relay" \
  "$CARGO_TARGET_DIR/release/oneiron-guest" "$context/"

"$ONEIRON_BROWSER_DOCKER" build \
  --iidfile "$context/image-id" \
  --tag "$ONEIRON_BROWSER_TAG" \
  "$context" >&2
image=$(cat "$context/image-id")

# The binaries link against this host's libraries; one built against a newer
# glibc than the image's would fail only when a run starts its browser.
missing=$("$ONEIRON_BROWSER_DOCKER" run --rm --network none --entrypoint ldd "$image" \
  /usr/local/bin/oneiron-fence /usr/local/bin/oneiron-browser-relay /sbin/oneiron-guest \
  /usr/local/bin/lightpanda 2>&1 \
  | grep 'not found' || true)
if [ -n "$missing" ]; then
  echo "$missing" >&2
  echo "a binary does not load in $image; build on a host whose glibc is no newer than the image's" >&2
  exit 1
fi

echo "$image"
