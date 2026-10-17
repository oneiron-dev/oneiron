#!/usr/bin/env bash
# Builds the desktop guest image on a Linux host and prints its local image
# id (`sha256:<64 hex>`), the value `[desktop] image` pins. Nothing is pushed
# to a registry. See README.md.
#
# It builds `cua-driver` from trycua/cua at CUA_REV (cloned into
# ONEIRON_CUA_SRC when there is none), and oneiron-fence and oneiron-guest
# from this checkout as it stands, then builds the Dockerfile here with the
# driver's sha256. Every other line of output goes to stderr, so stdout holds
# the image id alone.
set -euo pipefail

# trycua/cua release 0.36.0 (MIT); the wire the engine speaks is this one's.
CUA_REV=6d6c734c127025fb39ad5d585a10382808b39dc1

: "${ONEIRON_CUA_SRC:=/opt/oneiron-desktop/cua}"
: "${ONEIRON_DESKTOP_DOCKER:=docker}"
: "${ONEIRON_DESKTOP_TAG:=oneiron-desktop-guest:local}"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)

if [ ! -d "$ONEIRON_CUA_SRC/.git" ]; then
  git clone https://github.com/trycua/cua "$ONEIRON_CUA_SRC" >&2
fi
if ! git -C "$ONEIRON_CUA_SRC" cat-file -e "$CUA_REV^{commit}" 2>/dev/null; then
  git -C "$ONEIRON_CUA_SRC" fetch --quiet origin "$CUA_REV" >&2
fi
# A local edit would build a driver the pin does not name.
if [ -n "$(git -C "$ONEIRON_CUA_SRC" status --porcelain --untracked-files=no)" ]; then
  echo "$ONEIRON_CUA_SRC has local changes; the driver is built only from $CUA_REV" >&2
  exit 1
fi
git -C "$ONEIRON_CUA_SRC" checkout --quiet --detach "$CUA_REV"

cua_rust="$ONEIRON_CUA_SRC/libs/cua-driver/rust"
(cd "$cua_rust" && CARGO_TARGET_DIR="$cua_rust/target" cargo build --release --locked -p cua-driver)

: "${CARGO_TARGET_DIR:=$repo/target}"
export CARGO_TARGET_DIR
(cd "$repo" && cargo build --release --locked -p oneiron-container --bin oneiron-fence)
(cd "$repo" && cargo build --release --locked -p oneiron-guest)

context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
cp "$here/Dockerfile" "$here/entrypoint.sh" "$context/"
cp "$cua_rust/target/release/cua-driver" "$context/cua-driver"
cp "$CARGO_TARGET_DIR/release/oneiron-fence" "$CARGO_TARGET_DIR/release/oneiron-guest" "$context/"

driver_sha256=$(sha256sum "$context/cua-driver" | cut -d' ' -f1)
echo "cua-driver $CUA_REV sha256 $driver_sha256" >&2

"$ONEIRON_DESKTOP_DOCKER" build \
  --build-arg "CUA_DRIVER_SHA256=$driver_sha256" \
  --iidfile "$context/image-id" \
  --tag "$ONEIRON_DESKTOP_TAG" \
  "$context" >&2
image=$(cat "$context/image-id")

# The binaries link against this host's libraries; one built against a newer
# glibc than the image's would fail only when a run starts its desktop.
missing=$("$ONEIRON_DESKTOP_DOCKER" run --rm --network none --entrypoint ldd "$image" \
  /usr/local/bin/cua-driver /usr/local/bin/oneiron-fence /sbin/oneiron-guest 2>&1 \
  | grep 'not found' || true)
if [ -n "$missing" ]; then
  echo "$missing" >&2
  echo "a binary does not load in $image; build on a host whose glibc is no newer than the image's" >&2
  exit 1
fi

echo "$image"
