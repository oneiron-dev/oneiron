#!/usr/bin/env bash
# Builds the desktop guest image on a Linux host and prints its image id:
# the config digest (`sha256:<64 hex>`), the id a VM vault's guest-runtime
# descriptor and its podman store name (FIX 8938). Nothing is pushed to a
# registry. See README.md.
#
# It builds `cua-driver` from trycua/cua at CUA_REV (cloned into
# ONEIRON_CUA_SRC when there is none), and oneiron-fence and oneiron-guest
# from this checkout as it stands, then builds the Dockerfile here with the
# driver's sha256. The Dockerfile is the only route.
# --store-id prints instead the id this docker store answers the image as
# (`docker image inspect` .Id): the manifest digest under the containerd
# image store, the config digest under the classic one. Both ids also go
# to stderr, as does every other line of output, so stdout holds the image
# id alone.
set -euo pipefail

# trycua/cua release 0.36.0 (MIT); the wire the engine speaks is this one's.
CUA_REV=6d6c734c127025fb39ad5d585a10382808b39dc1

: "${ONEIRON_CUA_SRC:=/opt/oneiron-desktop/cua}"
: "${ONEIRON_DESKTOP_DOCKER:=docker}"
: "${ONEIRON_DESKTOP_TAG:=oneiron-desktop-guest:local}"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)

usage() {
  echo "usage: build.sh [--store-id]" >&2
  exit 2
}

print=config
while [ $# -gt 0 ]; do
  case "$1" in
    --store-id) print=store; shift ;;
    *) usage ;;
  esac
done

# The one stdout line: the config digest, or with --store-id the store's id.
emit() {
  local store=$1 config=$2
  echo "this docker store answers the image as $store; its config digest is $config" >&2
  if [ "$print" = store ]; then echo "$store"; else echo "$config"; fi
}

# The archive's ids, as its own manifest.json and index.json name them:
# `<config digest> <manifest digest or -> <tag>`. The config digest is
# checked against the config's bytes (guest/browser/build.sh and
# deploy/firecracker/build.py archive_image read it the same way).
archive_ids() {
  python3 - "$1" <<'PY'
import hashlib
import json
import sys
import tarfile
from pathlib import PurePosixPath

with tarfile.open(sys.argv[1]) as tar:
    listed = tar.extractfile("manifest.json")
    manifest = json.load(listed) if listed else None
    if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
        sys.exit("an image archive's manifest must name exactly one image")
    config = manifest[0].get("Config")
    member = tar.extractfile(config) if isinstance(config, str) else None
    if member is None:
        sys.exit("an image archive holds no config its manifest names")
    digest = hashlib.sha256(member.read()).hexdigest()
    if PurePosixPath(config).name.removesuffix(".json") != digest:
        sys.exit("an image archive's config is not the bytes its name says")
    try:
        index = json.load(tar.extractfile("index.json"))
        manifests = index["manifests"]
        named = manifests[0]["digest"] if len(manifests) == 1 else "-"
    except (AttributeError, KeyError, TypeError, ValueError):
        named = "-"
    tags = manifest[0].get("RepoTags") or ["-"]
print(f"sha256:{digest} {named} {tags[0]}")
PY
}

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

# The config digest comes from the saved image's own manifest.json,
# whichever id this store's --iidfile gave.
"$ONEIRON_DESKTOP_DOCKER" save -o "$context/image.tar" "$image" >&2
ids=$(archive_ids "$context/image.tar")
read -r config _ _ <<< "$ids"
emit "$("$ONEIRON_DESKTOP_DOCKER" image inspect --format '{{.Id}}' "$image")" "$config"
