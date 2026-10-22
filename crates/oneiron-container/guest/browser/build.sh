#!/usr/bin/env bash
# Builds or imports the browser guest image on a Linux host and prints its
# image id: the config digest (`sha256:<64 hex>`), the id a VM vault's
# guest-runtime descriptor names (FIX 8938). Nothing is pushed to a
# registry. See README.md.
#
# Three routes, chosen by the first argument; none falls back to another:
#   build.sh                  the image-family route (the default): rebuilds
#                             the browser variant with ../../images/build.py
#                             from the mirror and work dir in
#                             ONEIRON_BROWSER_IMAGES_MIRROR and
#                             ONEIRON_BROWSER_IMAGES_WORK, then loads its
#                             OCI archive;
#   build.sh --archive FILE   loads a built browser.oci.tar whose sha256 is
#                             release.toml's browser oci_archive_sha256;
#   build.sh --dockerfile     the Dockerfile route: builds oneiron-fence,
#                             oneiron-browser-relay and oneiron-guest from this
#                             checkout as it stands, then builds the
#                             Dockerfile here, which fetches Lightpanda 1.0.0
#                             by its SHA-256.
# --store-id, with any route, prints the id this docker store answers the
# image as (`docker image inspect` .Id) instead: the manifest digest under
# the containerd image store, the config digest under the classic one.
# Every other line of output goes to stderr, so stdout holds the image id
# alone.
set -euo pipefail

: "${ONEIRON_BROWSER_DOCKER:=docker}"
: "${ONEIRON_BROWSER_TAG:=oneiron-browser-guest:local}"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
images=$repo/crates/oneiron-container/images

usage() {
  echo "usage: build.sh [--store-id] [--archive <browser.oci.tar> | --dockerfile]" >&2
  exit 2
}

route=family
archive=
print=config
while [ $# -gt 0 ]; do
  case "$1" in
    --store-id) print=store; shift ;;
    --archive)
      [ "$route" = family ] && [ $# -ge 2 ] || usage
      route=archive archive=$2
      shift 2
      ;;
    --dockerfile)
      [ "$route" = family ] || usage
      route=dockerfile
      shift
      ;;
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
# checked against the config's bytes (deploy/firecracker/build.py
# archive_image reads it the same way).
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

# Loads an OCI archive, checks the store answers it with one of the
# archive's own ids, tags it ONEIRON_BROWSER_TAG and emits its ids.
load_archive() {
  local archive=$1 ids config manifest tag loaded
  ids=$(archive_ids "$archive")
  read -r config manifest tag <<< "$ids"
  if [ "$tag" = - ]; then
    echo "$archive names no tag to load it under" >&2
    exit 1
  fi
  "$ONEIRON_BROWSER_DOCKER" load -i "$archive" >&2
  loaded=$("$ONEIRON_BROWSER_DOCKER" image inspect --format '{{.Id}}' "$tag")
  if [ "$loaded" != "$config" ] && [ "$loaded" != "$manifest" ]; then
    echo "$tag is $loaded after the load, not $archive's image ($config / $manifest)" >&2
    exit 1
  fi
  "$ONEIRON_BROWSER_DOCKER" tag "$loaded" "$ONEIRON_BROWSER_TAG" >&2
  emit "$loaded" "$config"
}

# The browser output release.toml records, one field of it.
release_output() {
  python3 - "$images/release.toml" "$1" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as stream:
    output = tomllib.load(stream)["variants"]["browser"]["outputs"]["linux/amd64"]
print(output.get(sys.argv[2], ""))
PY
}

case "$route" in
  family)
    : "${ONEIRON_BROWSER_IMAGES_MIRROR:?the image-family route needs ONEIRON_BROWSER_IMAGES_MIRROR, the retained input mirror (README.md); --archive and --dockerfile are the other routes}"
    : "${ONEIRON_BROWSER_IMAGES_WORK:?the image-family route needs ONEIRON_BROWSER_IMAGES_WORK, a scratch and artifact directory (README.md)}"
    # The fetch verifies (or fills) the whole mirror against the committed
    # lock, so it names every scope the lock covers; never --learn here.
    scopes=$(python3 - "$images/packages.lock.toml" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as stream:
    print(" ".join(f"--variant {s}" for s in tomllib.load(stream)["scopes"] if s != "tools"))
PY
)
    family=(--repo "$repo" --mirror "$ONEIRON_BROWSER_IMAGES_MIRROR" --work "$ONEIRON_BROWSER_IMAGES_WORK")
    # shellcheck disable=SC2086
    python3 "$images/build.py" fetch "${family[@]}" $scopes >&2
    python3 "$images/build.py" build "${family[@]}" --variant browser >&2
    python3 "$images/build.py" receipt --work "$ONEIRON_BROWSER_IMAGES_WORK" --variant browser >&2
    python3 "$images/build.py" manifest --work "$ONEIRON_BROWSER_IMAGES_WORK" --variant browser >&2
    archive=$ONEIRON_BROWSER_IMAGES_WORK/artifacts/browser/browser.oci.tar
    got=$(sha256sum "$archive" | cut -d' ' -f1)
    if [ "$got" = "$(release_output oci_archive_sha256)" ]; then
      echo "the rebuilt archive is release.toml's browser output, byte for byte ($got)" >&2
    else
      echo "the rebuilt archive ($got) is not release.toml's browser output; its receipt is beside it" >&2
    fi
    load_archive "$archive"
    exit 0
    ;;
  archive)
    want=$(release_output oci_archive_sha256)
    got=$(sha256sum "$archive" | cut -d' ' -f1)
    if [ -z "$want" ] || [ "$got" != "$want" ]; then
      echo "$archive has sha256 $got; release.toml's browser output is ${want:-unbuilt}" >&2
      exit 1
    fi
    load_archive "$archive"
    exit 0
    ;;
esac

# The Dockerfile route.
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

# The config digest comes from the saved image's own manifest.json,
# whichever id this store's --iidfile gave.
"$ONEIRON_BROWSER_DOCKER" save -o "$context/image.tar" "$image" >&2
ids=$(archive_ids "$context/image.tar")
read -r config _ _ <<< "$ids"
emit "$("$ONEIRON_BROWSER_DOCKER" image inspect --format '{{.Id}}' "$image")" "$config"
