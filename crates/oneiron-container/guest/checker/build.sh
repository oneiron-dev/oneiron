#!/usr/bin/env bash
# Builds or imports the merge queue checker image on a Linux host, writes its
# receipt and prints its image id: the config digest (`sha256:<64 hex>`),
# the id a VM vault's guest-runtime descriptor names (FIX 8938). Nothing is
# pushed to a registry. See README.md.
#
# Three routes, chosen by the first argument; none falls back to another:
#   build.sh                  the image-family route (the default): rebuilds
#                             the checker variant with ../../images/build.py
#                             from the mirror and work dir in
#                             ONEIRON_CHECKER_IMAGES_MIRROR and
#                             ONEIRON_CHECKER_IMAGES_WORK, then loads its
#                             OCI archive;
#   build.sh --archive FILE   loads a built checker.oci.tar whose sha256 is
#                             release.toml's checker oci_archive_sha256;
#   build.sh --dockerfile     the Dockerfile route: builds oneiron-fence and
#                             oneiron-guest from a `git archive` of HEAD
#                             inside the Dockerfile's own base stage, then
#                             builds the Dockerfile here from a context of
#                             checker.py, those binaries and that archive;
#                             the image installs Rust 1.96 and fetches the
#                             lockfile's dependency store.
# --store-id, with any route, prints the id this docker store answers the
# image as (`docker image inspect` .Id) instead: the manifest digest under
# the containerd image store, the config digest under the classic one.
# --when-lock-changed, with any route, builds only when the lockfile the
# route builds from (HEAD's for --dockerfile, release.toml's engine input
# otherwise) is not the one the kept receipt names, or the tagged image is
# gone; otherwise it prints the kept image's id and builds nothing. Run on
# every Cargo.lock change, it keeps the store holding every crate a check
# needs (FIX 7317).
# The config digest (image-id) and the receipt (image.json) land in
# ONEIRON_CHECKER_OUT on every route. Every other line of output goes to
# stderr, so stdout holds the image id alone.
set -euo pipefail

: "${ONEIRON_CHECKER_DOCKER:=docker}"
: "${ONEIRON_CHECKER_TAG:=oneiron-queue-checker:local}"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
images=$repo/crates/oneiron-container/images

usage() {
  echo "usage: build.sh [--store-id] [--when-lock-changed] [--archive <checker.oci.tar> | --dockerfile]" >&2
  exit 2
}

route=family
archive=
print=config
when=always
while [ $# -gt 0 ]; do
  case "$1" in
    --store-id) print=store; shift ;;
    --when-lock-changed) when=lock; shift ;;
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

: "${CARGO_TARGET_DIR:=$repo/target}"
export CARGO_TARGET_DIR
: "${ONEIRON_CHECKER_OUT:=$CARGO_TARGET_DIR/checker-image}"
mkdir -p "$ONEIRON_CHECKER_OUT"

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

# The receipt, written inside the image by its own Python: the toolchain is
# the one the seed plan's RUSTUP_TOOLCHAIN selects, and the helper, fence and
# guest digests are of the files the image holds. `image` is the config
# digest, as image-id is.
# usage: receipt <store id> <config digest> <source commit> <Cargo.lock sha256>
receipt() {
  "$ONEIRON_CHECKER_DOCKER" run --rm -i --network none --entrypoint /usr/bin/python3 \
    --env "IMAGE=$2" --env "SOURCE_COMMIT=$3" --env "CARGO_LOCK_SHA256=$4" \
    --env RUSTUP_TOOLCHAIN=1.96 \
    "$1" - > "$ONEIRON_CHECKER_OUT/image.json" <<'PY'
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
}

# The image-id file and the one stdout line: the config digest, or with
# --store-id the store's id on stdout.
emit() {
  local store=$1 config=$2
  echo "$config" > "$ONEIRON_CHECKER_OUT/image-id"
  echo "this docker store answers the image as $store; its config digest is $config" >&2
  if [ "$print" = store ]; then echo "$store"; else echo "$config"; fi
}

# A value release.toml records: `inputs.engine.<key>` or the checker output's <key>.
release_value() {
  python3 - "$images/release.toml" "$1" "$2" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as stream:
    release = tomllib.load(stream)
table = release["inputs"]["engine"] if sys.argv[2] == "input" else \
    release["variants"]["checker"]["outputs"]["linux/amd64"]
print(table.get(sys.argv[3], ""))
PY
}

# --when-lock-changed: the kept image's id, and exit, when its receipt names
# the lockfile this route builds from and the tag still names an image.
if [ "$when" = lock ]; then
  if [ "$route" = dockerfile ]; then
    want_lock=$(git -C "$repo" show HEAD:Cargo.lock | sha256sum | cut -d' ' -f1)
  else
    want_lock=$(release_value input cargo_lock_sha256)
  fi
  # The receipt's lock, when the receipt is of the image image-id names.
  kept_lock=$(python3 - "$ONEIRON_CHECKER_OUT" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
try:
    receipt = json.loads((out / "image.json").read_text())
    kept = (out / "image-id").read_text().strip()
    print(receipt["cargo_lock_sha256"] if receipt.get("image") == kept else "")
except (OSError, KeyError, TypeError, ValueError):
    print("")
PY
)
  if [ -n "$want_lock" ] && [ "$kept_lock" = "$want_lock" ] \
    && store=$("$ONEIRON_CHECKER_DOCKER" image inspect --format '{{.Id}}' "$ONEIRON_CHECKER_TAG" 2>/dev/null); then
    echo "the kept image's store is of lockfile $want_lock already; nothing is built" >&2
    if [ "$print" = store ]; then echo "$store"; else cat "$ONEIRON_CHECKER_OUT/image-id"; fi
    exit 0
  fi
  echo "the lockfile is ${want_lock:-unknown}, the kept image's store of ${kept_lock:-none}; building" >&2
fi
rm -f "$ONEIRON_CHECKER_OUT/image-id" "$ONEIRON_CHECKER_OUT/image.json"

# Loads an OCI archive built from source commit $2, checks the store answers
# it with one of the archive's own ids, tags it ONEIRON_CHECKER_TAG, writes
# the receipt and emits its ids.
load_archive() {
  local archive=$1 commit=$2 ids config manifest tag loaded
  ids=$(archive_ids "$archive")
  read -r config manifest tag <<< "$ids"
  if [ "$tag" = - ]; then
    echo "$archive names no tag to load it under" >&2
    exit 1
  fi
  "$ONEIRON_CHECKER_DOCKER" load -i "$archive" >&2
  loaded=$("$ONEIRON_CHECKER_DOCKER" image inspect --format '{{.Id}}' "$tag")
  if [ "$loaded" != "$config" ] && [ "$loaded" != "$manifest" ]; then
    echo "$tag is $loaded after the load, not $archive's image ($config / $manifest)" >&2
    exit 1
  fi
  "$ONEIRON_CHECKER_DOCKER" tag "$loaded" "$ONEIRON_CHECKER_TAG" >&2
  receipt "$loaded" "$config" "$commit" "$(release_value input cargo_lock_sha256)"
  emit "$loaded" "$config"
}

case "$route" in
  family)
    : "${ONEIRON_CHECKER_IMAGES_MIRROR:?the image-family route needs ONEIRON_CHECKER_IMAGES_MIRROR, the retained input mirror (README.md); --archive and --dockerfile are the other routes}"
    : "${ONEIRON_CHECKER_IMAGES_WORK:?the image-family route needs ONEIRON_CHECKER_IMAGES_WORK, a scratch and artifact directory (README.md)}"
    # The fetch verifies (or fills) the whole mirror against the committed
    # lock, so it names every scope the lock covers; never --learn here.
    scopes=$(python3 - "$images/packages.lock.toml" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as stream:
    print(" ".join(f"--variant {s}" for s in tomllib.load(stream)["scopes"] if s != "tools"))
PY
)
    family=(--repo "$repo" --mirror "$ONEIRON_CHECKER_IMAGES_MIRROR" --work "$ONEIRON_CHECKER_IMAGES_WORK")
    # shellcheck disable=SC2086
    python3 "$images/build.py" fetch "${family[@]}" $scopes >&2
    python3 "$images/build.py" build "${family[@]}" --variant checker >&2
    python3 "$images/build.py" receipt --work "$ONEIRON_CHECKER_IMAGES_WORK" --variant checker >&2
    python3 "$images/build.py" manifest --work "$ONEIRON_CHECKER_IMAGES_WORK" --variant checker >&2
    archive=$ONEIRON_CHECKER_IMAGES_WORK/artifacts/checker/checker.oci.tar
    got=$(sha256sum "$archive" | cut -d' ' -f1)
    if [ "$got" = "$(release_value output oci_archive_sha256)" ]; then
      echo "the rebuilt archive is release.toml's checker output, byte for byte ($got)" >&2
    else
      echo "the rebuilt archive ($got) is not release.toml's checker output; its receipt is beside it" >&2
    fi
    load_archive "$archive" "$(python3 "$images/build.py" engine-commit)"
    exit 0
    ;;
  archive)
    want=$(release_value output oci_archive_sha256)
    got=$(sha256sum "$archive" | cut -d' ' -f1)
    if [ -z "$want" ] || [ "$got" != "$want" ]; then
      echo "$archive has sha256 $got; release.toml's checker output is ${want:-unbuilt}" >&2
      exit 1
    fi
    load_archive "$archive" "$(release_value output engine_commit)"
    exit 0
    ;;
esac

# The Dockerfile route.
# The receipt names the commit; a local edit would build an image it does
# not name.
if [ -n "$(git -C "$repo" status --porcelain --untracked-files=no)" ]; then
  echo "$repo has local changes; the image is built only from a commit" >&2
  exit 1
fi
commit=$(git -C "$repo" rev-parse HEAD)

context=$(mktemp -d)
builder=
trap 'rm -rf "$context"; [ -z "$builder" ] || "$ONEIRON_CHECKER_DOCKER" rm -f "$builder" >/dev/null 2>&1' EXIT
cp "$here/Dockerfile" "$here/checker.py" "$context/"
mkdir "$context/tree"
git -C "$repo" archive --format=tar "$commit" | tar -x -C "$context/tree"
lock_sha256=$(sha256sum "$context/tree/Cargo.lock" | cut -d' ' -f1)

# The fence and the guest are built from that archive inside the
# Dockerfile's own base stage, so they link against the image's glibc, not
# this host's (FIX 7320). The builder container's tree, crates and target
# stay in it; only the two binaries are copied out, owned by this user.
"$ONEIRON_CHECKER_DOCKER" build --target base --iidfile "$context/base-id" "$context" >&2
builder=$("$ONEIRON_CHECKER_DOCKER" create --workdir /src \
  --env RUSTUP_TOOLCHAIN=1.96 --env CARGO_TARGET_DIR=/build/target \
  "$(cat "$context/base-id")" sh -c \
  'cargo build --release --locked -p oneiron-container --bin oneiron-fence && cargo build --release --locked -p oneiron-guest')
"$ONEIRON_CHECKER_DOCKER" cp "$context/tree/." "$builder:/src" >&2
"$ONEIRON_CHECKER_DOCKER" start --attach "$builder" >&2
for binary in oneiron-fence oneiron-guest; do
  "$ONEIRON_CHECKER_DOCKER" cp "$builder:/build/target/release/$binary" "$context/$binary" >&2
done

"$ONEIRON_CHECKER_DOCKER" build \
  --iidfile "$context/image-id" \
  --tag "$ONEIRON_CHECKER_TAG" \
  "$context" >&2
image=$(cat "$context/image-id")

# The binaries were built in the image's base stage; they still have to load
# in the image, or a check would fail only when it starts its guest.
missing=$("$ONEIRON_CHECKER_DOCKER" run --rm --network none --entrypoint ldd "$image" \
  /usr/local/bin/oneiron-fence /usr/local/bin/oneiron-guest 2>&1 \
  | grep 'not found' || true)
if [ -n "$missing" ]; then
  echo "$missing" >&2
  echo "a binary does not load in $image" >&2
  exit 1
fi

# The config digest comes from the saved image's own manifest.json,
# whichever id this store's --iidfile gave.
"$ONEIRON_CHECKER_DOCKER" save -o "$context/image.tar" "$image" >&2
ids=$(archive_ids "$context/image.tar")
read -r config _ _ <<< "$ids"
receipt "$image" "$config" "$commit" "$lock_sha256"
emit "$("$ONEIRON_CHECKER_DOCKER" image inspect --format '{{.Id}}' "$image")" "$config"
