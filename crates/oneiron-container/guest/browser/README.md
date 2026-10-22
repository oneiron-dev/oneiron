# Browser guest image

The browser that a code run's `self.browser.*` verbs drive: Lightpanda 1.0.0
(the engine agents start on) or headless Chromium, each speaking CDP over
the container's stdio only (entrypoint.sh). The engine starts one per run
under the `[browser]` section (docs/ops/run-with-models.md); the runtime adds
`--network none`, `--read-only`, a non-root user, `--cap-drop ALL` and tmpfs
scratch.

## Build

On a Linux host with Docker (or another Docker-compatible CLI), git and
python3 3.11 or newer, from a checkout of this repository, `build.sh` takes
one of three routes. The flag picks the route, and a failing route never
falls back to another:

```sh
# the image-family route (the default)
ONEIRON_BROWSER_IMAGES_MIRROR=/srv/oneiron-images/mirror \
ONEIRON_BROWSER_IMAGES_WORK=/srv/oneiron-images/work \
  crates/oneiron-container/guest/browser/build.sh
# import a built archive, no rebuild
crates/oneiron-container/guest/browser/build.sh --archive /srv/oneiron-images/browser.oci.tar
# the Dockerfile route
crates/oneiron-container/guest/browser/build.sh --dockerfile
```

- **Image family (default).** It rebuilds the `browser` variant with
  `crates/oneiron-container/images/build.py` (docs/ops/guest-image-family.md)
  and loads the OCI archive it writes. The steps are `fetch` (never
  `--learn`: the committed lock decides, and the fetch checks the whole
  mirror against it), then `build`, `receipt` and `manifest`, against the
  mirror and work dir the two variables name. The host is the builder's:
  Linux x86_64, unprivileged user and mount namespaces, util-linux
  `unshare`, network for the fetch. The binaries are built inside the
  image's own userspace at release.toml's `inputs.engine.commit`, not from
  this checkout as it stands, so the checkout must hold that commit. The
  receipt, SBOM, provenance and `image-release.json` stay beside the archive
  under `<work>/artifacts/browser/`. stderr says whether the rebuilt archive
  is release.toml's browser output byte for byte.
- **`--archive FILE`.** It loads a `browser.oci.tar` that is already built.
  Its sha256 must be release.toml's browser `oci_archive_sha256`; anything
  else is refused, never loaded. Use this route to adopt the recorded
  output on another host.
- **`--dockerfile`.** This is the route as it was before the image family:
  1. it builds `oneiron-fence`, `oneiron-browser-relay` and `oneiron-guest`
     from this checkout as it stands, with host Cargo (rustup);
  2. it builds this directory's Dockerfile, which installs Chromium from the
     pinned Debian base and Lightpanda 1.0.0 from its GitHub release, kept
     only when its SHA-256 is the one the Dockerfile names for the
     architecture (amd64 or arm64);
  3. it checks that every binary it built, and Lightpanda, loads inside the
     image. A host glibc newer than the image's fails here, not when a run
     starts its browser.

Every route prints one line on stdout, the image's **config digest**
(`sha256:<64 hex>`), and sends everything else to stderr. For an archive the
digest comes from its own `manifest.json` Config, hashed against the config
bytes (the rule `deploy/firecracker/build.py` uses). The Dockerfile route
saves the built image and reads the digest the same way; it does not take
it from `--iidfile`. The config digest is the id a VM vault's guest-runtime
descriptor names (FIX 8938).

`--store-id` works with any route. It prints instead the id this host's
docker store answers the image as (`docker image inspect` `.Id`). Each
route also writes that id to stderr: "this docker store answers the image
as …".

Nothing is pushed to a registry. `ONEIRON_BROWSER_DOCKER` names the
container CLI (default `docker`). `ONEIRON_BROWSER_TAG` names the tag the
image also gets (default `oneiron-browser-guest:local`), so a prune of
untagged images keeps it. An imported archive also keeps its own
`oneiron-image-browser:candidate` tag.

## Two ids

An image built here has two digests that are never interchangeable:

- the **config digest**, printed by default. A classic docker image store
  and the VM vault's podman store answer the image by it;
- the **manifest digest** (release.toml's `oci_manifest_digest`). A docker
  that uses the containerd image store answers the image by it, and there
  the config digest does not resolve: on nelly (docker 29.9.0, containerd
  snapshotter) `docker image inspect <config digest>` says "No such image".

## Pin

Put the id this host's store answers in the engine's config. That is the
default output on a classic store, and the output of `--store-id` (or the
stderr line) on a containerd store:

```toml
[browser]
runtime = "/usr/bin/docker"
image = "sha256:<the id>"
```

A VM vault's guest-runtime descriptor takes the config digest
(`deploy/firecracker/build.py`, from the same archive).

A local id names the image only on the host that holds it. Build or import
on the host that serves the engine, or move the image with `docker save`
and `docker load`, which keep its config. Running the build on a serving
host is an ops step. A host whose config still pins an image built before
Lightpanda was added sets `engine = "chromium"` in the same section until it
pins one built here.

## Host fence

The OCI backend mounts the host's fence (`ONEIRON_FENCE_LAUNCHER`) over the
image's entrypoint, so a serving host stages a fence that loads in the
image's glibc. The Dockerfile route leaves one in
`$CARGO_TARGET_DIR/release/oneiron-fence` as a side effect of its host
build. The image-family and `--archive` routes build no host fence. The
image holds its own at `/usr/local/bin/oneiron-fence`, built in the image's
userspace; its sha256 is the receipt's `fence_sha256`. Stage the host fence
as its own step and record its hash beside the image id.
