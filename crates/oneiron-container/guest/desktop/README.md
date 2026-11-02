# Desktop guest image

The Linux desktop that a code run's `self.desktop.*` verbs drive: Xvfb, its
session and accessibility buses, Openbox, a fixed app set (Mousepad,
Gnumeric, AbiWord, Galculator) and `cua-driver`, which serves MCP over the
container's stdio only. The engine starts one per run under the `[desktop]`
section (docs/ops/run-with-models.md); the runtime adds `--network none`,
`--read-only`, a non-root user, `--cap-drop ALL` and tmpfs scratch.

## Build

On a Linux host with Docker (or another Docker-compatible CLI), git, rustup
and the driver's native build packages (Debian/Ubuntu: `build-essential
pkg-config libx11-dev libxi-dev libxtst-dev libxext-dev libwayland-dev
libxkbcommon-dev`), from a checkout of this repository:

```sh
crates/oneiron-container/guest/desktop/build.sh              # prints the config digest
crates/oneiron-container/guest/desktop/build.sh --store-id   # prints this docker store's id
```

It:

1. builds `cua-driver` from trycua/cua at
   `6d6c734c127025fb39ad5d585a10382808b39dc1` (release 0.36.0, MIT) with
   `cargo build --release --locked -p cua-driver` in `libs/cua-driver/rust`,
   cloning trycua/cua into `ONEIRON_CUA_SRC` (default
   `/opt/oneiron-desktop/cua`) when there is none. It refuses a clone with
   local changes;
2. builds `oneiron-fence` and `oneiron-guest` from this checkout as it
   stands;
3. builds this directory's Dockerfile with `CUA_DRIVER_SHA256` set to the
   driver's sha256, which the Dockerfile checks before it installs the
   driver;
4. checks that every binary loads inside the image (a host glibc newer than
   the image's fails here, not when a run starts its desktop);
5. saves the image and prints its **config digest**, `sha256:<64 hex>`, as
   the only line on stdout. The digest comes from the saved image's own
   `manifest.json` Config, hashed against the config bytes (the rule
   `guest/browser/build.sh` and `deploy/firecracker/build.py` use), not from
   `--iidfile`. With `--store-id` it prints instead the id this host's
   docker store answers the image as (`docker image inspect` `.Id`). Both
   ids also go to stderr: "this docker store answers the image as ...".

The Dockerfile is the only route; there is no image-family or archive
route for the desktop yet.

Nothing is pushed to a registry. `ONEIRON_DESKTOP_DOCKER` names the
container CLI (default `docker`), and `ONEIRON_DESKTOP_TAG` the tag the image
also gets (default `oneiron-desktop-guest:local`), so a prune of untagged
images keeps it.

## Pin

An image built here has two digests that are never interchangeable:

- the **config digest**, printed by default. A classic docker image store
  and a VM vault's podman store answer the image by it, and a VM vault's
  guest-runtime descriptor names it (`deploy/firecracker/build.py`);
- the **manifest digest**. A docker that uses the containerd image store
  answers the image by it, and there the config digest does not resolve.

Put the id the serving store answers in the engine's config. For a direct
docker runtime that is `build.sh --store-id` (on a classic store it equals
the default output):

```toml
[desktop]
runtime = "/usr/bin/docker"
image = "sha256:<the id>"
```

A VM vault's descriptor and podman store take the default output, the
config digest.

A local id names the image only on the host that holds it. Build on the host
that serves the engine, or move the image with `docker save` and
`docker load`, which keep its config digest; a containerd store answers the
loaded image by its manifest digest, so read the id there with
`docker image inspect --format '{{.Id}}'`. Running the build on a serving
host is an ops step.
