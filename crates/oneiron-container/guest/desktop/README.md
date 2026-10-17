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
crates/oneiron-container/guest/desktop/build.sh
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
5. prints the local image id, `sha256:<64 hex>`, as the only line on stdout.

Nothing is pushed to a registry. `ONEIRON_DESKTOP_DOCKER` names the
container CLI (default `docker`), and `ONEIRON_DESKTOP_TAG` the tag the image
also gets (default `oneiron-desktop-guest:local`), so a prune of untagged
images keeps it.

## Pin

Put the printed id in the engine's config:

```toml
[desktop]
runtime = "/usr/bin/docker"
image = "sha256:<the printed id>"
```

A local id names the image only on the host that holds it. Build on the host
that serves the engine, or move the image with `docker save` and
`docker load`, which keep its id. Running the build on a serving host is an
ops step.
