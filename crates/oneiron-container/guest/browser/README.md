# Browser guest image

The browser that a code run's `self.browser.*` verbs drive: Lightpanda 1.0.0
(the engine agents start on) or headless Chromium, each speaking CDP over
the container's stdio only (entrypoint.sh). The engine starts one per run
under the `[browser]` section (docs/ops/run-with-models.md); the runtime adds
`--network none`, `--read-only`, a non-root user, `--cap-drop ALL` and tmpfs
scratch.

## Build

On a Linux host with Docker (or another Docker-compatible CLI), git and
rustup, from a checkout of this repository:

```sh
crates/oneiron-container/guest/browser/build.sh
```

It:

1. builds `oneiron-fence`, `oneiron-browser-relay` and `oneiron-guest` from
   this checkout as it stands;
2. builds this directory's Dockerfile, which installs Chromium from the
   pinned Debian base and Lightpanda 1.0.0 from its GitHub release, kept only
   when its SHA-256 is the one the Dockerfile names for the architecture;
3. checks that every binary it built, and Lightpanda, loads inside the image
   (a host glibc newer than the image's fails here, not when a run starts its
   browser);
4. prints the local image id, `sha256:<64 hex>`, as the only line on stdout.

Nothing is pushed to a registry. `ONEIRON_BROWSER_DOCKER` names the
container CLI (default `docker`), and `ONEIRON_BROWSER_TAG` the tag the image
also gets (default `oneiron-browser-guest:local`), so a prune of untagged
images keeps it.

## Pin

Put the printed id in the engine's config:

```toml
[browser]
runtime = "/usr/bin/docker"
image = "sha256:<the printed id>"
```

A local id names the image only on the host that holds it. Build on the host
that serves the engine, or move the image with `docker save` and
`docker load`, which keep its id. Running the build on a serving host is an
ops step. A host whose config still pins an image built before Lightpanda
was added sets `engine = "chromium"` in the same section until it pins one
built here.
