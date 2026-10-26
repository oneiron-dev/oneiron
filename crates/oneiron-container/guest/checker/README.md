# Merge queue checker image contract

The image a merge queue check runs in (FIX 6868). The engine starts one
guest per check under the `[merge_queue]` section, through the sandbox's
own selector (`select_backend_for_session(Untrusted, …)`): Firecracker on
a KVM host with it installed, else the OCI fenced container. The guest runs
as uid/gid 10001 under the engine fence with no network: every off-session
destination is denied (`network = "deny"`).

The guest's command is `checker.py`, the trusted helper. The engine sends
it the pinned Git tree of the exact commit under check, never the live
checkout, its `.git`, config, hooks or a host mount. The helper copies it
to `/tmp/queue-check/src`, runs the repository's frozen `.oneiron/checks.json`
commands there with exactly their argv and environment, and sends each
child's actual exit status and output back. It installs nothing and
fetches nothing; a program the image lacks holds the check, naming it.

## What the image provides

- `/usr/local/bin/oneiron-queue-check`: this directory's `checker.py`,
  root-owned and not writable by uid 10001, run by `/usr/bin/python3`.
- Python 3 at `/usr/bin/python3` and Git.
- The Rust toolchain the engine seed plan names: `cargo` under
  `/opt/cargo/bin`, `RUSTUP_HOME=/opt/rustup`, toolchain `1.96`
  (rust-toolchain.toml), and the native build dependencies the workspace's
  `cargo check --locked --workspace --all-features` needs (a C toolchain,
  pkg-config, the system libraries its `-sys` crates link; the Dockerfile
  names each package and what needs it).
- A dependency store preseeded from the baseline lockfile at
  `/opt/queue-check/cargo-home` (`cargo fetch --locked` at image build). The
  helper copies it into the plan's scratch `CARGO_HOME` before a command
  runs, so `--locked` resolves offline.
- `oneiron-fence` and `oneiron-guest` built from the same checkout, at
  `/usr/local/bin` with `/sbin/oneiron-guest` linked to the guest, as the
  code image places them.
- For the Firecracker backend, the same image as a rootfs profile the host
  provisions (`crates/oneiron/src/code_sandbox/firecracker.rs`); for the OCI
  backend, the fence launcher named by `ONEIRON_FENCE_LAUNCHER`.

## Build

On a Linux host with Docker (or another Docker-compatible CLI), git and
python3 3.11 or newer, `build.sh` takes one of three routes. The flag picks
the route, and a failing route never falls back to another:

```sh
# the image-family route (the default)
ONEIRON_CHECKER_IMAGES_MIRROR=/srv/oneiron-images/mirror \
ONEIRON_CHECKER_IMAGES_WORK=/srv/oneiron-images/work \
  crates/oneiron-container/guest/checker/build.sh
# import a built archive, no rebuild
crates/oneiron-container/guest/checker/build.sh --archive /srv/oneiron-images/checker.oci.tar
# the Dockerfile route
crates/oneiron-container/guest/checker/build.sh --dockerfile
```

- **Image family (default).** It rebuilds the `checker` variant with
  `crates/oneiron-container/images/build.py` (docs/ops/guest-image-family.md)
  and loads the OCI archive it writes. The steps are `fetch` (never
  `--learn`: the committed lock decides), then `build`, `receipt` and
  `manifest`, against the mirror and work dir the two variables name. The
  host is the builder's: Linux x86_64, unprivileged user and mount
  namespaces, network for the fetch. The helper, fence, guest, toolchain and
  store come from release.toml's `inputs.engine.commit`, which the checkout
  must hold, not from the checkout as it stands. The builder's own receipt,
  SBOM, provenance and `image-release.json` stay under
  `<work>/artifacts/checker/`.
- **`--archive FILE`.** It loads a `checker.oci.tar` that is already built.
  Its sha256 must be release.toml's checker `oci_archive_sha256`; anything
  else is refused, never loaded.
- **`--dockerfile`.** This is the route as it was before the image family:
  1. it refuses a checkout with local changes to tracked files, since the
     receipt names the commit;
  2. it builds `oneiron-fence` and `oneiron-guest` from a `git archive` of
     HEAD inside the Dockerfile's own `base` stage, in a container of its
     own, so they link against the image's glibc and not the host's, and
     copies only the two binaries out (FIX 7320);
  3. it builds this directory's Dockerfile from a context of `checker.py`,
     those binaries and that archive. The image gets its packages
     from the pinned Debian base, and Rust `1.96` from rustup-init 1.29.1,
     kept only when its SHA-256 is the one the Dockerfile names for the
     architecture. A stage of its own fetches the dependency store from the
     archived manifests and lockfile; the image keeps the store, not the
     tree;
  4. it checks that both binaries load inside the image, so a binary that
     does not fails here, not when a check starts its guest.

Every route writes the receipt and prints one line on stdout, the image's
**config digest** (`sha256:<64 hex>`); everything else goes to stderr. For
an archive the digest comes from its own `manifest.json` Config, hashed
against the config bytes (the rule `deploy/firecracker/build.py` uses). The
Dockerfile route saves the built image and reads the digest the same way;
it does not take it from `--iidfile`. `--store-id` works with any route. It
prints instead the id this host's docker store answers the image as
(`docker image inspect` `.Id`), which every route also writes to stderr. A
docker on the containerd image store answers by the manifest digest, and
there the config digest does not resolve. A classic store answers by the
config digest.

Its outputs go to `ONEIRON_CHECKER_OUT`, by default `checker-image` under
`CARGO_TARGET_DIR` (the checkout's `target/` when unset):

- `image-id`: the config digest, on every route and with `--store-id`;
- `image.json`: the receipt, written inside the image: `image` (the config
  digest), `source_commit` (HEAD for the Dockerfile route, else the engine
  commit the image was built from), `cargo_lock_sha256`, `rustc`
  (`rustc -vV` of the toolchain `RUSTUP_TOOLCHAIN=1.96` selects), `cargo`
  (`cargo -V`), and the SHA-256 of the helper, fence and guest the image
  holds (`helper_sha256`, `fence_sha256`, `guest_sha256`).

Nothing is pushed to a registry. `ONEIRON_CHECKER_DOCKER` names the
container CLI (default `docker`), and `ONEIRON_CHECKER_TAG` the tag the
image also gets (default `oneiron-queue-checker:local`), so a prune of
untagged images keeps it. An imported archive also keeps its own
`oneiron-image-checker:candidate` tag.

The image-family image has no rustup. `/opt/cargo/bin` links straight to
the pinned toolchain in place of rustup's proxies, so `RUSTUP_TOOLCHAIN`
selects nothing. Nothing that runs in the image may use `cargo +toolchain`:
without a proxy, `+1.96` is not a toolchain selector (FIX 8977).

The store holds what the lockfile named at the built commit. When
Cargo.lock gains a crate or a version, rebuild the image: a check that
needs a crate the store lacks cannot fetch it and is held
(`Held(MissingOfflineInput)`). `--when-lock-changed`, with any route,
builds only when the lockfile the route builds from is not the one the
kept receipt (`image.json`) names, or the tagged image is gone; otherwise
it prints the kept image's id and builds nothing. Run it on every
Cargo.lock change (FIX 7317). The Dockerfile route builds from HEAD's
lockfile; the image-family and `--archive` routes from release.toml's
`inputs.engine`, which a lock change moves only with a new release.

## Pin

Put the id this host's store answers and the receipt's identities in the
engine's config. On a classic store that is the printed id; on a
containerd store it is the `--store-id` output (or the stderr line):

```toml
[merge_queue]
runtime = "/usr/bin/docker"
image = "sha256:<the id>"
toolchain = { rust = "<release and commit-hash from the receipt's rustc>", cargo_lock = "sha256:<the receipt's cargo_lock_sha256>" }
# The guest limits default to these (QUEUE_CHECK_DEFAULT_LIMITS in
# crates/oneiron-server/src/config/merge_queue.rs). They are defaults, not
# required keys; a key set here wins.
# memory_mib = 32768
# tmpfs_mib = 16384
# pids = 1024
# cpu_millis = 4000
```

All of `/tmp/queue-check` (the source, the store's copy and the target dir)
is guest tmpfs, so `memory_mib` covers it as well as the compiler.

A local id names the image only on the host that holds it. Build or import
on the host that serves the engine, or move the image with `docker save` and
`docker load`, which keep its config. The OCI backend mounts the host's
fence (`ONEIRON_FENCE_LAUNCHER`) over the image's entrypoint. The
image-family and `--archive` routes build no host fence: stage one that
loads in the image's glibc, and record its hash beside the image id.

Without the section a check answers that it needs configuration and names
the keys; it never runs on the host instead. On a host with no isolated
backend (a Mac) the check names `merge_queue.checker_backend`.

## The host opt-in

`checker_backend = "host"` runs the same helper as a host child with an
empty environment, over the same protocol, and needs an explicit
`helper` argv and `toolchain` pin:

```toml
[merge_queue]
checker_backend = "host"
helper = ["/usr/bin/python3", "/opt/oneiron/checker.py"]
toolchain = { rust = "1.96.0" }
```

The host child reaches what the host reaches; its receipts say
`network = "host"` and are never reused.
