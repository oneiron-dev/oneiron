# Guest image family: build, rebuild, retain, hand off

The guest images (the code/minimal base, browser, desktop/CUA, checker, a
generic agent sandbox and the vault) come from one builder in
`crates/oneiron-container/images/`. Pinned mkosi assembles each image from a
frozen Debian snapshot, and the guest binaries are built inside the image's
own userspace. One assembled tree is exported twice: as an OCI image for the
no-KVM container backend and as a root-only ext4 rootfs for Firecracker.
Nothing here changes which image a host runs. The existing recipes under
`crates/oneiron-container/guest/`, with their pins and receipts, stay
authoritative until an adoption change names a new image.

## Files

- `release.toml` is the one release list. `[inputs]` holds the frozen inputs:
  - the Debian base's index, platform, config and layer digests;
  - the snapshot, derived from the base's build epoch;
  - mkosi's tag, commit and archive hash;
  - the exact Rust release and its dist component hashes;
  - the engine commit and the `Cargo.lock` hash;
  - every existing pin, by path + sha256 at that commit;
  - the contract revisions;
  - the Lightpanda, CUA, Bun and tsrs payload pins.

  `[variants.*.outputs."linux/amd64"]` holds what a build measured.
  `[variants.*.budget]` holds proposed targets.
- `packages.toml` holds requests only: the tools tree, `[base]` and one
  overlay per variant.
- `packages.lock.toml` is the resolved closure: every `.deb` by name,
  version, arch, size and sha256.

`python3 build.py validate` checks that the three agree. It needs no Linux
host. It refuses a moving `latest`, a malformed hash or commit, a missing
variant, a stale lock scope, and an output field on an unbuilt variant.

## Build

Fetch and build run on a Linux x86_64 host. They need python3 3.11 or newer,
the util-linux `unshare` (2.38 or newer, for `--map-user`), libseccomp,
network for the fetch phase, and unprivileged user and mount namespaces. They
need no root, no sudo and no container daemon. Fleet render boxes are
containers without user namespaces; book the builder elsewhere.

Two namespaces nest:
- `build.py` re-executes itself as root of a single-uid user namespace with a
  private mount namespace (and, for `build`, no network namespace peers at
  all). Its own steps run there: the bootstrap unpack, the fetch root below,
  the exporter, which reads every tree back whatever its modes.
- mkosi runs one namespace down, as the invoking uid again
  (`unshare --map-user`). mkosi 27.1 takes uid 0 with `CAP_SYS_ADMIN` for real
  root, and its essential-package tar extraction then chowns to ids no
  single-uid namespace maps. As a regular uid it takes its own unprivileged
  path: every tool in a sandbox that maps that uid to root, package managers
  with `chown()` made a no-op. `MKOSI_FORCE_USERNS_FALLBACK=1` keeps it on
  plain `unshare(CLONE_NEWUSER)`, never systemd-nsresourced's foreign uid
  range, whose files the builder could not read back.

Every host-side tool (git, tar, unshare, mount, mkosi itself) runs with a
scrubbed environment: PATH and the locale, no `HOME` (mkosi gets an empty one
in the work dir), no git system config or attributes, no `TAR_OPTIONS`,
`CARGO_*`, `RUST*` or user site-packages.

1. **Fetch (online).** `build.py fetch --repo R --mirror M --work W --variant base`
   puts every input in the mirror `M` and checks it against its pin:
   - the base's amd64 rootfs layer, over the registry HTTP API;
   - the mkosi source archive;
   - the Rust components;
   - payloads;
   - a clean `CARGO_HOME` filled by `cargo fetch --locked` at the engine commit;
   - the Debian packages for the tools tree and the requested variants.

   Cargo reads `.cargo/config.toml` in every parent of its working directory,
   so a work dir under a home directory would pick up that home's Cargo
   config. The pinned cargo therefore runs in a root of its own: a tmpfs in a
   nested mount namespace, holding the pinned base layer's `/usr` and a copy
   of its `/etc`, the engine source at `/src`, the store's `CARGO_HOME` at
   `/cargo-home`, the pinned Rust at `/rust`, `/proc` and five device nodes.
   Of the host it keeps only the CA bundle and the resolver file, both copied
   in. `HOME` is unset. The config walk is `/src/.cargo/config.toml` (the
   pinned repo file) and an empty `/`.

   The `.deb` files come through mkosi's own apt run against our sources
   file. That file pins main, updates and security to the snapshot,
   verifies every InRelease signature with the archive keyring, and skips
   `Valid-Until` on those sources only.

   The first run on a fresh mirror passes `--learn` and writes
   `packages.lock.toml`. Commit that lock. A later fetch without `--learn`
   refuses any `.deb` whose bytes differ from the lock, and any newly
   downloaded `.deb` the lock does not name.
2. **Build (offline).** `build.py build --variant base` re-enters a namespace
   with no network at all and works from the mirror alone:
   1. It unpacks the base layer as a bootstrap tree.
   2. mkosi builds the **tools tree** from it (`ToolsTree=` the bootstrap
      tree). The tools tree is apt, dpkg, the keyring, e2fsprogs and the rest
      of `packages.toml [tools]`, from the same snapshot. Its content hash is
      the **builder identity**, `tools_tree_sha256`. The Debian base digest
      is only its seed.
   3. mkosi builds the variant with `ToolsTree=` the tools tree.
      `mkosi.build.chroot` compiles the plan's binaries inside the image plus
      its build overlay, so they link against the glibc the image ships. It
      runs `--locked --offline` with the mirror's clean `CARGO_HOME`,
      `--remap-path-prefix` for every build path, and `SOURCE_DATE_EPOCH`.
   4. `mkosi.postinst` places the guest account, pinned files, payloads and
      links. `mkosi.finalize` empties `machine-id` and removes random seeds,
      credentials, keys, apt lists and caches, logs, the ldconfig aux cache
      and backup files. Licence files and dpkg's database stay.
   5. The exporter refuses a tree whose files name a build-machine path.
   6. The exporter writes one deterministic `rootfs.tar`: sorted entries,
      mtimes clamped to the epoch, and explicit ownership (below). It builds
      both outputs from that tar:
      - `<variant>.oci.tar` is an OCI layout with `index.json` plus docker's
        `manifest.json`, so `docker load` accepts it;
      - `rootfs.ext4` comes from `mke2fs -d rootfs.tar` in the tools tree:
        root-only, with no partition table, ESP or UKI, and the kernel kept
        separate.

      The ext4 is refused above the engine's 4 GiB Firecracker rootfs cap;
      the cap does not move.
   7. It writes `rootfs.members.tsv`: every tar member with its type, mode,
      owner, size, mtime and sha256 (or link target). This is the payload
      identity a second build compares.
   8. It writes the SBOM and the provenance statement (below).
3. **Receipt.** `build.py receipt --variant base` writes `receipt.json` and
   prints the `[variants.base.outputs."linux/amd64"]` block. Paste the block
   into `release.toml` with `state = "built-candidate"`. The receipt also
   compares the measured bytes with the variant's proposed budget and the
   Firecracker cap.
4. **Release manifest.** `build.py manifest --work W --variant base` writes
   `image-release.json` beside the artifacts (see "Verify a release" below).

**SBOM and provenance.** Each build writes two unsigned documents beside its
artifacts. The receipt, the `release.toml` block (`sbom_sha256`,
`provenance_sha256`) and the release manifest's `sbom` field name them by
digest. Signing them is the release signature's seam (`manifest.md`).
- `sbom.spdx.json` is SPDX 2.3 JSON. It lists:
  - the image (OCI manifest digest, archive sha256);
  - every installed Debian package, with a purl and its `.deb` sha256 from the
    lock;
  - each native binary with its sha256. The binary `CONTAINS` the Cargo
    packages it links: `cargo tree -e normal` in the build chroot, so with
    the features this build resolved. Crates only its build compiled are
    `BUILD_DEPENDENCY_OF` it.
  - for the checker, every crate archive and git source in the offline store;
  - the pinned payloads (Lightpanda, the Rust components) and pinned repo
    files placed in the image.

  Licences are what each crate declares. A Debian package's licence is
  `NOASSERTION`: its copyright file is not machine-read here.
- `provenance.json` is an in-toto Statement v1 with a SLSA provenance v1
  predicate:
  - the builder: the tools tree's content hash, mkosi's pin and the builder
    commit;
  - every input pin, each a resolved dependency: the engine commit, the base
    layer, the mkosi archive, the Rust components, the Debian sources plus the
    lock hash, `Cargo.lock`, the git dependencies, payloads and pinned files;
  - the epoch, seed and rootfs UUID;
  - the OCI archive, manifest, config, `rootfs.tar` and `rootfs.ext4` digests
    as subjects.

**Ownership.** The single-uid build leaves every file root-owned on disk, so
the tar states each owner explicitly:
- the default is `0:0`;
- data.tar owners and set-id bits come from each installed `.deb`;
- dpkg statoverrides win over those;
- `packages.toml owners` rules win over all. They cover maintainer-script
  ownership dpkg does not record, such as `/etc/shadow` `root:shadow` the way
  the pinned base layer ships it, and any path of the guest's own.

The existing recipes give the guest no path in the image: its HOME is the
run-time `/tmp`. The receipt lists every non-root entry and its source.
Ownership a maintainer script sets and no rule names stays root.

## Rebuild from the mirror, and retention

A release is rebuildable while its mirror exists. That mirror is the `blobs/`,
`pkgcache/`, `mkosi-cache/` (the signed apt metadata) and `cargo-home/`
directories. Run `build` (and `fetch` without `--learn`, to re-verify) against
the same `--mirror` with any checkout that holds the pinned engine commit. The
work directory is disposable.

Keep a mirror while any `release.toml` output at `built-candidate` or later
names its lock, and keep the artifacts of the current and the previous
generation. snapshot.debian.org keeps the archive, so a lost mirror can be
refetched. Then the lock and the pins still decide what counts. A changed
byte fails the fetch; nothing re-resolves.

## Four different proofs

- **Pins** (`[inputs]`) say what a build reads. A pin is an identity, not an
  approval.
- **Built digests** (`outputs`) say what one build produced. There are three
  digest namespaces, never interchangeable:
  - `oci_index_digest`, `oci_manifest_digest` and `oci_config_digest` are
    OCI digests. `oci_config_digest` is the image id a classic-store
    `docker load` reports; a containerd-store load reports the manifest
    digest.
  - `oci_archive_sha256` and `ext4_sha256` are file hashes.
  - The Firecracker host pins are BLAKE3 values, computed when a host adopts
    the rootfs.
- **Signatures**: none exist yet. Each build has a release manifest
  (`image-release.json`), but no signing key exists, so no envelope exists
  either. No key is in the repo, a log or a receipt.
- **Boot proof**: a candidate is not qualified until a fresh boot reaches its
  protocol. Each variant needs its own boot: a browser serves CDP, a checker
  runs a check, a desktop serves MCP and a display. A receipt is provenance,
  not a boot.

## Byte fields

| Field | Meaning |
|---|---|
| `compressed_bytes` | Size of `<variant>.oci.tar`, what a host transfers to `docker load`. |
| `oci_layer_bytes` | The gzipped layer blob alone. |
| `unpacked_bytes` | The sum of regular-file sizes in the tree: the read-only payload the budget limits. |
| `rootfs_tar_bytes` | The uncompressed layer (`rootfs.tar`) with tar headers. |
| `sparse_capacity_bytes` | The ext4 file's length, which the engine's 4 GiB verifier measures, sparse space included. |
| `ext4_allocated_bytes` | Blocks the ext4 file occupies on the build host's disk. |
| `writable_bytes`, `peak_ram_bytes` | Run-time measurements from a boot. They stay absent until one is made. |

Budgets in `release.toml` are proposed engineering targets, not checks. The
browser's 2 GiB and the desktop's 3 GiB runtime memory defaults are config
values, not image sizes. The checker's provisional 2-8 GiB payload can exceed
the 4 GiB Firecracker cap. Its first build decides between pruning, a split,
or a reviewed bound change.

## Verify a release

The wire, the signature rule and the result vocabulary are in
`crates/oneiron-container/images/manifest.md`. This section covers the
operator's part.

1. **Emit.** After `receipt`, run
   `build.py manifest --work W --variant <variant>` on the build host. Pass
   `--kernel <file>` to list an operator-supplied kernel. The emitter measures
   every artifact itself, then refuses with `error[pin-mismatch]` if any
   measurement differs from the receipt. In a builder work dir it takes BLAKE3
   from the tools tree's `b3sum`. Run outside one, it writes `blake3: null`
   with the manifest fact `blake3_unmeasured`, and a Firecracker host pin
   cannot bind to that manifest.
2. **Sign.** There is no step yet: no signing key exists. The seam is
   `--signer-cmd CMD`, which receives the manifest bytes on stdin and writes
   one envelope (`image-release.sig.json`) on stdout. The signature covers
   the manifest file's exact bytes, so never re-indent or re-save a manifest
   after signing. Re-emitting a manifest without a signer deletes the old
   envelope.
3. **Ship.** `image-release.json`, and later its envelope, travel beside the
   variant's artifacts. Its paths are relative to its own directory.
4. **Verify.** Each launch door runs `observe_release` before it starts a
   guest and records the result as `image_release` in the session manifest.
   A Hypnos import is meant to run it as well (LC builds that call). Today
   no host-owned binding from an image to its manifest exists, so every
   launch records `image_release_manifest_absent` and
   `image_signature_unavailable`. A signed manifest with no verifier
   configured records `image_signature_unverifiable`.
5. **Policy.** `IMAGE_SIGNATURE_POLICY` is `ObserveOnly`, so these facts
   never refuse a launch or an install. Every existing pin, fence and
   image-match check still decides as before. Requiring a verified signature
   narrows what runs, so it waits for an owner ruling, an enrolled trust root
   and a rollout.

To check a manifest by hand, compare `artifacts.rootfs_ext4.sha256` with
`sha256sum rootfs.ext4`, and `blake3` with `b3sum rootfs.ext4` (the value the
host's Firecracker rootfs pin must equal). Compare the OCI digests with
`index.json` and the blobs inside `<variant>.oci.tar`.

## Candidate hand-off to the acceptance smoke

A candidate goes to the lane's existing OCI acceptance smoke without touching
the smoke's default inputs or any serving config:

1. Copy `<variant>.oci.tar` to the booked Linux host and run `docker load -i`
   there. Record the local image id it prints, and keep the receipt's
   manifest digest beside it.
2. Give the smoke its own kind directory, for example
   `/srv/acceptance/<candidate-kind>/`. Write only that id to its
   `image-id.txt`.
3. Stage the engine, broker and the **matching host fence** in that kind's
   `bin/` with their hashes. The OCI backend mounts the host's fence over the
   image's, so both identities travel together.
4. Run the smoke for that kind. Do not rerun the smoke's own build step: it
   would overwrite the candidate.

Booting the Firecracker rootfs is a separate step. It needs a host
`ONEIRON_MICROVM_OCI_IMAGES` row and BLAKE3 pins for that rootfs. Nothing in
this pack installs those.

## Repeatability

Pinning inputs does not make filesystem bytes identical. `SOURCE_DATE_EPOCH`
clamps file mtimes and the fixed seed fixes the rootfs UUID and hash seed.
The tar is written in sorted order with explicit owners. Still, two builds
can differ in places no pin reaches:
- ext4 block placement;
- gzip framing across zlib versions;
- whether a package's maintainer script writes a timestamp or a random value;
- the order a build script emits.

A second, independent build compares payload hashes file by file and reports
filesystem metadata differences. It does not call a digest-pinned base
"reproducible" until that comparison holds.
