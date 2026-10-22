# Guest image family: build, rebuild, retain, hand off

The guest images (the code/minimal base, browser, desktop/CUA, checker, a
generic agent sandbox and the vault) come from one builder in
`crates/oneiron-container/images/`. Pinned mkosi assembles each image from a
frozen Debian snapshot, and the guest binaries are built inside the image's
own userspace. One assembled tree is exported twice: as an OCI image for the
no-KVM container backend and as a root-only ext4 rootfs for Firecracker.
Nothing here changes which image a host runs: a host runs what its config
pins. `guest/browser/build.sh` and `guest/checker/build.sh` produce their
images through this builder by default, and `--dockerfile` keeps each
one's Dockerfile recipe (see "Producers" below). The other recipes under
`crates/oneiron-container/guest/`, with their pins and receipts, stay as
they are.

## Files

- `release.toml` is the one release list. `[inputs]` holds the frozen inputs:
  - the Debian base's index, platform, config and layer digests;
  - the snapshot, derived from the base's build epoch;
  - mkosi's tag, commit and archive hash;
  - the exact Rust release and its dist component hashes;
  - the engine commit and the `Cargo.lock` hash;
  - every existing pin, by path + sha256 at that commit;
  - the contract revisions;
  - the Lightpanda, Bun and tsrs payload pins, and the CUA driver's source
    pin: its archive sha256, the paths taken from it, its `Cargo.lock` hash
    and the Rust release its source pins.

  `[variants.*.outputs."linux/amd64"]` holds what a build measured.
  `[variants.*.budget]` holds proposed targets.
- `packages.toml` holds requests only: the tools tree, `[base]` and one
  overlay per variant.
- `packages.lock.toml` is the resolved closure: every `.deb` by name,
  version, arch, size and sha256.

`python3 build.py validate` checks that the three agree. It needs no Linux
host. It refuses a moving `latest`, a malformed hash or commit, a missing
variant, a stale lock scope, and an output field on an unbuilt variant.

`fetch` and `build` refuse a plan the builder cannot install before they
enter a namespace or download anything: a payload kind with no installer
(`mkosi_run.INSTALLERS` has `file`, `archive`, `npm` and `rust-toolchain`),
or a source build whose pin lacks a field the build needs. Every tool they
run writes to stderr. `build` prints its record JSON on stdout, whole and last,
so stdout is one JSON document.

## Build

Fetch and build run on a Linux x86_64 host. They need python3 3.11 or newer,
the util-linux `unshare` (2.38 or newer, for `--map-user`), libseccomp,
network for the fetch phase, and unprivileged user and mount namespaces. They
need no root, no sudo and no container daemon. Fleet render boxes are
containers without user namespaces; book the builder elsewhere.

Two namespaces nest:
- `build.py` re-executes itself as root of a single-uid user namespace with a
  private mount namespace; for `build` it also gets a network namespace of its
  own with nothing but loopback. Its own steps run there: the bootstrap unpack, the fetch root below,
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
   - payloads: a file or zip by sha256, an npm tarball by its sha512 SRI
     integrity (`blobs/sha512/<hex>`; a mirror hit is hashed again);
   - a clean `CARGO_HOME` filled by `cargo fetch --locked` at the engine commit;
   - for each external source build (desktop-cua's `cua-driver`): its
     archive, its pinned Rust, and a Cargo store of its own,
     `cargo-home-<pin>/`, filled by `cargo fetch --locked` from the source's
     own `Cargo.lock` in the same fetch root. The checker's store never
     holds its crates;
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
   `Valid-Until` on those sources only. It is mkosi's build-sandbox source
   list. The finished tools tree carries the same file as its only apt
   source; mkosi would otherwise leave the tree a `trixie.sources` for
   deb.debian.org, which no pin governs.

   The first run on a fresh mirror passes `--learn` and writes
   `packages.lock.toml`: a replacement lock, covering only the scopes that
   run named, so name every variant. Commit that lock. A later fetch without `--learn`
   refuses any `.deb` whose bytes differ from the lock, and any newly
   downloaded `.deb` the lock does not name.
2. **Build (offline).** `build.py build --variant base` re-enters a namespace
   with no network at all and works from the mirror alone:
   1. It unpacks the base layer as a bootstrap tree.
   2. mkosi builds the **tools tree** from it (`ToolsTree=` the bootstrap
      tree). The tools tree is apt, dpkg, the keyring, e2fsprogs and the rest
      of `packages.toml [tools]`, from the same snapshot. Its content hash is
      the **builder identity**, `tools_tree_sha256`. The Debian base digest
      is only its seed. Before hashing, the builder drops ldconfig's aux
      cache and the logs, and replaces the tree's apt sources with the
      snapshot file. A tree kept from an earlier build is finished the same
      way before its hash is compared, so one finished by an older builder
      is rebuilt.
   3. mkosi builds the variant with `ToolsTree=` the tools tree.
      `mkosi.build.chroot` compiles the plan's binaries inside the image plus
      its build overlay, so they link against the glibc the image ships. It
      runs `--locked --offline` with the mirror's clean `CARGO_HOME`,
      `--remap-path-prefix` for every build path, and `SOURCE_DATE_EPOCH`.
      An external source build runs after it, in `env -i` with only the
      variables it names: its own Rust and store, `--remap-path-prefix` and
      C `-ffile-prefix-map` for its source, store, toolchain and target dir,
      `SOURCE_DATE_EPOCH`, and the pin's `build_env` (for the CUA driver,
      the two source SHAs its build script would otherwise ask git for).
      Default features, as the Docker recipe built it.
   4. `mkosi.postinst` places the guest account, pinned files, payloads,
      launchers and links. An npm package is unpacked without npm or its
      lifecycle scripts: `package/package.json` must name the pinned
      package and version, `package/` goes, a link or `..` member refuses
      it, and modes are normalized (directories 0755, files 0644, files the
      tarball marks executable 0555). A launcher is two lines,
      `#!/bin/sh` and `exec <runtime> <entry> "$@"`, 0555. `mkosi.finalize` empties `machine-id` and removes random seeds,
      credentials, keys, apt lists and caches, logs, the ldconfig aux cache
      and backup files. Licence files and dpkg's database stay. For a plan
      with an offline Cargo store (the checker), it then normalizes the
      store copied into the image (see "Checker store" below).
   5. The exporter refuses a tree whose files name a build-machine path.
   6. The exporter writes one deterministic `rootfs.tar`: sorted entries,
      mtimes clamped to the epoch, explicit ownership (below), and each
      entry's extended attributes (below). It builds both outputs from that
      tar:
      - `<variant>.oci.tar` is an OCI layout with `index.json` plus docker's
        `manifest.json`, so `docker load` accepts it;
      - `rootfs.ext4` comes from `mke2fs -d rootfs.tar` in the tools tree:
        root-only, with no partition table, ESP or UKI, and the kernel kept
        separate.

      The ext4 is refused above the engine's 4 GiB Firecracker rootfs cap;
      the cap does not move.
   7. It writes `rootfs.members.tsv`: every tar member with its type, mode,
      owner, size, mtime, sha256 (or link target) and xattrs. This is the
      payload identity a second build compares.
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
  - each external source build's binary (desktop-cua's `cua-driver`) with its
    sha256, the source archive and lock it came from, and the Cargo packages
    it links and compiled, joined with that source's own `Cargo.lock` in an
    SPDX id space of their own;
  - for the checker, every crate archive and git source in the offline store;
  - the pinned payloads (Lightpanda, Bun, each npm package with its sha512
    and purl, the Rust components) and pinned repo files placed in the image.

  Licences are what each crate declares, and an npm package's own
  `package.json` licence. A Debian package's
  `licenseDeclared` is read from its own `/usr/share/doc/<package>/copyright`
  in the built image; symlinked doc directories resolve inside the image.
  The rules:
  - Only a DEP-5 file (`Format:` copyright-format 1.0) is read.
  - Each Files paragraph's `License:` must be a plain list of short names
    joined by one operator, all `or` or all `and`. A comma, a
    `with … exception` or mixed operators leave the package `NOASSERTION`.
  - A short name maps to an SPDX id only through `attest.DEBIAN_TO_SPDX`.
    That one table holds the names Debian's own list defines unambiguously:
    GPL/LGPL/AGPL by version and `+`, Expat as MIT, BSD-2/3/4-clause,
    Apache-2.0, Artistic-2.0, CC0-1.0, ISC, MPL, OFL-1.1, Python-2.0, Zlib,
    and SPDX's own `-only`/`-or-later` forms.
  - Any other name with its text in the file becomes
    `LicenseRef-Debian-<name>-<text sha256 prefix>`, and that text goes
    under the document's `hasExtractedLicensingInfos`. Vague names such as
    MIT, BSD, Artistic or public-domain land here.
  - When that text names `/usr/share/common-licenses/<name>`, the file's own
    text is appended after the package's text, read from the built image
    (symlinks resolved inside it), never from the build host or tools tree;
    a missing file adds nothing (FIX 10350). The package's grant stays
    first: whether a GPL is "only" or "or later" is the grant's, never the
    common file's, and a bare `GPL` or `LGPL` is never mapped to an SPDX id
    because a system symlink points at one version.
  - A name with no text, a missing file, or a file that is not DEP-5 leaves
    the package `NOASSERTION`, with the reason in `licenseComments`.
  - The Files paragraphs of one package are joined with AND: each covers
    some of its files.
  - `licenseConcluded` stays `NOASSERTION`. This is the packager's
    declaration, not a legal conclusion.
- `provenance.json` is an in-toto Statement v1 with a SLSA provenance v1
  predicate:
  - the builder: the tools tree's content hash, mkosi's pin and the builder
    commit;
  - every input pin, each a resolved dependency: the engine commit, the base
    layer, the mkosi archive, the Rust components, the Debian sources plus the
    lock hash, `Cargo.lock`, the git dependencies, payloads (an npm one by
    sha512), each source build's archive, commit, lock hash and Rust
    components, and pinned files;
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

**Extended attributes and file capabilities.** A maintainer script's
`setcap` leaves a `security.capability` attribute on the file. The checker's
`gst-ptp-helper` (libgstreamer1.0-0) is the case in today's variants. The
exporter exports only the names in `export.XATTR_KEEP`, exactly
`security.capability` today (FIX 10349); it reads them without following
symlinks and writes each one as a PAX `SCHILY.xattr.<name>` record holding
the raw value bytes. A value that is not UTF-8 goes out under
`hdrcharset=BINARY`, byte for byte. The export policy:
- `security.capability` is written as a v2 value (magic, permitted and
  inheritable masks, no rootid), which a guest's own root reads as given.
  Inside the builder's namespace the kernel already reads the value as v2.
  A v3 value is translated only when its rootid is the builder's mapped
  root (0, or the invoking uid). Any other capability value is refused.
- No other name is exported, whatever the build host's filesystem put on a
  file: an SELinux label (`security.selinux`), IMA/EVM, a POSIX ACL,
  `user.*` or `trusted.*` never reaches the layer, the members listing or
  the tools-tree hash. A package that needs another name gets it added to
  `XATTR_KEEP` by an explicit decision, once both forms carry it.
- So the OCI layer and the ext4 rootfs carry the same set: `mke2fs -d
  rootfs.tar` imports through libarchive, and e2fsprogs 1.47.2 keeps only
  `security.capability` (and `gnu.translator`) from a tar.
- `rootfs.members.tsv` adds a ninth column, `xattrs`, holding sorted
  `name=<hex>` pairs joined by `;`. The tools tree's `tree_digest` hashes
  the same text.

**Checker store.** The checker ships the offline Cargo store at
`/opt/queue-check/cargo-home`. A check never runs against it in place: the
helper copies it into the plan's writable scratch `CARGO_HOME`
(`.oneiron/checks.json`). `mkosi.finalize` normalizes the copy in the
image, never the mirror, so that two fetches of one lock give the same
bytes (FIX 9353):
- it removes `.global-cache` (with `-wal` and `-shm`), cargo's SQLite record
  of last-use times; the scratch copy recreates it;
- it first removes each checkout's `.git/index` (stat data) and `.git/logs`
  (times). They are roots the bare db does not have: in runs f1 and f2 they
  were still there when the checkout was repacked, so its pack differed from
  the db's by a few bytes and the pair stayed two files (FIX 10348);
- it repacks every git object store, each `git/db` repo and each checkout's
  `.git`, from its refs. The image's own git does this (`mkosi-chroot
  /usr/bin/git`, so the tools tree carries no git) with fixed options:
  `pack.threads=1`, `pack.window=10`, `pack.depth=50`,
  `repack -a -d -f -F -n --no-write-bitmap-index`, and no reverse index,
  bitmap, multi-pack index or commit-graph. The server's pack and delta
  choices no longer reach the image. No `gc`, reflog expiry or prune runs:
  `-d` drops only packs the new one makes redundant;
- it links a checkout pack byte-identical to its db's pack back to that
  pack (same name, `cmp`), as the fetch left them.

Each checkout keeps its sources, `.cargo-ok`, HEAD, refs and objects.

## Rebuild from the mirror, and retention

A release is rebuildable while its mirror exists. That mirror is the `blobs/`
(`sha256/` and `sha512/`), `pkgcache/`, `mkosi-cache/` (the signed apt
metadata), `cargo-home/` and each source build's `cargo-home-<pin>/`
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
    `docker load` reports, and the id a VM vault's guest-runtime descriptor
    names. A containerd-store load reports the manifest digest, and there
    the config digest does not resolve (nelly, docker 29.9.0, checked
    10-22).
  - `oci_archive_sha256` and `ext4_sha256` are file hashes.
  - The Firecracker host pins are BLAKE3 values, computed when a host adopts
    the rootfs.
- **Signatures**: none exist yet. Each build has a release manifest
  (`image-release.json`), but no signing key exists, so no envelope exists
  either. No key is in the repo, a log or a receipt.
- **Boot proof**: a candidate is not qualified until a fresh boot reaches its
  protocol. Each variant needs its own boot: a browser serves CDP, a checker
  runs a check, a desktop serves MCP and a display. A receipt is provenance,
  not a boot. An output's state is `boot-proved` when a smoke booted an
  image whose rootfs layer is byte-identical to that output's. The output's
  `note` names that smoke: host, time, kind, run and what it measured. The
  proof covers exactly that leg.

## Byte fields

| Field | Meaning |
|---|---|
| `compressed_bytes` | Size of `<variant>.oci.tar`, what a host transfers to `docker load`. |
| `oci_layer_bytes` | The gzipped layer blob alone. |
| `unpacked_bytes` | The sum of regular-file sizes in the tree: the read-only payload the budget limits. |
| `rootfs_tar_bytes` | The uncompressed layer (`rootfs.tar`) with tar headers. |
| `sparse_capacity_bytes` | The ext4 file's length, which the engine's 4 GiB verifier measures, sparse space included. |
| `ext4_allocated_bytes` | Blocks the ext4 file occupies on the build host's disk. |
| `builder_peak_rss_bytes` | The builder's largest single process (`ru_maxrss` over the build and its waited-for children), not a sum. |
| `ext4_refused`, `ext4_needed_bytes` | Present instead of the ext4 fields when the capacity would pass the 4 GiB cap. |
| writable / snapshot bytes | Not an image property: both forms mount the rootfs read-only, and run-time writes land in the session's tmpfs (browser 512 MiB, checker 16 GiB by config). Only a boot measures them. |
| guest peak RAM, cold boot | Unmeasured by a build: they need the acceptance smoke (a boot). The browser's OCI Lightpanda leg sampled a peak in its smoke (its `note`); cold boot is unmeasured. |

Budgets in `release.toml` are proposed engineering targets, not checks. The
browser's 2 GiB and the desktop's 3 GiB runtime memory defaults are config
values, not image sizes. The checker's provisional 2-8 GiB payload can exceed
the 4 GiB Firecracker cap. Its first build decides between pruning, a split,
or a reviewed bound change.

## Measured: the current outputs (10-22, runs f1 and f2)

`release.toml` records run f1 (kel, builder commit `0684edada9`, verify mode
from the committed lock, 554 packages, tools tree `8a18ff6616c5…`). Run f2
(bel) built the same head from a fresh store and measured the same bytes
for every variant (see Repeatability). The budgets are RESULT.md's proposed
payload budgets.

| Variant | State | Compressed transfer (OCI archive) | Unpacked filesystem (file bytes) | Payload budget | Sparse ext4 capacity | ext4 allocated | Builder peak RSS (kel) |
|---|---|---|---|---|---|---|---|
| base | built-candidate | 37.1 MiB (38,901,760) | 105.9 MiB (110,999,048) | <= 256 MiB: within | 224.0 MiB (234,881,024) | 131.3 MiB | 2.14 GiB |
| browser | boot-proved (OCI, Lightpanda) | 362.6 MiB (380,180,480) | 1,014.8 MiB (1,064,102,555) | <= 2 GiB: within | 1.17 GiB (1,258,291,200) | 1.05 GiB | 2.11 GiB |
| checker | boot-proved (OCI, offline check) | 994.0 MiB (1,042,298,880) | 2.70 GiB (2,896,004,908) | 2-8 GiB provisional: within | 3.19 GiB (3,422,552,064) | 2.99 GiB | 2.00 GiB |

- **base and browser** have the same `rootfs.tar`, layer and ext4 bytes as
  run b6. Their OCI ids are new only because the builder-commit label is
  gone (FIX 9354).
- **The browser is `boot-proved` for one leg.** L11-B's OCI accept smoke
  booted b6's image on nelly (10:16 JST, kind c6, run
  `smoke-65745c0aebf6-1022-101536`, SMOKE rc=0), and that image's layer is
  this output's byte for byte. The smoke ran Lightpanda only and sampled a
  Docker MemUsage peak of 11,303,649 bytes. Chromium, Firecracker and cold
  boot were not measured. The output's `note` says exactly this.
- **The checker is new bytes** (store normalization, the capability xattr),
  proved by their own smoke. L11-A's acceptance smoke ran f1's image on kel
  (12:5x JST) as an OCI container with `--network none`, uid 10001 and
  `--memory 18g`. Its five legs: the image id, the contents (cargo and
  rustc 1.96.1, rustfmt, clippy, no rustup), the helper hash, the source
  copy, and an offline `cargo check --locked --workspace --all-features`.
  The check ran from a `cp -a` scratch copy of the normalized store and
  returned rc=0 in 620 s, so the store normalization leaves a store cargo
  resolves offline. Peak RAM was not sampled, and Firecracker was not
  measured.
- **All three fit the 4 GiB Firecracker rootfs cap**, the checker by about
  0.81 GiB. On top of the Debian closure, the checker's payload holds:
  - about 0.60 GiB of Rust toolchain (rustc, cargo, rust-std, rustfmt and
    clippy: 643,217,165 bytes);
  - about 0.79 GiB of offline Cargo store (846,002,586 bytes: the crates the
    lock names for x86_64 Linux, plus the git dependencies). The store is
    42.6 MB larger than b6's. Each git dependency's db and checkout now hold
    their own repacked pack, about 50 MB together: the two repacks differ
    by a few bytes, so they are no longer one hard-linked file.

  The store grows with `Cargo.lock`, so the cap's margin shrinks as
  dependencies are added. The cap does not move here.
- Writable and snapshot bytes are unmeasured. The guest's peak RAM is
  measured only for the browser's Lightpanda leg, above; the checker's
  smoke stayed under its 18 GiB limit unsampled.
- The whole build job's cgroup peak, anonymous memory plus page cache, was
  15.4 GiB on kel (16,586,764,288 bytes, run f1) and 12.3 GiB on bel
  (13,168,214,016 bytes, run f2), under a 16 GiB booking. kel and bel cap a
  guest at 16 GiB. The fetch's largest process was 473 MiB.
- The image's non-root and set-id paths match the pinned Debian base layer's
  for every package the variant installs:
  - `/etc/shadow` and `/etc/gshadow` are `root:shadow 0640`;
  - `su`, `mount` and `umount` are setuid;
  - `unix_chkpwd` is `root:shadow 2755`;
  - `/var/mail` is `root:mail 2775`;
  - `dbus-daemon-launch-helper` is `root:messagebus 4754`, through dpkg's
    statoverride.

  The Docker-built images have more set-id files, from packages these
  variants do not install: passwd and login (`chfn`, `chsh`, `passwd`,
  `chage`, …). They also have utmp logs, which `mkosi.finalize` drops.

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

## Producers: guest/browser and guest/checker build.sh

`crates/oneiron-container/guest/browser/build.sh` and
`crates/oneiron-container/guest/checker/build.sh` each take three routes,
chosen by flag, with no fallback between them:
- **the image-family route (default):** `build.py fetch` (never `--learn`)
  over every scope the lock covers, then `build`, `receipt` and `manifest`
  for that variant, against the mirror and work dir in
  `ONEIRON_BROWSER_IMAGES_MIRROR`/`_WORK` (`ONEIRON_CHECKER_IMAGES_…` for
  the checker); then `docker load` of the archive;
- **`--archive FILE`:** `docker load` of a built archive whose sha256 is the
  variant's `oci_archive_sha256` in `release.toml`. No rebuild;
- **`--dockerfile`:** the Dockerfile recipe as it was (host Cargo, the
  Dockerfile, the glibc load check, amd64 or arm64).

Every route prints one stdout line, the image's config digest, read from
the archive's `manifest.json` Config the way `deploy/firecracker/build.py`
reads it (FIX 8938). `--store-id` prints instead the id this host's docker
store answers (`docker image inspect` `.Id`); every route also writes that
id to stderr. A host whose docker uses the containerd image store pins the
store id. The checker's `image-id` and `image.json` receipt name the config
digest on every route. The image-family and `--archive` routes build no
host fence; stage it as its own step (both READMEs).

## Candidate hand-off to the acceptance smoke

A candidate goes to the lane's existing OCI acceptance smoke without touching
the smoke's default inputs or any serving config:

1. Copy `<variant>.oci.tar` to the booked Linux host, with `receipt.json`,
   `image-release.json`, `sbom.spdx.json` and `provenance.json` beside it.
   Check its sha256 against `oci_archive_sha256`. Run `docker load -i` there.
   The archive names `oneiron-image-<variant>:candidate`, so `docker load`
   prints that tag; take the id from
   `docker image inspect --format '{{.Id}}' oneiron-image-<variant>:candidate`.
   On a containerd image store (the fleet hosts' docker today) the id is
   the release's `oci_manifest_digest`; on a classic store it is
   `oci_config_digest`. Record the id beside the receipt's digests.
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

**The candidates (10-22).** Run b6's browser went to nelly, the L11-B
acceptance host: archive sha256 `5d900355867e…`, loaded id
`sha256:90074501db23…` (the manifest digest), config digest
`sha256:7f65d68d0ec5…`. Its smoke is the browser's boot proof above. Run
f1's outputs stayed on kel, loaded into its containerd-store docker:
- the browser: archive sha256 `71dfd70f06ac…`, manifest
  `sha256:afeac611ec30…`, config `sha256:7e6fee8804c1…`;
- the checker, smoked there by L11-A: archive sha256 `27446d5730f7…`, manifest
  `sha256:51fe794a2173…`, config `sha256:3980a4fd96a6…`, from engine
  commit `95afa460192b…`. Its `gst-ptp-helper` reads
  `cap_net_bind_service,cap_net_admin,cap_sys_nice=ep` under `getcap` in the
  loaded image.

The fence inside every image is `oneiron-fence` sha256 `3d6c6ef9942b…`,
built in the image's own trixie userspace. The browser entrypoint and the
checker helper are the pinned repo files, byte for byte, so the Chromium
flags and the helper are unchanged.

## Repeatability

Pinning inputs does not make filesystem bytes identical. `SOURCE_DATE_EPOCH`
clamps file mtimes and the fixed seed fixes the rootfs UUID and hash seed.
The tar is written in sorted order with explicit owners. Still, two builds
can differ in places no pin reaches:
- ext4 block placement;
- gzip framing across zlib versions;
- whether a package's maintainer script writes a timestamp or a random value;
- the order a build script emits.

A second, independent build compares payload hashes file by file
(`rootfs.members.tsv`) and reports filesystem metadata differences. It does
not call an image reproducible until that comparison holds.

### Findings (10-22)

**Runs f1 (kel) and f2 (bel), after the follow-up fixes:** base, browser
and checker are all bit-for-bit repeatable across the two hosts. For every
variant these are identical:
- the lock, `rootfs.tar`, the layer and its diff_id, `rootfs.ext4`, and the
  OCI config, manifest, index and archive;
- every native binary;
- every member's sha256, mode, owner, size, mtime and xattrs. The checker
  has 86,229 entries and 71,594 files; no entry exists on only one side.

The checker's one xattr is `gst-ptp-helper`'s
`security.capability=0100000200148000000000000000000000000000` (v2,
effective; `cap_net_bind_service`, `cap_net_admin`, `cap_sys_nice`). The
store normalization removed every b4 to b6 difference listed below.

The earlier runs were three clean builds of the same inputs, each in a fresh
store, with no mirror reused:
- b4 on kel learned the lock.
- b5 on bel built in verify mode from the committed lock.
- b6 on kel ran in verify mode after the tools-tree fix below.

Every builder run went through the fleet. The comparison covers the lock,
each tar member's sha256 and metadata, the OCI layer digest and the ext4
sha256.

- **Lock:** byte-identical. Every `.deb` matched its locked sha256 on the
  second host.
- **base and browser: bit-for-bit repeatable payload and filesystem.** Across
  the two hosts:
  - `rootfs.tar` (the OCI layer's diff_id) is identical;
  - the gzipped layer digest is identical, so the zlib framing matched;
  - `rootfs.ext4`'s sha256 is identical: block placement, UUID, hash seed and
    timestamps all matched;
  - every native binary's sha256 is identical;
  - every member has the same sha256, mode, owner, size and mtime: 2,407 files
    of 3,110 entries for base, 7,667 of 10,325 for browser. No entry exists
    on only one side.

  The OCI config, manifest and archive digests differed only because b4 to
  b6 carried the builder commit as a config label and manifest annotation
  (`dev.oneiron.image.builder-commit`), and each run built a different
  commit of this branch. Exports now leave it out (FIX 9354): an image's
  ids are fixed by its payload. The builder commit stays in the build
  record, the receipt (`builder.commit`), the SBOM's creator, the
  provenance's builder id and resolved dependencies, and, through the
  receipt's hash, `image-release.json`.
- **checker: repeatable except inside the Cargo store's git machinery.**
  Of 86,248 entries (71,598 files), these differ:
  - 10 files have different contents: cargo's `.global-cache` (an SQLite
    database of last-use times), and for each of the three git dependencies
    the checkout's `.git/index` (stat data) and its two reflogs. The reflogs
    read `unknown <unknown> <time>`, so no host identity is in them; only the
    time differs.
  - Between b4 and b5, 8 paths existed on only one side: the git object
    packs of formualizer and iroh. Each fetch received the same commits in a
    pack with different bytes, so the pack names differed. Between b5 and b6
    the packs matched, so this one varies from fetch to fetch.

  Everything else matches byte for byte: the toolchain, the Debian closure,
  every crate archive in the store, both binaries and every mode and owner.
  So `rootfs.tar`, the layer and the ext4 differ, and the unpacked size
  differs by a few KiB (370 bytes between b4 and b5, 4,096 between b5 and
  b6). As built then, the checker was **not** reproducible. The store
  normalization ("Checker store" above) fixes that, as runs f1 and f2
  show.
- **Builder identity.** The first two tools trees (b4, b5) differed in two
  files only: `var/cache/ldconfig/aux-cache`, which holds library inodes and
  ctimes, and `var/log/alternatives.log`, which holds wall-clock times. The
  builder now drops both before hashing. Recomputed that way, all three
  trees (b4, b5 and b6) give the same `tools_tree_sha256`,
  `133b6c46a144fa74b37376a5406b14295bc088f15692f5888985393828d688e9`.
  Since the tools tree carries only the snapshot sources (FIX 9355), and
  xattrs enter its digest, f1 and f2 both give
  `8a18ff6616c547e81c08eeba661a8e071cf1e7d74744bfa6be8284b1d49151d4`.
- **Builder memory.** The job cgroup peaked at 13.0 GiB on kel and 16.0 GiB on
  bel. That is anonymous memory plus page cache; the largest single process
  was 2.0-2.2 GiB.
