# Guest image family builder

One Debian-based guest image family, five variants (vault, browser,
desktop-cua, checker, generic-agent) over a common base, built by pinned
mkosi with pinned inputs. Linux x86_64 hosts only, no root, no Docker daemon.
The runbook is [docs/ops/guest-image-family.md](../../../docs/ops/guest-image-family.md).

| File | Holds |
|---|---|
| `release.toml` | The one release list: frozen inputs (base digests, Debian snapshot, mkosi, Rust, engine commit, existing pins by path + sha256, contract revisions, payloads), proposed budgets, and each variant's built outputs (absent until measured). |
| `packages.toml` | Requests only: the tools tree, `[base]` and the five overlays (packages, build-only packages, native bins, external source builds, files, payloads, launchers, links, directories, empty files, owners, OCI run config). |
| `packages.lock.toml` | The resolved Debian closure, written by the first `fetch --learn`. |
| `build.py`, `imagebuild/` | `validate`, `fetch`, `build --variant`, `receipt`, `manifest`; `imagebuild/attest.py` writes each build's SBOM and provenance statement. |
| `release-manifest.schema.json`, `manifest.md` | The release manifest's closed wire (`image-release.json` and its detached signature envelope), the verification results and the observe-only policy. |
| `mkosi.conf`, `mkosi.tools.conf` | Fixed mkosi defaults the generated per-build configs include. |
| `mkosi.build.chroot`, `mkosi.postinst`, `mkosi.finalize` | The native and external source builds inside the image's userspace, plan placement, and the strip step. |

```sh
python3 build.py validate
python3 build.py fetch   --repo <checkout> --mirror /srv/oneiron-images/mirror --work /srv/oneiron-images/work --variant base
python3 build.py build   --repo <checkout> --mirror /srv/oneiron-images/mirror --work /srv/oneiron-images/work --variant base
python3 build.py receipt --work /srv/oneiron-images/work --variant base
python3 build.py manifest --work /srv/oneiron-images/work --variant base
```

`<checkout>` is a git checkout that holds `inputs.engine.commit`. One fetch
can take several `--variant` flags; a `--learn` fetch writes a replacement
lock, so it must name every variant the lock should cover. A payload kind
with no installer (`file`, `archive`, `npm`, `rust-toolchain` have one) or an
incompletely pinned source build is refused before any namespace, fetch or
download. Every tool's output goes to stderr; `build` prints its record JSON
on stdout, whole and last.

What the phase-3 variants install, all from pins checked in the fetch:
- desktop-cua: `/usr/local/bin/cua-driver` (0555), built in the image's
  build overlay with no network from trycua/cua at its pinned commit (the
  codeload archive by sha256, only its `extract` paths), its own Cargo.lock
  and Cargo store (`<mirror>/cargo-home-cua-driver`, never the checker's) and
  the Rust the source pins; its licence texts in `/usr/share/doc/cua-driver`.
- generic-agent: Bun at `/usr/local/bin/bun` (the zip's one member), the npm
  packages tsrs, @tsrs/wasm and @tsrs/linux-x64-gnu unpacked without npm under
  `/opt/tsrs/node_modules` (their sha512 integrity checked on every use), and
  `/usr/local/bin/tsrs` and `/usr/local/bin/tsrs-wasm`, two-line launchers
  that run the packages' entry files under Bun. There is no Node.

What the vault (phase 4) installs, with no guest plumbing:
- the engine's `oneiron-server`, `oneiron-broker`, `oneiron-vm-init` and
  `oneiron-vm-outbox` in `/usr/bin`, built in release in the image's build
  overlay (build-essential, pkg-config, and cmake for expat-sys's bundled
  Expat);
- the pinned `deploy/firecracker/oneiron-vault-init`, unmodified, at
  `/usr/sbin/oneiron-vault-init` (the kernel's `init=/sbin/oneiron-vault-init`
  in the merged /usr);
- `mount`, and busybox with one link, `/usr/bin/reboot`, for the init's
  `reboot -f`;
- the mountpoints `/vault`, `/config`, `/restore` and `/etc/oneiron`, and an
  empty regular file, `/etc/resolv.conf` (0644), which the guest network
  covers with a file bind mount.

Its receipt's `vault_capabilities` holds what deploy/firecracker/build.py's
rootfs receipt would: guest runtime revision 0 with a null descriptor (no
rootless guest runtime is staged), and trusted organ builds revision 1.
Measured (run @@VTAG@@): @@VAULT_SIZES@@.

The vault output is an export, not something this family launches. It has an
OCI form because every output does, but the vault runs only as a Firecracker
microVM (`host.kvm` is true). LC's vault VM boots `rootfs.ext4` read-only,
with a kernel the family does not build (`manifest --kernel` lists one) and
its own vault, config and restore disks. Hypnos imports the standalone image
of deploy/firecracker/build.py (its `manifest.json` and `rootfs-receipt.json`),
not this output: taking the family's vault is LC's
`vault-family-artifact-import`.

Each build writes these under `<work>/artifacts/<variant>/`:
- `rootfs.tar` (xattrs: only security.capability is exported, as v2) and
  `rootfs.members.tsv` (every member's sha256 and xattrs);
- `<variant>.oci.tar` (an OCI layout `docker load` accepts);
- `rootfs.ext4` (root-only, for Firecracker's `/dev/vda`), unless its
  capacity would pass the engine's 4 GiB cap, when the record says
  `ext4_refused` instead;
- `sbom.spdx.json` (SPDX 2.3, Debian licences read from each package's
  DEP-5 copyright file in the image, a LicenseRef's text with the image's own
  /usr/share/common-licenses file it names; Cargo, source-build and npm
  packages with their checksums) and `provenance.json` (in-toto, SLSA v1),
  both unsigned;
- `build-record.json`, and `receipt.json` from `receipt` (it names every
  payload and source pin used and what each installed, measured).

`manifest` adds `image-release.json` there.

`../guest/browser/build.sh` and `../guest/checker/build.sh` take this
builder as their default route (rebuild from a mirror, or `--archive` to
import a recorded output) and print the image's config digest;
`--dockerfile` keeps each one's Dockerfile recipe. The builder reads those
recipes by hash at the engine commit. A built output is a candidate, not a
deployed image: no signing key exists, so its release manifest is
unsigned. A `boot-proved` output names its smoke in its `note`, and that
proof covers exactly what the note says.

Moving `inputs.engine.commit` is a refresh of every pin read at it: each
`[inputs.files]` sha256, `cargo_lock_sha256` and the contract `defined_at`
lines are recomputed at the new commit (never mixed with an older one), and
every output built from the old commit leaves its `boot-proved` state until
the new candidate is smoked again.
