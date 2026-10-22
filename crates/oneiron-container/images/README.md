# Guest image family builder

One Debian-based guest image family, five variants (vault, browser,
desktop-cua, checker, generic-agent) over a common base, built by pinned
mkosi with pinned inputs. Linux x86_64 hosts only, no root, no Docker daemon.
The runbook is [docs/ops/guest-image-family.md](../../../docs/ops/guest-image-family.md).

| File | Holds |
|---|---|
| `release.toml` | The one release list: frozen inputs (base digests, Debian snapshot, mkosi, Rust, engine commit, existing pins by path + sha256, contract revisions, payloads), proposed budgets, and each variant's built outputs (absent until measured). |
| `packages.toml` | Requests only: the tools tree, `[base]` and the five overlays (packages, build-only packages, native bins, files, payloads, owners, OCI run config). |
| `packages.lock.toml` | The resolved Debian closure, written by the first `fetch --learn`. |
| `build.py`, `imagebuild/` | `validate`, `fetch`, `build --variant`, `receipt`, `manifest`; `imagebuild/attest.py` writes each build's SBOM and provenance statement. |
| `release-manifest.schema.json`, `manifest.md` | The release manifest's closed wire (`image-release.json` and its detached signature envelope), the verification results and the observe-only policy. |
| `mkosi.conf`, `mkosi.tools.conf` | Fixed mkosi defaults the generated per-build configs include. |
| `mkosi.build.chroot`, `mkosi.postinst`, `mkosi.finalize` | The native build inside the image's userspace, plan placement, and the strip step. |

```sh
python3 build.py validate
python3 build.py fetch   --repo <checkout> --mirror /srv/oneiron-images/mirror --work /srv/oneiron-images/work --variant base
python3 build.py build   --repo <checkout> --mirror /srv/oneiron-images/mirror --work /srv/oneiron-images/work --variant base
python3 build.py receipt --work /srv/oneiron-images/work --variant base
python3 build.py manifest --work /srv/oneiron-images/work --variant base
```

`<checkout>` is a git checkout that holds `inputs.engine.commit`. One fetch
can take several `--variant` flags; a first `--learn` fetch must name every
variant the lock should cover. Each build writes these under
`<work>/artifacts/<variant>/`:
- `rootfs.tar` and `rootfs.members.tsv` (every member's sha256);
- `<variant>.oci.tar` (an OCI layout `docker load` accepts);
- `rootfs.ext4` (root-only, for Firecracker's `/dev/vda`), unless its
  capacity would pass the engine's 4 GiB cap, when the record says
  `ext4_refused` instead;
- `sbom.spdx.json` (SPDX 2.3) and `provenance.json` (in-toto, SLSA v1),
  both unsigned;
- `build-record.json`, and `receipt.json` from `receipt`.

`manifest` adds `image-release.json` there.

The existing recipes in `../guest/` and their pins and receipts stay as they
are: this builder reads them by hash and replaces none of them. A built
output here is a candidate, not a deployed image: no signing key exists, so
its release manifest is unsigned, and no boot or smoke has qualified one.
