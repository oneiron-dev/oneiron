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
| `build.py`, `imagebuild/` | `validate`, `fetch`, `build --variant`, `receipt`. |
| `mkosi.conf`, `mkosi.tools.conf` | Fixed mkosi defaults the generated per-build configs include. |
| `mkosi.build.chroot`, `mkosi.postinst`, `mkosi.finalize` | The native build inside the image's userspace, plan placement, and the strip step. |

```sh
python3 build.py validate
python3 build.py fetch   --repo <checkout> --mirror /srv/oneiron-images/mirror --work /srv/oneiron-images/work --variant base
python3 build.py build   --repo <checkout> --mirror /srv/oneiron-images/mirror --work /srv/oneiron-images/work --variant base
python3 build.py receipt --work /srv/oneiron-images/work --variant base
```

`<checkout>` is a git checkout that holds `inputs.engine.commit`. Each build
writes `rootfs.tar`, `<variant>.oci.tar` (an OCI layout `docker load`
accepts), `rootfs.ext4` (root-only, for Firecracker's `/dev/vda`),
`build-record.json` and `receipt.json` under `<work>/artifacts/<variant>/`.

The existing recipes in `../guest/` and their pins and receipts stay as they
are: this builder reads them by hash and replaces none of them. A built
output here is a candidate, not a deployed image: no signature exists yet and
no boot or smoke has qualified one.
