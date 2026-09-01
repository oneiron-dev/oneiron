# Vendored `heed` 0.20.5 — provenance, seam, and audit (ONE-218)

`crates/heed/vendor/heed-0.20.5` is a **pinned local vendor of the published
heed 0.20.5 crate** with one added open seam. The repository root manifest
substitutes it for the registry copy with

```toml
[patch.crates-io]
heed = { path = "crates/heed/vendor/heed-0.20.5" }
```

and excludes it from the workspace. The dependency graph is otherwise
untouched: the package keeps name `heed`, version `0.20.5`, edition 2021, and
every upstream dependency requirement — including `lmdb-master-sys` at the
already-locked `0.2.6` — so no version moves and no dependency is added.

## Why this fork exists

`Store::open_existing` (`crates/oneiron/src/store/open_gates.rs`) binds a vault
root as a directory descriptor (`open(O_DIRECTORY|O_RDONLY|O_NOFOLLOW|
O_CLOEXEC)`), validates both LMDB entries `openat`-relative to it, and then must
open the LMDB environment **through that descriptor**, as
`/proc/self/fd/<dirfd>`, so that a rename, swap, or ABA of the caller's
pathname cannot redirect the environment onto a directory the door never bound.

Upstream `EnvOpenOptions::open` cannot do that. Its first act is
`canonicalize_path(path)` (upstream `src/env.rs:52-53`, used at the top of
`open`), which resolves `/proc/self/fd/<dirfd>` back into an ordinary pathname;
`mdb_env_open` then receives a `CString` of **that** pathname. The capability is
discarded, and the final dereference is a fresh pathname walk separated in time
from the walk that produced it — exactly the window the descriptor binding
exists to close. That is finding `M1_HEED_CANONICALIZATION_STRIPS_THE_
DESCRIPTOR_BOUND_ENV_PATH` in the binding K3 MATERIAL2 adjudication.

The fork adds one seam that keeps the exact open path and the cache identity
separate, and changes nothing else.

## Upstream pin

| Fact | Value |
| --- | --- |
| Upstream source root | `/home/lexi/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/heed-0.20.5` |
| crates.io checksum (unpatched lock entry) | `7d4f449bab7320c56003d37732a917e18798e2f1709d80263face2b4f9436ddb` |
| Upstream `src/env.rs` SHA-256 | `cfca096b00d446431092c897f9939ff79834d9a8984208e21d8274b7d6a5d343` |
| Upstream VCS commit (`.cargo_vcs_info.json`) | `947c3aa814b9a5eab764a95f84242fe1756cf61a`, `path_in_vcs = "heed"` |
| Pinned LMDB C source behind it | `lmdb-master-sys-0.2.6/lmdb/libraries/liblmdb/mdb.c`, SHA-256 `56bf21f1d42fe36f42e52cf4dad7c3d910214182cceb46751ee7042fe299ad3a` |

## Inventory

**Byte-for-byte from the pinned registry root** (unchanged, verifiable with
`sha256sum` against the source root above):

```
Cargo.lock                    Cargo.toml.orig               .cargo_vcs_info.json
README.md
examples/all-types.rs         examples/clear-database.rs    examples/cursor-append.rs
examples/custom-comparator.rs examples/multi-env.rs         examples/nested.rs
examples/rmp-serde.rs
src/cookbook.rs               src/cursor.rs                 src/database.rs
src/iteration_method.rs       src/iterator/iter.rs          src/iterator/mod.rs
src/iterator/prefix.rs        src/iterator/range.rs         src/lib.rs
src/mdb/lmdb_error.rs         src/mdb/lmdb_ffi.rs           src/mdb/lmdb_flags.rs
src/mdb/mod.rs                src/reserved_space.rs         src/txn.rs
```

(Upstream's packaging `Cargo.lock` is carried verbatim, like the existing
`crates/oneiron-seal/vendor/pkix-chain-0.4.1` snapshot. It is inert: this
package is resolved by the Oneiron root lockfile.)

**Changed from upstream — exactly two files:**

- `Cargo.toml` — a provenance COMMENT BLOCK only. No package, dependency,
  feature, or target value is altered, and no table is added or removed.
- `src/env.rs` — the open seam described below. Nothing else in the file, and
  no other source file, is touched.

**Added by this vendor:**

- `LICENSE-MIT` — the crate declares `license = "MIT"` but the published tarball
  ships no license file; this is the canonical MIT text with the holder taken
  from the crate's own metadata. MIT is already on the `deny.toml` allow list,
  so no allowance change is needed.
- `crates/heed/PROVENANCE.md` — this file, following the vendoring-record
  convention of `crates/oneiron-seal/vendor/README.md`.

**Deliberately not copied:** the registry extraction marker `.cargo-ok`.

## The seam

```rust
pub unsafe fn open_with_cache_identity<B, A>(
    &self,
    open_path: &Path,
    cache_identity: PathBuf,
    before_open: B,
    after_open: A,
) -> Result<Env>
where
    B: FnOnce(),
    A: FnOnce();
```

- `open_path` goes **straight** into `CString::new(open_path.as_os_str()
  .as_bytes())` and then into `mdb_env_open`. It is never canonicalized,
  re-resolved, joined, or replaced by `cache_identity`.
- `cache_identity` is the `OPENED_ENV` map key and nothing else: the
  single-`Env`-per-identity lookup, `Env::path`, `Env::prepare_for_closing`,
  `EnvInner::drop` de-registration, and `env_closing_event`. It never reaches
  LMDB. Oneiron passes the already-canonical vault root, which is the same key
  upstream would have produced, so heed's registry behaviour is unchanged.
- `before_open` fires after all path, option, and cache preparation,
  **immediately before** the single `mdb_env_open`; `after_open` fires the
  instant it returns, before the result is inspected and before the `Env` is
  published. Both are no-ops on the ordinary `open` path.

The full `# Safety` contract is on the method itself. In summary: every
`EnvOpenOptions::open` requirement still applies; `open_path` must name the
intended environment for the whole call and, for a `/proc/self/fd/<fd>` path,
`fd` must stay open at least until the call returns; `cache_identity` must
identify that environment one-to-one; and the hooks must neither re-enter heed
(the environment-map write lock is held) nor unwind across the LMDB call.

`EnvOpenOptions::open` keeps its exact public behaviour: it canonicalizes as
before and then delegates to the shared body with the canonicalized path used
as *both* the cache identity and the open path, with no-op hooks. There is one
`mdb_env_create`, one option-setup block, and **one** `mdb_env_open` call site
in the crate — `open_locked` — not parallel implementations.

## LMDB audit (against the pinned `mdb.c`)

- **The proc-fd path stays a capability for the whole of `mdb_env_open`.**
  `mdb_fname_init` (`mdb.c:4832-4852`) copies the passed path and appends
  `/data.mdb` and `/lock.mdb` (`mdb_suffixes`, `mdb.c:4817-4820`); every open
  inside `mdb_env_open` — `lock.mdb` via `mdb_env_setup_locks`
  (`mdb.c:5442`), `data.mdb` (`mdb.c:5766-5769`), and the synchronous meta
  descriptor `me_mfd` (`mdb.c:5788`) — resolves through that string. LMDB
  performs no canonicalization of its own, so each one resolves through the
  bound directory inode, not through any ordinary pathname.
- **No later re-walk.** `mdb_env_open` `strdup`s the path into `env->me_path`
  (`mdb.c:5745`). Across the whole pinned source `me_path` is only declared
  (`1549`), assigned (`5745`), null-checked (`5749`), `free`d in
  `mdb_env_close0` (`5857`), and returned by `mdb_env_get_path` (`10861`) —
  which heed never calls. Nothing re-opens the environment by pathname after
  `mdb_env_open` returns; all later I/O uses the retained `me_fd`/`me_lfd`/
  `me_mfd` descriptors.
- **Belt and braces on the descriptor.** Oneiron nevertheless keeps the bound
  directory descriptor alive for the whole environment lifetime (it is moved
  into `OwnedEnv`), so the `/proc/self/fd/<dirfd>` entry cannot become a
  recycled descriptor even if some future LMDB path did re-read `me_path`.

## Workspace and ratchet posture

The package sits under a `vendor/` directory and is **excluded** from the
Oneiron workspace: `members = ["crates/*"]` would otherwise glob `crates/heed`,
which holds no manifest of its own, so the root manifest carries
`exclude = ["crates/heed"]`. Consequences, all intentional:

- `cargo fmt`, workspace-wide clippy, and `cargo test` do not reach upstream
  bytes, so the vendored tree cannot be silently reformatted or relinted away
  from the pinned upstream source.
- The repository ratchet (`scripts/ratchet/check.sh`) already excludes
  `*/vendor/*` from its giant-file scan and only counts `#[allow(`/print
  macros under `crates/*/src` — there is no `crates/heed/src`. Vendoring here
  therefore moves none of the three counts and needs **no baseline edit**.
- heed's own upstream unit tests live in `src/env.rs` and are not run here.
  The seam's two load-bearing properties are proved from the Oneiron side, at
  the real door, by the engine tests in `crates/oneiron/src/store/tests.rs`
  (final-dereference replacement, ABA across the C call, and the cache-identity
  registration observed through `heed::env_closing_event`).

## Re-vendoring

Re-copy the registry root over `vendor/heed-0.20.5`, then re-apply exactly the
two changed files above. Any upstream version move must re-run this audit: the
seam depends on `OPENED_ENV` being keyed by a `PathBuf` the caller can choose
and on `mdb_env_open` receiving a string the caller supplies.
