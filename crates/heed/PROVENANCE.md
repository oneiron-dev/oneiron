# Vendored `heed` 0.20.5 — provenance, seam, and audit (ONE-218)

`crates/heed/vendor/heed-0.20.5` is a **pinned local vendor of the published
heed 0.20.5 crate** with one added open seam. The repository root manifest
substitutes it for the registry copy with

```toml
[patch.crates-io]
heed = { path = "crates/heed/vendor/heed-0.20.5" }
```

and excludes it from the workspace. The package keeps name `heed`, version
`0.20.5` and edition 2021. ONE-218 kept every upstream dependency requirement;
OF-570 then moved the C library to `lmdb-master3-sys` and added the page
cipher's crates (see "OF-570: mdb.master3 and sealed pages").

## Why this fork exists

`Store::open_existing` (`crates/oneiron/src/store/open_gates/open_existing_door.rs`,
with the binding in `open_gates/vault_root_bind.rs`) binds a vault root as a
directory descriptor (`open(O_DIRECTORY|O_RDONLY|O_NOFOLLOW|
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
| Upstream source root | `<host-home>/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/heed-0.20.5` |
| crates.io checksum (unpatched lock entry) | `7d4f449bab7320c56003d37732a917e18798e2f1709d80263face2b4f9436ddb` |
| Upstream `src/env.rs` SHA-256 | `cfca096b00d446431092c897f9939ff79834d9a8984208e21d8274b7d6a5d343` |
| Upstream VCS commit (`.cargo_vcs_info.json`) | `947c3aa814b9a5eab764a95f84242fe1756cf61a`, `path_in_vcs = "heed"` |
| Pinned LMDB C source behind it (ONE-218) | `lmdb-master-sys-0.2.6/lmdb/libraries/liblmdb/mdb.c`, SHA-256 `56bf21f1d42fe36f42e52cf4dad7c3d910214182cceb46751ee7042fe299ad3a` |
| LMDB C source behind it since OF-570 | `lmdb-master3-sys-0.2.6/lmdb/libraries/liblmdb/mdb.c`, SHA-256 `0e7c948b4aa3492b4581ed14fcf187952c90317569c0f6962e8e6e885743f893` |
| Vendored copy of that crate since FIX 1910 | `crates/heed/vendor/lmdb-master3-sys-0.2.6`: upstream plus the key-wipe hunks (see "FIX 1910" below) |

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

**Changed from upstream** (ONE-218; OF-570 changed more, see below):

- `Cargo.toml` — a provenance comment block and packaging-only exclusions for
  `/.cargo_vcs_info.json` and `/Cargo.toml.orig` (ONE-1441). Package identity,
  dependency requirements, features, and targets are unchanged; no table is
  added or removed.
- `src/env.rs` — the open seam described below. Nothing else in the file, and
  no other source file, is touched.
- `src/txn.rs`, `src/database.rs`, `src/env.rs`, `src/mdb/lmdb_ffi.rs` — the
  PAGE-FULL trace accessors, see that section below.

**Added by this vendor:**

- `LICENSE-MIT` — the crate declares `license = "MIT"` but the published tarball
  ships no license file; this is the canonical MIT text with the holder taken
  from the crate's own metadata. MIT is already on the `deny.toml` allow list,
  so no allowance change is needed.
- `crates/heed/PROVENANCE.md` — this file, following the vendoring-record
  convention of `crates/oneiron-seal/vendor/README.md`.

**Deliberately not copied:** the registry extraction marker `.cargo-ok`.

## OF-570: mdb.master3 and sealed pages

Owner ruling 2026-10-09 (E2-HOT B): engine page AEAD is an opt-in "maximum"
tier ("megalock") that warns it is slower. The pinned `lmdb-master-sys` (LMDB
0.9.70) has no page hook, so this vendor links **mdb.master3** instead:
`lmdb-master3-sys` 0.2.6 (LMDB 0.9.90, mdb.c SHA-256
`0e7c948b4aa3492b4581ed14fcf187952c90317569c0f6962e8e6e885743f893`). Its data
format is 3 and it refuses format-1 files; the owner's decree ("no existing
vaults") makes that a clean break, not a migration.

Every environment uses mdb.master3. A plain environment opens exactly as
before, with no hook and the single read-only map. A sealed one is opened with
`EnvOpenOptions::page_key`:

- `src/page_seal.rs` (added) is the `MDB_enc_func`: XChaCha20-Poly1305 under
  the page key, a fresh random 24-byte nonce for every seal, the nonce and the
  16-byte tag in the 40-byte per-page authentication area, and the clear page
  number and txn id as associated data. It never unwinds into C. This avoids
  the defects canon RESEARCH-1223 records for heed3's own sealing: a nonce
  built from page number and txn id, reused on a spill or a restarted txn.
- `src/env.rs`: the `page_key` option (never printed or serialized, wiped on
  drop); the cipher installed right after `mdb_env_create`; `WRITE_MAP` and
  `FIXEDMAP` refused with a key; a read of the main tree's first page before a
  sealed env is published, since meta pages are clear and a wrong key would
  otherwise open; `Env::is_sealed`; `Env::flags` masking mdb.master3's
  encryption and chunk-remap bits; `copy_to_file` and `copy_to_fd` refused for
  a sealed env (mdb.master3's compacting copy writes decrypted pages unsealed
  and its plain copy reads past the meta-only map).
- `src/txn.rs`, `src/cursor.rs`, `src/database.rs`: mdb.master3 may unmap a
  decrypted page chunk while its transaction lives, so heed's "valid for the
  whole transaction" borrow would dangle. A sealed env's returned keys and
  values are copied into a per-transaction stash (wiped on drop) and live
  until the transaction ends. A plain env stays zero-copy.
- `src/mdb/lmdb_ffi.rs`, `lmdb_error.rs`, `lmdb_flags.rs`, `src/lib.rs`: the
  FFI alias points at `lmdb_master3_sys`, and the module is registered.
- `Cargo.toml`: `lmdb-master3-sys` replaces `lmdb-master-sys`, every LMDB
  feature forwards to it, and `chacha20poly1305` 0.11, `getrandom` 0.4 and
  `zeroize` 1.9 are added (all already in the lock).

LC backup shipper rows (FIX 5826 batch) add one read accessor:

- `src/txn.rs`: `RoTxn::id` returns `mdb_txn_id` of the live transaction (a
  write transaction reaches it through `Deref`), the id the backup watermark
  records; `src/mdb/lmdb_ffi.rs` re-exports `mdb_txn_id`, which
  `lmdb-master3-sys` already binds. No other behaviour changes.

The result-body collector (FIX 22101) adds one read accessor:

- `src/env.rs`: `Env::oldest_reader_txn_id` clears stale reader slots
  (`mdb_reader_check`), then reads the reader table through
  `mdb_reader_list` and returns the lowest transaction id a live slot
  holds, or `None` when no read transaction is live; the collector unlinks
  a released body file only once that id reaches the transaction that
  released it. `src/mdb/lmdb_ffi.rs` re-exports `mdb_reader_list`, which
  `lmdb-master3-sys` already binds. No other behaviour changes.

The descriptor seam's audit holds for mdb.master3: `me_path` is still only
declared, assigned, null-checked, freed and returned by `mdb_env_get_path`
(mdb.master3 `mdb.c:1659, 6248, 6252, 6362, 11646`), and every file open goes
through `mdb_fname_init` (`mdb.c:5228`). The line numbers in the audit below
are the earlier library's.

## FIX 1910: vendored `lmdb-master3-sys` 0.2.6 and the page-key wipe

mdb.master3 copies the page key into its own heap (`MDB_env.me_enckey`, set
by `mdb_env_set_encrypt`). Upstream frees that copy unwiped, both when a key
is replaced and on the final `mdb_env_close`. heed also leaked a created env
on some early exits of `open_locked`, so that copy was never freed at all.

To fix the C side, `crates/heed/vendor/lmdb-master3-sys-0.2.6` vendors the
same crate: same version, features and FFI. Two edges select it.
`heed-0.20.5/Cargo.toml` names it as a path dependency, the edge maturin
follows into the sdist, as the workspace heed dependency does. The root
`[patch.crates-io]` sends any registry requirement to the same tree. The root
manifest excludes it from the workspace. In `Cargo.lock` the package lost its
registry `source` and `checksum` lines and nothing else changed.

| Fact | Value |
| --- | --- |
| Upstream package | `lmdb-master3-sys` 0.2.6, the crates.io archive `lmdb-master3-sys-0.2.6.crate` |
| crates.io checksum (the earlier lock entry, verified on the archive) | `78b1f49b7494125af9b87ddb83cb4828d4ddbaf83c3ed132d5ebd0d43d02f525` |
| Upstream VCS commit (`.cargo_vcs_info.json`) | `57025ff083b6fc68c9313edccb28c75d7ccf751f`, `path_in_vcs = "lmdb-master3-sys"` |
| Upstream `mdb.c` SHA-256 | `0e7c948b4aa3492b4581ed14fcf187952c90317569c0f6962e8e6e885743f893` |
| Licences | crate `Apache-2.0`; liblmdb under the OpenLDAP Public License (`lmdb/libraries/liblmdb/LICENSE`, `COPYRIGHT`) |

**Byte-for-byte from the archive** (verifiable with `sha256sum` against the
extracted `.crate`):

```
Cargo.toml.orig               .cargo_vcs_info.json          README.md
build.rs                      bindgen.rs                    src/lib.rs
src/bindings.rs
lmdb/libraries/liblmdb/midl.c lmdb/libraries/liblmdb/lmdb.h lmdb/libraries/liblmdb/midl.h
lmdb/libraries/liblmdb/LICENSE                              lmdb/libraries/liblmdb/COPYRIGHT
```

**Deliberately not copied:** the archive's packaging `Cargo.lock` and
`.rustfmt.toml`, the extraction marker `.cargo-ok`, and liblmdb's tools, tests,
sample crypto module and docs (`mdb_{copy,drop,dump,load,stat}.{c,1}`,
`mtest*.c`, `mplay.c`, `module.c`, `crypto.c`, `chacha8.{c,h}`, `Makefile`,
`Doxyfile`, `intro.doc`, `sample-*.txt`, `tooltag`, `.gitignore`). `build.rs`
compiles only `mdb.c` and `midl.c`, and `mdb.c` includes only `lmdb.h` and
`midl.h`. Every feature and the optional `bindgen` regeneration path keep
their inputs.

**Changed from upstream:**

- `lmdb/libraries/liblmdb/mdb.c` (12,347 lines with these hunks alone, 12,345
  with the ITS#10551 hunks below; upstream 12,327):
  - `:6488-6506` adds `mdb_enckey_clear`, inside `#if MDB_RPAGE_CACHE`. It
    wipes the saved `me_enckey.mv_size` bytes through a volatile pointer, then
    frees them and sets the pointer to NULL and the length to zero.
  - `:6526`: `mdb_env_close` calls it in place of upstream's `free`
    (upstream `:6506`).
  - `:11635`: `mdb_env_set_encrypt` calls it in place of upstream's `free`
    (upstream `:11617`), once the new copy is allocated and filled. The
    `EINVAL` (bad argument, active env) and `ENOMEM` returns come first and
    keep the old key.
  - `mdb_env_close_active` is unchanged. A failed `mdb_env_open` leaves the
    env reusable with its key, and the final `mdb_env_close` wipes it.
- `Cargo.toml:30-33`: the ONE-1441 packaging exclusion of
  `/.cargo_vcs_info.json` and `/Cargo.toml.orig`, as for heed. Package
  identity, dependencies, features and targets are unchanged.

**heed side:**

- `src/env.rs`: `open_locked` arms `EnvCloseGuard` (`:419-422`, type
  `:596-618`) right after `mdb_env_create`. Its drop calls `mdb_env_close`
  once. `disarm` (`:498`) hands the env to `EnvInner`, whose drop remains the
  only close of a published env.
  - The guard replaces the two explicit closes: a failed `mdb_env_set_encrypt`,
    and a failed open or wrong page key.
  - It also covers the exits that leaked a created env: a map size that is
    not a page multiple, and the `?` of `mdb_env_set_mapsize`,
    `mdb_env_set_maxreaders` and `mdb_env_set_maxdbs`.
- `Cargo.toml:112-113` adds the path dependency; the header comment
  (`:20-22`) names it.

Line numbers elsewhere in this file cite the upstream `mdb.c` (SHA-256
above). Add 20 to an upstream line after 6487 to find it in the vendored copy;
after upstream line 10678, see the ITS#10551 section for the offset.

**Re-vendoring:** re-extract the crates.io archive with the checksum above.
Re-copy the files listed, then re-apply the `mdb.c` and `Cargo.toml` hunks.

## PAGE-FULL trace: three read-only accessors

FIX row TRAP-REGISTER-WAIT-PAGE-FULL: writes on several engine paths failed now
and then with `MDB_PAGE_FULL` (the cause is in the next section). The engine's
canonical accessors (`oneiron-store` `overlay_db/accessors.rs`) trace such a
failure; the trace needs three facts heed 0.20.5 does not expose. Each is a
read, opens no transaction, and runs only after a write has already failed:

- `src/txn.rs`: `RoTxn::environment`, the `Env` the transaction holds alive
  (for `Env::info`: the map size and the last page number).
- `src/database.rs`: `Database::raw_flags`, the persisted flags of one
  database from `mdb_dbi_flags`; `src/mdb/lmdb_ffi.rs` re-exports that
  function.
- `src/env.rs`: `Env::page_size`, `ms_psize` from `mdb_env_stat`. LMDB marks a
  transaction failed on `MDB_PAGE_FULL`, so `Database::stat` on it answers
  `MDB_BAD_TXN`; the page size then comes from the environment.

Each addition is marked `ONEIRON FORK (PAGE-FULL trace)`. Re-vendoring
re-applies them with the files listed above.

## PAGE-FULL cause: upstream ITS#10551 in `mdb.c`

FIX row TRAP-REGISTER-WAIT-PAGE-FULL. mdb.master3 pads a leaf node's key and
its data to even lengths separately (upstream ITS#8988, already in this copy):
`LEAFSIZE` and `mdb_node_add` count `NODESIZE + EVEN(key) + EVEN(data)`.
`mdb_page_split` still chose its split point with the older count,
`NODESIZE + key + sizeof(indx_t) + data`, and padded only the running total.
So it counted 2 bytes short for every node whose key and data are both
odd-sized. With such nodes on the page, it could pick a split whose half was a
few bytes over the page; `mdb_node_add` then answered `MDB_PAGE_FULL`, the
transaction failed, and nothing was written. `vault_meta` keys are 33 bytes
long, so many engine writes could reach it.

Upstream fixed it on mdb.master3 in commit
`567292b5d4896d558c7f4fffbf711b86432cc15a` (27 Jul 2026, "ITS#10551 lmdb: fix
mdb_page_split nodesize calculation"). This copy carries its three hunks
verbatim:

- `mdb_branch_size` (`:9189`) returns `EVEN(sz + sizeof(indx_t))`.
- `mdb_page_split` no longer pads the new node's size again after
  `mdb_leaf_size` / `mdb_branch_size` (`:10695-10698`); both return even sizes.
- Its split-point loop (`:10750`, `:10755`) adds
  `NODESIZE + EVEN(NODEKSZ(node)) + sizeof(indx_t)` and `EVEN(NODEDSZ(node))`
  per node, with no running `EVEN`.

The page format does not change, only where a later split cuts a page; pages
an older build wrote read as before. `mdb.c` is now 12,345 lines, SHA-256
`ec8b7dbffb54a5775db1e67507f32cd3cad3152cbc09c5bb47bb81f2dac8df9c`. To find an
upstream line in this copy, add 20 up to upstream line 10678, 19 from 10680 to
10737, and 18 from 10739 on (upstream 10679 and 10738 are the two removed
lines). `crates/oneiron-store/tests/lmdb_page_split.rs` is the regression
test: four puts of 33-byte keys, the last of which answered `MDB_PAGE_FULL`
before this change.

**Re-vendoring:** re-apply these three hunks with the FIX 1910 hunks, or take
an upstream mdb.master3 that contains commit `567292b5d489`.

## ITS#10519: overflow runs count the authentication area

FIX row LMDB-MASTER3-UPSTREAM-FIXES-AUDIT. A sealed environment (OF-570)
keeps `AUTH` = 40 bytes (the nonce, then the tag) at the tail of every page
and every overflow run: `mdb_page_encrypt` (`:7162`) seals the run less its
16-byte clear prefix and its last 40 bytes, and writes the nonce and tag into
those 40. `me_pagespace` leaves the area out of a leaf or branch page, but
`OVPAGES` sized an overflow run from the value alone,
`(PAGEHDRSZ-1 + size) / psize + 1`. A value whose last byte fell into the
run's last 40 bytes got one page too few. Those value bytes were never
sealed, the commit still succeeded, and every later read returned other bytes
in their place. With 4 KiB pages (`PAGEHDRSZ` 24) that is every value of
4033-4072 bytes, and the same 40 lengths below each later page end. Two paths
size a run: `mdb_node_add` (a new value) and the in-place overwrite in
`mdb_cursor_put` (a value written earlier in the same transaction).

Upstream fixed it on mdb.master3 in commit
`e27f3d616b7b39c8294c0135ac60476b88cc5189` (9 Jun 2026, "ITS#10519 LMDB: fix
ovpage size calculation with encryptino & checksums"). This copy carries its
three hunks verbatim:

- `OVPAGES(env, size)` (`:1154-1158`) adds `me_sumsize + me_esumsize` under
  `MDB_RPAGE_CACHE`.
- Its two callers, `_mdb_cursor_put` (`:8782`) and `mdb_node_add` (`:9259`),
  pass the env.

A plain environment (no page key, no checksum) has both sizes 0 and counts as
before. A run keeps the page count it was written with (`op_pages` in its
node); readers, `mdb_ovpage_free` and the overwrite test read that count,
never `OVPAGES`, so runs an older build wrote read and free as before (stored
change: keep). A value an older build already cut stays cut: its lost bytes
were never written. `mdb.c` is now 12,349 lines, SHA-256
`fd8391fc979ce2bee80d3645fd996b7d713818aa72c192fe41036d3b40627a82`. Every
line this file cites in the vendored copy after `:1154` (FIX 1910, PAGE-FULL
trace, ITS#10551) is now 4 lines further down. To find an upstream line after
1154 in this copy, add 4 to the offset the sections above give (4 up to
upstream line 6487, 24 after it, and so on).
`crates/oneiron-store/tests/lmdb_sealed_overflow.rs` is the regression test:
values of each length near the end of a one- and a two-page run, put new and
overwritten in their transaction, read back from a sealed environment.

**Re-vendoring:** re-apply these three hunks with the hunks above, or take an
upstream mdb.master3 that contains commit `e27f3d616b7b`.

## Upstream LMDB hardening: ITS#10454, ITS#9291, ITS#10520

FIX row LMDB-MASTER3-UPSTREAM-FIXES-AUDIT. The audit read every mdb.master3
commit after this copy's base (`10161b20fef8`) up to `ba47717cc877`
(20 Oct 2026) and took the ones that fix a fault on a path oneiron uses.
This copy carries each one verbatim, in upstream order, plus fork hunks
(`ONEIRON FORK (LMDB audit)`) that close faults the review of these hunks
found (upstream's head `ba47717cc877` still has every one):

- `bd9cd548b02e77fea8e9ba5d03993b1a688ef223` (15 Apr 2026, ITS#10454, "can't
  rely on O_DSYNC on MacOS") and its follow-up
  `4e8a093a861dbfd4adadd14fb66af9d233bf297e` (27 Apr 2026, "fix prev commit
  for Mac OSX + WRITEMAP"). macOS does not honour `O_DSYNC` on the metapage
  descriptor, so a commit could return before its meta page was stable.
  `mdb_env_write_meta` (`:4811`) now syncs the meta write explicitly
  (`MDB_FDATASYNC`, which is `F_FULLFSYNC` there), under `__APPLE__` only. The
  follow-up corrects the WRITEMAP branch, which oneiron never takes (sealed
  environments refuse WRITE_MAP), and is carried so the copy matches upstream.
  - Fork (`:4929-4946`): upstream returns a failed sync as a plain error,
    with the new meta still in the page cache, so the failed commit could
    show on a later read or reopen. The fork handles it as the failed meta
    `pwrite` above it: it writes the old meta back (retrying an interrupted
    write) and marks the env `MDB_FATAL_ERROR`. If the old meta cannot be
    written back whole, the commit is indeterminate (a reopen in the same
    boot may see it), and the call answers `MDB_PANIC` instead of the sync's
    error.
- `340f04593e3a05db615b3444fac9f3572ed75e3f` (ITS#9291, "quick sanity check on
  env open"). `mdb_env_open2` (`:5524-5556`) refuses a data file whose FREE or
  MAIN root lies past its end (`MDB_PAGE_NOTFOUND`) or whose FREE and MAIN
  page counts exceed it (`MDB_CORRUPTED`). Before it, a file truncated to its
  meta pages opened, and the first read of a missing page faulted the process.
  It is upstream's quick check, not a walk of every page: a file cut below a
  named database's page only, with both roots and the counts inside it, still
  opens (FIX row LMDB-TRUNCATED-NAMED-DB-PAGE-SIGBUS; the page bound below
  makes the first read of the missing page answer `MDB_CORRUPTED`).
  - Fork (`:5528-5532`): the check divides by the meta's page size, which
    nothing had checked yet, so a meta page holding 0 faulted the process
    (SIGFPE). The fork refuses a page size that `mdb_env_set_pagesize` would
    refuse (under 256 or over `MAX_PAGESIZE`) with `MDB_INVALID`.
  - Fork (`:5540-5544`): upstream compares a root with `>` against the count
    of whole pages, so a root that starts exactly at the end of the file
    passed. The fork compares with `>=`.
- `c9912dbeaf10afa8a36c07a28d8daf270e7a6566` (10 Jun 2026, ITS#10520, "cleanup
  on crypto errors and exits"). A sealed environment decrypts each page chunk
  into a heap buffer (`menc`) that its page cache keeps until the environment
  closes. `mdb_env_close_active` (`:6421-6424`) now frees each cached chunk's
  buffer, and `mdb_rpage_get` frees the buffer of a chunk whose page fails to
  open. Before it, every close leaked one buffer per chunk read (64 KiB on
  4 KiB pages), and every open under a wrong page key leaked one.
  - Fork (`:7126`, `:7197`): that failed chunk's mapping was leaked too,
    since neither page cache holds it. The fork unmaps it next to
    upstream's `free`.

`mdb_enckey_clear` and its two calls (FIX 1910) are in other functions and
unchanged. The page format does not change, and no stored row changes meaning
(stored change: keep). `mdb.c` is now 12,415 lines, SHA-256
`70c41d4acef742617239b29cd6f45b073e0334ce52cd6d6a4655d8ab2629d7f2`. Line
numbers in this section cite this copy. The FIX 1910 hunks are now at `:6553`
(`mdb_enckey_clear`), `:6590` (`mdb_env_close`) and `:11705`
(`mdb_env_set_encrypt`); every vendored line after `:4862` that an older
section cites has moved by up to 66 lines. Regression tests:
`crates/oneiron-store/tests/lmdb_open_damaged_file.rs` (ITS#9291 and its
fork hunks: a data file truncated to its meta pages, one cut so that its FREE
root starts at the end, and one whose meta pages hold a zero page size each
refuse to open) and
`crates/oneiron-store/tests/lmdb_sealed_page_buffers.rs` (ITS#10520 and its
fork hunk: the C heap stays flat over sealed read-and-close cycles, and the
heap and the process's mappings stay flat over opens under a wrong page key;
Linux with glibc). ITS#10454 and its fork hunk have no deterministic test:
both are macOS durability paths that only a power loss or a failing disk
shows.

The audit left the rest, with its reasons in the FIX row: Windows- and
BSD-only commits, the copy, compact-copy and incremental dump paths (oneiron
never copies an environment, and heed refuses to copy a sealed one), checksums
(oneiron sets none), PREVSNAPSHOT rollback, `MDB_MULTIPLE`, `mdb_drop` of
MAIN_DBI, new error codes, the DUPSORT page-counter fixes (ITS#9388, #10642,
#10643: no oneiron code reads a DUPSORT database's page counters), sub-page
growth (ITS#7772: space use only, no fault), and ITS#10518 (`741c1e8c899d`,
child-txn mutex init: no observable effect on glibc, macOS or Android, and on
Windows its nested commit path frees the txn without destroying the new
mutex, so it would leak one handle per nested commit).

**Re-vendoring:** re-apply these commits and the five `ONEIRON FORK (LMDB
audit)` hunks with the hunks above, or take an upstream mdb.master3 that
contains commit `c9912dbeaf10` and re-check each fork hunk against it.

## Page bound: a read past the end of a cut data file

FIX row LMDB-TRUNCATED-NAMED-DB-PAGE-SIGBUS (found by the review of the
ITS#9291 hunk above). A data file cut below a named database's page or below
an overflow run, with the FREE and MAIN roots and their counts inside it,
passes ITS#9291's check and opens. The first read of a page the cut removed
then touched the map past the end of the file, and the process died with
SIGBUS: plain and sealed environments alike, since `mdb_rpage_get` maps a
sealed environment's chunks from the same file. Upstream's head `ba47717cc877`
has no such check. The fork (`ONEIRON FORK (page bound)`) adds one:

- `mdb_page_get` (`:7441-7453`), at `mapped:`, so for the plain map, for
  `mdb_rpage_get`, and for a parent's spilled page: unless the environment
  uses `MDB_WRITEMAP` (oneiron never does; sealed environments refuse it), it
  asks `mdb_page_in_file` (`:7352-7381`) whether
  `[pgno, pgno + numpgs)` lies inside the data file. A page past the end
  answers `MDB_CORRUPTED` and marks the transaction failed (`MDB_TXN_ERROR`),
  as the `mt_next_pgno` check above it does. The range test subtracts
  (`pgno <= pages - numpgs`), so a corrupt overflow count cannot wrap past
  it, and a count of 0 checks the page itself.
- It checks each page lookup. A pointer that an earlier lookup returned is
  not checked again; the file does not shrink, so it stays inside it. The
  meta pages are read with `pread` at open, which refuses a short file.
- `MDB_env.me_file_pages` (`:1673-1676`) caches the file's whole pages. The
  open sets it from ITS#9291's length read (`:5541`); a miss reads the length
  again (`mdb_fsize`) before it refuses. Without `MDB_WRITEMAP` the data file
  never shrinks while it is open, and every cached value comes from a real
  length read, so the cache can lag the file (one more `fstat`) but never
  exceed it. Only something outside LMDB's rules can shrink an open file (a
  `MDB_WRITEMAP` handle on the same file, which LMDB forbids, or an outside
  truncate); the cache then runs high and the read goes ahead as it did
  before the fork. A failed length read or a zero length (a raw partition)
  reads the page as before.
- It refuses no whole file: pages a write transaction spills or flushes are
  written before they are read back through the map, and the free pages past
  the end that upstream's `mm_last_pg` comment allows ("the file may be
  shorter if the freeDB lists the final pages") are never read through the
  map, since a reused free page is a fresh heap copy until it is written.
- Cost: one comparison per page read, and one `fstat` after the file grew.

The page format does not change, and no stored row changes meaning (stored
change: keep): a file that read before reads the same, and a cut file that
faulted now answers an error. C runs on sel (lane log
`lanes/kimi/OPUS-TESTKIT/check/truncproto/t3/t3-runs.log`): without the fork
both cuts fault (SIGBUS), plain and sealed; with it both answer
`MDB_CORRUPTED`; a reader opened on a small file that another process grew
by 40 MB, and a write transaction plus a nested child that spill, read every
row back on both. Regression tests: four more in
`crates/oneiron-store/tests/lmdb_open_damaged_file.rs` (a named database's
leaf and an overflow run's last page cut off, plain and sealed).

`mdb.c` is now 12,463 lines, SHA-256
`ad402eff08862df1d77abd3e9ba6bd9d4d54b6efbc97b59c9af43b4e817cd985`. Line
numbers in this section cite this copy. Against the copy the section above
cites, lines after `:1672` moved down by 4, after `:5536` by 5, after `:7346`
by 36 and after `:7405` by 48.

**Re-vendoring:** re-apply the four `ONEIRON FORK (page bound)` hunks, or take
an upstream mdb.master3 that refuses a page past the end of the data file on
every read through the map.

## Re-packaging for the Python sdist (ONE-1441)

The workspace dependency also declares this vendor as a path dependency so
maturin includes the audited fork in the Python sdist. Maturin queries that
path with `cargo package --list --allow-dirty`. The upstream archive's
`.cargo_vcs_info.json` is a Cargo-reserved output name and causes that query
to fail if it is selected as a source input.

The active `Cargo.toml` excludes only the root `.cargo_vcs_info.json` and
`Cargo.toml.orig` from package inputs. Both upstream files remain unchanged
in this checkout as provenance records; Cargo owns their generated names
when creating a new package. The Rust sources, including the ONE-218 seam,
README, and license remain package inputs.

`Cargo.toml.orig` is the upstream pre-publication manifest, not a replacement
for the active normalized manifest. It refers to `../README.md` and sibling
`../heed-traits`, `../heed-types`, and `../lmdb-master-sys` paths that are not
part of this snapshot. Keep the normalized dependency requirements and local
README path in `Cargo.toml`. Neither the workspace path dependency nor the
root patch is replaced with registry heed, and the sdist archive, vendored
source identity, and extracted offline-build assertions remain unchanged.

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
which holds no manifest of its own, so the root manifest lists `crates/heed`
and `crates/heed/vendor/heed-0.20.5` in `exclude`. Consequences, all
intentional:

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
