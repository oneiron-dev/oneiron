# Vendored `loro` 1.16.2 and `loro-internal` 1.16.2 — provenance and delta (FIX 5688 KS7-3)

`crates/loro/vendor/loro-1.16.2` and `crates/loro/vendor/loro-internal-1.16.2`
are local vendors of the published crates at the exact versions `Cargo.lock`
pins, with one added module. The repository root manifest substitutes them for
the registry copies with

```toml
[patch.crates-io]
loro = { path = "crates/loro/vendor/loro-1.16.2" }
loro-internal = { path = "crates/loro/vendor/loro-internal-1.16.2" }
```

and excludes `crates/loro` and both vendor directories from the workspace,
like the heed and paste vendors. Package names, versions, editions, features
and every dependency requirement are unchanged, so no version moves and no
dependency is added. The other loro crates (`loro-common` 1.16.0,
`loro-delta` 1.13.0, `loro_fractional_index` 1.13.0, `loro-kv-store` 1.16.0,
`loro-rle` 1.6.0, `loro-thunderdome` 0.6.2) stay on the registry.

## Why this vendor exists

KS-7 erase must reach mixed sync carriers (window snapshots and updates,
request rows, the queue) in old checkpoints without losing other owners'
history. The Engine ruled design (d): lossless per-owner atomization of
root-map Loro documents, for checkpoint copies only. Live documents, the sync
wire and every reader stay as they are. The pinned public API has no way to
split a document into a payload-free causal skeleton and rebuild a native
document after some payloads are erased: the shallow-root state and the
change store are private. This vendor adds that split and join.

## Upstream pin

| Fact | `loro` | `loro-internal` |
| --- | --- | --- |
| Upstream source root | `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/loro-1.16.2` | `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/loro-internal-1.16.2` |
| crates.io checksum (unpatched lock entry, equals the `.crate` SHA-256) | `8e86dea63b66576db244cbc3a40bdb17517263c93f318e2fbe08aca3be1192cb` | `8d5806b65ee68c3ae7891959dd968898860dab74fbf6498b312de9b548dce5ec` |
| Upstream VCS commit (`.cargo_vcs_info.json`) | `af130d97d8b110add13283fc5bfc81d97a9a609f`, `crates/loro` | `af130d97d8b110add13283fc5bfc81d97a9a609f`, `crates/loro-internal` |
| Upstream SHA-256 of each changed file | `src/lib.rs` `e2373b73e459c6dfcfb8a30ce2880a9dc86f5bf7dcb0bba2e001c26826264a8d` | `src/encoding.rs` `aab26dc4cbe9f5d91512a8659ea609ab2863d0a5f161a6cc582fab352b4816f7`; `src/oplog/change_store.rs` `ddedd8560f5c4125c21b7cafa572532a5cf15cfd04ee167bdf8d7799adf19626` |
| License | MIT (`LICENSE` shipped) | MIT (declared; the package ships no license file) |

## Inventory

**Byte-for-byte from the `.crate` archives** (unpacked, then compared with the
registry source roots): every file of both packages except the ones listed
below, including upstream's packaging `Cargo.lock`, `Cargo.toml.orig`,
`.cargo_vcs_info.json`, examples, tests, benches and upstream's own
`AGENTS.md`/`CLAUDE.md` notes. The first commit of this vendor holds the
unmodified trees.

**Changed from upstream:**

- `loro-internal-1.16.2/src/encoding.rs` — one line declares
  `pub mod checkpoint_parts;`.
- `loro-internal-1.16.2/src/oplog/change_store.rs` — `ChangeStore::encode_from`
  becomes `pub(crate)` so the join can write the original start and latest
  versions of a trimmed history. No body change.
- `loro-1.16.2/src/lib.rs` — a `loro::checkpoint` module re-exporting the new
  types, and the two `LoroDoc` methods below delegating to the internal ones.

**Added by this vendor:**

- `loro-internal-1.16.2/src/encoding/checkpoint_parts/` (`mod.rs`, `types.rs`,
  `capture.rs`, `join.rs`) — the split and join.
- `loro-internal-1.16.2/LICENSE` — the crate declares `license = "MIT"` but the
  published archive has no license file; this is the upstream repository's MIT
  text, copied from the sibling `loro-1.16.2/LICENSE` (same repository and
  commit).
- `crates/loro/PROVENANCE.md` — this file.

**Deliberately not copied:** the registry extraction marker `.cargo-ok`.

## The added API

```rust
impl LoroDoc {
    pub fn export_root_map_checkpoint<C: checkpoint::Classify + ?Sized>(
        &self,
        fixed_roots: &[&str],
        classify: &mut C,
    ) -> checkpoint::Capture;

    pub fn join_root_map_checkpoint(
        skeleton: &checkpoint::Skeleton,
        available: &[checkpoint::Atom],
        erased: &[checkpoint::AtomId],
    ) -> Result<checkpoint::Joined, checkpoint::CheckpointError>;
}
```

Capture reads the document under its own locks, without the implicit-commit
barrier, and never changes it. It returns `Capture::Classified(Parts)` only
when all of these hold, and `Capture::Unclassified(reason)` otherwise (never
an error):

- the document is quiescent: attached, no uncommitted transaction, nothing
  pending, not mid-import, no deleted root containers;
- every container in the retained history, the latest state and the shallow
  root is a root `Map` named in `fixed_roots` (no mergeable or reserved names);
- every op is a map insert or delete, and no value holds a container
  reference at any depth or is a mergeable-child marker, so nested child CRDTs,
  history-only child references and mergeable children are all refused;
- the caller's `Classify::plain_key` proves every key an opaque id or a fixed
  schema name (keys stay plaintext in the skeleton);
- `Classify::holders` names at least one rightful holder for every value and
  every commit message.

`Parts` holds the `Skeleton` (root names, retained changes with ids, deps,
lamports and timestamps, plaintext keys, atom ids for values and messages, the
shallow root's start version and map winners, each key's latest winner, both
version vectors and frontiers, and one slot per atom naming its kind and
holders) and one `Atom` per value or message site. A shallow-root winner whose
op is retained shares that op's atom. A key's latest winner is the greatest
(lamport, peer) among its retained ops and its shallow-root winner, which is
how Loro's history cache resolves it; capture checks the document's latest
state against those winners by value, because Loro keeps an older id in state
when a write leaves the value unchanged. `to_bytes` and `from_bytes` use
postcard, which keeps binary values typed.

Join takes the skeleton, the opened atoms and the ids of the erased ones
(every slot must be exactly one of the two). An erased value becomes a map
delete at its original op id and lamport, so it wins or loses exactly where the
original write did, and an erased message becomes no message. A full-history
document is rebuilt by importing the history through Loro's JSON change path;
a shallow one is assembled as a native shallow snapshot (the retained changes
over the original start version, and the shallow-root maps rebuilt from their
winners) whose latest state Loro replays on import. The result is re-exported
through `ExportMode::Snapshot`, reopened, and proven against the skeleton:
every op keeps its id, lamport, timestamp, deps, message, key and value; every
shallow-root winner keeps its peer, lamport and opened value; the latest state
holds the latest winners' opened values; both version vectors and frontiers
are unchanged. On any mismatch join returns
`CheckpointError::Diverged` and no bytes; otherwise `Joined { bytes, report }`
with `report.equivalent` set. `LoroDoc::from_snapshot` opens the bytes.

No snapshot, update or JSON format changes, and nothing outside
`checkpoint_parts` calls the new code.

## Workspace and ratchet posture

As for heed and paste: the vendors sit under `vendor/` and are excluded from
the workspace, so `cargo fmt`, workspace clippy and `cargo test` do not reach
them, and the ratchet's giant-file scan skips `*/vendor/*`. The Oneiron
workspace `[lints]` do not apply to them.

## Re-vendoring

Unpack the new `.crate` archives over both vendor directories, then re-apply
the three changed files and the added module above, and update this file. The
join relies on the fast-snapshot layout, `ChangeStore::encode_from`, map-state
encoding, and the shallow-root store; any upstream move must re-run the KS7-3
fleet probe before landing.
