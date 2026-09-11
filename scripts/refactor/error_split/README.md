# scripts/refactor/error_split — the `Error` enum split (option B)

Tooling for the ratified split of `crates/oneiron/src/error.rs`: keep the
21-variant cross-cutting bag flat on `Error`, move the other 203 variants into
12 domain enums behind `#[error(transparent)]` `#[from]` wrappers, and leave
`ErrorKind` byte-identical.

Governing pin: `DESIGN-error-enum.md` §3 option B and §4. The design's counts
were taken at `909add1e`; the numbers here are re-measured at the branch base
and differ where main moved (two variants added since).

Nothing here edits `crates/` unless you pass `--apply`.

## The four pieces

| File | What it is |
|---|---|
| `assignment.py` | The one hand-authored input: which variant belongs to which domain, which payload types and `From` impls move with it, and why each judgment call went the way it did. |
| `build_manifest.py` | Parses the live enum, joins it with `assignment.py` and a fresh reference census, writes `manifest.json`. Fails if the table and the enum disagree. |
| `rewrite.py` | Rewrites `Error::Variant` call sites into `Error::Domain(DomainError::Variant …)` across `crates/`. Idempotent. |
| `check_invariance.py` | Proves the split changed shape and nothing else. Exit 0/1. |
| `errparse.py` | Shared Rust-source parsing. Not run directly. |

`manifest.json` is generated, committed, and is the contract the other two read.

## Order of operations

### 0. Refresh the manifest (whenever main has moved)

```
python3 scripts/refactor/error_split/build_manifest.py
```

It prints per-domain counts and the variants with zero references. If it exits
1, a variant was added to or removed from `Error` and `assignment.py` needs the
one-line edit it names. **Do this on the branch base before anything else** —
every later step reads the manifest, and a stale manifest silently skips a
variant.

### 1. Baseline the checker

```
python3 scripts/refactor/error_split/check_invariance.py <base-rev>
```

Against an untouched tree this reports `0 of 12 domains split yet` for check e
and PASS for the rest. That is the "nothing moved yet" baseline; if it does not
pass here, the tooling is wrong, not the split.

`<base-rev>` is the commit the branch was cut from. The checker reads the base
`error.rs` with `git show <rev>:crates/oneiron/src/error.rs`. Add `--skip-size`
to skip check g, which builds a probe crate and needs `cargo`.

### 2. The pilot: `sync`

`sync` is the pilot because it exercises every hard case at once — 11
`#[cfg(feature = "sync")]` gates, a `#[source]` boxed error, `loro::LoroError`,
three constructor helpers, 288 lines of context types, and consumers on both
sides of the crate boundary.

```
python3 scripts/refactor/error_split/rewrite.py --dry-run --domains sync
python3 scripts/refactor/error_split/rewrite.py --apply    --domains sync
```

Then, by hand, in this order:

1. Create `crates/oneiron/src/error/sync.rs`: `pub enum SyncError` holding the
   16 variants **verbatim** — same names, same `#[error("…")]` strings, same
   `#[cfg]` lines, same doc comments — plus `SyncError::kind()` carrying the
   matching arms out of `Error::kind()`.
2. Move the payload types the manifest's `moving_items` lists for `sync`
   (`SyncConfigField`, `SyncSelectorValidation`, `SyncProtocolPruneScope`,
   `SyncProtocolValidation`, `SyncEngineContext`, `SyncRollbackError`) and the
   three constructors (`sync_protocol`, `sync_engine`, `sync_engine_rollback`).
3. In `error/mod.rs` — `error.rs` becomes a directory module, `mod sync;` plus a
   `pub use` seam so every `crate::error::*` path still resolves: delete the 16 variants, add
   `#[error(transparent)] Sync(#[from] SyncError),`, replace their `kind()` arms
   with `Self::Sync(inner) => inner.kind(),`, and delegate `WindowBusy` in
   `is_retryable`. Re-export the moved types from `error` so the existing path
   uses keep resolving.
4. Fix the sites the rewrite listed as unresolvable (see below).
5. `cargo fmt` **the changed files only** — never `cargo fmt --all`, never
   `crates/heed/**` or `vendor/`.
6. `python3 scripts/refactor/error_split/check_invariance.py <base-rev>`, then
   the `WORKFLOW.md` gate.

### 3. The other 11 domains

One scripted run once the pilot is green:

```
python3 scripts/refactor/error_split/rewrite.py --dry-run
python3 scripts/refactor/error_split/rewrite.py --apply
```

Then repeat steps 1–6 per domain. `--domains a,b,c` limits a run to a subset if
the compile-fix is easier in batches.

## What `rewrite.py` does

Code sites take the nested form, which is valid in every position
(construction, `?`-return, `.ok_or`, `map_err`, `matches!`, `if let`, match
arm), so one rule covers all of them:

```
Err(Error::InvalidSkillBody(x))     ->  Err(Error::Artifact(ArtifactError::InvalidSkillBody(x)))
.ok_or(Error::EditProposalStale)    ->  .ok_or(Error::Artifact(ArtifactError::EditProposalStale))
matches!(e, Error::Foo { .. })      ->  matches!(e, Error::Domain(DomainError::Foo { .. }))
oneiron::Error::Foo(_)              ->  oneiron::Error::Domain(oneiron::error::DomainError::Foo(_))
```

Doc comments take the **plain leaf path**, because an intra-doc link resolves a
path and the wrapper is not part of the leaf's path. The gate runs
`RUSTDOCFLAGS="-D warnings" cargo doc`, so a stale link is a build failure, not
a warning:

```
/// [`Error::InvalidSkillBody`]
///   ->  /// [`ArtifactError::InvalidSkillBody`](crate::error::ArtifactError::InvalidSkillBody)

/// [`Error::IncompatibleAnalyzer`]: crate::Error::IncompatibleAnalyzer
///   ->  /// [`StoreError::IncompatibleAnalyzer`]: crate::error::StoreError::IncompatibleAnalyzer
```

The link target is always spelled out in full so it resolves without an import.
A `use` that only a doc link reads is an `unused_imports` warning, and the gate
denies warnings. A label that already carries its own `(target)` has that target
REPLACED, not appended — otherwise the line ends up `[`X`](path)(path)`, which
renders as broken prose and resolves nothing.

**Residue the rustdoc gate will name.** In a file that ALSO has code sites, the
domain enum ends up imported, so the label `[`SyncError::X`]` resolves on its
own and the explicit target becomes `rustdoc::redundant_explicit_links` — an
error under `-D warnings`. Fix is to drop the `(path)` in those files only; the
gate names every one. The pilot hit 2 (both in `sync/manager.rs`), and only on
`pub` items, because rustdoc does not check links on items it does not
document.

**Imports.** Bare `Error::Foo` sites need the domain enum in scope, so the
script inserts `use crate::error::{…};` — into the innermost enclosing `mod`
block, not blindly at the top of the file, because a top-level `use` is not in
scope inside `#[cfg(test)] mod tests { … }`. The statement lands after the last
`use` at that scope's own brace depth; a `use` inside a function body is
skipped, because placing the import after it would make it function-local and
every site in a sibling function would fail to resolve. Pass
`--no-add-imports` to skip this and fix imports by hand.

The one import decision the script cannot make is the `#[cfg]`: a file whose
only use of the enum sits under `#[cfg(feature = "sync")]` needs the import
gated the same way, or the featureless build reports `unused_imports` and the
gate denies warnings. The sync pilot needed that on four files. Let the
compiler name them.

**Idempotent.** `ArtifactError::Foo` has no word boundary before `Error::`, so a
second run matches nothing. Re-running after a partial compile-fix is safe.

**Never guessed, always listed.** Three site classes are reported and left
untouched:

* a tuple or struct variant used as a bare function value
  (`map_err(Error::Foo)`), which needs a closure;
* an occurrence inside a string literal;
* an occurrence inside a `macro_rules!` body, where a rewrite can be wrong
  under token pasting.

At the time of writing there are three, all in `oneiron`, listed by the dry run.

## What `check_invariance.py` proves

| | Check |
|---|---|
| a | The multiset of leaf variant names across root + domain enums equals the manifest, minus anything marked `delete`. Catches a dropped, renamed or duplicated variant. |
| b | Every `#[error("…")]` block is byte-identical to the base revision's for the same variant name. This is what keeps the 71 literal-message tests and the 246 `to_string()` lines true. |
| c | `pub enum ErrorKind` and its doc block are textually unchanged. `ErrorKind` Debug names are persisted on disk as quarantine reason codes and are the server's mapping key; they are frozen under every option. |
| d | Every leaf is mapped by a `kind()` — root's or its domain's — with no wildcard arm anywhere in the chain. |
| e | No `Error::<moved variant>` survives under `crates/`, and no bag variant was moved into a domain enum. Only enforced for domains whose file exists. |
| f | `scripts/ratchet/root-surface-check.sh` passes. |
| g | `size_of::<Error>()` stays at or under 128 bytes (clippy `result_large_err`'s default). Measured by building a throwaway probe crate outside the repo; it copies `rust-toolchain.toml` so it builds on the pinned channel. |

Checks a–e are per-domain aware, so the same command is meaningful against an
untouched tree, after the pilot, and after the full run.

## The two possibly-dead variants

`AnalyzerAssetMissing` and `OffRecordPromoteUnauthenticated` have zero
references anywhere in the repo outside `error.rs`. Both are kept, marked
`dead: true` in the manifest with the full evidence under `dead_verdict`.

The reason is not sentiment. Deleting either one edits `ErrorKind`, and "`ErrorKind`
byte-identical" is the single invariant that makes this refactor mechanically
verifiable (check c). Folding a semantic deletion into a mechanical move trades
that away for nothing: a never-constructed variant costs zero call sites and
moves with its domain like any other. Both are also forward declarations of
unbuilt fail-closed doors — `promote_turn` takes no actor argument today, so the
authentication `OffRecordPromoteUnauthenticated` describes cannot happen yet, and
no dict-asset preflight exists for `AnalyzerAssetMissing`. Deleting them drops
the only record of that intent.

Deletion is safe whenever someone wants it, and is a separate one-line PR:
neither `ErrorKind` name appears in `remote_rejection_reason`'s allowlist in
`sync/quarantine/keys_classifier.rs`, so neither can ever have been persisted as
a quarantine reason code, and `reason_code_for` only ever sees a constructed
error.

`VaultRead` also has zero direct references but is **not** dead — `thiserror`
generates its `From<VaultReadError>`, and `?` on a `VaultReadError` is the only
caller. The manifest records that under `reachable_via`.

## Things worth knowing before you start

* **Domain enums are exported at `oneiron::error::`, not at the crate root.**
  The root-surface pin stays at 702 names. Re-exporting the 12 at the root would
  move it to 714 and needs a reviewed `--regen`.
* **`From<CompactionPacketError> for Error` must stay at the root.** The `#[from]`
  on the wrapper only gives `From<MaintenanceError>`; the existing one-hop
  conversion is load-bearing and has to keep working by delegating.
* **Two `From` impls live outside `error.rs`** — `commitment_schedule.rs` and
  `connector_key/charter.rs`. The first targets bag variants and is untouched;
  the second targets `ConnectorCharterCompile` and the rewrite fixes its body in
  place.
* **`error.rs` is touched by roughly 6% of commits.** Land this in a quiet
  window, as few PRs as possible, and rebase open branches once. Every open
  branch that adds a variant will conflict on the enum.
* **After the first domain lands, the root enum lives in `error/mod.rs`.** All
  three scripts read either spelling, and both `rewrite.py` and the census in
  `build_manifest.py` skip the whole `crates/oneiron/src/error/` directory —
  rewriting inside it would nest the enum in itself. Rebuild the manifest after
  each domain so `file` and `src_line` stay true; the census counts
  `<Domain>Error::X` as well as `Error::X`, so a rebuild on a half-split tree
  does not report every moved variant as dead.
* **`cargo nextest run -p oneiron --features sync` does not build on this tree,
  and did not before the split.** `sync::selector::tests` calls
  `put_selector_test_federation_grant`, which is `#[cfg(feature =
  "test-hooks")]`. Use `--features sync,test-hooks` for the sync-profile lane.
* **`RUSTDOCFLAGS="-D warnings" cargo doc -p oneiron --all-features --no-deps`
  fails at the branch base** with 236 pre-existing unresolved intra-doc links in
  files this refactor does not touch. Judge the gate on the delta: the split
  must add none.
