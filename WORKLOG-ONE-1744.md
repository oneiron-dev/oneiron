# WORKLOG — ONE-1744 (MS-02) redirect projection + read-time canonicalization

Lane: MS · gh-stack MS-A layer 1 of 3 · branch `ONE-1744` off `w5/ms/main`
(carries merge SHA `3e04f02` = ONE-1747 MS-05).
Worktree: `/Volumes/Cinema/w5-lt/ms`
Blueprint: `/Users/olety/.claude-wave5/blueprints/MS/ONE-1744.md`
Claims: `/Users/olety/.claude-wave5/blueprints/MS/CLAIMS.md`
Prior lane worklog (adjacent-surface lessons): `WORKLOG-ONE-1747.md`

## seg0 — read + recon

### Lessons carried from the 1747 worklog
- Oracle is an INTEGRATION test: every symbol it binds must be re-exported in
  `lib.rs`, not merely `pub` in-module (1747 lost a cycle to this).
- Arming discipline: un-ignore + seam→real, never weaken. Ignore census
  (main vs branch) at the end proves only the 1744 entries moved.
- Seed-band law: fixture seeds must avoid `PINNED_ID_BYTES`
  (`0x00,0x11,0x42,0x47,0xA1..=0xA6,0xD7,0xE1,0xFF`).
- `Cargo.lock` never committed; no `git add -A`; workers never push.

### Ground truth (branch HEAD)

`crates/oneiron/src/identity_topology.rs` (3434 lines):
- `EmptyHeads` guard: `evaluate_transition` :716-718 (the lift site).
  Forward-reference doc sites: module header :34-36 (well, :33-38 in this
  tree), `SplitOp.heads` :372-376, rejection variant :551-555.
- Shell edges written at the apply door :2542 (`MergedInto`) / :2553
  (`SplitInto`); commit chokepoint `write_identity_event_in_txn` :3375.
- Sync twin `reconcile_identity_topology_edges_in_txn` :3355 → free fn
  `reconcile_identity_topology_edges_for_store_in_txn` :2140 → the actual
  edge mutator `reconcile_shell_edges_for_sources_in_txn` :2219.
- Lifecycle state is derived FROM EDGES (`entity_lifecycle_state_in_txn`
  :2426 counts `MergedInto`/`SplitInto` peers) — so a zero-head split leaves
  NO edge and reads back `Active`. This is exactly the blueprint's
  "rebuild input = edges + type-76 ledger" witness.
- Fold `fold_identity_topology_log` :854 · `IdentityTopologyFold` :833 with
  `states` / `current_event` / `resolved_proposals` / `rejections`.
- Free (store-level) twins exist for every vault method the reconciler needs
  (`fold_effective_identity_topology_events_for_store_in_txn` :2024,
  `identity_topology_events_for_store_in_txn` :1952,
  `desired_shell_edges_for_store_entity_in_txn` :2060).

`crates/oneiron/src/store.rs`: `vault_meta` is `OverlayDb` with
`get/put/delete/prefix_iter`. Prefix consts live in the :254-340 block.
`identity_topology.rs` already keeps its own vault_meta key locally
(`IDENTITY_TOPOLOGY_SEQ_KEY` :89) — precedent for keeping the redirect
prefix in the owning module. Blueprint claims store.rs for the prefix; I put
the const where the family's own precedent puts it (see Design below) and
leave store.rs untouched → strictly SMALLER claim footprint, no seam risk.

`crates/oneiron/tests/merge_split_oracle.rs` (942 lines): 5 `ms02_*` tests
:458-535, 5 seam stubs :187-216 (`resolve_entity`, `split_into_zero_heads`,
`drop_redirect_projection`, `rebuild_redirect_projection_from_edges`,
`write_note_claim_about`).

`crates/oneiron/src/deletion.rs` :46 `HISTORICAL_CARRIER_CLASSES` — the
ARCH-0038 list MS-07/ONE-1749 will append `REDIRECT_CARRIER_CLASS` to.
Not touched here (1749 is the lane's only deletion.rs claimant).

### Base moved mid-segment (orchestrator relay, no action needed)
PR #565's merge had gone to the sandbagged stack base `w5/ms/main`; it was
replayed as PR #569 onto `main` and branch `ONE-1744` rebased. New HEAD
`571f6e8` on top of `main@e0352a0` (which also carries the byte-77
SECRET_CUSTODY wave, ONE-1919 #566). Verified after the move: all 1747
content present in ancestry, my in-flight edits and untracked files intact,
`w5/ms/main` retired — `main` is the only base.

### Design ruling: the zero-head lift forces a lifecycle-read fix

`entity_lifecycle_state_in_txn` (:2426) derives state **from edges**. A
zero-head split writes NO `split_into` edge, so the retired entity would
read back `Active` while `fold_identity_topology_log` (which runs
`evaluate_transition`) records it as `Split`. That divergence is not
cosmetic:

> zero-head split E · then merge(E → F). The door reads E's edge-derived
> state = `Active` and APPLIES, writing a `merged_into` edge. The fold
> evaluates the merge against `states[E] = Split` → `NotActive` → REJECTED.
> Ledger and edge truth permanently diverge — the exact wedge this module's
> reconciler exists to prevent.

So the lift requires the lifecycle read to consult the one witness the edges
structurally cannot carry: the type-76 ledger's zero-head split set. This
also satisfies the blueprint done-means "lifecycle state for the retired
entity is a shell/terminal state". Cost is contained by hoisting the fold:
the apply door computes the zero-head set ONCE per op instead of once per
participant.

### Design ruling: hook the chokepoint, not the call sites

Blueprint names two maintenance hooks (`write_identity_event_in_txn` and
`reconcile_identity_topology_edges_in_txn`). But the sync-side reconciler is
a *wrapper*: both it and `reconcile_shell_edges_after_eviction_in_txn`
(ONE-1604-D1 authority dominance) funnel into
`reconcile_shell_edges_for_sources_in_txn` :2219. Hooking the named wrapper
alone leaves the table stale after an authority eviction — the same bug the
blueprint diagnoses for the apply dispatcher, one door over. So the hooks
are the two real chokepoints:
1. `write_identity_event_in_txn` — the local event+edges commit.
2. `reconcile_shell_edges_for_sources_in_txn` — the edge mutator BOTH
   reconcile paths share.

Sub-ruling: that reconciler early-returns when its edge op list is empty.
Redirect maintenance must run **past** that return — a sync-ingested
zero-head split moves no edge at all, so the early return is precisely the
case that would leave its row unwritten.

### Design ruling: the const lives with the family, not in store.rs

Blueprint claims `store.rs` for the vault_meta prefix. The family's own
precedent (`IDENTITY_TOPOLOGY_SEQ_KEY` at identity_topology.rs:99) keeps its
key with the module that owns the keyspace, and `vault_meta` readers already
ignore unknown prefixes. So `REDIRECT_TABLE_META_PREFIX` lives in
`identity_redirect.rs` and **store.rs is not touched at all** — a strictly
SMALLER claim footprint than the blueprint reserved, and one less shared-file
seam against the 1745/1748 belt tickets.

### Sabotage-verified, not just green

Each guard was checked by breaking it and watching the intended test fail:
1. **Zero-head rebuild.** Made `derive_redirect_row_in_txn` ignore the ledger
   (edges-only) → `ms02_redirect_table_rebuilds_identically_from_edges_alone`
   and `ms02_redirect_zero_heads_resolves_to_empty_set` both FAILED. The
   blueprint-mandated fixture strengthening is what catches this; without the
   zero-head op in the sequence the test cannot see the bug.
2. **Cycle guard.** Removing it FIRST RUN → **stack overflow / SIGABRT**, not
   a typed error. The depth bound was written as `path.len() >= MAX`, which
   does not grow on a cycle — so it was no backstop at all. **Fixed:** depth
   is now an explicit recursion counter threaded through the walk, genuinely
   independent of the path set. Re-ran the same sabotage → typed
   `CorruptedIndex`. Added
   `depth_guard_bounds_an_acyclic_chain_independently_of_the_cycle_guard`
   (acyclic over-long chain) so the depth guard is pinned on its own, and
   documented why the two guards are not derivable from each other.

### Oracle arming (`tests/merge_split_oracle.rs`)

- 5 × `#[ignore = "armed by ONE-1744"]` removed; **all five green**.
- 5 seam stubs → real APIs (`resolve_entity`, `split_into_zero_heads`,
  `drop_redirect_projection`, `rebuild_redirect_projection_from_edges`,
  `write_note_claim_about`).
- `ms02_redirect_table_rebuilds_identically_from_edges_alone`: doc re-scoped
  per the blueprint ("edges ALONE / edges are the sole truth" → "engine-
  authored truth alone — edges for the edge-ful ops, the type-76 ledger for
  the zero-head arm"), and the op sequence **strengthened** with a zero-head
  split plus two added asserts. Every pre-existing assert kept verbatim.
- **Fixture adaptation (arming, not weakening):** `write_note_claim_about`
  writes under `profile.` — the one prefix the DEFAULT policy manifest rates
  `criticality: normal`. Every unmatched predicate defaults to `critical`,
  which the Gate QUEUES (`gate.pending.criticality_floor`) rather than
  commits, so the first attempt (`core.conflict.open`) failed with
  `GateWriteRejected`. These contracts assert the SUBJECT is never rewritten;
  the predicate is incidental to them and the claim must actually commit for
  the assert to mean anything.
- Ignore census main vs branch: exactly the five 1744 entries removed;
  1745/1746/1748/1749 all unchanged. No assert weakened, widened, or deleted.

### MS-01 test updates (contract inversion, not deletion)

Two `identity_topology/tests.rs` sites asserted the PRE-lift contract
(`EmptyHeads`). Both are inverted to assert the new one — the transition-table
cell and the apply-door cell stay covered, now proving the zero-head split
APPLIES and shells its entity. The `EmptyHeads` variant itself is DELETED
(no-legacy law: nothing can produce it; pre-release means no wire to keep).

### Gate receipts (commit 4e34a48)
- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` —
  clean for every file this lane touches. **4 errors remain in
  `crates/oneiron/src/secret_custody/tests.rs` (lines 156/256/397/436):
  BASE-RED, charged to NO lane.** Verified byte-identical on my base
  (`e0352a0`) AND on current `origin/main` (`f478ea9`); this lane never opens
  that file (`git diff HEAD -- crates/oneiron/src/secret_custody/` is empty).
  Recipe defect on main, flagged for the orchestrator.
- `cargo test -p oneiron --all-features --lib identity_redirect` —
  **16 passed / 0 failed**.
- `cargo test -p oneiron --all-features --test merge_split_oracle` —
  **8 passed / 0 failed / 15 ignored** (5 ms02 newly armed + 3 ms05 from
  1747; the 15 ignored are 1745/1746/1748/1749 stubs, untouched).

### Status
- [x] blueprint + CLAIMS read end to end
- [x] 1747 worklog read
- [x] recon
- [x] rebase absorbed (571f6e8 / main e0352a0)
- [x] impl (projection, resolve, CID-7 doors, both maintenance chokepoints,
      zero-head lift + lifecycle-read fix)
- [x] oracle armed (5 ms02 green)
- [x] unit tests (16) + sabotage verification
- [x] cheap gate green (fmt · clippy · lib + oracle)
- [ ] NOT PUSHED — workers never push; orchestrator owns the stack.

### Packet check
`identity_redirect.rs` (new) + `identity_redirect/tests.rs` (new) ·
`identity_topology.rs` (+tests) · `lib.rs` · `tests/merge_split_oracle.rs`.
All within the ticket's claim slice; **`store.rs` NOT touched** (smaller than
claimed). `Cargo.lock` NOT committed. No `git add -A` — every path staged
explicitly.

### Note for the orchestrator (base drift)
`origin/main` has moved to `f478ea9` (5 redo lanes: #570 CB-A, #571 CA,
#573 CAL, #574 VOX, #575 GOV). My base `571f6e8` predates them. Of my claim
slice only `lib.rs` and `tests/merge_split_oracle.rs` changed on main, both
additively (GOV-1606 armed `count_standing_grants` + `ms06_streak_...` in
the oracle — a DIFFERENT test region from mine, per the GOV-R2 mirror
carve-out in CLAIMS.md). A rebase onto `f478ea9` should be textually clean;
it is the orchestrator's call, so I did not perform it.
