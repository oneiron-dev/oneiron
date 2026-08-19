# WORKLOG — ONE-1871 [L1-ENTITY flat] F5 concurrent ChildOf convergence

Lane: `ONE-1871`, flat off `origin/main` `4f5360daa` (post-E1: `validate_child_of_batch`
carries the final-state existence + role matrix + cycle checks; ONE-1375 streak tail
consumes the winning projection; ONE-1731 post-fence tree).

Seat: Opus impl (VERIFY-FIRST, `opus-watch` binding).
PACKET: `crates/oneiron/src/batch.rs` · `crates/oneiron/src/sync/quarantine.rs` ·
`crates/oneiron/tests/sync_quarantine.rs` · `crates/oneiron/tests/sync_convergence_props.rs`.
`crates/oneiron/src/sync/bridge.rs` read-only (L1-SPINE owned) — untouched.

---

## 1. Step 1 (VERIFY-FIRST): pre-fix divergence evidence

A throwaway probe (`one_1871_prefix_divergence_probe`, deleted after the evidence was
captured — the shipped regressions replace it) ran the blueprint's two-replica shape on
UNMODIFIED `main`:

* four non-TASK entities (`child`, `root`, `a_parent`, `b_parent`) authored on node-a and
  exchanged, plus `child --ChildOf--> root` at `T0+10`;
* both replicas go offline and reparent the SAME single-parent slot:
  node-a deletes `child→root` and adds `child→a_parent` at `created_at = T0+100`;
  node-b deletes `child→root` and adds `child→b_parent` at `created_at = T0+200`;
* one bidirectional `exchange` (2 rounds, inside the ARCH-0023b cap).

Observed on `4f5360daa` + probe only:

```
CRDT edges equal: true
CRDT edge keys: ["<child>:06:<a_parent>", "<child>:06:<b_parent>"]
child      = 019fdb3ecf207780857f7c3f3bbd4df2
root       = 019fdb3ecf207780857f7c41c6595c9c
a_parent   = 019fdb3ecf207780857f7c5be77e7dde
b_parent   = 019fdb3ecf207780857f7c6d98fd11ce
node-a LMDB parents: ["019fdb3ecf207780857f7c5be77e7dde"]   <- a_parent
node-b LMDB parents: ["019fdb3ecf207780857f7c6d98fd11ce"]   <- b_parent
quarantine rows a=1 b=1
```

**F5 CONFIRMED, and confirmed as a REAL divergence, not a by-design quarantine.**

* The CRDT `edges` map is byte-identical on both replicas (both candidate `ChildOf` keys
  survive, `EdgeKind::ChildOf = 6`) — the CRDT layer converged.
* The deterministic LMDB projection did NOT: each replica keeps the parent IT authored
  locally, i.e. opposite winners for the same slot from the same converged input.
* Each replica wrote exactly one `x:` quarantine row, reason `ChildOfCardinality`, for a
  VALID replicated reparent. The mechanism is exactly the one recorded in
  `oneiron-wave2/AUDIT-FINDINGS-2026-07-22.md` F5: `sync/bridge.rs::apply_materialized_edge_ops`
  sorts and component-groups incoming ops deterministically, but the already-STORED parent
  is not part of that ordering — it wins by being on disk first; the incoming valid edge
  then reaches `batch.rs::validate_child_of_batch`, sees `parents.len() == 2`, and is
  rejected `ChildOfCardinality` → quarantine-and-continue (ONE-1124).
* The result is *order-dependent by local history*, not by delivery order — which is why
  the sort in `apply_materialized_edge_ops` cannot fix it and why the repair belongs at
  the batch-validation entry, where stored state and incoming candidates are both visible.

Park was therefore NOT taken: divergence reproduces on current `main`, and the same-slot
quarantine is a defect of the projection, not an intentional design outcome.

## 2. Discriminator verdict: VARIANT holds (not call-path)

The blueprint required verifying, at implement time, whether the public
`PublicEdgeWithCreatedAt` surface lowers into the replicated `BatchOp::EdgeWithCreatedAt`
variant on the same code path. **It does not — the variant discriminator is sound.**
Grounding (all of `crates/oneiron`):

* `BatchOp::PublicEdgeWithCreatedAt` and `BatchOp::EdgeWithCreatedAt` are two SEPARATE
  enum variants (`batch.rs:240` / `batch.rs:248`).
* Every public timestamped builder pushes `PublicEdgeWithCreatedAt`:
  `BatchBuilder::edge_with_created_at` / `edge_with_created_at_and_vad` (`batch.rs:653`,
  `:675`) and the `TxnBatchBuilder` twins (`batch.rs:1291`, `:1313`). `BatchOp::Edge` is
  the untimestamped public arm.
* The ONLY producers of `BatchOp::EdgeWithCreatedAt` are crate-internal:
  `BatchBuilder::edge_with_value_fields` / `TxnBatchBuilder::edge_with_value_fields`
  (`batch.rs:691`, `:1331`; consumers = `sync/window.rs:1687` forward-remat healing,
  `ppr/tests.rs`, `batch/tests.rs`), `sync/bridge.rs:969` (Observer B), and the
  fixed-kind identity/claim/affect/repo effect stampers
  (`identity_topology.rs` FacetOf/MergedInto/SplitInto/HasFacet + reserved topology kinds,
  `affect.rs`/`claim.rs`/`repo_mutation.rs` `Supersedes`). None of the fixed-kind stampers
  can emit `EdgeKind::ChildOf`; the two `edge_with_value_fields` consumers that CAN carry
  ChildOf are both sync replay/heal paths, which is precisely the intended scope.
* The one place that REWRITES an op into a timestamped form —
  `session_overlay.rs::promotion_replay_op` (`:559`) — lowers `BatchOp::Edge` into
  `PublicEdgeWithCreatedAt` (`:585`) and explicitly REJECTS a journaled
  `EdgeWithCreatedAt` with `InvariantViolation` (`:600`). There is no public→replicated
  lowering anywhere.

So no new sync-origin flag and no public mode were introduced: normalization keys on the
`BatchOp::EdgeWithCreatedAt` variant alone.

## 3. Citation correction — ARCH-0016 **I6**, not I7

Verified against the canon
(`/Users/olety/Desktop/code/oneiron-docs/generated/oneiron/backend/oneiron-arch-0016-productivity-plugin-v1.md`,
"Nine invariants the tree must hold"):

* **I6** — "Concurrent reparent (CRDT) = LWW. Acceptable in Phase 2 (single user). Phase 8
  may need tree CRDT." ← the correct anchor for this ticket.
* **I7** — "Derived state repair — on write / materialization / startup: verify ChildOf,
  BelongsTo, listId consistent with parentId. Rebuild if not." ← what the ticket cited.

The ticket's I7 citation is **off by one**. Recorded in the production doc comment on
`resolve_replicated_child_of_slots`, in the recut quarantine test, and in the test-suite
section header. (Adjacent, deliberately NOT implemented: **I9** post-merge cycle repair
"break at node with later learned_at" — the blueprint pins cycle handling as unchanged
`CycleDetected` quarantine, no auto-break. Noted so the next reader does not mistake the
omission for an oversight.)

## 4. Change shape

Production, `crates/oneiron/src/batch.rs` (+217 lines, one new private function and two
private types; no public surface, no layout change):

* `ChildOfCandidate { parent, learned_at, origin }` + `ChildOfCandidateOrigin::{Stored,
  Replicated { op_index }}` — the blueprint's keystone skeleton, kept verbatim in shape.
  `precedence_key() -> (u64, [u8; 16])` is `(learned_at, *parent.as_bytes())`, maximum wins.
  `learned_at` is the persisted structural `created_at` (ARCH-0034 12 B `weight +
  created_at`) — there is no versioned `parentId` body field and none was added.
* `resolve_replicated_child_of_slots(store, rtxn, ops) -> Result<Vec<BatchOp>>` — groups the
  batch's replicated `ChildOf` adds by child, unions them with the child's stored parents
  read out of `edges_out` (skipping any the same batch already deletes), and if the child
  ends up with more than one DISTINCT candidate parent, rewrites the op vector: keep the
  winner's add, drop every lower-precedence incoming add, and inject `DeleteEdge` for every
  stored loser at the index of the child's first replicated op (so deletes precede the add).
  Fast paths return the vector untouched when no replicated `ChildOf` add exists or no child
  has a real slot race — every non-racing batch in the engine is byte-identical to before.
* Hook point: one line in `apply_ops_with_origin`, immediately before
  `ChildOfBatchOverlay::from_ops(&ops)` / `validate_child_of_batch`. So the overlay sees the
  winner add and the loser deletes together — cardinality is already ONE when the validator
  runs, and the whole swap is one atomic strict batch inside the applying `wtxn`. Nothing
  stages between the delete and the add, so no zero-parent or two-parent state exists.
* Anti-absorption guard beyond the variant discriminator: if the same batch also carries a
  PUBLIC `ChildOf` add (`BatchOp::Edge` / `BatchOp::PublicEdgeWithCreatedAt`) for that child,
  the child is skipped entirely and the strict public path judges the batch unchanged. The
  guarantee is structural, not "no caller does that today".
* Explicitly unchanged: `sync/bridge.rs` (L1-SPINE, read-only), the 12-byte structural
  layout, `EdgeKind::ChildOf = 6`, `MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS`, the quarantine
  record schema, the CRDT map keys, and `Cargo.toml` / `Cargo.lock`.

`crates/oneiron/src/sync/quarantine.rs` (+10 lines, comment only): the `ChildOfCardinality`
arm of `remote_rejection_reason` KEEPS its classification (per the blueprint's "do not remove
`CycleDetected`/`ChildOfCardinality` from the remote rejection classifier"); its comment now
says what actually reaches it — a valid same-slot race is LWW-resolved upstream and produces
no `x:` row, so this arm is the path for a genuinely invalid strict op only.

### Tests

`crates/oneiron/tests/sync_convergence_props.rs`:

| test | proves |
|---|---|
| `concurrent_child_of_reparent_lww_converges` | the two-replica F5 shape converges on the later-stamped link. The winner carries the SMALLER parent-id bytes, so the test separates the clock from the tiebreak. Also asserts both candidates survive in the CRDT map, exactly one `ChildOf` row survives per replica, the loser keeps no reverse edge, and ZERO `x:` rows exist. |
| `concurrent_child_of_reparent_equal_clocks_break_on_parent_id_bytes` | equal `learned_at` → both replicas pick the lexicographically greater PARENT id. |
| `child_of_lww_projection_is_order_independent` | ARCH-0023b `scour:A192` proptest (exact blueprint name). Four candidates with generated clocks, a generated permutation, generated batch grouping, and a forced regime flag; every case runs the permuted/grouped arrangement AND the reversed single-batch arrangement on two fresh vaults through real Observer-B materialization, then asserts the two `edges_out` projections are byte-identical to each other and to the literal ARCH-0034 expectation. Both regimes (stored parent wins / replicated parent wins) run every case, asserted by `prop_assert_eq!(winner == stored, stored_wins)`. |
| `public_child_of_second_parent_is_never_lww_normalized` | HARD LAW. A public `edge_with_created_at` second parent stamped `T0+9_999` (far later than the stored link, so LWW absorption would have made it WIN) still returns `Error::ChildOfCardinality` and leaves the stored parent in place; same for the untimestamped `edge` arm. Passes pre- AND post-fix, by design. |
| `replicated_child_of_winner_still_faces_the_role_matrix` | the post-E1 validator runs on the SELECTED winner: a later-stamped candidate whose parent role forbids the child role is rejected as a unit, stages nothing, leaves the stored parent, and is quarantined. Passes pre- and post-fix. |
| `habit_checkin_reparent_recomputes_only_the_committed_parents` | ONE-1375 seam under a real race: both replicas reparent one `HabitCheckin` offline to different Habits. Winner `(1,1)`, the Habit the check-in actually left `(0,0)`, the LWW LOSER's Habit `(0,0)` (no phantom counter), an untouched Habit `(1,1)`, no `x:` rows, `assert_converged`. |

`crates/oneiron/tests/sync_quarantine.rs`:

| test | proves |
|---|---|
| `child_of_same_slot_race_resolves_lww_without_quarantine` (recut of `child_of_cardinality_violation_quarantines_only_failing_op`) | two same-slot candidates at equal clocks: the greater parent id wins, the loser is omitted (and still present in the CRDT map), the non-ChildOf sibling still lands (ONE-1124 no-abort property intact), and quarantine is EMPTY. |
| `child_of_cycle_still_quarantined` (new, blueprint-named) | a candidate that WINS the slot on a late clock and then forms a cycle is rejected `CycleDetected` with the existing record shape (container `Edges`, `crdt_key_hash` = xxh3_64 of the CRDT key), the cycle edge never commits, the parent it would have displaced survives, and a non-ChildOf sibling in the same batch still lands. |

### Pre-fix / post-fix regression evidence

Against base `batch.rs` at `4f5360daa`, tests unchanged:

```
concurrent_child_of_reparent_lww_converges .................... FAILED
concurrent_child_of_reparent_equal_clocks_break_on_parent_id ... FAILED
child_of_lww_projection_is_order_independent ................... FAILED
habit_checkin_reparent_recomputes_only_the_committed_parents ... FAILED
replicated_child_of_winner_still_faces_the_role_matrix ......... ok   (guard)
public_child_of_second_parent_is_never_lww_normalized .......... ok   (guard)
child_of_cardinality_violation_quarantines_only_failing_op ..... FAILED at
    "deterministic-first ChildOf op must land"  (the assertion this ticket changes)
```

With the fix: all green.

## 5. Deviations, scoping notes, PACKET_AMEND candidates

1. **DEVIATION (cosmetic, hook point).** The blueprint names `apply_ops_with_gate_mode` as
   the normalization site. On current `main` that function is a thin forwarder; the overlay
   is built in `apply_ops_with_origin`. The insertion went where the blueprint's ANCHOR
   points — "immediately before `ChildOfBatchOverlay::from_ops` and `validate_child_of_batch`"
   — i.e. `apply_ops_with_origin`. Same call path, same law, different function name than the
   spec text. No PACKET impact (same file, same L1-ENTITY carve-out in
   `L1-ENTITY/CLAIMS.md:12`).
2. **CONTRACT CHANGE, declared.** `tests/sync_quarantine.rs::child_of_cardinality_violation_quarantines_only_failing_op`
   asserted the pre-1871 behavior (first-sorted candidate lands, second quarantined
   `ChildOfCardinality`) — the exact behavior this ticket exists to remove. It was recut, not
   deleted: the ONE-1124 no-abort/per-op-isolation property it guarded is preserved in the
   recut test and re-anchored on a still-invalid class by the new `child_of_cycle_still_quarantined`.
   The file is inside this lane's PACKET.
3. **SCOPING NOTE — dangling-parent leg.** Done-means asks that the post-E1 dangling-parent
   check also run against the winner. It structurally does: the winner op is left untouched in
   the op vector, and `validate_child_of_batch` runs its pinned ladder (cardinality →
   existence → cycle → role) on the resolved slot; the cycle and role legs are proven by
   named tests. A genuinely dangling parent is NOT reachable from the replicated path to
   assert directly: Observer B hydrates both endpoints from the CRDT before composing the op
   and DEFERS ("endpoint absent or tombstoned") rather than emitting an edge op for a missing
   endpoint, so `ChildOfParentMissing` cannot be produced through this door. Asserting it
   would require reaching `BatchOp` directly, which lives in `src/batch/tests.rs` — outside
   this lane's declared 4-file PACKET. Flagged rather than absorbed.
4. **PACKET_AMEND candidate, NOT taken.** The pre-fix verification run made proptest write
   `crates/oneiron/tests/sync_convergence_props.proptest-regressions` (a seed that failed only
   against pre-fix code). It was deleted: it is not in the declared PACKET, and the shipped
   named regressions already cover that shape deterministically. If the lane wants the seed
   pinned, that is a one-file amendment, not a silent addition.
5. **BASE NOTE (no action taken by this seat).** `origin/main` advanced by one commit
   (`836214ec9` ONE-1412 FED-05, PR #641) while this lane ran; the branch is still cut from
   `4f5360daa`. Rebase is script-owned (stacking law) — flagged for WF-PUB/merge, not done here.
6. No `Cargo.toml` / `Cargo.lock` edits. No `sync/bridge.rs` edits. No push, no merge.

## 6. Gates

* `cargo fmt -p oneiron -- --check` — clean.
* `cargo clippy -p oneiron --all-features --all-targets` — clean (`unwrap_used`,
  `items_after_statements`, `redundant_clone` all fixed during the run).
* `cargo clippy --workspace --all-features --all-targets` — clean.
* `cargo check -p oneiron` (default features) — clean; the normalization is not sync-gated
  and compiles in the non-sync build.
* **Final gate `cargo test -p oneiron --all-features` — GREEN**, 52 test binaries, exit 0.
  Flake note: one earlier full run showed a single red in
  `bm25::tests::bm25_diagnostics_increment_for_targeted_search_corruption` (a process-global
  diagnostics counter shared across parallel tests in the lib binary — nothing in this diff
  touches bm25, text postings, or diagnostics). It passed in isolation and on every
  subsequent full run. Charged to no lane, per the flake guard.

## 7. K3 SIMPLIFY pass (tip of impl leg)

Deletion-biased audit of the impl tip. Verdict: the leg was already deletion-tight —
one private function + two private types, existing helpers reused (`child_of_prefix`,
`parse_strict_edge_record`), no wrapper layers, no duplicated helper surfaces in the
test files, clippy-clean. One deletion made:

* dropped `PartialEq, Eq` from the `ChildOfCandidate` / `ChildOfCandidateOrigin`
  derives — never compared (the loser loop keys on `candidate.parent: EntityId`;
  `max_by_key` needs `Ord` on the KEY, not the item). Speculative generality, gone.
  `Debug/Clone/Copy` stay: `.copied()` consumes `Copy`, `Debug` is house default.

Considered and deliberately KEPT (not cruft):

* the two early returns (`children.is_empty()`; `dropped/injected` empty) — the second
  is the hot no-op path for idempotent re-delivery, not a defensive branch;
* both `ok_or(Error::InvariantViolation)` arms — unreachable by construction, but
  `unwrap` is lint-banned and this is the house idiom for invariant points;
* the long doc comments — they carry blueprint-mandated content (I6/I7 off-by-one
  record, the variant-discriminator verdict, why-the-repair-lives-here). Trimming them
  would delete law, not fat.

Untouched per the simplify law: every test assertion/fixture, the public surface, the
precedence key, strict local cardinality, the atomic single-batch shape.

Gates re-run after the pass: `cargo fmt -p oneiron -- --check` clean ·
`cargo clippy -p oneiron --all-features --all-targets` clean ·
`cargo test -p oneiron --all-features --test sync_convergence_props --test sync_quarantine`
GREEN (27 + 17). The derive deletion is behavior-neutral; the pre-pass full-suite green
(section 6) stands.


## 8. VERDICT-FIX (Opus fix leg on the simplify tip)

Sol finder returned 3 items; K3 verdict adjudicated all three CONFIRMED REAL,
`FIX-REQUIRED`, nothing banked. Every fix below is mutation-verified: the named test was
run RED on the pre-fix tip and GREEN after, with the failure text matching the finder's
predicted trace.

### F1 (P1, `child-of-atomicity`) + F3 (P2, `quarantine-bypass`) — FIXED, one chokepoint

Both are the same root defect the verdict named: **the resolver rewrote the op vector
without ever proving the candidates it was arbitrating could actually apply.**

* F1: the winner's injected stored-loser `DeleteEdge` staged, then the winner itself was
  rejected by `validate_edge_weight` inside `apply_edge_with_created_at`.
  `InvalidEdgeWeight` / `InvalidVad` are quarantine-and-CONTINUE kinds, so the sync path
  keeps the same `RwTxn` and commits the reparent's demolition without its construction —
  a zero-parent slot (which passes `validate_child_of_batch`, so nothing downstream
  catches it either). Directly violates the blueprint's one-atomic-strict-batch law.
* F3: an incoming loser was dropped unconditionally before any gate, so a MALFORMED
  remote op became the one op in the engine that fails no gate because it reaches none.
  The blueprint keeps valid losers silent and invalid remote ops quarantine-eligible;
  pre-fix both were silent.

Fix — `crates/oneiron/src/batch.rs`, in `resolve_replicated_child_of_slots`, after the
`distinct.len() <= 1` no-race exit and BEFORE winner selection / loser omission /
delete injection: every replicated candidate for the raced slot is probed with
`encode_edge_value(...)` — the exact function `apply_edge_with_created_at` runs, so the
gate and the probe cannot drift. A malformed candidate raises its own typed error with
**nothing staged**, which is precisely what the sync caller already assumes of an up-front
gate: the ONE-1124 component retry then re-applies per op and quarantines the one bad op
alone while valid siblings land.

Chokepoint, not call-site: one loop covers winner and losers, and covers `InvalidVad` /
provenance-on-structural as well as `InvalidEdgeWeight`, because it runs the encoder
rather than re-listing its checks. No new error kind, no quarantine-schema change, no
classifier change, no reordering of the injected deletes.

Mutation evidence (`cargo test -p oneiron --all-features --test sync_quarantine`):

| test | pre-fix | post-fix |
|---|---|---|
| `replicated_child_of_winner_failing_a_write_gate_keeps_the_stored_parent` | RED — `left: []` (the committed zero-parent slot, exactly as traced) | GREEN — stored parent survives, 1 `InvalidEdgeWeight` row |
| `malformed_replicated_child_of_loser_is_still_quarantined` | RED — `0` quarantine rows | GREEN — 1 `InvalidEdgeWeight` row, non-`ChildOf` sibling still lands |

Both new tests live in `crates/oneiron/tests/sync_quarantine.rs` (packet-owned), with one
new 12-byte structural-value helper. The F5 contract they bracket is unchanged and still
asserted: a VALID lower-precedence candidate produces no `x:` row
(`child_of_same_slot_race_resolves_lww_without_quarantine`, still green).

### F2 (P1, `child-of-lww-projection`) — REPRODUCED, NOT FIXED HERE: **PACKET_AMEND / seam ruling requested**

Confirmed real and reproduced (see below), and the verdict's own fix-dispatch note holds:
**the repair cannot live in this packet.** The resolver arbitrates over `{ops in this
batch} ∪ {the single row LMDB projects}`. A candidate that lost an earlier round is still
live in the CRDT edge map — F5's contract deliberately keeps it there — but it left no
LMDB trace, so no later batch can see it:

1. `A@100` + `B@90` arrive together → `A` projects, `B` is CRDT-only.
2. A later delta deletes `A` and adds `C@80` (`B` is unchanged, so it is in neither the
   batch nor `edges_out`).
3. Required projection = max over live candidates = `B@90`. Actual = `C@80`.
   Delete-only variant: zero parents, while a valid live candidate exists.

Two replicas whose deltas were cut differently therefore disagree on the projection while
agreeing on the edge map — the F5 class itself, one delivery grouping over.

Recorded as an executable oracle in the repo's `#[ignore = "armed by …"]` convention:
`crates/oneiron/tests/sync_convergence_props.rs::child_of_projection_follows_live_candidates_not_delta_history`.
Verified to reproduce (`--ignored` run fails with `left: [0x63…] right: [0x52…]` — it takes
`C@80` where `B@90` is required); ignored, so the default gate stays green and the arming
lane inherits the proof instead of rebuilding it.

Why not in-packet, explicitly:

* `batch.rs` has no reach to the Loro doc — it sees LMDB and the op vector, by design.
* `sync/bridge.rs` is L1-STORAGE-SPINE-owned and read-only for this lane (blueprint
  "Edges & waits"; PACKET line).
* The alternatives inside `batch.rs` are all worse than the hole: a shadow-candidate LMDB
  table is a new projection schema; keeping losers as rows breaks the single-parent
  cardinality this ticket exists to protect. Both are redesigns the blueprint forbids
  ("no CRDT map key change", "changes only the deterministic LMDB projection").

Proposed seam (for the amendment ruling): when a delta removes or displaces a child's
stored `ChildOf` winner, the bridge re-presents that child's remaining live CRDT
candidates in the same batch, so the resolver arbitrates over the full set it is already
specified to arbitrate over. That is a bridge-side read of the map it already owns, plus
no change at all to `resolve_replicated_child_of_slots` — which is why it wants a SPINE
lane, not a packet violation here.

### Gates (fix leg)

* `cargo fmt -p oneiron -- --check` — clean.
* `cargo clippy -p oneiron --all-features --all-targets` — clean.
* `cargo test -p oneiron --all-features` — GREEN (final gate; see run log below).
* Diff ⊆ packet: `crates/oneiron/src/batch.rs`, `crates/oneiron/tests/sync_quarantine.rs`,
  `crates/oneiron/tests/sync_convergence_props.rs`, this worklog. No `Cargo.toml`/`Cargo.lock`,
  no `sync/bridge.rs`, no push, no merge.
