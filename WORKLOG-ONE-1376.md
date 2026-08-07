# WORKLOG — ONE-1376 [L1-ENTITY E1-L3] STO-04 TASK parent/child tree validation

Branch `ONE-1376`, cut from `origin/main` @ `47ac630` (ONE-1924 #628 + ONE-1375 #631 +
spine 1728/1730/1729 all merged). Blueprint:
`/Users/olety/.claude-wave5/blueprints/L1-ENTITY/ONE-1376.md`.

## What landed

`validate_child_of_batch` in `crates/oneiron/src/batch.rs` was extended IN PLACE — no
parallel validator in `Vault`, no new door. `ChildOfBatchOverlay` gained the batch's final
`BatchOp::Put` outcome, so validation now reads FINAL entity state alongside the final edge
state it already read.

Pinned check order (doc-commented on the fn, load-bearing):

1. final single-parent cardinality → `Error::ChildOfCardinality` (unchanged);
2. no-parent early success — a root of ANY role stays legal;
3. parent existence in final state → `Error::ChildOfParentMissing { parent }` (new);
4. self / ancestor cycle → `Error::CycleDetected` (unchanged, still BEFORE any role rule);
5. TASK role nesting, last (new).

New surfaces:

- `crates/oneiron/src/habit.rs` — `TaskRole::allows_child(child)`, verbatim from the
  keystone skeleton. `Goal -> Milestone`, `Milestone -> Task`, `Habit -> HabitCheckin`;
  every other TASK pair rejected, same-role included.
- `crates/oneiron/src/batch.rs` — `EffectiveEntity { Missing, NonTask(u8), Task(TaskRole) }`,
  `effective_entity_after_batch`, `stored_entity`, `validate_task_nesting`.
- `crates/oneiron/src/error.rs` — `ChildOfParentMissing { parent }`,
  `TaskChildOfParentNotTask { child_role, parent_entity_type }`,
  `TaskChildOfNesting { parent_role, child_role }`. All three coarse-map onto the existing
  `ErrorKind::InvalidTaskBody`, so remote replay stays quarantine-and-continue and no sync
  policy changes in this ticket. No new `ErrorKind` variant was minted.

Deletions: the redundant `validate_task_checkin_child_parent` call inside
`validate_child_of_batch`. The matrix subsumes it and does so on FINAL state (strictly
stronger than the old LMDB-only read). The landed check-in door itself is untouched and
still guards the replay edge path (`apply_edge_with_created_at`) and the TASK put path
(`validate_task_role_put_invariants`), so the Habit rule was generalized, not duplicated.

`stored_task_role` was rewritten as a two-line projection of `stored_entity` rather than
duplicating the header/role decode.

Explicit non-changes (ChildOf-canonical residue, per blueprint): nothing writes or repairs
`parentId`, `listId`, `position`, or `BelongsTo`; `vault.rs::subtree`/`ancestors` untouched;
`crates/oneiron/src/types.rs` NOT created; `Cargo.toml`/`Cargo.lock` untouched (the lock
regenerates in-worktree — never staged, never committed).

## Named tests (exact names, all in `crates/oneiron/src/batch/tests.rs`)

- `cycle_reject` — the closing edge of a `Goal -> Milestone -> Task` chain is BOTH an
  ancestor cycle AND a matrix violation; the assertion is that `Error::CycleDetected` is what
  gets reported, i.e. a role error cannot mask a cycle. Plus the degenerate self-parent case.
  No edge from either rejected batch is visible.
- `dangling_parent_reject` — an absent final-state parent fails with
  `Error::ChildOfParentMissing` carrying the missing id; `err.kind()` is asserted to be
  `ErrorKind::InvalidTaskBody`; no edge is written.
- `valid_tree_accept` — commits `Milestone -> Goal`, `Task -> Milestone`,
  `HabitCheckin -> Habit` in child→parent storage direction, then walks `ancestors`. Also
  proves a root of every role commits.

Supporting tests added alongside:

- `child_of_existence_reads_final_batch_state` — parent put LATER in the same batch is
  accepted; parent deleted by the batch without a re-put is dangling; a delete followed by a
  re-put commits.
- `task_child_of_role_matrix_rejects_every_pair_outside_the_table` — exhaustive 5x5 sweep
  over `TaskRole::ALL` against an INDEPENDENT literal legal-pair table in the test (not
  `allows_child`, so the matrix cannot silently widen). Covers `Task -> Goal`,
  `Milestone -> Milestone`, `HabitCheckin -> Milestone`, and Habit-parents-only-HabitCheckin
  mechanically, and asserts the exact role bytes on each rejection. Ends with the TASK child
  under a non-TASK (PERSON) parent → `TaskChildOfParentNotTask`.
- `non_task_child_of_keeps_tree_guarantees_without_role_rules` — a PERSON tree keeps
  cardinality + cycle rejection, now also rejects a missing parent, and a non-TASK child
  under a TASK parent carries no role rule (the matrix keys off the edge SOURCE).

## Existing tests: recut, none deleted, no assertion weakened

The new parent-existence check and the role matrix both bite fixtures that used
`ENTITY_TYPE_TASK` + `TaskRole::Task` as a generic node, or wrote a ChildOf edge with no
parent row at all. 22 lib tests + 1 integration test went red and were recut:

Rule applied uniformly: **generic ChildOf topology tests hold a NON-TASK pair.** Tree
cardinality, cycles, dangling parents, and the `subtree`/`ancestors` walks are
domain-agnostic; the role matrix engages only when the edge source is a TASK and gets its
own dedicated coverage in `batch/tests.rs`. Deep chains (200-node, 5-level, 4-level) cannot
be expressed in a 3-level role DAG at all, so a per-test mix would have been arbitrary.

- `crates/oneiron/src/tests.rs` — new `put_tree_nodes(batch, &[ids])` helper stages
  `ENTITY_TYPE_PERSON` rows; 14 topology tests now thread it. Every assertion is byte-identical
  to what landed. The two overflow tests
  (`ancestors_and_cycle_checks_overflow_on_depth_cap`,
  `cycle_checks_fail_loud_before_positive_match_beyond_traversal_cap`) additionally stage the
  ONE parent row their batch names, so `IndexOverflow("child_of_cycle_check")` is still what
  the walk reports rather than the new dangling-parent rejection.
  `mixed_path_through_child_of_carries_no_ppr_mass` renamed its `task` seed to `leaf` since
  the node is no longer a TASK.
- `crates/oneiron/src/batch/tests.rs` —
  `public_timestamped_builder_keeps_structural_edge_layout` now uses the matrix-valid
  `Milestone` parent / `Task` child pair (it is about edge value layout, not nesting).
- `checkin_on_non_habit_rejected` and `habit_with_checkins_cannot_change_role` are green
  unchanged. Note: `checkin_on_non_habit_rejected` now fails EARLIER — the batch-level matrix
  catches it before the edge-apply check-in door — but the typed kind it asserts
  (`ErrorKind::InvalidTaskBody`) is identical and the landed door is still in place for the
  replay edge path.
- `generic_child_of_writes_reject_second_parent` still asserts `Error::ChildOfCardinality`.

## PACKET_AMEND candidates (declared, not silently absorbed)

PACKET for this lane was `batch.rs + batch/tests.rs + habit.rs + error.rs + src/tests.rs`.
Three files outside it needed fixture-only edits (no production code in any of them):

1. `crates/oneiron/src/ppr/tests.rs` — `child_of_and_assigned_to_are_never_traversed` wrote
   `child --ChildOf--> parent` with no parent row. Added one `put_entity` of the parent as a
   PERSON. 8 lines. `ppr.rs` is a lane-claimed file (CLAIMS.md line 15); its test sibling is
   arguably inside that claim, flagged anyway.
2. `crates/oneiron/src/sync/bridge/tests.rs` — the three
   `apply_materialized_edge_ops_*child_of*` tests build deliberately CYCLIC TASK shapes that
   the role DAG cannot express in either direction. Added a local `put_tree_nodes` helper
   (PERSON rows) and swapped those three setups to it. `sync/bridge.rs` is explicitly NOT
   claimed by this lane (CLAIMS.md line 63, L1-STORAGE-SPINE). **This is the real amendment
   ask.** Fixture-only, 3 test functions, ~60 lines net negative.
3. `crates/oneiron/tests/sync_quarantine.rs` — `child_of_cardinality_violation_quarantines_only_failing_op`
   needs BOTH candidate ChildOf edges admitted by nesting so that cardinality is what rejects
   the second; the parents are now `Milestone` over a `Task` child, via a new
   `task_body_with_role(role)` alongside the existing `task_body()`. This file IS claimed by
   L1-ENTITY (CLAIMS.md line 55, under ONE-1871 post-E1) — same lane, different ticket.

No collision was found for any of the three: all edits are inside test functions that no
other declared claim names.

## Blueprint deviations (declared)

1. **`effective_entity_after_batch` parameter names.** The keystone skeleton writes
   `txn: &heed::RoTxn<'_>` and `overlay: &ChildOfBatchOverlay`; the landed file uses `rtxn`
   and `child_of_overlay` throughout `validate_child_of_batch` /
   `would_create_child_of_cycle`. Kept the file's names — shape, arity, and order are
   identical to the skeleton. Cosmetic.
2. **`EffectiveEntity::NonTask(u8)` payload is read.** The skeleton carries the byte without
   naming a consumer; leaving it unread would have been a dead field. It is surfaced in
   `Error::TaskChildOfParentNotTask { parent_entity_type }`, which makes the endpoint
   rejection diagnosable ("TASK child under entity type 3") instead of opaque. The blueprint
   only pins "stable role bytes" for the role fields, which is honoured separately.
3. **`TaskRole::allows_child` is `pub(crate)`**, verbatim per the skeleton, even though its
   sibling `TaskRole` methods are `pub`. No external caller exists.
4. **`validate_task_nesting` has an unreachable `EffectiveEntity::Missing => Ok(())` arm.**
   The caller rejects a missing parent one step earlier (order step 3), so the arm cannot
   fire; it is commented as such. The alternative — a second "existing entity" enum — buys
   type-level exhaustiveness at the cost of a whole extra type. Judged not worth it.

## Interpretation note (relay HARD LAW vs one done-means line)

Done-means line: "a parent deleted later in the same batch is treated as dangling."

Taken literally as ops `[put(parent), edge(child→parent), delete(parent)]`, the landed
overlay's `final_edge_override` already clears any ChildOf edge whose endpoint is deleted at
a LATER index — the batch's final EDGE state contains no such edge, so there is nothing
dangling to reject and the batch commits with no edge written. Erroring there would
contradict the relay's HARD LAW that validation reads final edge state.

Implemented per the relay's operative phrasing instead: "absent from LMDB+puts or
**deleted-without-reput** is dangling", i.e. ops `[delete(parent), edge(child→parent)]` —
the ordering where the edge SURVIVES into final state with no parent behind it. That is what
`child_of_existence_reads_final_batch_state` pins, together with the delete-then-reput case.
Flagging for the screener in case the intended reading was the other one.

## Observations / residue (not fixed here)

- **Sync replay reach.** `EdgeWithCreatedAt` ops go through the same
  `validate_child_of_batch`, so a remote ChildOf edge arriving with no parent row is now
  rejected → quarantined-and-continued (`ErrorKind::InvalidTaskBody`). In practice Observer-B
  already hydrates edge endpoints from current CRDT state before applying, so the new check
  is a backstop rather than a common path; the whole `sync_quarantine` /
  `sync_convergence_props` / `sync_edge_kind_gating` suite is green.
- **Non-TASK dangling parents also map to `ErrorKind::InvalidTaskBody`.** Per the relay
  ("all mapped to coarse `ErrorKind::InvalidTaskBody`"). The name reads oddly for a
  `code_revision` session tree; the coarse kind is what keeps the sync classifier unchanged,
  which is the point. If a screener wants a distinct kind, that is an ErrorKind mint and a
  quarantine-classifier edit — out of scope here.
- **`code_revision.rs` keeps its own `validate_child_of_insert`.** It writes ChildOf rows
  directly to the store, bypassing `apply_ops` entirely, so it never reaches the batch
  validator and did not gain the existence check. Untouched, unclaimed, stated as residue.
- **A role CHANGE on an existing TASK does not re-validate its existing ChildOf edges.**
  `affected_children` only covers children named by an edge op in the batch. The Habit case
  is already guarded by `validate_task_role_put_invariants`; a general re-validation is a
  different ticket.
- Pre-release, no legacy: existing rows are not swept or repaired.

## Gates

- `cargo fmt -p oneiron --check` — clean.
- `cargo clippy --workspace --all-features --all-targets` — clean for every crate this lane
  touches. One pre-existing warning in `oneiron-seal` (deprecated `generic-array` method),
  present on `47ac630`, untouched.
- **FINAL GATE `cargo test -p oneiron --all-features` — PASS, exit 0.** 3984 lib + all
  integration binaries + doctests, 0 failed.

### Base-red, charged to no lane (verified by re-running at `47ac630` in this worktree)

- `oneiron-driver`: 21 failures (session lifecycle assertions). Identical 60-pass/21-fail
  split on the base commit. Zero `ChildOf*` errors in the output.
- `oneiron-server`: 1 failure,
  `handler::tests::the_real_codec_rows_run_the_same_codec_package_axum_resolves`
  (tokio-tungstenite 0.28 vs 0.29). Reproduces at `47ac630`; it is a stale-`Cargo.lock`
  resolution artifact — the committed lock predates deps already on main, so cargo re-locks
  in-worktree. Resolves at int-compose / merge when the lock is regenerated.

## Commits

- `9b4ceda` WIP: final-state ChildOf tree validation (existence + TASK role matrix)
- `55f78e9` WIP: recut existing ChildOf topology fixtures to non-TASK / matrix-valid pairs
- `857ff05` WIP: sync_quarantine cardinality fixture uses matrix-valid Milestone parents
