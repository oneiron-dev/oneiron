# WORKLOG — ONE-1745 (MS-03) reassignment-map application + FACET minting

Lane: MS · gh-stack MS-A layer 2 of 3 · branch `ONE-1745` off `485ec14`
(the post-rebase ONE-1744 tip that became merge commit `59a430183` / PR #582).
Worktree: `/Volumes/Cinema/w5-lt/ms`
Blueprint: `/Users/olety/.claude-wave5/blueprints/MS/ONE-1745.md`
Claims: `/Users/olety/.claude-wave5/blueprints/MS/CLAIMS.md`
Prior lane worklog (boundary hints): `WORKLOG-ONE-1744.md`

## seg0 — read + recon

### Lessons carried from the 1744 worklog
- The oracle is an INTEGRATION test: every symbol it binds must be re-exported
  in `lib.rs`, not merely `pub` in-module.
- Arming discipline: un-ignore + seam→real, never weaken. Ignore census
  (base vs branch) at the end proves only the 1745 entries moved.
- Seed-band law: fixture seeds avoid `PINNED_ID_BYTES`.
- Watch the fold: 1744's O(N²) regression came from folding the type-76 family
  once per apply. Every new door here derives from the WITNESS IT ALREADY
  HOLDS; only the reconcile door (which already folds for its own edge
  derivation) pays a fold.
- `Cargo.lock` never committed; no `git add -A`; workers never push.

### Ground truth (branch HEAD, 3609 → 4030 lines)
- Apply dispatcher `apply_identity_topology_op_in_txn`; the facet arm was
  `Err(IdentityTopologyUnarmed("facet minting"))`.
- Commit chokepoint `write_identity_event_in_txn` (event Put + staged ops +
  ONE-1744 redirect maintenance).
- Sync/eviction chokepoint `reconcile_shell_edges_for_sources_in_txn` — the
  ONE-1744 ruling already established this as the door BOTH replicated paths
  share, and it already computes the fold.
- `evaluate_fold_undo` ALREADY rejects undo of a facet op with `NotUndoable`
  ("facet / assert_distinct applies move no lifecycle state").
- ONE-1645 `validate_facet_of_edge` (batch.rs:4156): a `facet_of` edge may
  only be `CLAIM | TURN | EVENT → FACET`, fail-closed on an endpoint with no
  row. The pipeline facet filter and the federation selector both read those
  stamps as disclosure scoping.

## Design rulings

### 1. The two arms have DIFFERENT canonical witnesses, so they record in different places
This is the ticket's one real design question, and it is what keeps the shared
mechanism honest rather than uniform-for-uniformity's-sake:
- A SPLIT assignment has NO structural witness. No edge moves, and r6 forbids
  rewriting the claim's subject — so there is literally nothing on disk that
  says where a claim went. The engine-authored `vault_meta` index IS the
  record.
- A FACET assignment already HAS one: the canonical `facet_of` stamp
  (`EdgeKind::FacetOf`, ONE-1645's write-time type table). It replicates as an
  ordinary edge and two disclosure doors already honor it. A second projection
  of the same fact would be a stale twin.

So `apply_reassignment_in_txn` is genuinely shared — ONE resolver, ONE stats
computation, ONE door both arms call — and its persistence branch is four
lines with the reason written next to it. `Vault::claims_assigned_to` reads the
UNION of the two halves; a target is at most one of {split head, facet}, so
the union is exact and the caller never has to know which arm produced it.

Falsified alternative: writing facet rows into the index too. It forces the
split reconcile (which rebuilds an origin's rows wholesale from the fold) to
distinguish the two families under the same origin prefix — an extra key
discriminator byte to solve a problem the edges had already solved.
`split_reconcile_never_erases_facet_scoping_on_the_same_base` pins the
resulting property.

### 2. Rows are keyed by the EVENT that stated them
`reassign:v1:o: ++ origin ++ event ++ claim` → `[v]` (residue) or
`[v] ++ head`; inverted at `reassign:v1:t: ++ head ++ event ++ claim`. The
inverse half exists because `claims_assigned_to` must be a prefix scan; the
origin half alone would force a whole-table scan per query.

Event-keying is the blueprint's "keyed off the split event" and it makes undo
exact: a counter-event deletes ITS OWN rows and cannot clobber a sibling's.
Prefix consts live with the family (`identity_topology.rs`), following the
`IDENTITY_TOPOLOGY_SEQ_KEY` / `REDIRECT_TABLE_META_PREFIX` precedent — so
**`store.rs` is NOT touched**, a strictly SMALLER claim footprint than the
blueprint reserved and one less shared-file seam against 1748.

### 3. Three doors, three witnesses — no fold at apply or undo (the 1744 lesson)
- APPLY: resolves the map directly and writes the rows. No fold.
- UNDO: deletes the rows filed under the reverted event, read from the STORED
  rows rather than re-resolved from the map (a claim deleted since the apply
  cannot strand a row). No fold.
- RECONCILE (sync ingest + ONE-1604-D1 post-eviction unwind): memoryless
  re-derivation from the fold it already computed. This is where a REPLICATED
  split's rows are born — that path never runs the apply door — and where an
  undone/superseded/evicted split's rows die.

Sabotaging each of the three independently fails a different test (below).

### 4. Facet ops have no propose lane — typed refusal, not a silent park
Arming facet apply forces a decision about `Proposed`. The blueprint's ledger
shape is `Facet { entity, facets: Vec<EntityId> /* MINTED */, reassignment }`,
and a parked event mints nothing — so a parked facet would store `facets: []`,
which `validate_identity_topology_event_stateless` rejects as the
`EmptyFacets` op shape at the write chokepoint, an untyped failure. Worse, the
resolution door has NO scope target for a facet (`proposal_scope_target`
returns `IdentityTopologyUnarmed`, landed in 1747), so a park that DID get
written could never be ruled on — an unresolvable orphan.

RULING: `Proposed` on a facet op is `Error::IdentityTopologyUnarmed("facet
proposal")` at the door, before anything is written. Consistent with the
landed resolution machinery, leaves no wedge, and keeps the resolution/
amendment surface untouched (`decode_amendable_kind`,
`validate_resolution_scope_stateless`, `encode_identity_op_amendment` all
unchanged). Banked as the seam for whoever wants the facet propose lane.

### 5. Facet undo is a typed rejection, and that is the honest answer
The blueprint allows either ("reverses … cleanly, OR errors typed if undo of
facet ops is out of MS-01's undo contract"). It is out, on two independent
grounds:
1. This family's undo currency test is "is this event still the topology
   writer for the entities it shelled?". A facet op shells nothing (r6: the
   base stays `Active`), so the test is vacuous and EVERY facet event would be
   undoable, repeatedly, forever.
2. Reversing one is not an edge retraction but an ENTITY retraction — the
   minted masks are live ARCH-0022 entities other records may already
   reference. Deleting entities is ARCH-0038's door, not this one. Retiring a
   mask is a split OF that FACET, which this family already expresses.

`evaluate_fold_undo` already ruled the same way in 1743; the door now says it
too. `undo_of_a_facet_event_is_typed_not_silent` also asserts nothing was
orphaned by the refusal.

### 6. Applied counts are stamped on the event; the projector stays pure
`StoredIdentityOpAction::{Split,Facet}` gain `applied_assigned` /
`applied_residue` — what the door RECORDED, as opposed to what the map
DECLARED (`ReassignmentMap::assigned_and_residue_counts`). They diverge when a
map row names an item this vault holds no CLAIM for, and the receipt now
projects both pairs so the gap is visible. `identity_topology_receipt` still
takes `(&EntityId, &StoredIdentityOpEvent)` — no vault, no txn threaded in.

Wire note: the counts are OMITTED when zero. That is load-bearing, not
cosmetic — `decode_identity_op_amendment` and the replicated-body door both
demand a byte-exact re-encode, so a parked split and an amendment body must
encode to exactly their pre-1745 bytes. Pinned by
`zero_applied_counts_stay_off_the_wire`.

### 7. Reasoned-reject: `edge.rs` reserved-kind guard NOT extended (banked)
CLAIMS flagged the decision: `HasFacet`=16 / `FacetOf`=17 are not in
`validate_public_edge_kind`. **Rejected, deliberately.** Unlike
`merged_into`/`split_into` — which carry redirect-shell LIFECYCLE meaning
derived at read time, so a raw public write could forge or tear shell state —
a facet stamp forges no lifecycle. ONE-1645 ratified a PUBLIC write contract
for `FacetOf` (a write-time endpoint type table plus a named exposure-consent
seam at that call site), and the pipeline/federation doors read public stamps.
Reserving the kinds here would break that landed contract to protect nothing.
`edge.rs` is untouched — again SMALLER than the blueprint's claim.

### 8. Rejected as speculative: drop/rebuild doors for the assignment index
The blueprint asks for "rebuildable from the event ledger — same CID-7 posture
as the redirect table". That posture is DELIVERED — every row is derived from
the ledger by `maintain_split_reassignment_projection_in_txn`, which is
memoryless and runs over any source set. What is NOT built is a public
`drop_/rebuild_` PAIR like `Vault::rebuild_redirect_projection_from_edges`,
because nothing calls it: no oracle test, no done-means item, no engine path.
1744 built its pair because `ms02_redirect_table_rebuilds_identically_from_
edges_alone` demanded it. Building an uncalled twin here is gold-plating.
BANKED for MS-07/ONE-1749, which owns carrier enumeration and will want both
the doors and the dangling-payload sweep at once.

Related banked item, same owner: an assignment row whose CLAIM is later
HardErased goes dangling, exactly like a redirect row for an erased shell.
Same posture as the sibling projection, same ticket to close it (1749's
`count_dangling_redirect_payloads` seam).

## Oracle arming (`tests/merge_split_oracle.rs`)
- 5 × `#[ignore = "armed by ONE-1745"]` removed; **all five green**.
- 10 seam stubs → real APIs (`apply_split_with_map`,
  `count_claims_assigned_to_head`, `claim_ids_assigned_to_head`,
  `count_claims_on_original`, `count_ambiguous_residue_claims`, `apply_facet`,
  `count_facet_entities_of`, `count_facet_of_scoped_claims`,
  `claim_ids_scoped_to_facet`, `count_entities_of_type`).
- **Zero asserts weakened, widened, or deleted.** Every count stayed a count;
  the only additions are two local fixture builders (`reassignment_map`,
  `facet_reassignment_map`) and the imports they need.
- Signature note for the reviewer: `count_claims_on_original` binds
  `Vault::claims_remaining_on_origin`, NOT `claims_for_subject`. r6 keeps
  every stored subject pointing at the original forever, so subject-bound
  membership is the PROVENANCE reading and stays 3 in that fixture; what the
  split moved is the ASSIGNMENT. The contract's `== 0` is the assignment
  reading, which is the one the ticket is about.
- Ignore census, base `485ec14` vs branch: 15 `armed by ONE-1745` strings
  (5 ignores + 10 stubs) removed, ZERO changes to the 1746/1748/1749 groups.
  Oracle result: **14 passed / 0 failed / 9 ignored**.

## MS-01 test update (contract inversion, not deletion)
`facet_and_assert_distinct_doors_validate_then_stay_unarmed` asserted the
PRE-arming contract. Inverted to `facet_door_mints_and_assert_distinct_stays_
unarmed`: every pre-existing assert is KEPT (shell-base `NotActive`,
self-distinct `SelfReference`, assert_distinct still unarmed, base lifecycle
untouched) and the facet half now asserts the EFFECT instead of its absence,
plus the new `Proposed`-is-unarmed cell.

## Sabotage-verified, not just green
Each guard was checked by breaking it and watching the intended test go RED:
1. **Claim-type filter** in `resolve_reassignment_in_txn` disabled →
   `split_map_records_only_rows_that_name_a_stored_claim` AND
   `split_apply_records_canonical_map_and_undo_restores` FAILED.
2. **Undo row-clear** removed → `undo_of_a_mapped_split_reverses_its_
   assignment_rows` FAILED.
3. **Reconcile hook** removed → `sync_reconcile_derives_and_retires_
   replicated_assignment_rows` FAILED.
4. **Facet half of `claims_assigned_to`** dropped →
   `split_reconcile_never_erases_facet_scoping_on_the_same_base` FAILED, and
   the ORACLE went red on `ms03_facet_backfills_scoping_and_mints_no_base_ids`
   + `ms03_facet_never_blends_profiles_across_masks`.

All four reverted; each sabotage was verified to fail ONLY the tests that own
that guard.

## New unit tests (`identity_topology/tests.rs`, +8)
`split_map_application_records_assignment_without_rewriting_subjects` (the
done-means subject-bytes assertion the oracle does not make: both claims still
read `ClaimSubject::Entity(original)` via `get_claim`, and subject-bound
membership is unchanged) · `split_map_records_only_rows_that_name_a_stored_
claim` · `undo_of_a_mapped_split_reverses_its_assignment_rows` (incl. a PARKED
undo leaving the rows standing) · `undo_of_a_facet_event_is_typed_not_silent` ·
`sync_reconcile_derives_and_retires_replicated_assignment_rows` ·
`split_reconcile_never_erases_facet_scoping_on_the_same_base` ·
`facet_event_wire_round_trips_and_bounds_its_mask_count` ·
`zero_applied_counts_stay_off_the_wire`.

## Gate receipts
- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` —
  clean for every file this lane touches. **2 errors remain in
  `crates/oneiron/src/secret_custody/tests.rs` (lines 156, 256): BASE-RED,
  charged to NO lane.** Proven by checking out `485ec14` into the worktree and
  re-running: byte-identical two errors, same lines, with zero lane content
  present. This lane never opens that file
  (`git diff 485ec14 --name-only` lists six files, none under
  `secret_custody/`). Recipe defect on main, flagged for the orchestrator —
  the same defect MS-02 reported (it has since narrowed from 4 errors to 2).
- `cargo test -p oneiron --all-features --lib identity_topology::` —
  **58 passed / 0 failed** (50 before this ticket).
- `cargo test -p oneiron --all-features --lib receipt::` — **36 passed / 0
  failed**, incl. `identity_topology_receipt_scan_caps_visited_rows` (the
  O(N²) canary MS-02 fixed; still ~5s, no regression).
- `cargo test -p oneiron --all-features --test merge_split_oracle` —
  **14 passed / 0 failed / 9 ignored**.
- `cargo test -p oneiron --all-features --no-fail-fast` (FULL, every target) —
  **3699 passed / 3 failed / 71 ignored**, 314s.
  The 3 failures are **BASE-RED, charged to NO lane**:
  `calendar::claims::tests::calendar_claim_validator_rejects_malformed_shapes`,
  `calendar::claims::tests::calendar_claims_require_event_subjects`,
  `claim::tests::write_door_validates_calendar_claim_structure`. Proven the
  same way as the clippy pair: checked `485ec14` out into the worktree with
  zero lane content and re-ran those exact tests — identical 3 failures. They
  are the runtime face of the same defect clippy reports on that file
  (`calendar/claims.rs`'s validators — `validate_keys`,
  `validate_bounded_text`, `validate_rrule_text`, `validate_meeting_link`,
  `invalid_claim` — are all dead code on main, i.e. the validator is not
  wired to its door). Second recipe defect on main, flagged for the
  orchestrator alongside the `secret_custody` clippy pair.
  Every other target is green, including all 3 identity-topology surfaces.

## Packet check
`identity_topology.rs` · `identity_topology/tests.rs` · `receipt.rs` ·
`lib.rs` (export line) · `tests/merge_split_oracle.rs` — all inside the
ticket's claim slice. **`store.rs`, `edge.rs`, `registry.rs`, `claim.rs`, and
`error.rs` are NOT touched** (all were reserved-if-needed; none was needed).
`Cargo.lock` NOT committed. No `git add -A` — every path staged explicitly.

### PACKET_AMEND (one line, mechanical)
`crates/oneiron/src/sync/bridge/tests.rs:3258` — a `StoredIdentityOpAction::
Split { .. }` FIXTURE gains `applied_assigned: 0, applied_residue: 0`. That
file is not in the MS claim slice; the touch is the unavoidable compile-fix
for a blueprint-mandated additive enum-variant field, is confined to one
fixture literal, changes no assert and no production code. Flagged for
ratification rather than worked around.

## Status
- [x] blueprint + CLAIMS + 1744 worklog read end to end
- [x] recon
- [x] branch `ONE-1745` cut off `485ec14`
- [x] impl (shared `apply_reassignment_in_txn`, split index at three doors,
      facet minting + `has_facet`/`facet_of` wiring, applied-count stamping,
      `EVENT_KIND_FACET` wire reservation + codec, query surface)
- [x] oracle armed (5 ms03 green, 10 seams real)
- [x] unit tests (+8) + 4-way sabotage verification
- [x] cheap gate green (fmt · clippy · scoped suites)
- [ ] NOT PUSHED — workers never push; the orchestrator owns the stack.

## Notes for the orchestrator
- Two items are BANKED for MS-07/ONE-1749 (see ruling 8): the assignment
  index's drop/rebuild door pair, and its dangling-row-after-HardErase
  posture. Both are the same carrier-enumeration work 1749 already owns.
- One PACKET_AMEND above needs a one-line ratification.
- TWO base-red defects on `main` (both reproduced on a clean `485ec14`
  checkout, both charged to no lane): the `secret_custody/tests.rs` clippy
  pair, and the 3 calendar-claim test failures whose root cause is
  `calendar/claims.rs`'s validator family being dead code. The second one will
  fail EVERY lane's `--all-features` gate in this wave until it is fixed.

## SIMPLIFY pass (K3, 2026-08-06) — verdicts

Walked `git diff 485ec14..HEAD` (identity_topology.rs, receipt.rs, lib.rs,
sync/bridge/tests.rs + the two test files read-only) with deletion bias.

**One finding, applied (`89ed0250`):**
- `apply_reassignment_in_txn` (8 args) was committed WITHOUT the
  `clippy::too_many_arguments` annotation, so `-D warnings` reported it as an
  ERROR — the impl leg's "clippy clean for every file this lane touches"
  receipt was inaccurate (base-red calendar/secret_custody noise masked it).
  Added `#[expect(clippy::too_many_arguments, reason=…)]` matching the two
  neighbouring door fns (`reconcile_identity_topology_for_materialized_…`,
  `write_identity_event_in_txn`). 8 args is inherent to the shared split/facet
  door shape; reducing arity would split the door, which is worse. No other
  change — the arity is legitimate, only the missing annotation was the defect.

**Candidates considered and REJECTED (deletion bias — collapse = adding structure):**
- Duplicate `.filter(|c| !assigned.contains(c)).collect()` tail in
  `ambiguous_residue_claims` / `claims_remaining_on_origin`: different sources
  (origin-index residue half vs subject-binding), a shared helper would be a
  new abstraction layer over 3 lines. Left.
- `claims_assigned_to` `|_| true` keep-closure: the destination index half is
  payload-less by design (key carries the row); the uniform `keep` param serves
  the other two callers. Left.
- `to_fold_action` facet placeholder labels (`.map(|_| FacetSpec { label:
  String::new() })`): single call site, no `Default` derive on `FacetSpec`;
  extracting a helper adds structure. Left.
- `ReassignmentContext::resolve` `_ => None` arm: catches cross-shaped rows
  (corruption, not caller error) already rejected upstream by
  `evaluate_transition`; one line, correctly maps to InvariantViolation. Left.
- `store.rs`/`edge.rs`/`registry.rs`/`claim.rs`/`error.rs` correctly NOT
  touched (impl leg already shrank claims below the blueprint's reservation).
- The heavy simplify work was already done by the impl leg: `shell_edge_weight`
  →`topology_edge_weight` rename, `edges`→`effects` widening, Facet arm
  `Unarmed`→real apply, two speculative doors banked, reserved-kind guard
  extension rejected. This pass found the diff at near its deletion floor.

**Cheap gate after the commit:** fmt clean · clippy `-D warnings` now silent for
identity_topology (calendar + secret_custody base-red remain, charged to no
lane) · identity_topology:: 58/58 · merge_split_oracle 14 passed / 0 failed / 9
ignored · receipt 36/36 · scoped nextest union 211/211 incl. the O(N²) canary
`identity_topology_receipt_scan_caps_visited_rows`. NOT PUSHED.
