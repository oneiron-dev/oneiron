# WORKLOG — ONE-1746 (MS-04) `entity.distinct_from` + merge re-proposal suppression

Lane: MS · gh-stack MS-A layer 3 of 3 · branch `ONE-1746` cut off `origin/main`
@ `8225cec4` (MS-02 #582 and MS-03 #588 both merged, so the stack flattens to
base=main).
Worktree: `/Volumes/Cinema/w5-lt/ms`
Blueprint: `/Users/olety/.claude-wave5/blueprints/MS/ONE-1746.md`
Claims: `/Users/olety/.claude-wave5/blueprints/MS/CLAIMS.md`
Prior lane worklogs: `WORKLOG-ONE-1744.md`, `WORKLOG-ONE-1745.md`

## What shipped

1. **Claim write path.** `validate_distinct_from_claim_structure` in
   `identity_topology.rs`, dispatched from the literal chain in
   `claim::validate_claim_body_and_decode`. The value IS the normalized pair
   (`{a, b}`, strictly ascending) and the subject must be the pair's
   lex-first entity — the two bounds that make one unordered pair exactly one
   claim, enforced on EVERY type-0 write door (the op door's and an agent's
   direct `put_claim` alike), not just the engine's.
2. **Apply arm.** `AssertDistinct` mints the claim through the engine claim
   door and records a type-76 `assert_distinct` event naming `{a, b, claim}`.
   Idempotent: a live claim for the pair is ADOPTED, never duplicated.
   Transitions are empty (§6 moves no lifecycle state).
3. **Re-proposal suppression.** At the top of `apply_identity_topology_op_in_txn`,
   behind `!write.is_effective()`: a PROPOSED merge naming both sides of a
   pair an effective claim covers is refused
   `IdentityTopologyRejection::DistinctPairSuppressed { a, b }`. Pair-exact,
   `Auto`/`Approved` never blocked, superseding/retracting the claim lifts it.
4. **Reads.** `Vault::distinct_claims_for_pair` (suppressing set) and
   `Vault::open_merge_proposals_for_pair` (parked, unresolved, pair-naming).
5. **Oracle.** All three `ms04_*` arms un-ignored, seams swapped for the real
   API, no assert weakened. Ignore census (`grep -c '#\[ignore'`): base 10,
   branch 7 — exactly the three `ms04_*` moved, nothing else.

## Design rulings (deviations from the blueprint, with reasons)

### D1 — NO `CLAIM_PREDICATE_REGISTRY` entry (blueprint said add one)
The blueprint's §1 asks for `PREDICATE_ENTITY_DISTINCT_FROM` as the 5th entry,
widening `[&str; 4]` → `[&str; 5]`, on the stated grounds that "the entry buys
structural validation + the namespace-convention test".

Ground truth on main: `claim/tests.rs::registered_predicates_carry_layer_prefix`
asserts every registry entry's first segment is in
`PREDICATE_LAYER_NAMESPACES` = `[core, companion, eiri]`. `entity.distinct_from`
starts with `entity`, so the entry would turn that pinned test RED. The stated
benefit is also void: structural validation comes from the dispatch arm, and
the registry gates no write (claim.rs:149-152 — well-formed unknown predicates
are accepted).

The fifteen other predicate families on main (`channel_identity`,
`identity_reputation`, `actor.*`, `comm.*`, `calendar.*`, `campaign.*`,
`disclosure.*`, …) all validate through a dispatch arm with NO registry row.
Ruling: follow the house pattern — dispatch arm only. Widening
`PREDICATE_LAYER_NAMESPACES` to bless `entity` as a LAYER would be the wrong
fix (core/companion/eiri are product layers; `entity` is a family), and
editing the pinned test to accommodate a new entry would be weakening it.
Side benefit: strictly LESS churn in the shared `claim.rs`, so less merge
friction with the SKILLS lane's predicate tickets. Rationale is recorded on
the const's doc comment so a later reader does not re-litigate it.

### D2 — the op door writes through the ENGINE claim door, not the public one
`Vault::put_claim` runs the write gate. The default policy manifest rates every
unmatched predicate `critical`, and `criticality == Critical && consent.is_none()`
queues `gate.pending.criticality_floor` instead of committing — so routing
`assert_distinct` through the public door made all three oracle arms fail with
`GateWriteRejected { outcome: "pending" }`: the ticket's core function would be
dead on arrival in any default-manifest vault.

Two ways out. (a) Register the predicate in the DEFAULT policy manifest with
`criticality: normal` — the house pattern (`skill_hub` ×3, `provider_confidence`
×2, `edge.provenance` all have exactly that row) — but that is `gate.rs`, which
this lane's CLAIMS.md lists under **Explicitly NOT MS** with a named live
collision (DREAMER 1314 claims it this batch). (b) Write through
`put_reserved_claim_in_txn`, the crate-private engine door, which keeps the
source-trust check and skips the criticality ladder.

Ruling: **(b)**. It is not a workaround, it is the ratified consent shape:
ARCH-0055 r3 makes `Auto` this family's default and states the propose lane is
a caller's choice, "never an engine-imposed gate" — which is why merge and
split already write their edges through this door ungated. Leaving the floor in
force for one family member only would be exactly the engine-imposed gate r3
forbids. The asymmetry that remains is the DESIGN: an agent minting the
predicate directly through `put_claim` keeps the full gate, and until that
write is approved it suppresses nothing — the ratified §6 rule. The engine
door's doc comment in `claim.rs` was widened by one sentence to say it serves
family doors that own their predicate's decision, so the call site is not a
silent mismatch with the door's stated purpose.

**Owner check-in item:** if the owner would rather the criticality floor apply
to this predicate on both doors, the follow-up is the one-row `gate.rs` default
manifest entry, once DREAMER 1314 releases the file. Nothing else changes.

### D3 — a `Proposed` assert MINTS its claim (in the `Proposed` state)
Blueprint done-means: "an agent-minted assert with Proposed approval does NOT
suppress until approved". That requires a `Proposed` row to be able to exist.
Withholding it (the facet arm's answer) would strand the proposal: there is no
resolution door for this op kind — `proposal_scope_target` refuses it and
`decode_amendable_kind` admits merge/split only — so a park could never be
ruled on. The consent axis therefore lands ON the claim's `appr` column, which
IS the standard claim approval flow this predicate rides. Outcome stays
`Parked` (the event is legibility, nothing suppresses); the exception is
documented at `IdentityOpOutcome::Parked`'s definition, not just at the arm.

### D4 — idempotence is "already at least as effective", not "already exists"
A live `Proposed` row must NOT absorb an effective assertion — otherwise any
producer could neutralise an owner-ruled assertion by proposing it first. So
the reuse test is: any live row absorbs a proposal; only an effective row
absorbs an effective assertion. Unit-tested
(`a_proposed_distinct_assertion_suppresses_nothing_until_it_is_effective`).

### D5 — suppression cost is one claim sweep per PARTICIPANT, never per PAIR
A merge names up to `MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS` (256) entities;
checking every unordered pair would be 32k scans. Because the write path pins
the claim's subject to the pair's lex-FIRST entity, any pair with both sides in
the op's named set hangs off a member of that set — so N sweeps suffice and
`named.contains(&row.pair.1)` is the whole both-sides-named test. (Carried
straight from the 1744 O(N²) lesson.)

### D6 — an assert_distinct event is NOT undoable
Its retraction door already exists and is the claim's own lifecycle
(supersede / retract). A ledger counter-event would be a second, shadow
retraction path over the same row. `evaluate_fold_undo` already said
`NotUndoable` for this kind; the apply-side door now says it explicitly too,
and the comment states the settled reason rather than "arms in ONE-1746".

## Packet

`git diff --name-only origin/main`:

- `crates/oneiron/src/identity_topology.rs` (+ `identity_topology/tests.rs`) — claimed
- `crates/oneiron/src/claim.rs` — claimed (dispatch arm + one door doc sentence;
  no registry edit, see D1)
- `crates/oneiron/tests/merge_split_oracle.rs` — claimed
- `crates/oneiron/src/receipt.rs` — **PACKET_AMEND (one line, no collision).**
  CLAIMS.md lists receipt.rs as an MS-lane SHARED file but tags it 1747/1748.
  The touch is the additive `AssertDistinct` arm the new enum variant makes the
  compiler demand, which the blueprint itself named (`receipt.rs:2160`
  exhaustive-match update). Additive match arm + three field keys, no refactor
  — inside the file's own seam rule. 1747 is already merged, so no in-flight
  MS conflict.
- `crates/oneiron/src/lib.rs` — NOT touched: the new reads are inherent `Vault`
  methods and `DistinctClaimRow` is private, so no export line was needed.

`Cargo.lock` not committed; no `git add -A`; no push.

## Gates

- `cargo fmt --all -- --check` — clean
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean
- `cargo test -p oneiron --all-features` — 42 test binaries, **0 failed**
  (lib: 3509 passed / 17 ignored; `merge_split_oracle`: 17 passed / 6 ignored,
  the remaining ignores are the ONE-1748 and ONE-1749 contracts)

## Tests added (identity_topology/tests.rs)

- `assert_distinct_mints_one_normalized_claim_per_unordered_pair` — symmetry,
  idempotent adoption, normalized value + lex-first subject, pair-exactness
- `distinct_claim_suppresses_only_proposed_merges_over_the_covered_pair` —
  both directions refused typed, a merely-touching pair still parks, the
  effective lane never blocked
- `a_proposed_distinct_assertion_suppresses_nothing_until_it_is_effective` (D3+D4)
- `retracting_the_distinct_claim_lifts_suppression` — and the ledger event
  survives the retraction (r1)
- `assert_distinct_event_is_not_undoable` (D6)
- `assert_distinct_event_wire_round_trips_and_pins_the_normalized_pair` —
  descending and self-paired wire rows rejected; the kind stays unamendable
- `distinct_from_claim_structure_pins_the_pair_and_its_subject` — five
  negatives against the validator
- `facet_door_mints_and_assert_distinct_stays_unarmed` renamed to
  `facet_and_assert_distinct_doors_mint_their_own_effects`; its assert_distinct
  half now asserts the effect instead of its absence (arming, not weakening —
  every pre-existing assert kept).

## SIMPLIFY (K3, 2026-08-06)

Deletion-biased pass over the impl tip. ONE edit warranted:

- Collapsed the single-caller `pub(crate) fn distinct_claims_for_pair_in_txn`
  layer into the public `distinct_claims_for_pair` door — the `in_txn` split
  is the house idiom for txn-composable reads, but nothing composes this one
  (suppression reads `active_distinct_claims_in_txn` directly), so the wrapper
  was speculative generality.

Everything else held: every helper has real callers, the doc density carries
the ratified ARCH-0055 §6 consent rationale (house style), no test
assertions/fixtures or public API touched.

Gates after: `cargo fmt --check` clean · `cargo clippy -p oneiron
--all-features --all-targets -- -D warnings` clean · `cargo nextest run -p
oneiron --all-features` 3828 passed / 64 skipped.

## VERDICT-FIX (Opus, 2026-08-06) — 1 verdict-verified REAL P2

Finder raised 6 items; 5 were rejected-with-derivation by the verdict leg (3
banked for postmortem/GATE-2). ONE survived verification.

### F1 (P2, `unresolvable-proposed-assertion`) — FIXED

**The defect.** A `Proposed` `assert_distinct` wrote an Active-`Proposed`
claim through `put_reserved_claim_in_txn`, which mints no
`PendingGateConsentRecord` (the reserved door runs only
`check_reserved_claim_policy`). So the parked row had NO approval door:
`proposal_scope_target` is unarmed for `AssertDistinct`, so
`resolve_identity_proposal` can never rule on the park, and session-bundle
approval needs session tags the row does not carry. That contradicted the
family contract "`Proposed` PARKS … until approved" — the park could never be
approved by anything. Worse, the reuse predicate then skipped the `Proposed`
row on an effective re-assert and minted a SECOND Active row for the same
pair, so one-active-claim/idempotence held only for the all-effective flow.

**The fix (ruled shape, not a redesign).** RE-ASSERTION IS THE RESOLUTION
DOOR. In `assert_distinct_claim_in_txn` the reuse test is now bare pair
existence; when the incoming write is effective and the live row is not, the
row's approval is PROMOTED IN PLACE and its id returned — the effective op IS
the ruling (`Vault::merge_session_bundle`, `gate.rs`, is the precedent for
flipping a parked claim's `appr` and re-putting the same id).

- New `promote_distinct_claim_approval_in_txn`: reads the stored row, moves
  ONLY the approval cell, and re-puts through the same reserved door with the
  proposer's occurred window and `learned_at` read back off the entity header
  — value, subject, confidence and source stay verbatim. WHO ruled is recorded
  on the ruling's own type-76 event, which is the family's authority, so
  attribution is not lost by preserving the proposer's `src`.
- The abusable direction stays shut: a `Proposed` write never demotes an
  effective row, so proposing a pair first still cannot neutralize an
  owner-ruled assertion — it can only pre-park the row that ruling promotes.
- Source-trust still runs on the PROMOTED body, so an `Auto` ruling over an
  untrusted source is refused exactly as on a fresh mint (`check_source_trust`
  short-circuits for `Approved`), and refusal fails the whole op closed.
- Documented in three places the old text asserted the false contract: the
  module header (new RE-ASSERTION paragraph), `apply_identity_topology_op`
  (the park's door named), and `active_distinct_claims_in_txn` (why the
  approval axis is returned unfiltered).

**Tests.** New
`an_effective_re_assertion_promotes_the_parked_distinct_row_in_place`:
propose → assert `resolve_identity_proposal` rejects with
`IdentityTopologyUnarmed` (there is no other door) → effective assert in the
REVERSED pair order → SAME claim id, approval promoted, value/subject/source/
confidence unchanged, occurred+learned window still the propose-time
`(200, 200, 200)`, exactly ONE Active row covering the pair, and suppression
now live. `a_proposed_distinct_assertion_suppresses_nothing_until_it_is_effective`
flipped its `assert_ne!` to `assert_eq!` + an approval assertion (it pinned
the defect).

**Mutation-verify (both halves).**
- M1 — restore the pre-fix `find` predicate: both tests RED on the second
  minted id (`assert_eq!(ruled_claim, parked_claim)`, two distinct `EntityId`s).
- M2 — keep the widened reuse but drop the promote call: both tests RED on
  `left: Proposed / right: Approved` (and `/ Auto`).

**Gates.** `cargo fmt --check` clean · `cargo clippy -p oneiron --all-features
--all-targets` clean · `cargo nextest run -p oneiron --all-features` **3829
passed / 64 skipped**.

Diff: `crates/oneiron/src/identity_topology.rs` +
`crates/oneiron/src/identity_topology/tests.rs` + this worklog. No
`Cargo.toml` / `Cargo.lock`.
