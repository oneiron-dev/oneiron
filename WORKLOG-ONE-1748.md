# WORKLOG — ONE-1748 [MS-06] consent-graduation ramp

Branch `ONE-1748` off `origin/main` 8de9a46f3. Blueprint:
`/Users/olety/.claude-wave5/blueprints/MS/ONE-1748.md`.

## What landed

New module `crates/oneiron/src/consent_graduation.rs` (+ `consent_graduation/tests.rs`):
per-scope outcome statistics, the derived graduation offer, the owner-tap
acceptance door, and transparent self-demotion projected as a SECOND
`ReceiptKind::Gate` receipt family.

Oracle: `ms06_ramp_scope_keys_on_op_class_agent_tuple`,
`ms06_self_demotion_is_receipted_never_silent`,
`ms06_merge_split_never_gated_by_ramp` un-ignored; all seven ONE-1748 `seam`
stubs swapped for real engine doors. `ms06_streak_offers_standing_grant_never_auto_grants`
was already armed by ONE-1606 and is untouched. One ADDITIVE oracle test added
(`ms06_demotion_from_graduated_revokes_the_standing_grant`) — no existing assert
weakened, widened, or deleted.

## Load-bearing rulings honoured

1. **Self-demotion rides a second Gate projector.** `consent_graduation::demotion_receipts`
   is registered beside `gate_receipts` in `receipt::collect_receipt_records`,
   reading this module's own `ramp_demote:v1:` vault_meta rows. NO synthetic
   `GateDecisionRecord` is written into the gate-decision store (ONE-1637's
   erasure-chain H0 index is untouched). `ProposalOutcome` stays at exactly
   three states — `ms05_proposal_outcome_has_exactly_three_states` still green.
2. **Merge/split are never gated by the ramp.** `op_kind_is_ramp_eligible` is
   false for every identity-topology op kind, so those scopes never reach an
   offer, a grant, or a state other than the inert `Propose`.
   `apply_identity_topology_op_in_txn` and every merge/split applier contain
   zero references to the ramp (grep evidence below).

## Blueprint deviations (declared, none silently absorbed)

**D1 — §2/§5 tension, resolved as MEASURE-universally / GRADUATE-selectively.**
The blueprint's §2 makes the stats a rebuildable projection of the ARCH-0055 r7
proposal-outcome receipts; §5 puts identity-topology ops off the ramp entirely.
Those two are in direct tension today because identity topology is the ONLY
producer of `ProposalOutcome` receipts on main — a fold that filtered §5's
excluded kinds would rebuild from nothing, and `rebuild_ramp_stats_from_receipts`
would be untestable and dead. Ruling: **statistics are universal measurement**
(any scope's counters move), **graduation is gated** (offer / accept / standing
grant / non-`Propose` state are refused for ineligible kinds). This keeps every
piece live, keeps both oracles strict, and reads §5's "never placed on the
propose→auto ramp" as what it governs — the escalator, not the tally.

**D2 — `accept_graduation_offer` takes an `&AuthenticatedOwner`.** The blueprint
skeleton is `accept_graduation_offer(&self, scope) -> Result<EntityId>`; that
signature would let the engine mint its own authority, contradicting DEC-0006
invariant 5 and the oracle it is named against. The door now requires the owner
and routes through the one `Vault::create_standing_grant`.

**D3 — it returns `ConsentReceipt`, not `EntityId`.** Standing grants are keyed
by `grant_ref` (the bound digest hex), not an `EntityId`; `create_standing_grant`
returns `ConsentReceipt`. Returning a fabricated `EntityId` would invent an id
space the consent registry does not have.

**D4 — `RampState` is DERIVED, never stored, and there is no offer row family.**
`Graduated` is "a live standing grant exists for this scope's bound";
`Offered` is "eligible ∧ clean streak ≥ floor ∧ no grant yet". Because
`ConsentGrantRow::grant_ref()` is the bound digest, a grant the owner minted
through the plain `create_standing_grant` door — exactly what the ONE-1606-armed
oracle does — is the SAME row the ramp reads. No second bookkeeping table, so
nothing can drift out of agreement with the consent registry. This deleted the
`ramp_offer:` row family the naive shape would have needed.

**D5 — `store.rs` is NOT touched.** PACKET allowed vault_meta prefix consts
there; the house precedent set by `identity_redirect::REDIRECT_TABLE_META_PREFIX`
(and cited in its own doc comment) is that the family owning a keyspace owns its
key shape. All three prefixes (`ramp_stats:v1:`, `ramp_floor:v1:`,
`ramp_demote:v1:`) live in `consent_graduation.rs`. Strict under-use of the
packet, not an overrun.

**D6 — `outbound_grant.rs` untouched and no `StandingProposeGrant` sibling was
built.** The blueprint left this as its one open implementation call.
`GrantBound::action(actor, class, envelope)` already expresses the DEC-0006 bound
exactly — actor = the acting skill/agent, class = op kind, envelope = the target
class — and `StandingConsentGrant`/`ConsentGrantRow` already carry it with an
Active|Revoked lifecycle. A parallel grant family would have been a second
authority store to keep in sync with the first.

**D7 — `error.rs` is NOT touched.** CLAIMS lists error.rs for 1747/(1749), not
1748. Every rejection reuses `Error::InvalidConsentBound` (which is what the
condition actually is: a tuple that cannot form a bound, or an op kind with no
propose lane to skip) or `Error::CorruptedIndex` for unreadable rows.

## PACKET_AMEND candidate — `crates/oneiron/src/consent.rs`

`consent.rs` is not in the ONE-1748 packet or the MS CLAIMS table. Two ADDITIVE
`pub(crate)` doors were added to it, with no change to any existing signature or
behaviour:

- `standing_grant_is_active_in_txn(store, txn, grant_ref) -> Result<bool>`
- `revoke_standing_grant_in_txn(store, wtxn, grant_ref) -> Result<bool>`

Why unavoidable: §4 and the Done-means require the demotion to **revoke** the
standing grant, and the grant row's codec + key helper are private to consent.rs.
The public `Vault::revoke_consent_grant` demands an `AuthenticatedOwner` — correct
for an owner-initiated revocation, wrong for self-demotion, where the point is that
REDUCING one's own authority needs no owner and only GRANTING does. The in-txn door
also writes no receipt of its own, so a demotion records exactly one act rather
than a revocation receipt and a demotion receipt describing the same event.

Collision risk: LOW. GOV-CONSENT ONE-1606 (the file's author this wave) is merged
on main; no other CLAIMS row names consent.rs. Both additions are new items at a
disjoint location. Fable ruling requested per the PACKET_AMEND path.

Also worth flagging on the shared-file ledger (both strictly additive, in packet):

- `receipt.rs`: `FIELD_OP_KIND` / `FIELD_TARGET_CLASS` / `FIELD_SCOPE_ACTOR` /
  `FIELD_GRANT_REF` widened `const` → `pub(crate) const` (no value change), one new
  `FIELD_DEMOTION_REASON`, one new projector line in `collect_receipt_records`.
  No refactors in the high-fan-in file.
- `identity_topology.rs`: ONE call site in `resolve_identity_proposal_in_txn`
  (after the ledger write, in the same txn) plus one new `pub(crate) fn
  is_identity_topology_op_kind` so the family's wire vocabulary is enumerated in
  exactly one place. Nothing in any apply path.

## Known holes (banked, not buried)

- **Replicated resolutions do not fold incrementally.** Sync admission owns no
  ramp state, so a resolution arriving over the wire moves no counter until
  `rebuild_ramp_stats_from_receipts` runs. This is the same division of labour
  `identity_redirect` draws between `maintain_redirect_projection_in_txn` and
  `rebuild_redirect_projection_from_edges`; documented on the recorder. Wiring
  sync would need a sync-lane claim this ticket does not hold.
- **The rebuild reproduces receipt-backed scopes.** A caller that folds through
  the public `Vault::record_proposal_outcome_for_ramp` without a durable ruling
  record behind it owns a projection the CID-7 rebuild cannot re-derive. The
  door's contract says so explicitly. No such caller exists today; the propose-lane
  surfaces that will use it (ED-05's consumers) carry their own receipts.
- **OF-037 checker band / ONE-1403.** Nothing here special-cases
  `CallPurpose::AutoCheck`; graduated scopes are expected to keep routing through
  the checker when configured. No TODO was pinned because no call site in this
  ticket touches the checker seam.

## Gates

- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean.
- `cargo nextest run -p oneiron --all-features` — **3847 passed, 0 failed,
  61 skipped** (the 61 are pre-existing, incl. the three ms07/ONE-1749 parks).
- `merge_split_oracle`: 21 passed, 3 skipped (all ms07). All five ms06 tests green.

### Mutation verification (each guard proven load-bearing)

| mutation | red tests |
|---|---|
| `op_kind_is_ramp_eligible` → always true | `ms06_merge_split_never_gated_by_ramp`, `identity_topology_op_kinds_never_graduate` |
| drop the demotion projector from `collect_receipt_records` | `ms06_self_demotion_is_receipted_never_silent`, `an_amendment_in_a_graduated_scope_demotes_it_receipted` |
| `revoke_standing_grant_in_txn` → no-op | `ms06_demotion_from_graduated_revokes_the_standing_grant`, `a_rejection_demotes_and_a_clean_approval_does_not` |

All three mutations were reverted; `git diff` confirmed clean before the final run.

### Grep evidence for "merge/split apply paths contain zero ramp checks"

`rg 'consent_graduation|RampScope|record_ramp_outcome' crates/oneiron/src/identity_topology.rs`
returns hits only in `is_identity_topology_op_kind` (the vocabulary predicate) and
inside `resolve_identity_proposal_in_txn` (the resolution door, structurally after
apply). `apply_identity_topology_op_in_txn` and the merge/split/facet appliers
contain none.

`InboxReviewDial` is untouched — it appears in no file in this diff.

## Files

- `crates/oneiron/src/consent_graduation.rs` (new)
- `crates/oneiron/src/consent_graduation/tests.rs` (new, 14 tests)
- `crates/oneiron/src/consent.rs` (PACKET_AMEND — two additive `pub(crate)` doors)
- `crates/oneiron/src/receipt.rs` (additive: 1 field key, 4 visibility widenings, 1 projector line)
- `crates/oneiron/src/identity_topology.rs` (one call site + one predicate fn)
- `crates/oneiron/src/lib.rs` (module + re-exports)
- `crates/oneiron/tests/merge_split_oracle.rs` (arming + 1 additive test)

`Cargo.lock` not committed. No `git add -A`. No push, no merge.

## SIMPLIFY (K3, 2026-08-06)

Deletion-biased pass over the impl tip (939845c7d). One edit, no structural
additions, no test/assertion/public-API touches:

- `record_outcome_for_scope_in_txn`: dropped the redundant counters re-read
  after `append_demotion_in_txn`. The append helper folds exactly
  `counters.apply_demotion(at)` into the row this fn had just written, so the
  local fold is byte-identical to the re-read. One store round-trip deleted.
- Examined and KEPT: the `record_ramp_outcome_in_txn` discard-wrapper (deleting
  it would force `Counters` visibility wider — an addition, not a deletion);
  the post-commit read txn in `record_proposal_outcome_for_ramp` (read-what-you-
  committed is the conservative house pattern); all docs (load-bearing doctrine).
- Observation for the finder, NOT changed here (out of simplify scope):
  `ramp_fold_events` decodes `StoredDemotion` without the `row.v` version check
  that `demotion_receipts` performs — inconsistent, benign at v1.
- PACKET_AMENDs already declared by the implementer stand: consent.rs (+2
  pub(crate) doors needing consent.rs's private grant-row codec) and store.rs
  untouched (prefix consts live in consent_graduation.rs per the
  identity_redirect precedent). No new packet surface introduced by this pass.

Gates after the edit: `cargo fmt --all -- --check` clean ·
`cargo clippy -p oneiron --all-features --all-targets -- -D warnings` clean ·
`nextest --lib consent_graduation` 14/14 · `nextest --test merge_split_oracle`
21 passed / 3 skipped (pre-existing ms07 parks). Demotion-path tests
(`an_amendment_in_a_graduated_scope_demotes_it_receipted`,
`a_rejection_demotes_and_a_clean_approval_does_not`, both ms06 demotion
oracles) green against the edit.

## VERDICT-FIX (Opus, 2026-08-06)

Round input: finder FINDINGS (7 items) + verdict `FIX-REQUIRED` (6 REAL, 1
rejected-with-derivation, 2 banked). All 6 REAL findings fixed at their
chokepoint; the rejected finding is NOT relitigated; BANKED-2 (the false
`identity_redirect`-parity comment) folded in as instructed.

### F1 — P1 `graduation-streak-not-backed-by-receipts` (finding 1)

The tension the verdict named — the blueprint pins BOTH the public door AND
receipts-alone rebuildability — is reconciled by making the door's ruling
DURABLE rather than by deleting the door (the ms06 eligible-scope oracle feed
drives through it).

- New append-only `vault_meta` family `ramp_outcome:v1:` ‖ at ‖ row id, written
  by `record_proposal_outcome_for_ramp` BEFORE the counters move.
- Written only on the door path. `OutcomeWitness::{Ledger, Door}` threads the
  distinction through `record_outcome_for_scope_in_txn`: an identity-topology
  resolution already has its type-76 row (and its r7 proposal-outcome receipt),
  and a second record would double-count on every refold.
- The rows project as `Gate` receipts beside the demotion rows (same second
  projector, `ramp_outcome:` receipt-id prefix, `is_ramp_outcome_receipt`
  discriminator), so a door-recorded streak is witnessed by real receipts.
  Deliberately not `ReceiptKind::ProposalOutcome`: every member of that family
  names a real type-76 resolution event and ED-01 joins it on `proposal_ref`.
- The rebuild folds them, so an earned streak survives a refold instead of
  being deleted by it.
- Mutation-verified: with the row append disabled,
  `a_door_recorded_streak_is_witnessed_by_receipts_and_survives_the_rebuild`
  fails at `left: 0 / right: 12` outcome receipts.

### F2 — P1 `stale-offer-can-mint-grant` (finding 2)

`accept_graduation_offer` now demands `derive_state_in_txn == RampState::Offered`
INSIDE the transaction that writes the grant row.

- Required a transaction-composable mint: `consent.rs` gained
  `create_standing_grant_in_txn`, and the public `create_standing_grant` became
  the one-line `with_write_txn` wrapper around it (pure extraction, no semantic
  change). This extends the already-declared consent.rs PACKET_AMEND.
- Mutation-verified: with the Offered check disabled,
  `a_retracted_offer_cannot_be_taken_by_a_stale_tap` fails — the rejection has
  already receipted the demotion and the stale tap still mints the grant.

### F3 — P2 findings 4 + 5 + 6, one chokepoint: the rebuild's fold input

`ramp_fold_events` (read txn, receipt-query driven, `at`-ordered) is replaced by
`ramp_fold_events_in_txn`:

- **Ordering (finding 4):** a total `FoldKey = (watermark, rank, id)`. Ledger
  rulings carry their own `seq`; ramp rows stamp `after_seq`, the identity-
  topology causality clock read at write time (`read_identity_topology_seq_in_txn`,
  widened to `pub(crate)` — visibility only, no logic change). `rank` puts a ramp
  row after the ruling of the same watermark, which is exactly the demotion a
  ruling triggers in its own transaction; `id` breaks remaining ties in mint
  order, matching `fold_identity_topology_log`'s own `(seq, event_id)`.
  Caller-supplied `at` is now DATA only (it feeds `updated_at`), never order.
  Mutation-verified: restoring `at`-primary ordering fails
  `the_rebuild_folds_in_ledger_order_not_clock_order` with exactly the traced
  divergence (`streak 0 / last Rejected` vs `streak 1 / last ApprovedUntouched`).
- **Scan-to-write window (finding 5):** the whole fold input is now read on the
  SAME write transaction that deletes and rewrites the projection. Structural
  fix — no deterministic single-process interleaving hook exists to test it, so
  it is verified by construction (`self.ramp_fold_events_in_txn(&*wtxn)` is the
  first statement inside `with_write_txn`) and covered against regression by the
  existing rebuild-parity tests.
- **Truncation (finding 6):** the ledger half no longer goes through the public
  receipt query (`identity_topology_receipts` visits only the newest
  `MAX_RECEIPT_QUERY_SCAN` type-76 rows across ALL kinds). It enumerates
  `identity_topology_events_in_txn` — documented in identity_topology.rs as "the
  ONE enumeration surface the fold, the receipt projection, and any rebuild
  share" — which is uncapped, and applies the SAME duplicate suppression the
  receipt projector applies (`ProposalAlreadyResolved` rejections from
  `fold_identity_topology_log`). Structural fix; a >100k-row red-before is not
  constructible in a unit test, so the evidence is the code path plus the
  rebuild-parity tests staying green. This keeps the door's contract stronger
  than "rebuild from receipts": it folds the ledger the receipts project.

### F4 — P2 `invalid-public-scope-commits-before-error` (finding 7)

`RampScope::validate()` re-checks what `RampScope::new` would have produced
(non-empty, within `MAX_CONSENT_REF_LEN`, and already normalized — an
un-normalized twin keys to its own row). Every public MUTATOR runs it before its
first write: `record_proposal_outcome_for_ramp`, `demote_scope_to_propose`,
`set_ramp_streak_floor`, `accept_graduation_offer`. Readers are unchanged (a
bogus tuple reads as absent). With no invalid row constructible, the all-offers
scan can no longer be poisoned into a global `CorruptedIndex`.
Mutation-verified: with the record door's `validate()` removed,
`an_unbuildable_public_scope_never_commits_a_row` fails on the first assert.

### BANKED-2 (P3 hygiene, folded in)

The `record_outcome_for_scope_in_txn` doc no longer claims `identity_redirect`
draws the same incremental/rebuild division — redirect IS maintained at the sync
reconciliation chokepoint. Replaced with the ratified reasoning: consent grants
are `vault_meta`-resident and never replicate, so a replica holds no ramp
authority to be stale about and lagging counters are fail-closed; surfacing
offers from replicated rulings would be a design amendment (fold at the sync
reconcile chokepoint, as redirect does), not a fix.

### Not relitigated

Finding 3 (`replica-ramp-projection-divergence`) — rejected by the verdict with
derivation. No change beyond the comment correction above.

### Tests added (4, all red-before / green-after where constructible)

`a_door_recorded_streak_is_witnessed_by_receipts_and_survives_the_rebuild` ·
`a_retracted_offer_cannot_be_taken_by_a_stale_tap` ·
`the_rebuild_folds_in_ledger_order_not_clock_order` ·
`an_unbuildable_public_scope_never_commits_a_row`.
Module suite 14 → 18 tests. No existing assertion weakened; all five `ms06_*`
oracles still armed and green.

### Gates

`cargo fmt --all` clean · `cargo clippy -p oneiron --all-features --all-targets`
clean (zero warnings) · `cargo test -p oneiron --all-features` GREEN: 3535 lib
tests + every integration binary, 0 failed (merge_split_oracle 21 passed / 3
ms07 parks). One full-suite run before that flaked on
`batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`
— a wall-clock second-boundary race in the authority-fold sidecar migration,
untouched by this diff, green in isolation and green on the re-run (flake guard
applied, charged to no lane).

### Packet

Unchanged from the impl round plus two notes:
- `consent.rs` — the declared PACKET_AMEND now covers three additive `pub(crate)`
  doors (`standing_grant_is_active_in_txn`, `revoke_standing_grant_in_txn`,
  `create_standing_grant_in_txn`); the third is an extraction of the existing
  public door's body, which keeps its exact semantics.
- `identity_topology.rs` — one visibility widening
  (`read_identity_topology_seq_in_txn` → `pub(crate)`) beside the lane's single
  call site. Chosen over duplicating the seq-key decode in
  `consent_graduation.rs`, which would drift silently if the encoding changed.
- `receipt.rs` stays additive: the only edit this round renames the ONE
  registered projector call (`demotion_receipts` → `ramp_receipts`).
- `store.rs` untouched · `outbound_grant.rs` untouched · no `Cargo.toml` /
  `Cargo.lock` change · no `git add -A` · no push, no merge.
