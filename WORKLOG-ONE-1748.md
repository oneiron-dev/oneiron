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
