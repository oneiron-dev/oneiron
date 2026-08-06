# WORKLOG — ONE-1789 [CAL-07] event outcome machinery

Branch `ONE-1789`, cut off `origin/main` 8225cec4f (ONE-1782 + ONE-1791 merged, flat).
Blueprint: `/Users/olety/.claude-wave5/blueprints/CAL/ONE-1789.md`.

## Packet (as built)

CREATE
- `/Volumes/Cinema/w5-lt/cal-1789/crates/oneiron/src/calendar/outcome.rs`
- `/Volumes/Cinema/w5-lt/cal-1789/crates/oneiron/tests/calendar_outcome.rs`

MODIFY
- `/Volumes/Cinema/w5-lt/cal-1789/crates/oneiron/src/calendar/mod.rs`
- `/Volumes/Cinema/w5-lt/cal-1789/crates/oneiron/src/calendar/claims.rs`
- `/Volumes/Cinema/w5-lt/cal-1789/crates/oneiron/src/inbox.rs`

Plus this worklog. No other file touched; `gate.rs` and
`tests/calendar_surface_oracle.rs` (concurrent cal-gate leg) are untouched, and
`Cargo.lock` is not committed.

## DEVIATIONS from the blueprint

### D1 (blocking, ruled by the dep-reservation law) — `plan_outcome_check_in` returns an engine-local wake

Blueprint keystone: `plan_outcome_check_in(...) -> Option<WakeEntry>` consuming
`oneiron_vault_contract::{Schedule, WakeEntry}`, with the blueprint itself noting
"`crates/oneiron` has no `oneiron-vault-contract` dependency at HEAD; the path dep is
appended by ONE-1783's shared `Cargo.toml` claim".

ONE-1783 has NOT landed (CAL frontier is `1782 → 1791 → 1789 → 1783`), so at this
commit the dependency does not exist, and `crates/oneiron/Cargo.toml` is ONE-1783's
exclusive single-writer claim (CLAIMS.md) — the dep reservation belongs to 1783, not
to this lane, and reservations are the only source of deps. Appending it here would be
a packet violation AND an unreserved dep.

Built instead: `calendar::outcome::OutcomeCheckInWake { id, at_utc, reason_tag }` — the
exact three wake fields, exact-instant by construction, documented as the 1:1 image of
`WakeEntry { id, at: Schedule::Exact { at }, reason_tag }`. The swap once 1783 lands the
path dep is one `impl From<OutcomeCheckInWake> for WakeEntry` (or a return-type change);
no call site or law changes. **PACKET_AMEND candidate (not taken):** one line in
`crates/oneiron/Cargo.toml` would have let the keystone type be used verbatim — flagged
for the orchestrator rather than absorbed.

`plan_outcome_check_in` keeps the ratified arity/order; `_event_ref` is unused at this
layer (the host wake carries only id/at/reason_tag, and the due-time recheck takes the
EVENT explicitly), and the parameter stays so the later `WakeEntry` swap and host call
sites need no edit.

### D2 (additive) — `CheckInResolution::recorded_value()`

Done-means requires the inbox check-in row to be "removed or resolved after an answer".
The row is derived from claim state (no new stored state), so a `Rescheduled` answer that
records nothing would leave the card surfacing forever. `recorded_value()` maps
`RescheduleRequested` to `{ outcome: unknown, basis: owner_attested, recorded_at }`: the
owner answered (row resolves), the outcome is still `unknown` (CA-04 gets no transition
evidence), and no fifth wire value is invented. `resolve_owner_check_in` itself keeps the
ratified pure signature and variants.

### D3 (interpretation, no signature change) — `accept_check_in_recording`

The ratified signature carries a `BlobArtifactBody` and no bytes, so this door cannot be
the append itself. It opens (idempotently) the EVENT's recording artifact and returns its
id; the upload's bytes ride the existing public append-only chain
(`Vault::append_blob_artifact_version`), per the "no second blob store" non-claim. The
artifact id is derived from the EVENT with the house helper
`entity_id_from_hash_material` (same primitive `blob_artifact.rs` uses for ASSET ids), so
EVENT↔recording resolves without a new edge, predicate, or registry row — the three
things this ticket's NON-CLAIMS forbid.

### D4 (placement) — inbox check-in projection shape

`inbox.rs` gets the additive `InboxExceptionClass::MeetingOutcomeCheckIn` variant plus
`Vault::inbox_meeting_outcome_check_ins(&[DueOutcomeCheckIn]) -> Vec<InboxCheckInException>`.
It is a sibling projection, NOT a member of the dreamer-run group projection: the existing
`InboxGroup` surface is keyed on a dreamer run's pending-consent tray, and a calendar
check-in has no run, no pending consent row, and no diff handle. Nothing in the existing
projection, classifier, dial, or bundle-verb path changed.

## Notes / rulings taken in-lane

- `PREDICATE_CALENDAR_EVENT_OUTCOME` is defined in `outcome.rs` (keystone) and imported by
  `claims.rs` for the family table + validator branch; the other twelve constants keep
  their CAL-00 home.
- Outcome claims are written through the direct claim door (`put_claim_in_txn`) with
  `ClaimApprovalStatus::Auto` and the caller's `ClaimSource`, mirroring `comm.rs`. The write
  still passes through the real gate and the real source-trust rule — nothing here routes
  around either.
- Write + supersede run in ONE `with_write_txn`, per the `supersede_claim_in_txn` contract,
  so a rejected supersession can never leave two live heads.
- Multiple live heads (should be impossible after this door) resolve lowest-claim-id-wins,
  matching CAL-09's single-cardinality contest in `calendar/query.rs`.
- The check-in row surfaces iff meeting-class ∧ no live outcome claim, so an owner answer
  or newly arrived machine evidence retracts it with no retraction bookkeeping.

## Found while building (both pinned by the oracle)

1. **Out-of-order evidence would have wedged the supersede.** `supersede_claim_in_txn`
   closes the prior head at the instant the caller passes and refreshes its envelope to
   `{old_start, now}`. CAL-08's transcript path supersedes an owner answer with evidence
   *observed during the meeting*, i.e. an EARLIER `recorded_at` — which inverts the window
   and the engine rejects the whole write. Fixed at the door:
   `closed_at = value.recorded_at.max(old_value.recorded_at)`. Mutation-verified — reverting
   the clamp fails `event_outcome_supersedes_prior_live_claim_without_deleting_history`
   with a hard error on the late write, not a soft assertion.
2. **Source trust rules on the outcome head.** Recording with `ClaimSource::Imported`
   (or tool_output / generated) is refused `SourceNotTrustedForAuto` unless the manifest
   carries an explicit Auto permit. Kept as-is and pinned in
   `pre_start_cancel_records_cancelled_pre_start_and_skips_grace_card`: a loud refusal beats
   parking an outcome the read path cannot see. CAL-02's importer inherits this seam.

## Inherited hole (NOT owned by CAL-07, no fix attempted)

`gate::default_policy_manifest()` has no `calendar.` rule, so on a default-seeded vault
EVERY calendar claim write — including this one — is gate-pending
(`gate.pending.criticality_floor`). CAL-09 already pins this
(`calendar_claims_are_gate_pending_under_the_default_policy_manifest`); the fix is one
manifest rule in `crates/oneiron/src/gate.rs`, a lane-wide CAL non-claim currently owned by
a concurrent cal-gate leg. `tests/calendar_outcome.rs` therefore runs on
`Vault::open_unseeded_for_test`, exactly like the CA-01 gate oracle, and says so in its
module doc.

## Gates

- `cargo fmt --all -- --check` clean; `cargo clippy -p oneiron --all-features --all-targets`
  clean (zero warnings).
- `cargo test -p oneiron --all-features --test calendar_outcome` — 18 oracles green (the 17
  named in the blueprint plus the grep oracle the done-means asks for).
- `cargo test -p oneiron --all-features` (full, 3526 lib + all integration bins) green.
- Observed flake, charged to no lane:
  `batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once` went red
  once in a back-to-back double suite run and green 3/3 on re-run plus green in the other
  full runs. It asserts `migrated >= observed_before` where both sides are
  `unix_seconds_now()` — a wall-clock assertion in the sync/authority fold, no calendar,
  inbox, or claim-family code in its path.
