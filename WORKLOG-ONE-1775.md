# WORKLOG — ONE-1775 [CA-04] stage ladder machinery

Worktree: `/Volumes/Cinema/w5-lt/ca-1773` · branch `ONE-1775` off `origin/main`
9d61c66f4 (1776 #623 + 1789 #602 merged — dispatch gate / formal edge #10
satisfied).
Blueprint: `/Users/olety/.claude-wave5/blueprints/CA/ONE-1775.md`.
Claims: `/Users/olety/.claude-wave5/blueprints/CA/CLAIMS.md`.

## Packet — exact, no amendments

CREATE
- `crates/oneiron/src/campaign/stage.rs`
- `crates/oneiron/tests/campaign_stage_ladder_oracle.rs`

MODIFY
- `crates/oneiron/src/campaign.rs` — module declaration + doc comment ONLY
  (collision order `1774 -> 1777 -> 1776 -> 1775` honored; 1776 is the parent
  commit).

`git diff --name-only origin/main...HEAD` is exactly those three paths plus this
worklog.

Explicitly NOT touched: `campaign/claims.rs` (CA-01 interfaces imported —
`CrmStageValue`, `StageKey`, `StageEvidenceClass`, `EvidenceBasis`,
`CampaignMemberValue`, both encoders, `supersede_crm_stage_in_txn`,
`decode_*_value`), `comm.rs` / `comm/tests.rs`, `claim.rs`, `calendar/**`
(`EventOutcome`, `EventOutcomeClaimValue`, `read_event_outcome`,
`PREDICATE_CALENDAR_EVENT_OUTCOME`, `project_event_outcome`,
`record_event_outcome` all imported), `attempt_queue.rs`,
`dreamer_runner.rs`, `campaign/presets.rs`, `registry.rs`, `store.rs`,
`vault.rs`, `lib.rs`, `task_verb.rs`, `Cargo.toml`, `oneiron-docs/`.

`Cargo.lock` was ALREADY dirty in the worktree on arrival; never staged, not in
any commit.

**PACKET_AMEND candidates: none.**

## Gates

- `cargo fmt -p oneiron` clean.
- `cargo clippy -p oneiron --all-features --all-targets` clean, zero warnings.
- `cargo check -p oneiron --all-features` clean.
- `cargo check -p oneiron` (default features) clean apart from ONE pre-existing
  warning, charged to no lane: `dead_code` on
  `crates/oneiron/src/batch.rs:4388 facet_of_endpoints_provably_off_table`
  (`batch.rs` is not in this diff; the warning is on the base commit).
- `cargo test -p oneiron --all-features -j 6`: **50 test binaries + doctests,
  0 failed.**
- `cargo test -p oneiron --all-features --test campaign_stage_ladder_oracle`:
  **17 passed.**

Source scans from the blueprint's done-means, both empty as required:
- `rg -n "struct CrmStageValue|enum EvidenceBasis|enum StageEvidenceClass|struct StageKey|enum CalendarEventOutcome|struct CalendarEventOutcomeValue|enum EventOutcomeRead|SilentUnknown" crates/oneiron/src/campaign/stage.rs` → no matches.
- `rg -n "ENTITY_TYPE_|register_structural_kind|TypeByteBand" crates/oneiron/src/campaign/stage.rs` → no matches. No byte, no registry row, no registration path.

## Done-means checklist

| Blueprint bullet | Where |
|---|---|
| `campaign.rs` exports `stage`; `cargo check` clean with no edits to `comm.rs` / `claim.rs` / calendar / queue / registry | packet section above |
| `cargo test --test campaign_stage_ladder_oracle` passes | 17 tests |
| `cold_membership_never_creates_crm_stage` | present |
| `positive_now_reply_auto_promotes_with_message_evidence` | present |
| `propose_mode_is_a_dial_not_a_gate` | present |
| `positive_later_snoozes_and_reenters_at_touch_one` | present (+ `reentry_rides_the_existing_enrollment_attempt_kind` for the CA-03 half) |
| `warm_reconnect_requires_real_prior_evidence` | present |
| `held_outcome_is_required_for_call_held` | present |
| `silent_outcome_is_none_and_projects_unknown` | present |
| `explicit_unknown_never_promotes` | present (also covers `cancelled_pre_start`) |
| `no_show_routes_same_day_d3_then_snooze` | present |
| `replacement_stage_supersedes_prior_head` | present — see finding F1 |
| `coded_and_external_ingress_use_projector_only_path` | present |
| `owner_attested_is_allowed_only_after_proposal_sent` | present — see deviation D3 |
| `deposit_and_desk_hooks_do_not_mint_source_truth` | present |
| both source scans | above |

Tests added beyond the checklist: `a_self_contradicting_ladder_is_rejected`,
`an_unrouted_code_and_an_unconfigured_transition_are_not_errors`,
`complaint_and_exit_reuse_campaign_member_state`,
`reentry_rides_the_existing_enrollment_attempt_kind`.

## Blueprint deviations — all declared, none silently absorbed

### D1 — `StageEvidence` cannot derive serde (compile-blocking skeleton defect)

The keystone skeleton spells
`#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] pub struct StageEvidence { .. evidence_refs: Vec<EntityId> .. }`.
`EntityId` has **no serde impl** (`crates/oneiron/src/entity_id.rs:9` derives
`Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash` only), and the
blueprint itself states this at its `CrmStageValue` note. The derive does not
compile.

Shipped: `StageEvidence` derives `Debug, Clone, PartialEq, Eq`. Every other
skeleton type keeps its ratified derive list verbatim — `PromotionMode`,
`StageDefinition`, `StageTransitionRule`, `ReplyCode`, `ReplyDisposition`,
`ReplyRouteRule`, `NoShowRecoveryRule`, and `StageLadderDefinition` are all
serde-derived exactly as written (they compose only `String`, `bool`, `u64`, and
CA-01's serde-derived token types), so the ladder DEFINITION — the thing
ONE-1779 will load from host config — still round-trips.

### D2 — `ReentryPlan` gains one OPTIONAL field so `snooze_with_wake` can actually call CA-03

Ratified invariant: `snooze_with_wake` "preserves the existing channels and
optional `derivation`, **then calls the CA-03 enqueue surface** using
`"campaign.enrollment.macro"`".

CA-03's enqueue surface at HEAD is
`CampaignEnrollmentRunner::enqueue(&CampaignEnrollmentAttemptPayload { membership_event_ref, campaign_program_ref, program_step_ref }, run_id, now)`.
The ratified `snooze_with_wake` signature carries none of those three refs, the
ratified `ReentryPlan` carries none of them, and they cannot be derived from the
vault: `campaign_program` is keyed by `program_ref` (no campaign→program index
exists) and `CampaignEnrollmentEvent` rows are written only by CA-03's private
`put_event` behind `detect_enrollment`. The seam is UNDERDEFINED.

Proposed amendment, shipped: one additive field
`pub reentry_attempt: Option<CampaignEnrollmentAttemptPayload>`. All five
ratified fields keep their names, types, and order. `Some(..)` makes the ratified
sentence true — the attempt is vetted through CA-03's own
`enrollment_dedupe_key` door and then enqueued through
`CampaignEnrollmentRunner::enqueue`. `None` is required rather than gold-plating:
`apply_coded_reply`'s Snooze route builds its plan from a `CodedCommReply`, which
names no program, so a mandatory field would have walled the reply path outright.

CA-04 still mints no timer, no recurrence primitive, and no attempt kind; the
kind is re-exported from CA-03 (`CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND`) so a
caller cannot spell a second one.

### D3 — the owner-attestation boundary is DERIVED from the ladder, not spelled

Ratified: "`OwnerAttested` is accepted only when the transition is strictly after
`proposal_sent` and its rule permits it." A literal `"proposal_sent"` in
`stage.rs` would put consultancy stage content in the engine, which CLAIMS.md
prohibits ("No engine-owned consultancy template body text… ONE-1779 ships the
preset shape and loader only") and which the blueprint restates ("Do not place
consultancy strings or desk rhythm content in this layer").

Derivation used instead: the blueprint defines `proposal_sent` as the stage that
"consumes a document artifact plus send receipt", so the earliest stage entered
by a `StageEvidenceClass::DocumentArtifactAndSendReceipt` transition IS the
boundary, and "strictly after" is a position comparison in the declared
`stages` order. `require_owner_attestable` enforces
`rule.owner_attested_allowed && stage_index(rule.to) > proposal_boundary_index`.
A ladder declaring no such transition has nothing to attest past and refuses
owner-attested evidence.

The oracle is deliberately non-tautological: the test ladder sets
`owner_attested_allowed: true` on `replied -> call_booked`, and the position rule
still refuses it — a ladder may withhold attestation from a late stage but cannot
grant it to an early one.

### D4 — `validate_ladder` adds a `(from, evidence_class)` uniqueness rule

`apply_event_outcome` cannot name `call_held` (D3's reason), so it selects the
held transition by `(current stage, CalendarEventOutcome)`. Two transitions
leaving one stage on the same evidence class would make that selection
arbitrary, so the definition validator rejects it alongside the duplicate
`(from, to)` rule. Both are "this definition contradicts itself" checks, not
process opinions; nothing else was added — a ladder with no head-earning
transition, or a zero bump delay, are configuration choices and pass.

### D5 — `PromotionMode::Propose` writes a `Proposed` head and does NOT supersede

Nothing has been decided under the dial, so superseding the prior head would
promote by another name, and discarding the proposal would make Propose a no-op.
Shipped: the same canonical value lands `ClaimApprovalStatus::Proposed` +
lifecycle `Active`, and resolution belongs to the crate's EXISTING claim-approval
machinery. CA-04 mints no second approval mechanism.

Declared consequence: while a proposal is outstanding, the party carries two
lifecycle-active `crm.stage` heads for that campaign, so the next AUTO promotion
fails closed on the head check rather than silently discarding one of the two.
That is the honest outcome of a genuine contest; AUTO callers never reach it.

### D6 — resolving the outcome CLAIM reference

The blueprint requires `apply_event_outcome` to "resolve and retain the live
outcome-claim reference as evidence", but CAL-07's ratified reader returns the
VALUE (`Result<Option<EventOutcomeClaimValue>>`), not the claim id.
`live_event_outcome_claim` resolves it through the public claim surface
(`claims_for_subject_in_txn` + `get_claim_in_txn`) filtered on CAL-07's public
`PREDICATE_CALENDAR_EVENT_OUTCOME`, ordered by `(valid_from, claim_id)` — which
mirrors CAL-07's own `(recorded_at, claim_id)` contest rule, since
`record_event_outcome` pins `valid_from = value.recorded_at`. No CAL-07 file is
touched, no reader is shadowed, and no second outcome decoder exists.

## Findings

**F1 — CA-01's stage-CAS rejection branches are unreachable from CA-04 ingress
(by design, not a gap).** `supersede_crm_stage_in_txn` has two rejection paths
("expected head is not current", "first head is not the only head") that a CA-04
call can never reach: every ingress reads the live head itself through
`live_stage_head`, which rejects a torn `(party, campaign)` first — earlier and
cheaper, before any claim is written. `replacement_stage_supersedes_prior_head`
therefore proves the property that matters (two writes → one live head, the
older `Superseded` and still readable; a planted competing head makes the next
promotion fail closed with the total claim count unchanged) rather than
pretending to exercise an unreachable branch. CA-01's happy-path supersession IS
exercised on every AUTO promotion.

**F2 — duplicated "replace a `campaign.member` head in one txn" primitive.**
`campaign/send_hygiene.rs` (CA-05) has a private `replace_member_head_in_txn`;
`campaign/stage.rs` now has a private `replace_member_state` doing the same
~25-line job for pause/exit/suppress. CA-04 cannot claim `send_hygiene.rs`, and
`campaign/claims.rs` is CA-01's (`1772 -> 1776` writer order, closed). Candidate
for one shared CA-01 helper in a later lane; not a PACKET_AMEND, since no file
outside this packet was touched.

**F3 — fixture clock ordering is load-bearing for stage tests.** The first oracle
run failed three tests with `InvalidTimeRange` because the booking hook's
`recorded_at` sat AFTER the calendar outcome's: superseding a head with evidence
recorded before it writes an inverted validity window. The fixture now times
evidence in ladder order (`REPLY_AT < BOOKING_AT < OUTCOME_AT < PROPOSAL_AT <
DEPOSIT_AT`). Worth knowing for ONE-1779's preset fixtures — this is a property
of the claim layer, not of CA-04.

**F4 — pre-existing default-features `dead_code` warning** on
`batch.rs::facet_of_endpoints_provably_off_table`. Not in this diff; charged to
no lane. Flagged because `cargo check` without `--all-features` is a recipe step.

## Known holes

**H1 — the CA-03 enqueue SUCCESS path is not exercised by this oracle.** Minting
a resolvable `CampaignEnrollmentEvent` requires `detect_enrollment` behind a full
`SavedQueryEvaluator` + `SavedQueryRecord` fixture (that is
`campaign_enrollment_oracle.rs`'s subject, ~150 lines of fixture). CA-04 proves
the call goes through CA-03's door by its REFUSAL — an unresolvable
`membership_event_ref` returns `Error::EntityNotFound` from CA-03's
`enrollment_dedupe_key` with the membership head untouched — plus the attempt
kind re-export identity. ONE-1779 will hold real preset + program fixtures and is
the cheap place to close this.

**H2 — `MembershipProvenance::trigger_evidence_refs` and
`CodedCommReply::thread_ref` are carried, not read.** Both are ratified fields
whose consumers are copy/rendering surfaces outside this layer. Kept verbatim
rather than trimmed, per the ratified shape.

## Laws honored (spot list)

- `member (cold)` is not a `crm.stage`: `route_membership_lane` writes nothing
  and returns a LANE; the first head needs configured transition evidence.
- Default promotion AUTO; Propose is a per-call dial, never a wall.
- Every accepted transition carries non-empty `evidence_refs` and a named
  `evidence_class`; the projector rejects an empty list at its own door and
  CA-01's decoder rejects it again at the write door.
- `crm.stage` stays projector-only: `project_stage_transition` is `pub(crate)`,
  so no external caller can name it, and `apply_coded_reply` /
  `apply_external_stage_evidence` / `apply_event_outcome` never call
  `put_claim` or `supersede_claim` for `crm.stage` — the replacement write and
  the prior head's supersession share ONE txn through
  `supersede_crm_stage_in_txn`.
- Coded replies consume already-projected comm replies as typed
  `CodedCommReply`; six ratified codes only; the LADDER decides every
  disposition (no hidden code→action mapping in Rust).
- Complaint/suppression reuses CA-01 `CampaignMemberState::Suppressed`; no new
  suppression primitive.
- Warm/cold is evidence-based: a blank thread token falls back to `Cold`, and a
  real thread / relationship reference rides the `WarmReconnect` lane.
- Snooze writes CA-01's exact `campaign.member` value with
  `paused { until?, new_trigger? }` (≥1 set, both for `AtOrNewTrigger`),
  preserving channels and optional `derivation`; re-entry restarts at touch 1
  (a non-zero `restart_touch_index` is rejected) and retains the reason
  evidence ref.
- Calendar outcomes read-side only: silence is `None` → Unknown, never `Held`;
  `no_show` emits `[SameDayReschedule, BumpAfter, Snooze]` in the ratified order
  and writes no held stage; `cancelled_pre_start` / explicit `unknown` / silence
  never advance.
- Deposit/desk are evidence hooks: the deposit hook adds exactly one claim, and
  it is a `crm.stage` carrying only the ledger REFERENCE.
- No new entity/type byte, registry row, timer, recurrence primitive, attempt
  kind, scheduler, or approval gate.

## SIMPLIFY pass (K3, 2026-08-07)

One bounded deletion-biased pass over the impl tip. Verdict: the impl leg was
already tight — no dead code, no speculative generality, no defensive branches
beyond the two declared chokepoint guards (empty-evidence at the projector
door, kept: it is THE single `crm.stage` write door, not a call-site), and the
doctrinal doc comments carry the ratified laws, so they stand.

One edit, duplication removal only:

- `stage_position()` helper extracted: the three projector callers
  (`promote_from_reply`, `promote_on_held`, `apply_external_stage_evidence`)
  each repeated the same two-step read of the live head — `live_stage_head`
  then split into `(previous_stage_claim_ref, from)`. That triple must stay in
  sync by construction, so it now has one home. Net: +14 / −9 lines, no public
  API, no test, no behavior change.

Explicitly NOT done (with reasons):

- Test file untouched per fixture-sync law (no assertion/fixture edits).
- `elapsed` / `at` / `declares` one-liners kept: they compress and name intent
  at their call sites; deleting them would trade clarity for line count.
- The `require_owner_attestable` undeclared-stage branch kept: unreachable
  after `validate_ladder`, but removing it would need an `expect` in non-test
  code — worse than the guard.
- The projector's empty-evidence guard kept (chokepoint, see above).

Gates re-run after the edit: `cargo fmt` clean, `cargo clippy -p oneiron
--all-features --all-targets` zero warnings, `cargo test -p oneiron --test
campaign_stage_ladder_oracle` 17/17 passed.
