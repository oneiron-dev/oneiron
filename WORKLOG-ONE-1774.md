# WORKLOG — ONE-1774 [CA-03] Enrollment consequence-writer = MACRO home-node job kind

Lane: CA · Chain CA-A, layer L4 of 4 (`1771 → 1772 → 1773 → 1774`).
Worktree: `/Volumes/Cinema/w5-lt/ca-1773` · Branch: `ONE-1774`.
Base: `33c02b331` (`origin/main` at cut time — `ONE-1773` merged as #605). base=main,
no stacking. The inherited `gate.rs` GATE edge is satisfied (`ONE-1728`, `ONE-1772`
merged) and `gate.rs` is NOT claimed by this lane.

## PACKET

| Path | Action |
|---|---|
| `crates/oneiron/src/campaign/enrollment.rs` | CREATE |
| `crates/oneiron/tests/campaign_enrollment_oracle.rs` | CREATE |
| `crates/oneiron/src/campaign.rs` | MODIFY (one `pub mod enrollment;` declaration) |
| `WORKLOG-ONE-1774.md` | CREATE (wave convention; every CA/w5 lane ships one at the repo root) |

`git diff --name-only origin/main...HEAD` is exactly those four paths. No
`dreamer_runner.rs`, `attempt_queue.rs`, `outbound_intent_ledger.rs`,
`outbound.rs`, `outbound_chokepoint.rs`, `gate.rs`, `saved_query.rs`,
`campaign/claims.rs`, `registry.rs`, `lib.rs`, `Cargo.toml`, or `Cargo.lock`
change. No new entity/type byte, registry row, scheduler, timer, recurrence
primitive, approval gate, or attempt kind beyond `campaign.enrollment.macro`.

## What landed

### Home-node designation (campaign-local)

`CampaignHomeNodeCandidate` / `CampaignHomeNodeClass` / `CampaignHomeNodeDesignation`
plus `elect_campaign_home_node_designation`, `campaign_home_node_designation`,
`require_campaign_home_node`, `local_campaign_home_node_candidate`. Election is
attached-cloud → always-on-local → primary-device, lowest stable node id inside a
tier; a DETACHED cloud node is ineligible rather than demoted; an empty or
all-ineligible set CLEARS the row. Persistence is `campaign:home_node_macro:v1`
only — the Dreamer's `dreamer:home_node_macro:v1` is never read or written
(oracle asserts `DreamerRunnerStore::home_node_designation()` stays `None` across
a campaign election). The selector is a minimal local copy of the
`dreamer_runner.rs` shape, per the ratified seam law.

### The persisted enrollment event

`CampaignEnrollmentEvent` (`campaign:enrollment_event:v1:<event_ref>`) carries
`{query, campaign, entity, owner_actor, epoch, valid_at, detected_at, transition,
cause, evidence_hash, definition_version, scope_digest}`. It is written ONLY by
`detect_enrollment`, which re-evaluates through ONE-1773 under the saved query's
own owner actor, mints the epoch from `next_membership_epoch`, and derives the
cause. `CampaignEnrollmentEvent::membership_event()` projects onto ONE-1773's
`MembershipEvent`; this module owns the durable row, not the event shape.

**Cause derivation** compares the current `(definition_version, effective-scope
digest)` against a `campaign:enrollment_context:v1:<query><entity>` row written in
the SAME txn as the event: definition moved → `DefinitionChange`; else scope moved
→ `ScopeChange`; else `DataChange`. Precedence is definition > scope > data
because a definition move can also move the effective scope and the more specific
explanation is the honest one. No filter, matcher, evidence-hash, or memo logic is
duplicated here — the digest is over `QueryScope::intersect`, and the verdict comes
from `SavedQueryEvaluator`.

### Campaign program state

`CampaignProgram` (`campaign:program:v1:`) and `CampaignProgramStep`
(`campaign:program_step:v1:`) with `put_/read` doors. The step is the single
persisted source for BOTH halves of the consequence: the CA-01 channel row
(`channel`, `basis_evidence`, `sender_ref`) and the optional outward leg
(`call_seq`, `verb`, frozen `payload`, `idempotency_supported`). CA-01 rejects a
channel-less `campaign.member`, so enrollment without a resolvable step fails
closed rather than writing an unreachable member.

### Payload, dedupe, runner

`CampaignEnrollmentAttemptPayload { membership_event_ref, campaign_program_ref,
program_step_ref }` — three refs and a schema version, nothing else. The wire form
is pinned by both an inline test and the oracle: any extra key (including a
smuggled `cause`) is rejected by the decoder, not ignored.
`enrollment_dedupe_key` hashes the persisted `(query, entity, epoch)` and is
documented and TESTED as hygiene only.

`CampaignEnrollmentRunner::{new, enqueue, claim_if_home, execute_claimed}`.
`claim_if_home` checks the designation BEFORE touching the queue, so a refused
claim leaves the row available to the designated worker. `execute_claimed`:
kind check → designation check → decode payload → resolve + cross-bind event /
program / step → route on the PERSISTED cause (`data_change` auto-applies;
`scope_change` / `definition_change` → `ReviewRequired`) → transition check →
live re-derivation through ONE-1773 (verdict must still be `Match` AND the
evidence hash must still match, else `SkippedStale`) → **designation re-checked
immediately before the write** → `commit_membership_plan`.

### Outward leg

`derive_enrollment_outbound_request` builds `OutboundCallRequest` from the durable
attempt id plus the persisted step's `call_seq`; `run_enrollment_outbound_leg`
hands a `PreparedEffect` to `outbound_chokepoint::execute_outbound_effect` — the
crate's only production lane combining governance, budget, the ONE-1691 ledger,
and transport. No connector is touched, no second ledger or idempotency scheme
exists, and the gate is preserved (an ungranted verb is refused with no send and
no frozen intent). The leg is self-contained over the attempt record, so crash
recovery re-enters it directly; `EnrollmentExecution::{Applied, AlreadyApplied}`
report the deterministic `IntentId` so a crash between the cohort write and the
intent record still converges on one send.

## Tests

- `crates/oneiron/src/campaign/enrollment.rs` — 14 in-crate tests (election order
  and rejection, campaign-key-only persistence, malformed-row fail-closed,
  refs-only payload, intent-before-transport with a ledger-reading transport
  fixture, ambiguous-send replay reusing the frozen intent, absent outward leg,
  foreign kind, mismatched refs, gate rejection, unresolvable ref, exact kind).
  The outward-leg arms live in-crate because `OutboundTransport` is `pub(crate)`.
- `crates/oneiron/tests/campaign_enrollment_oracle.rs` — 12 public-surface
  oracles, one per Done-means bullet that is reachable publicly:
  `campaign_attempt_kind_is_exact`,
  `campaign_home_node_election_matches_preference_order`,
  `campaign_designation_uses_only_campaign_vault_meta_key`,
  `non_home_node_cannot_claim_enrollment`,
  `leadership_is_rechecked_before_consequence_write`,
  `enrollment_payload_is_refs_only_and_not_trusted_membership`,
  `runner_derives_cause_and_outbound_request_from_persisted_state`,
  `data_change_entered_event_auto_enrolls`,
  `scope_and_definition_changes_require_review_not_auto_write`,
  `advisory_dedupe_is_not_correctness`,
  `same_epoch_reexecution_is_already_applied`,
  `older_epoch_cannot_overwrite_newer_epoch`.

Gates: `cargo fmt` clean · `cargo clippy -p oneiron --all-targets --all-features
-D warnings` clean · `cargo test -p oneiron --all-features` green (3626 lib +
every integration binary, 0 failures).

## Blueprint deviations (declared, none silently absorbed)

1. **`membership_event_ref` resolves to a CA-03-owned row, not a ONE-1773
   entity.** The blueprint types it `EntityId` and says the runner "resolves the
   membership event". As landed, ONE-1773 keys membership events by
   `(query, entity, epoch)` in `vault_meta` and writes them only INSIDE
   `commit_membership_plan` — so no addressable pre-commit event exists. CA-03
   therefore persists its own event row under a minted `EntityId`; the payload
   field name and type are unchanged.
2. **A detection door (`detect_enrollment`) was added.** It follows from (1):
   something engine-owned must mint the epoch, derive the cause, and persist the
   event before an attempt can reference it. Pinning the epoch AT DETECTION is
   what makes a retry land on the same epoch/content and report `AlreadyApplied`
   instead of writing a second cohort row one epoch later — re-minting at
   execution would have broken `same_epoch_reexecution_is_already_applied`.
   Neither this door nor `enqueue` accepts a cause, epoch, evidence hash,
   enrolled flag, or outbound request.
3. **`CampaignProgram` / `CampaignProgramStep` are minted here.** The blueprint
   requires deriving the outward request from "persisted campaign/program-step
   state, including its durable `call_seq`", and nothing in the tree persists
   campaign-program state (CA-04/ONE-1775 owns `campaign/stage.rs`, not this).
   The rows are minimal, campaign-local, and inside the claimed file: no pack
   manifest runtime, no loader, no generic campaign primitive.
4. **`CampaignProgramOutbound.idempotency_supported`** was added to the step so
   the chokepoint's idempotency hint comes from persisted program state rather
   than a hard-coded assumption.
5. **Rows are canonical JSON via `serde` (`deny_unknown_fields`) with hex refs,**
   not the MessagePack derive the blueprint sketch implies: `EntityId` has no
   `Serialize`/`Deserialize` impl, and `saved_query.rs` already uses canonical
   JSON for its own rows. Strictness is preserved (unknown key, duplicate key,
   wrong schema version, bad token, zero node id all fail closed — tested).
6. **`require_campaign_home_node` returns `CampaignHomeNodeAdmission`,** and
   `claim_if_home` returns `CampaignEnrollmentClaim`, rather than a `NotHomeNode`
   error. `error.rs` is not in the CA claim manifest, so no error variant could be
   minted; the typed enums keep the distinction the acceptance bullet asks for
   (mirrors `DreamerConsolidationAdmissionOutcome`).
7. **`EnrollmentExecution` gains `NotHomeNode(..)` / `NoHomeNode`** for the same
   reason — the pre-write designation re-check needs a reportable outcome.
8. **The outward bridge is
   `run_enrollment_outbound_leg(vault, authority, attempt, transport, now_ms)`,**
   not `dispatch_enrollment_outbound(vault, request)`. The production door
   (`execute_outbound_effect`) requires a gate input, an `OutboundBindingAuthority`,
   and a caller-supplied transport; the blueprint signature cannot reach it. Keeping
   the leg self-contained over the attempt record is also what makes the
   crash-after-claim recovery path a single call. It stays `pub(crate)` per the
   blueprint.
9. **`derive_enrollment_outbound_request` takes `&CampaignEnrollmentEvent` and
   `now_ms`** in addition to the blueprint's arguments — the campaign cross-bind
   the blueprint itself demands ("mismatched refs fail closed") is not decidable
   from the payload alone.
10. **Cause routing reads the PERSISTED cause on the event row**, derived at
    detection. The blueprint says both "derives the current cause" and "whose
    persisted cause is `data_change`"; every acceptance bullet tests the persisted
    reading, so that is what execution routes on.

**PACKET_AMEND candidates: none.** Every source change is inside the three claimed
paths; `WORKLOG-ONE-1774.md` follows the standing wave convention (worklogs live at
the repo root on `main`).

## Known holes / follow-ups

- `run_enrollment_outbound_leg` has no production caller yet — the host driver
  that pumps this queue is ONE-1778 surface work. It carries
  `#[cfg_attr(not(test), allow(dead_code))]`, the same posture `gate.rs` takes for
  crate-visible effect surfaces exposed ahead of their call sites.
- The gate input asserts `has_opted_in` / `has_permission` from the program step's
  own consent basis and sticky sender. That is an assertion about persisted state,
  not a decision — the gate remains the authority. CA-06 (`ONE-1777`) owns
  tightening this posture; no per-lead approval gate was added for ordinary
  `data_change`.
- `cargo clippy --workspace` fails on `oneiron-seal` with
  `sha2::digest::generic_array::GenericArray::as_slice` deprecated. That crate is
  untouched by this lane and the failure reproduces on the unmodified tree —
  pre-existing main defect, charged to no lane.
- Exit consequences are out of scope: `detect_enrollment` records `Entered`
  transitions and `execute_claimed` answers `SkippedStale` for anything else.
  The `Exited` write path is exercised through ONE-1773's own commit door.
