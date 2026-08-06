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

## Simplify pass (K3)

Deletion-biased pass over the impl tip; public API, test assertions, and
fixtures untouched. Three internal-only reductions in
`crates/oneiron/src/campaign/enrollment.rs` (−29/+18):

1. **Deleted the local `hex_lower` helper** (and its `std::fmt::Write` import) —
   it duplicated the crate-shared `entity_id::bytes_to_hex_lower`, which was
   already imported and in use for the dedupe key. All four encode sites now go
   through the shared implementation.
2. **Extracted `program_step_key`** next to the existing `context_key`, removing
   the duplicated `keyed(CAMPAIGN_PROGRAM_STEP_PREFIX, …)` construction in the
   step put/read doors.
3. **Bound `event.membership_event()` once** in `execute_claimed` instead of
   projecting it twice into the write plan.

Rejected candidates: the O(n²) duplicate-id scan in `select_campaign_home_node`
(candidate sets are ≤ a handful of nodes; a HashSet adds an import and churn for
nothing), the double `home_node_refusal` in `execute_claimed` (load-bearing —
the pre-write re-check is the ratified correctness mechanism), and the
ref-resolution overlap between `derive_enrollment_outbound_request` (public API)
and `run_enrollment_outbound_leg` (`pub(crate)` dispatch leg) — merging them
would change structure, not delete it.

Gates after the pass: `cargo fmt` clean · `cargo clippy -p oneiron --all-targets
--all-features -D warnings` clean · 12/12 oracle + 18/18 in-crate enrollment
tests green.

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

## VERDICT-FIX

Five verdict-verified REAL findings, each fixed at its chokepoint and each
mutation-verified (test written first, observed red on the pre-fix tip
`b1970a1ee`, green after). The two BANKED-REJECT items
(`frozen-intent-recovery-drift`, `home-node-check-toctou`) were not relitigated.

### P1 `cause-routing-review-bypass` — `enrollment.rs` cause baseline
`derive_cause` compared each detection against a per-ENTITY row written at the
previous DETECTION. That let a bulk move launder itself twice over: the row
advanced the instant a `DefinitionChange` was detected, so the next detection
under the same unreviewed definition read `DataChange` and auto-enrolled the
very change routed for review; and an entity the moved definition just swept in
has no row at all, and an absent row could only read as `DataChange` — the
population review exists for was exactly the population that skipped it.

Fix: one baseline row per QUERY (`campaign:enrollment_baseline:v1:<query>`)
holding the derivation state the owner last ACCEPTED, plus
`accept_enrollment_baseline(vault, event)` as the engine half of the review. A
query with no baseline pins one on first detection (nothing prior could have
moved). The per-entity context row and its two-put txn are deleted — the
per-query baseline subsumes them.

The acceptance door is not gold-plating: `ReviewRequired` with nowhere for a
ruling to land turns the ratified routing DIAL into a wall, since every later
detection under a moved definition would report the move forever. Presenting the
review stays ONE-1778 surface work; only its durable effect lives here.

Oracle: `a_definition_move_cannot_launder_itself_into_data_change` (second
sighting, swept-in newcomer, and the post-acceptance return to automatic).
Red-before: `left: DataChange, right: DefinitionChange`.

### P1 `duplicate-attempt-double-send` — outward identity scope (PACKET_AMEND)
ONE-1691 derives an intent from `(attempt_id, call_seq, server, tool,
payload_hash)` and dedupes sends by it, so whatever is passed as `attempt_id`
IS the definition of "the same send". Passing the queue row id made the send
identity a function of how many times the work was enqueued — and this module
tolerates duplicate attempts by design (dedupe is advisory) while
`AlreadyApplied` still owes its outward leg, so two rows minted two frozen
intents and sent the same enrollment twice.

Fix: `enrollment_consequence_id(event, step)` derives the ledger identity from
the consequence — `(query, entity, epoch)` (the watermark's own unit of
membership) plus campaign, program, and step. `derive_enrollment_outbound_request`
consequently no longer takes the `AttemptRecord` at all.

**PACKET_AMEND note for the record:** this departs from the blueprint's literal
"derives `OutboundCallRequest.attempt_id` from the durable queue attempt id"
(R2-18 / A16). Every property that phrase was protecting still holds — no clock,
no process counter, stable across restart, derived from persisted state only —
but the identity is now scoped to the consequence rather than the queue row,
which is what keeps advisory dedupe off the correctness path.

Test: `duplicate_attempts_for_one_transition_send_once`. Red-before: two distinct
intent ids for one transition.

### P1 `outbound-home-node-bypass` — `run_enrollment_outbound_leg`
The membership leg checked designation twice; the outward leg had no node
parameter and checked nothing. Because the leg is documented as the SELF-
CONTAINED crash-recovery entry point, no caller sequencing can cover it: a node
can apply the cohort row while designated, lose designation, and come back for
the send.

Fix: the leg takes `local_node_id` and re-reads the designation itself before
any ledger record or transport call, returning the new `EnrollmentOutboundLeg`
enum (`Dispatched` / `NoOutboundStep` / `NotHomeNode` / `NoHomeNode`) — the same
vocabulary the membership leg already answers in.

Test: `outward_leg_refuses_a_demoted_node`. Red-before: the demoted node sent.

### P2 `pending-epoch-dedupe-collision` — `enrollment_dedupe_key`
The epoch only advances when a COMMIT spends it, so every transition detected
before the first one lands shares one. Keying the coalescer on
`(query, entity, epoch)` alone therefore answered "same work" for genuinely
different pending transitions: the newer one inherited the older one's queue row
and never executed, which is an advisory key deciding what gets enrolled.

Fix: the key covers transition, cause, and evidence hash as well. Identical rows
still coalesce (the `advisory_dedupe_is_not_correctness` oracle still holds);
different ones no longer do.

Oracle: `distinct_pending_transitions_do_not_share_a_dedupe_key`. Red-before:
byte-identical keys for two different transitions.

### P2 `stale-bulk-event-misrouted` — check order in `execute_claimed`
Cause routing ran before the transition and live-evidence checks, so an event
whose entity had stopped matching returned `ReviewRequired` and parked dead work
in the owner's queue. Fix: staleness outranks cause — the two skip checks moved
above the routing dial.

Oracle: `stale_bulk_event_is_skipped_rather_than_parked_for_review`. Red-before:
`ReviewRequired { cause: DefinitionChange }` instead of `SkippedStale`.

### Gates
`cargo fmt -p oneiron -- --check` clean · `cargo clippy -p oneiron --all-features
--all-targets` clean (zero diagnostics in `enrollment.rs`) · `cargo test -p
oneiron --all-features` green: 3628 lib tests + every integration suite, 0
failed. Oracle 15/15, in-crate enrollment 16/16.

Diff stays inside the packet: `crates/oneiron/src/campaign/enrollment.rs` and
`crates/oneiron/tests/campaign_enrollment_oracle.rs` only. No `Cargo.toml`, no
`Cargo.lock`, no `saved_query.rs`, no `attempt_queue.rs`, no `gate.rs`.

### Known holes added by this round
- The per-query baseline is pinned by the FIRST detection a query ever sees. A
  definition or scope move that lands before any detection is therefore
  invisible — inherent to having no prior state, and closing it would need a
  query-authoring hook inside `saved_query.rs` (a NON-CLAIM).
- `accept_enrollment_baseline` is an unauthenticated engine door: it records
  that a ruling happened, not who made it. Binding it to an owner actor belongs
  with the review surface in ONE-1778.
