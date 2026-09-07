//! CAL-07 event outcome: evidence ladder, outcome head, post-end check-in.
//!
//! Four laws hold this layer together, and every function below is one of them
//! made mechanical:
//!
//! * **Silence is never `held`.** The absence of a live
//!   `calendar.event_outcome` claim is [`EventOutcome::Unknown`] at projection
//!   ([`read_event_outcome`] returns `None`, [`project_event_outcome`] maps it),
//!   never `Held` and never `NoShow`.
//! * **Elapsed calendar time is not evidence.** Passing the scheduled end mints
//!   nothing; it only arms a *question*. [`outcome_from_machine_evidence`] takes
//!   no clock, and the check-in wake carries no outcome.
//! * **Cancellation has two homes.** Imported cancellation and feed absence are
//!   CAL-00's `calendar.status` under the all-live-inbound-passports law and
//!   never touch this predicate. Only an explicit lifecycle cancellation
//!   established BEFORE the start records `cancelled_pre_start` here. This layer
//!   writes one home and READS both: a check-in that consulted only its own
//!   predicate would ask about a meeting the feed already called off.
//! * **The card has two independent doors.** An answer records an
//!   owner-attested outcome; a recording drop stores a blob and infers nothing.
//!   CAL-08 may later turn that blob into machine evidence.
//!
//! The engine owns no timer: [`plan_outcome_check_in`] returns an exact wake for
//! the host to deliver, and [`check_in_is_still_due`] rechecks meeting class,
//! current evidence, and current status when the host says it fired — a card is
//! never surfaced from the plan alone.
//!
//! Inherited hole, not owned here: `gate::default_policy_manifest()` carries no
//! `calendar.` rule, so on a default-seeded vault every calendar claim write —
//! including this one — is gate-pending. CAL-09's surface oracle pins that state
//! (`calendar_claims_are_gate_pending_under_the_default_policy_manifest`), and
//! the fix is one manifest rule in `gate.rs`, a lane-wide CAL non-claim. This
//! layer deliberately routes through the ordinary claim door rather than around
//! the gate.

use serde::{Deserialize, Serialize};

use super::claims::{
    CalendarStatus, CalendarStatusValue, PREDICATE_CALENDAR_STATUS, decode_event_outcome_value,
    decode_status_value, encode_event_outcome_value, require_event_subject,
};
use crate::blob_artifact::BlobArtifactBody;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    claim_surfaceable,
};
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::lens::{
    ButtonControl, CollectionAtom, GeneratedLens, LensAtom, LensAtomId, LensNode, LensText,
    LensTextSpan, MetaLineAtom, SelfUiAction, SelfUiActionId, SelfUiControl, SelfUiControlId,
    SelfUiOptionValue, SelfUiValue, TextBlockAtom,
};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// One recorded outcome per EVENT, superseded in place.
///
/// Defined here rather than beside CAL-00's twelve family constants because
/// this layer owns the predicate's semantics; `calendar::claims` imports it for
/// the family table and the structural validator.
pub const PREDICATE_CALENDAR_EVENT_OUTCOME: &str = "calendar.event_outcome";

/// Default grace between an EVENT's scheduled end and the check-in wake.
pub const DEFAULT_OUTCOME_GRACE_SECS: u64 = 30 * 60;

/// Opaque reason tag the host echoes back when the check-in wake fires.
pub const OUTCOME_CHECK_IN_REASON_TAG: &str = "calendar.event_outcome.check_in";

/// Domain separator for the per-EVENT recording artifact id.
const CHECK_IN_RECORDING_ARTIFACT_ID_DOMAIN: &[u8] = b"oneiron:calendar-outcome-recording:v1";

/// What actually happened at one EVENT.
///
/// A closed four-value set. `Unknown` is a real recorded value, not a missing
/// one: it says "the question was asked and nothing established an outcome",
/// which reads the same as silence and is never transition evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    Held,
    NoShow,
    CancelledPreStart,
    Unknown,
}

impl EventOutcome {
    /// Wire token for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::NoShow => "no_show",
            Self::CancelledPreStart => "cancelled_pre_start",
            Self::Unknown => "unknown",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "held" => Some(Self::Held),
            "no_show" => Some(Self::NoShow),
            "cancelled_pre_start" => Some(Self::CancelledPreStart),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// What established an [`EventOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcomeBasis {
    /// Explicit machine evidence: a transcript, join telemetry, a cancellation.
    Machine,
    /// The owner answered the check-in.
    OwnerAttested,
}

impl EventOutcomeBasis {
    /// Wire token for this basis.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::OwnerAttested => "owner_attested",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "machine" => Some(Self::Machine),
            "owner_attested" => Some(Self::OwnerAttested),
            _ => None,
        }
    }
}

/// Value of a `calendar.event_outcome` claim, subject = EVENT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventOutcomeClaimValue {
    pub outcome: EventOutcome,
    pub basis: EventOutcomeBasis,
    pub recorded_at: u64,
}

/// One piece of explicit machine evidence about an EVENT.
///
/// Imported cancellation and feed absence are deliberately NOT arms here: they
/// belong to CAL-00's `calendar.status` under the multi-source law, where a
/// single source's absence supersedes only its own passport. `evidence_ref` is
/// the caller's audit anchor — the ratified three-field wire value carries no
/// evidence slot, so it never rides the claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineOutcomeEvidence {
    /// An explicit lifecycle cancellation for this EVENT.
    CancelReceived {
        evidence_ref: EntityId,
        observed_at: u64,
    },
    /// A transcript exists for this EVENT.
    Transcript {
        evidence_ref: EntityId,
        observed_at: u64,
    },
    /// Join telemetry qualifying as attendance.
    JoinTelemetry {
        evidence_ref: EntityId,
        observed_at: u64,
    },
    /// A provider stated nobody joined.
    ExplicitNoShow {
        evidence_ref: EntityId,
        observed_at: u64,
    },
}

/// The signals that decide whether an EVENT is meeting-class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeetingClassSignals {
    pub external_attendee_count: u32,
    pub has_campaign_linkage: bool,
    pub has_commitment_linkage: bool,
    pub internal_meeting_opt_in: bool,
}

/// Whether an EVENT is meeting-class, i.e. worth asking the owner about.
///
/// Ambient calendar items, birthdays, focus blocks, all-day ambience, solo
/// events, and internal-only events without linkage or opt-in all answer `false`
/// and never arm the grace/check-in path.
#[must_use]
pub fn is_meeting_class(signals: MeetingClassSignals) -> bool {
    signals.external_attendee_count > 0
        || signals.has_campaign_linkage
        || signals.has_commitment_linkage
        || signals.internal_meeting_opt_in
}

/// Reads the outcome one piece of machine evidence earns, if any.
///
/// Returns `None` when the evidence does not earn an outcome. Scheduled time
/// passing is deliberately not an input to this function: `event_start_utc` is
/// used only to place a cancellation before or after the start, since a
/// cancellation that arrives once the EVENT has begun is an ordinary lifecycle
/// cancellation and leaves the outcome unknown.
#[must_use]
pub fn outcome_from_machine_evidence(
    event_start_utc: u64,
    evidence: &MachineOutcomeEvidence,
) -> Option<EventOutcomeClaimValue> {
    let (outcome, observed_at) = match *evidence {
        MachineOutcomeEvidence::CancelReceived { observed_at, .. } => {
            if observed_at >= event_start_utc {
                return None;
            }
            (EventOutcome::CancelledPreStart, observed_at)
        }
        MachineOutcomeEvidence::Transcript { observed_at, .. }
        | MachineOutcomeEvidence::JoinTelemetry { observed_at, .. } => {
            (EventOutcome::Held, observed_at)
        }
        MachineOutcomeEvidence::ExplicitNoShow { observed_at, .. } => {
            (EventOutcome::NoShow, observed_at)
        }
    };
    Some(EventOutcomeClaimValue {
        outcome,
        basis: EventOutcomeBasis::Machine,
        recorded_at: observed_at,
    })
}

/// Projects a read outcome claim: silence is `Unknown`, never `Held`.
#[must_use]
pub fn project_event_outcome(claim: Option<EventOutcomeClaimValue>) -> EventOutcome {
    claim.map_or(EventOutcome::Unknown, |value| value.outcome)
}

/// Writes one live `calendar.event_outcome` claim by superseding the prior
/// live claim for the EVENT. The caller supplies the evidence-appropriate source.
///
/// The replacement head and every supersession share ONE write transaction, so
/// a rejected supersession rolls the new head back with it and the EVENT can
/// never be left with two live outcomes. Superseded claims stay fully readable:
/// this is claim history, not a delete.
///
/// Every lifecycle-active prior head is closed, whatever its approval state — a
/// gate-pending `Proposed` outcome is invisible to readers but is still a head,
/// and leaving it open would let a later consent approval resurrect it beside
/// the claim that replaced it.
///
/// The claim lands `Auto` — an engine-recorded fact, the `comm.rs` stance for a
/// family projector — and carries the caller's [`ClaimSource`], which the shared
/// rules then rule on: source-trust decides whether that source may ride `Auto`
/// at all, and supersession decides whether it may replace a more trusted head.
/// A source needing an explicit Auto permit (imported / tool_output / generated)
/// is refused loudly here rather than parked as a claim the read path cannot
/// see — an outcome nobody can read is worse than an error.
///
/// # Errors
///
/// [`crate::error::Error::EntityNotFound`] when `event_ref` is not an EVENT row;
/// claim-body, policy, and supersession errors propagate from the shared claim
/// doors.
pub fn record_event_outcome(
    vault: &Vault,
    event_ref: EntityId,
    value: &EventOutcomeClaimValue,
    source: ClaimSource,
) -> Result<EntityId> {
    require_event_subject(vault, &event_ref)?;
    vault.with_write_txn(|txn| record_event_outcome_in_txn(vault, txn, event_ref, value, source))
}

mod conditional;
use conditional::record_event_outcome_in_txn;
pub(crate) use conditional::record_lifecycle_outcome_in_txn;

/// Reads the EVENT's live outcome claim.
///
/// Absence of a live claim returns `None`; projection maps `None` to `Unknown`
/// and never to `Held` or `NoShow`.
///
/// # Errors
///
/// Storage errors, and [`crate::error::Error::InvalidClaimBody`] when a stored
/// outcome value does not match the ratified wire shape.
pub fn read_event_outcome(
    vault: &Vault,
    event_ref: EntityId,
) -> Result<Option<EventOutcomeClaimValue>> {
    let rtxn = vault.store.env.read_txn()?;
    current_outcome_in(vault, &rtxn, &event_ref)
}

/// The EVENT's current readable outcome: the latest evidence among the heads a
/// reader may see.
///
/// One EVENT normally has one live head — [`record_event_outcome`] closes the
/// previous one in the same transaction. Two coexist only across a sync fork,
/// where two replicas each recorded an outcome and neither supersession crossed
/// the wire. That contest resolves on `(recorded_at, claim id)`, never on claim
/// id alone: ids are time-ordered UUIDv7 *per writer*, so across a fork the
/// lower id is not the earlier evidence, and picking it would invert this
/// layer's own rule that later evidence supersedes earlier. The id is the
/// tie-break, so the contest stays total and both replicas pick the same head.
fn current_outcome_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Option<EventOutcomeClaimValue>> {
    Ok(live_outcome_heads_in(vault, rtxn, event_ref)?
        .into_iter()
        .filter(|head| head.surfaceable)
        .max_by_key(|head| (head.value.recorded_at, head.claim_id))
        .map(|head| head.value))
}

/// One live `calendar.event_outcome` claim on an EVENT.
struct OutcomeHead {
    claim_id: EntityId,
    value: EventOutcomeClaimValue,
    /// Whether a reader may see it ([`claim_surfaceable`]).
    surfaceable: bool,
}

/// Every lifecycle-active `calendar.event_outcome` head on `event_ref`.
///
/// Live means lifecycle-active, deliberately wider than [`claim_surfaceable`]:
/// a gate-pending `Proposed` head is invisible to readers but is still a head,
/// and only the writer that supersedes it stops a later approval resurrecting it
/// beside its own replacement. On a default-seeded vault that is the ORDINARY
/// state of a calendar claim write, not an exotic one — see the module note on
/// the missing `calendar.` policy rule. `surfaceable` carries the read path's
/// consent gate forward unchanged.
fn live_outcome_heads_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Vec<OutcomeHead>> {
    let mut heads = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(rtxn, event_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_EVENT_OUTCOME
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        heads.push(OutcomeHead {
            claim_id,
            value: decode_event_outcome_value(&body.value)?,
            surfaceable: claim_surfaceable(&body),
        });
    }
    Ok(heads)
}

/// The EVENT's current `calendar.status`, under the same latest-evidence rule
/// as [`current_outcome_in`].
///
/// CAL-00 owns this predicate; CAL-07 only reads it, and has to: cancellation
/// has two homes by law, and the home this module never writes is exactly the
/// one a check-in must not ignore.
fn current_status_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Option<CalendarStatusValue>> {
    let mut heads = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(rtxn, event_ref)? {
        let Some(body) = vault
            .get_claim_in_txn(rtxn, &claim_id)?
            .filter(claim_surfaceable)
        else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_STATUS {
            continue;
        }
        heads.push((claim_id, decode_status_value(&body.value)?));
    }
    Ok(heads
        .into_iter()
        .max_by_key(|(claim_id, value)| (value.recorded_at, *claim_id))
        .map(|(_, value)| value))
}

/// One exact host wake: the three fields of the supervisor wake contract.
///
/// This is the engine-side image of `oneiron_vault_contract::WakeEntry` with
/// `Schedule::Exact` — exact by construction, since CAL never plans a window.
/// `crates/oneiron` does not depend on the contract crate at this commit (the
/// path dep is ONE-1783's reserved `Cargo.toml` append), so the fields ride this
/// struct and map one-to-one when that dep lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeCheckInWake {
    /// Stable, caller-assigned wake id.
    pub id: String,
    /// Exact fire instant, unix seconds UTC.
    pub at_utc: u64,
    /// Opaque tag echoed back when the wake fires.
    pub reason_tag: String,
}

/// Plans the post-end check-in wake for one EVENT, or `None` when the EVENT is
/// not meeting-class.
///
/// The engine owns no timer: this only describes the wake the host is asked to
/// deliver. `_event_ref` is unused at this layer — the wake carries id, instant,
/// and tag only, and the recheck at due time takes the EVENT explicitly — but it
/// stays in the ratified signature so the host call sites do not move when the
/// contract `WakeEntry` becomes available.
#[must_use]
pub fn plan_outcome_check_in(
    wake_id: String,
    _event_ref: EntityId,
    event_end_utc: u64,
    signals: MeetingClassSignals,
) -> Option<OutcomeCheckInWake> {
    is_meeting_class(signals).then(|| OutcomeCheckInWake {
        id: wake_id,
        at_utc: event_end_utc.saturating_add(DEFAULT_OUTCOME_GRACE_SECS),
        reason_tag: OUTCOME_CHECK_IN_REASON_TAG.to_owned(),
    })
}

/// One check-in wake the host has delivered as due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueOutcomeCheckIn {
    /// The wake id [`plan_outcome_check_in`] was given.
    pub wake_id: String,
    /// The EVENT the check-in asks about.
    pub event_ref: EntityId,
    /// The EVENT's scheduled start, carried for the card the host renders.
    pub scheduled_start_utc: u64,
    /// The meeting-class signals, re-read at due time by the caller.
    pub signals: MeetingClassSignals,
}

/// Rechecks meeting class and current state for one due wake.
///
/// A due wake is not a card. Three things can have changed in the half hour
/// since it was planned, and all three are re-read here rather than trusted:
///
/// * the EVENT may have stopped being meeting-class;
/// * an outcome may have arrived during the grace window — the card would ask a
///   question already answered;
/// * the EVENT may have been CANCELLED. That one never reaches this module's own
///   predicate: imported cancellation and feed absence are `calendar.status` by
///   law, so a recheck reading only `calendar.event_outcome` would ask the owner
///   how a meeting went that the feed already said was called off.
///
/// Suppressing the card mints nothing. A cancelled EVENT's outcome stays
/// `unknown` unless separate evidence establishes one — only a lifecycle
/// cancellation seen BEFORE the start earns `cancelled_pre_start`, and that goes
/// through [`outcome_from_machine_evidence`].
///
/// # Errors
///
/// Storage errors, and claim-body errors from reading either head.
pub fn check_in_is_still_due(vault: &Vault, due: &DueOutcomeCheckIn) -> Result<bool> {
    if !is_meeting_class(due.signals) {
        return Ok(false);
    }
    let rtxn = vault.store.env.read_txn()?;
    if current_outcome_in(vault, &rtxn, &due.event_ref)?.is_some() {
        return Ok(false);
    }
    Ok(current_status_in(vault, &rtxn, &due.event_ref)?
        .is_none_or(|status| status.status != CalendarStatus::Cancelled))
}

/// The owner's answer to a check-in card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckInAnswer {
    Held,
    NoShow,
    Rescheduled,
}

impl CheckInAnswer {
    /// Stable token the card's answer action carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::NoShow => "no_show",
            Self::Rescheduled => "rescheduled",
        }
    }
}

/// What one answer resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckInResolution {
    /// Record this outcome.
    Outcome(EventOutcomeClaimValue),
    /// Route the caller to the scheduling flow. `rescheduled` is a card
    /// disposition, never a fifth outcome value.
    RescheduleRequested {
        event_ref: EntityId,
        recorded_at: u64,
    },
}

impl CheckInResolution {
    /// The claim value this resolution records.
    ///
    /// A reschedule records an owner-attested `unknown`: the owner DID answer,
    /// so the check-in resolves and stops surfacing, while the outcome stays
    /// unknown until separate evidence establishes one of the other three. This
    /// is what lets the inbox row be pure claim state with nothing to retract.
    #[must_use]
    pub const fn recorded_value(&self) -> EventOutcomeClaimValue {
        match *self {
            Self::Outcome(value) => value,
            Self::RescheduleRequested { recorded_at, .. } => EventOutcomeClaimValue {
                outcome: EventOutcome::Unknown,
                basis: EventOutcomeBasis::OwnerAttested,
                recorded_at,
            },
        }
    }
}

/// Resolves one owner answer. Pure: the caller records the value and, for a
/// reschedule, also routes to the scheduling flow.
#[must_use]
pub fn resolve_owner_check_in(
    event_ref: EntityId,
    answer: CheckInAnswer,
    recorded_at: u64,
) -> CheckInResolution {
    let outcome = match answer {
        CheckInAnswer::Held => EventOutcome::Held,
        CheckInAnswer::NoShow => EventOutcome::NoShow,
        CheckInAnswer::Rescheduled => {
            return CheckInResolution::RescheduleRequested {
                event_ref,
                recorded_at,
            };
        }
    };
    CheckInResolution::Outcome(EventOutcomeClaimValue {
        outcome,
        basis: EventOutcomeBasis::OwnerAttested,
        recorded_at,
    })
}

/// The machine half of a check-in card: refs and the caller's action ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckInCardModel {
    pub event_ref: EntityId,
    pub scheduled_start_utc: u64,
    /// Action the three answer buttons invoke, with the answer token as its arg.
    pub answer_action_id: String,
    /// Action the recording drop zone invokes. Independent of the answer door.
    pub recording_upload_action_id: String,
}

/// The human half of a check-in card. Every string is a runtime/config input:
/// engine Rust hardcodes no product prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckInCopy {
    pub title: String,
    pub body: String,
    pub held_label: String,
    pub no_show_label: String,
    pub rescheduled_label: String,
    pub recording_label: String,
}

/// Builds the check-in card as a generated lens.
///
/// Two independent doors, four controls: three answer buttons carrying the
/// closed answer tokens on ONE answer action, and one recording drop zone on
/// its own action. The card states no outcome — it asks.
///
/// # Errors
///
/// [`crate::error::Error::InvalidConfig`] when a caller-supplied action id or
/// copy string violates the lens token/text bounds.
pub fn build_check_in_lens(model: &CheckInCardModel, copy: &CheckInCopy) -> Result<GeneratedLens> {
    let title = LensText::new(&copy.title)?;
    let body = LensText::new(&copy.body)?;
    let answer_action = SelfUiActionId::new(model.answer_action_id.as_str())?;

    let mut root = LensNode::with_fallback_text(
        LensAtomId::new("outcome-check-in-root")?,
        LensAtom::Sheet(CollectionAtom {
            title: title.clone(),
            rows: Vec::new(),
        }),
        title,
    );
    root.children.push(LensNode::with_fallback_text(
        LensAtomId::new("outcome-check-in-body")?,
        LensAtom::TextBlock(TextBlockAtom {
            spans: vec![LensTextSpan::Literal(body.clone())],
        }),
        body,
    ));
    root.children.push(LensNode::new(
        LensAtomId::new("outcome-check-in-event")?,
        LensAtom::MetaLine(MetaLineAtom {
            label: LensText::new("event_ref")?,
            value: LensText::new(model.event_ref.to_hex())?,
        }),
    ));
    root.children.push(LensNode::new(
        LensAtomId::new("outcome-check-in-scheduled-start")?,
        LensAtom::MetaLine(MetaLineAtom {
            label: LensText::new("scheduled_start_utc")?,
            value: LensText::new(model.scheduled_start_utc.to_string())?,
        }),
    ));

    for (answer, label) in [
        (CheckInAnswer::Held, &copy.held_label),
        (CheckInAnswer::NoShow, &copy.no_show_label),
        (CheckInAnswer::Rescheduled, &copy.rescheduled_label),
    ] {
        root.children.push(answer_button(
            model,
            answer,
            label.as_str(),
            answer_action.clone(),
        )?);
    }
    root.children.push(LensNode::new(
        LensAtomId::new("outcome-check-in-recording")?,
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: SelfUiControlId::new("outcome-check-in-recording")?,
            label: LensText::new(&copy.recording_label)?,
            action: SelfUiAction {
                command: SelfUiActionId::new(model.recording_upload_action_id.as_str())?,
                args: vec![SelfUiValue::Text(LensText::new(model.event_ref.to_hex())?)],
            },
        })),
    ));

    GeneratedLens::new(root)
}

fn answer_button(
    model: &CheckInCardModel,
    answer: CheckInAnswer,
    label: &str,
    command: SelfUiActionId,
) -> Result<LensNode> {
    let control_id = format!("outcome-check-in-answer-{}", answer.as_str());
    Ok(LensNode::new(
        LensAtomId::new(control_id.as_str())?,
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: SelfUiControlId::new(control_id)?,
            label: LensText::new(label)?,
            action: SelfUiAction {
                command,
                args: vec![
                    SelfUiValue::Text(LensText::new(model.event_ref.to_hex())?),
                    SelfUiValue::Token(SelfUiOptionValue::new(answer.as_str())?),
                ],
            },
        })),
    ))
}

/// Opens the EVENT's recording artifact for the card's upload door and returns
/// its id. Idempotent: the artifact id is derived from the EVENT, so a second
/// drop appends to the same version chain rather than forking a new artifact.
///
/// The bytes ride the existing append-only chain
/// ([`Vault::append_blob_artifact_version`]) — this door opens no second blob
/// store, parses no audio, and writes no outcome. CAL-08 may later consume the
/// stored blob through `file-drop-transcript` and supersede `unknown` with real
/// machine evidence.
///
/// # Errors
///
/// [`crate::error::Error::EntityNotFound`] when `event_ref` is not an EVENT row;
/// blob-artifact body errors propagate from the artifact door.
pub fn accept_check_in_recording(
    vault: &Vault,
    event_ref: EntityId,
    blob: BlobArtifactBody,
    recorded_at: u64,
) -> Result<EntityId> {
    require_event_subject(vault, &event_ref)?;
    let artifact_id = check_in_recording_artifact_id(&event_ref)?;
    if vault.get_blob_artifact(&artifact_id)?.is_none() {
        vault.put_blob_artifact(
            &artifact_id,
            &blob,
            TimeRange {
                start: recorded_at,
                end: recorded_at,
            },
            recorded_at,
        )?;
    }
    Ok(artifact_id)
}

/// The EVENT's recording artifact id.
///
/// Derived rather than stored: it resolves EVENT ↔ recording in both directions
/// without an edge kind, a second predicate, or a registry row — none of which
/// this layer is allowed to mint.
///
/// # Errors
///
/// [`crate::error::Error::InvariantViolation`] if id derivation exhausts its
/// salt space, which the shared helper treats as unreachable.
pub fn check_in_recording_artifact_id(event_ref: &EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(
        CHECK_IN_RECORDING_ARTIFACT_ID_DOMAIN,
        &[event_ref.as_bytes()],
    )
}
