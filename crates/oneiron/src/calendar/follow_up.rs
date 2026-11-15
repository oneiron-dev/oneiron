//! Meeting follow-up drafts (CAL-08; Engine RULING CAL-08-FOLLOWUP-APPROVAL =
//! A, ARCH-0060:190 "drafts, never sends"): every follow-up a meeting
//! transcript yields is a draft in the owner's inbox, internal meetings
//! included, and only the owner's approval sends it.
//!
//! A draft is one `calendar.follow_up` CLAIM about the PERSON it goes to,
//! written `Proposed` through the recording gate by
//! [`write_meeting_follow_up_draft`]. Its words come from the transcript's
//! TURNs, so its source is `Imported` and the gate holds it for the owner
//! whatever any manifest grants (ARCH-0027). It waits in one inbox run per
//! transcript SESSION, `mfu:<session hex>`, which holds only that meeting's
//! follow-ups.
//!
//! Approving that run is the one way a draft reaches the outbound gate:
//! [`schedule_approved_meeting_follow_ups`] mints an
//! [`ApprovedMeetingFollowUp`] from each approved draft, resolves the
//! recipient's native route then, and schedules one send as the agent that
//! wrote the draft. The connector executor asks
//! [`scheduled_meeting_follow_up_authorised`] before every attempt, and the
//! send's words are read from the approved draft itself
//! ([`Vault::meeting_follow_up_text`]), so a retracted or re-decided draft
//! stops a send that has not gone yet.
//!
//! `calendar.follow_up` stays out of `CALENDAR_CLAIM_PREDICATES`, as
//! `commitment.wake_proposal` stays out of the commitment family: a draft is a
//! proposal to send, not a fact about an EVENT. A `calendar.follow_up` claim
//! this door did not write (a consolidation's, an import's) carries no `mfu:`
//! run and no draft value, so it mints no token and sends nothing.
//!
//! The drafts' producer is the `producer` module: a transcript SESSION's
//! landing queues one drafting attempt, and a host worker's model drafts the
//! follow-ups the owner promised in it ([`run_meeting_follow_up_drafting`]).

mod producer;

pub(crate) use producer::enqueue_meeting_follow_up_drafting_in_txn;
pub use producer::{
    MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND, MEETING_FOLLOW_UP_INSTRUCTION,
    MEETING_FOLLOW_UP_MAX_DRAFTS, MEETING_FOLLOW_UP_MAX_RECIPIENTS,
    MEETING_FOLLOW_UP_MAX_TRANSCRIPT_BYTES, MeetingFollowUpDraftPayload, MeetingFollowUpDrafter,
    MeetingFollowUpRead, MeetingFollowUpRecipient, MeetingFollowUpRequest,
    MeetingFollowUpRunOutcome, MeetingFollowUpSilence, MeetingFollowUpSource, MeetingFollowUpTurn,
    run_meeting_follow_up_drafting,
};

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    session_claim_producer,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::MEETING_FOLLOW_UP;
use crate::error::{ClaimError, Error, Result};
use crate::human_task::HumanTaskError;
use crate::memory::{Memory, OutboundDraftInput, OutboundIntentReceipt};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::store::dreamer_attempt_kind::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::store::outbound_trigger::OutboundIntentSource;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use oneiron_base::human_task_followup::HUMAN_FOLLOWUP_VERB;
use oneiron_contracts::memory::{MemoryError, MemoryResult};

/// The predicate of a meeting follow-up draft.
pub const PREDICATE_MEETING_FOLLOW_UP: &str = "calendar.follow_up";

/// Schema version of the draft claim value.
pub const MEETING_FOLLOW_UP_SCHEMA_VERSION: u64 = 1;

/// The most bytes a draft's words may hold.
pub const MEETING_FOLLOW_UP_TEXT_MAX_BYTES: usize = 4_096;

/// Prefix of the inbox run a transcript SESSION's drafts wait in:
/// `mfu:<session hex>`.
pub const MEETING_FOLLOW_UP_RUN_PREFIX: &str = "mfu:";

/// The outbound trigger an approved draft's send carries
/// ([`OutboundIntentSource::MeetingFollowUp`]).
pub const MEETING_FOLLOW_UP_TRIGGER: &str = "meeting_follow_up";

/// Prefix of the ref that names one approved draft's send:
/// `meeting-follow-up:<claim hex>`. The send carries it as its trigger ref,
/// its idempotency key and its content ref.
pub const MEETING_FOLLOW_UP_REF_PREFIX: &str = "meeting-follow-up:";

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_SESSION_REF: &str = "session_ref";
const KEY_TEXT: &str = "text";
const KEY_TURN_REFS: &str = "turn_refs";

const PROVENANCE_KEY_SURFACE: &str = "surface";
const PROVENANCE_KEY_RUN: &str = "run";
const PROVENANCE_KEY_JOB_ID: &str = "job_id";

/// What a producer proposes: the meeting it heard, who the follow-up goes
/// to, its words, and the TURNs of that meeting the words come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeetingFollowUpDraft {
    /// The transcript SESSION.
    pub session_ref: EntityId,
    /// The PERSON the follow-up goes to.
    pub recipient: EntityId,
    /// The words to send.
    pub text: String,
    /// The SESSION's TURNs the words come from; at least one.
    pub turn_refs: Vec<EntityId>,
}

/// The inbox run a transcript SESSION's drafts wait in.
#[must_use]
pub fn meeting_follow_up_run_id(session_ref: &EntityId) -> String {
    format!("{MEETING_FOLLOW_UP_RUN_PREFIX}{}", session_ref.to_hex())
}

/// The deterministic claim id of one draft: the one derived-id rule
/// ([`EntityId::derive`]) under [`MEETING_FOLLOW_UP`], over the SESSION, the
/// recipient and the words. A producer that replays the same draft finds the
/// claim it already wrote.
#[must_use]
pub fn meeting_follow_up_claim_id(draft: &MeetingFollowUpDraft) -> EntityId {
    // The domain is non-empty UTF-8 and the version-8 stamp keeps a derived
    // id out of every reserved pattern, so neither refusal can occur.
    EntityId::derive(
        MEETING_FOLLOW_UP,
        &[
            draft.session_ref.as_bytes().as_slice(),
            draft.recipient.as_bytes().as_slice(),
            draft.text.as_bytes(),
        ],
    )
    .unwrap_or_else(|_| unreachable!("a derived meeting follow-up id is never reserved"))
}

/// Writes one draft `Proposed` and `Imported` through the recording gate, as
/// `author` (an agent, or the vault's Dreamer) in the attempt `attempt_id`,
/// and returns its claim id. Nothing is sent: the draft waits in its
/// SESSION's inbox run for the owner.
///
/// Read before write: the same draft written again is success with no
/// write, even after the owner decided it; a different draft under the same
/// id is refused.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for an author of another class or a System
/// author that is not the vault's Dreamer, empty or oversized words, no
/// cited TURN, a session that is not a SESSION, a recipient that is not a
/// PERSON, a TURN not witnessed into that SESSION, and a different draft
/// under the id; every gate refusal and store error as they come.
pub fn write_meeting_follow_up_draft(
    vault: &Vault,
    author: WriteActor,
    attempt_id: AttemptId,
    draft: &MeetingFollowUpDraft,
) -> Result<EntityId> {
    vault.with_write_txn_grouped(|wtxn| {
        write_meeting_follow_up_draft_in_txn(vault, wtxn, author, attempt_id, draft)
    })
}

/// [`write_meeting_follow_up_draft`] in the caller's writer.
pub(crate) fn write_meeting_follow_up_draft_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    author: WriteActor,
    attempt_id: AttemptId,
    draft: &MeetingFollowUpDraft,
) -> Result<EntityId> {
    validate_text(&draft.text)?;
    if draft.turn_refs.is_empty() {
        return Err(Error::InvalidClaimBody(
            "meeting follow-up cites no transcript turn",
        ));
    }
    let author_admitted = match author.actor_class() {
        EdgeActorClass::Agent => true,
        EdgeActorClass::System => {
            author == vault.dreamer_authority_in_txn(wtxn, vault.now_recorded_at())?
        }
        _ => false,
    };
    if !author_admitted {
        return Err(Error::InvalidClaimBody(
            "meeting follow-up author must be an agent or the vault Dreamer",
        ));
    }
    let claim_id = meeting_follow_up_claim_id(draft);
    let run_id = meeting_follow_up_run_id(&draft.session_ref);
    let value = encode_meeting_follow_up(draft);
    let mut envelope = WriteEnvelope::new(
        author,
        ClaimSource::Imported,
        WriteProvenance::new(draft_provenance(&run_id, attempt_id))?,
        ClaimApprovalStatus::Proposed,
    );
    // GATE-12's evidence floor: a Dreamer-run claim cites refs that still
    // resolve. The honest citation is the TURNs the words were heard in; the
    // meet is `Imported` because every transcript TURN is.
    let candidate = ClaimCandidate::new(
        PREDICATE_MEETING_FOLLOW_UP,
        ClaimSubject::Entity(draft.recipient),
        value.clone(),
        1.0,
    )
    .with_evidence(crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::authority::consolidation_evidence::ConsolidationEvidenceEnvelope {
            refs: draft.turn_refs.clone(),
            chain: Vec::new(),
            source_meet: ClaimSource::Imported,
        },
    ));
    let now = vault.now_recorded_at();
    if let Some(landed) = vault.get_claim_in_txn(&*wtxn, &claim_id)? {
        return match_landed_draft(&landed, draft, &value, &run_id).map(|()| claim_id);
    }
    require_transcript_evidence(vault, &*wtxn, draft)?;
    // The ONE write door: a raw claim write would omit the pending
    // consent row, and with it the owner's inbox approval.
    vault.sign_retained_machine_claim_in_txn(&*wtxn, &claim_id, &candidate, &mut envelope)?;
    vault
        .batch_in()
        .claim_candidate(
            &claim_id,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .apply_recording_gate_decisions(wtxn)?;
    vault
        .get_claim_in_txn(&*wtxn, &claim_id)?
        .ok_or(Error::InvalidClaimBody(
            "meeting follow-up draft is missing inside its own write transaction",
        ))?;
    Ok(claim_id)
}

/// The session must be a SESSION, the recipient a PERSON, and every cited
/// TURN one the engine recorded as witnessed into that SESSION.
fn require_transcript_evidence(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    draft: &MeetingFollowUpDraft,
) -> Result<()> {
    if vault.get_entity_type_in_txn(txn, &draft.session_ref)? != Some(ENTITY_TYPE_SESSION) {
        return Err(Error::InvalidClaimBody(
            "meeting follow-up session is not a SESSION",
        ));
    }
    if vault.get_entity_type_in_txn(txn, &draft.recipient)? != Some(ENTITY_TYPE_PERSON) {
        return Err(Error::InvalidClaimBody(
            "meeting follow-up recipient is not a PERSON",
        ));
    }
    for turn in &draft.turn_refs {
        if vault.get_entity_type_in_txn(txn, turn)? != Some(ENTITY_TYPE_TURN)
            || crate::compaction::turn_session_membership_in_txn(&vault.store, txn, turn)?
                != Some(draft.session_ref)
        {
            return Err(Error::InvalidClaimBody(
                "meeting follow-up cites a turn outside its session",
            ));
        }
    }
    Ok(())
}

/// Replay comparison. Approval and lifecycle are not compared: a decided
/// draft is a draft that advanced, and rewriting it would undo the owner's
/// answer. The attempt is not compared either: a later attempt may find the
/// draft an earlier one wrote.
fn match_landed_draft(
    landed: &ClaimBody,
    draft: &MeetingFollowUpDraft,
    value: &Value,
    run_id: &str,
) -> Result<()> {
    if landed.predicate != PREDICATE_MEETING_FOLLOW_UP
        || landed.subject != ClaimSubject::Entity(draft.recipient)
        || landed.source != Some(ClaimSource::Imported)
        || &landed.value != value
        || draft_run_id(landed).as_deref() != Some(run_id)
    {
        return Err(Error::InvalidClaimBody(
            "meeting follow-up id holds a different draft",
        ));
    }
    Ok(())
}

fn validate_text(text: &str) -> Result<()> {
    if text.trim().is_empty() {
        return Err(Error::InvalidClaimBody("meeting follow-up text is empty"));
    }
    if text.len() > MEETING_FOLLOW_UP_TEXT_MAX_BYTES {
        return Err(Error::InvalidClaimBody(
            "meeting follow-up text is too long",
        ));
    }
    Ok(())
}

fn draft_provenance(run_id: &str, attempt_id: AttemptId) -> Value {
    Value::Map(vec![
        (
            Value::from(PROVENANCE_KEY_SURFACE),
            Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
        ),
        (Value::from(PROVENANCE_KEY_RUN), Value::from(run_id)),
        (
            Value::from(PROVENANCE_KEY_JOB_ID),
            Value::from(crate::entity_id::bytes_to_hex_lower(attempt_id.as_bytes())),
        ),
    ])
}

fn encode_meeting_follow_up(draft: &MeetingFollowUpDraft) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(MEETING_FOLLOW_UP_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_SESSION_REF),
            Value::from(draft.session_ref.to_hex()),
        ),
        (Value::from(KEY_TEXT), Value::from(draft.text.as_str())),
        (
            Value::from(KEY_TURN_REFS),
            Value::Array(
                draft
                    .turn_refs
                    .iter()
                    .map(|turn| Value::from(turn.to_hex()))
                    .collect(),
            ),
        ),
    ])
}

/// A draft value read back: the SESSION and the words.
struct DraftFields {
    session_ref: EntityId,
    text: String,
}

fn decode_meeting_follow_up(value: &Value) -> Result<DraftFields> {
    let malformed = || Error::InvalidClaimBody("meeting follow-up value is malformed");
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    let get = |wanted: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(wanted)).then_some(value))
    };
    if get(KEY_SCHEMA_VERSION).and_then(Value::as_u64) != Some(MEETING_FOLLOW_UP_SCHEMA_VERSION) {
        return Err(Error::InvalidClaimBody(
            "unsupported meeting follow-up schema version",
        ));
    }
    let entity = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or_else(malformed)
    };
    let session_ref = entity(get(KEY_SESSION_REF))?;
    let text = get(KEY_TEXT)
        .and_then(Value::as_str)
        .ok_or_else(malformed)?
        .to_owned();
    validate_text(&text)?;
    let Some(Value::Array(turns)) = get(KEY_TURN_REFS) else {
        return Err(malformed());
    };
    if turns.is_empty() {
        return Err(malformed());
    }
    for turn in turns {
        entity(Some(turn))?;
    }
    Ok(DraftFields { session_ref, text })
}

/// The `run` a claim's Dreamer provenance names, when it is a draft run.
fn draft_run_id(body: &ClaimBody) -> Option<String> {
    let Value::Map(entries) = claim_provenance(body)? else {
        return None;
    };
    let entry = |wanted: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(wanted)).then(|| value.as_str())?)
    };
    if entry(PROVENANCE_KEY_SURFACE) != Some(DREAMER_RUNNER_ATTEMPT_KIND) {
        return None;
    }
    let job_id = entry(PROVENANCE_KEY_JOB_ID)?;
    if job_id.len() != 32 || !job_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    entry(PROVENANCE_KEY_RUN)
        .filter(|run| run.starts_with(MEETING_FOLLOW_UP_RUN_PREFIX))
        .map(str::to_owned)
}

fn claim_provenance(body: &ClaimBody) -> Option<&Value> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some("provenance")).then_some(value))
}

/// An APPROVED meeting follow-up draft, bound to the agent that wrote it and
/// to the native route its recipient had when it was read.
///
/// Opaque: there is no public constructor, so the only way to hold one is to
/// have re-read an approved draft through [`approved_meeting_follow_up`].
/// Approval is the owner's alone to set: only the inbox and run approval
/// doors move a `Proposed` draft to `Approved`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedMeetingFollowUp {
    claim_id: EntityId,
    recipient: EntityId,
    text: String,
    bound_actor: EntityId,
    channel: String,
    target: String,
}

impl ApprovedMeetingFollowUp {
    /// The draft claim this token was minted from.
    #[must_use]
    pub const fn claim_id(&self) -> EntityId {
        self.claim_id
    }

    /// The PERSON the follow-up goes to.
    #[must_use]
    pub const fn recipient(&self) -> EntityId {
        self.recipient
    }

    /// The approved words.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The agent that wrote the draft; its send is that agent's.
    #[must_use]
    pub const fn bound_actor(&self) -> EntityId {
        self.bound_actor
    }

    /// The channel of the recipient's native route.
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// The recipient's address on that channel.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The ref that names this draft's send: its trigger ref, idempotency
    /// key and content ref.
    #[must_use]
    pub fn send_ref(&self) -> String {
        meeting_follow_up_send_ref(&self.claim_id)
    }
}

/// The ref that names the send of the draft `claim_id`.
#[must_use]
pub fn meeting_follow_up_send_ref(claim_id: &EntityId) -> String {
    format!("{MEETING_FOLLOW_UP_REF_PREFIX}{}", claim_id.to_hex())
}

/// Mints the approved token from ONE draft claim, resolving its recipient's
/// native route now (`human_task::resolve_native_human_route`).
///
/// # Errors
///
/// [`Error::EntityNotFound`] for a missing claim, and
/// [`Error::InvalidClaimBody`] for a claim that is not an approved, active,
/// imported `calendar.follow_up` draft about a PERSON with a well-formed
/// value, a draft run of its own SESSION and an envelope actor, and for a
/// recipient the vault has no native route to.
pub fn approved_meeting_follow_up(
    vault: &Vault,
    claim_id: &EntityId,
) -> Result<ApprovedMeetingFollowUp> {
    let body = vault.get_claim(claim_id)?.ok_or(Error::EntityNotFound)?;
    if body.predicate != PREDICATE_MEETING_FOLLOW_UP {
        return Err(Error::InvalidClaimBody(
            "claim predicate is not calendar.follow_up",
        ));
    }
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::InvalidClaimBody("meeting follow-up is not active"));
    }
    if body.approval != ClaimApprovalStatus::Approved {
        return Err(Error::InvalidClaimBody("meeting follow-up is not approved"));
    }
    if body.source != Some(ClaimSource::Imported) {
        return Err(Error::InvalidClaimBody("meeting follow-up is not imported"));
    }
    let ClaimSubject::Entity(recipient) = &body.subject else {
        return Err(Error::InvalidClaimBody(
            "meeting follow-up is not about a person",
        ));
    };
    let recipient = *recipient;
    let fields = decode_meeting_follow_up(&body.value)?;
    if draft_run_id(&body) != Some(meeting_follow_up_run_id(&fields.session_ref)) {
        return Err(Error::InvalidClaimBody(
            "meeting follow-up provenance is not its session's draft run",
        ));
    }
    let bound_actor = session_claim_producer(&body).ok_or(Error::InvalidClaimBody(
        "meeting follow-up carries no envelope actor",
    ))?;
    let route = crate::human_task::resolve_native_human_route(vault, recipient).map_err(
        |error| match error {
            HumanTaskError::Engine(error) => error,
            _ => Error::InvalidClaimBody("meeting follow-up recipient has no native route"),
        },
    )?;
    Ok(ApprovedMeetingFollowUp {
        claim_id: *claim_id,
        recipient,
        text: fields.text,
        bound_actor,
        channel: route.channel,
        target: route.target,
    })
}

/// Converts ONE approved token into an outbound draft and schedules it
/// EXACTLY ONCE through [`Memory::schedule_outbound`], as the agent that
/// wrote the draft.
///
/// The token is re-read from current vault state first and must compare
/// equal: a draft retracted or re-decided since, or a recipient whose route
/// changed, is refused before any gate or queue work. The facade must then be
/// bound to the draft's author. A replay coalesces on the send's idempotency
/// key.
///
/// # Errors
///
/// A typed facade error for either guard, plus every `schedule_outbound`
/// refusal.
pub fn schedule_approved_meeting_follow_up(
    facade: &Memory<'_>,
    approved: ApprovedMeetingFollowUp,
) -> MemoryResult<OutboundIntentReceipt> {
    let current = approved_meeting_follow_up(facade.vault(), &approved.claim_id)
        .map_err(|_| stale_meeting_follow_up_token())?;
    if current != approved {
        return Err(stale_meeting_follow_up_token());
    }
    if facade.actor() != approved.bound_actor {
        return Err(MemoryError::from(Error::Claim(
            ClaimError::ActorLacksClaimAuthority {
                reason: "meeting follow-up is bound to the agent that drafted it",
            },
        )));
    }
    let send_ref = approved.send_ref();
    let draft = OutboundDraftInput {
        verb: HUMAN_FOLLOWUP_VERB.to_owned(),
        channel: approved.channel,
        target: approved.target,
        on_behalf_of: None,
        content_ref: Some(send_ref.clone()),
        idempotency_key: Some(send_ref.clone()),
        dedupe_key: None,
        trigger: MEETING_FOLLOW_UP_TRIGGER.to_owned(),
        trigger_ref: send_ref,
        job_ref: None,
        occurred_at: None,
        mention: None,
    };
    facade.schedule_outbound(&draft)
}

/// The approval half of a meeting follow-up: every approved draft among
/// `claims` schedules its send as the agent that wrote it. Run after an
/// approval door commits; other claims, and a `calendar.follow_up` claim no
/// draft run wrote, are passed over, and a replay is idempotent.
///
/// One result per draft, so the door can report a draft whose approval left
/// it inert (a recipient with no native route, a refused channel).
pub fn schedule_approved_meeting_follow_ups(
    vault: &Vault,
    claims: &[EntityId],
) -> Vec<(EntityId, MemoryResult<OutboundIntentReceipt>)> {
    let mut drafts = Vec::new();
    let mut results = Vec::new();
    for id in claims {
        // A claim that cannot be read is reported, never passed over.
        match vault.get_claim(id) {
            Ok(Some(claim))
                if claim.predicate == PREDICATE_MEETING_FOLLOW_UP
                    && claim.approval == ClaimApprovalStatus::Approved
                    && draft_run_id(&claim).is_some() =>
            {
                drafts.push(*id);
            }
            Ok(_) => {}
            Err(error) => results.push((*id, Err(MemoryError::from(error)))),
        }
    }
    if drafts.is_empty() {
        return results;
    }
    let dreamer = vault.dreamer_authority().ok();
    for id in drafts {
        let scheduled = approved_meeting_follow_up(vault, &id)
            .map_err(MemoryError::from)
            .and_then(|approved| {
                let class = dreamer
                    .filter(|actor| actor.entity_ref() == approved.bound_actor)
                    .map_or(EdgeActorClass::Agent, WriteActor::actor_class);
                let facade = vault.memory(approved.bound_actor, class);
                schedule_approved_meeting_follow_up(&facade, approved)
            });
        results.push((id, scheduled));
    }
    results
}

/// Whether a scheduled send still holds the approval that scheduled it.
///
/// A send is a meeting follow-up's when its trigger source is
/// `meeting_follow_up`, or its trigger ref or content ref names a draft. The
/// connector executor asks this before every attempt, the first and each
/// retry. The draft its trigger ref names must still mint an approved token,
/// and the send must carry exactly what that token schedules: its author,
/// the recipient's route now, and the draft's own ref. A retraction, a
/// declined or re-decided draft, or a route that moved therefore stops a
/// send that has not crossed yet, and approved words never ride another
/// send. Any other send is not this check's to judge.
pub(crate) fn scheduled_meeting_follow_up_authorised(
    vault: &Vault,
    task: &crate::outbound::ConnectorSendTask,
) -> Result<bool> {
    let intent = &task.intent;
    let source = OutboundIntentSource::parse(&intent.intent_source);
    let names_draft = |value: Option<&str>| {
        value.is_some_and(|value| value.starts_with(MEETING_FOLLOW_UP_REF_PREFIX))
    };
    if source != Some(OutboundIntentSource::MeetingFollowUp)
        && !names_draft(Some(intent.trigger_ref.as_str()))
        && !names_draft(intent.content_ref.as_deref())
    {
        return Ok(true);
    }
    let Some(claim_id) = intent
        .trigger_ref
        .strip_prefix(MEETING_FOLLOW_UP_REF_PREFIX)
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(false);
    };
    // Anything that does not mint an approved token authorises nothing.
    let Ok(approved) = approved_meeting_follow_up(vault, &claim_id) else {
        return Ok(false);
    };
    let send_ref = approved.send_ref();
    Ok(source == Some(OutboundIntentSource::MeetingFollowUp)
        && task.actor_ref == approved.bound_actor
        && intent.verb == HUMAN_FOLLOWUP_VERB
        && intent.channel == approved.channel
        && intent.target == approved.target
        && intent.on_behalf_of.is_none()
        && intent.trigger_ref == send_ref
        && intent.idempotency_key.as_deref() == Some(send_ref.as_str())
        && intent.content_ref.as_deref() == Some(send_ref.as_str())
        && intent.dedupe_key.is_none())
}

impl Vault {
    /// The words an approved meeting follow-up's send carries, read from the
    /// approved draft itself when the send goes; `None` for a content ref
    /// that names no draft.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] for a malformed draft ref, and every
    /// [`approved_meeting_follow_up`] refusal: a draft that is no longer
    /// approved sends no words.
    pub fn meeting_follow_up_text(&self, content_ref: &str) -> Result<Option<String>> {
        let Some(hex) = content_ref.strip_prefix(MEETING_FOLLOW_UP_REF_PREFIX) else {
            return Ok(None);
        };
        let claim_id = EntityId::from_hex(hex)
            .map_err(|_| Error::InvalidClaimBody("meeting follow-up ref is malformed"))?;
        Ok(Some(approved_meeting_follow_up(self, &claim_id)?.text))
    }
}

fn stale_meeting_follow_up_token() -> MemoryError {
    MemoryError::from(Error::InvalidClaimBody(
        "approved meeting follow-up token is stale",
    ))
}
