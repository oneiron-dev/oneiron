//! Approved-proposal token, actor binding, and the outbound adapter.

use rmpv::Value;

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, session_claim_producer,
};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult, OutboundDraftInput, OutboundIntentReceipt};

use super::wake_event::{
    COMMITMENT_WAKE_PROPOSAL_SCHEMA_VERSION, COMMITMENT_WAKE_TRIGGER, CommitmentWakeDue,
    CommitmentWakePhase, KEY_CHANNEL, KEY_CONTENT_REF, KEY_DEDUPE_KEY, KEY_DUE_AT, KEY_FIRE_AT,
    KEY_IDEMPOTENCY_KEY, KEY_INSTANCE_REF, KEY_OCCURRED_AT, KEY_ON_BEHALF_OF, KEY_PHASE,
    KEY_SCHEMA_VERSION, KEY_TARGET, KEY_TRIGGER_REF, KEY_VERB, PREDICATE_COMMITMENT_WAKE_PROPOSAL,
    PROVENANCE_KEY_JOB_ID, PROVENANCE_KEY_RUN, PROVENANCE_KEY_SURFACE, commitment_trigger_ref,
    required_string, required_u64,
};
use super::wake_fire::{WakeEligibility, wake_eligibility};
use super::wake_proposal::CommitmentWakeProposalDraft;

// ---------------------------------------------------------------------------
// 5. Approved token, actor binding, and the outbound adapter
// ---------------------------------------------------------------------------

/// An APPROVED commitment wake proposal, bound to the Dreamer agent that
/// authored it.
///
/// Opaque by construction: there is no public constructor and no field setter,
/// so the only way to hold one is to have re-read an approved row through
/// [`approved_commitment_wake`]. Landed inbox acceptance flips approval and
/// records no separate approver identity, so approval CAUSATION is enforced by
/// requiring [`ClaimApprovalStatus::Approved`] — which only the inbox door can
/// set — and author binding is what prevents cross-actor replay double-send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCommitmentWake {
    proposal_claim_id: EntityId,
    instance_id: EntityId,
    phase: CommitmentWakePhase,
    run_id: String,
    idempotency_key: String,
    verb: String,
    channel: String,
    target: String,
    on_behalf_of: Option<String>,
    content_ref: Option<String>,
    dedupe_key: Option<String>,
    occurred_at: u64,
    bound_actor: EntityId,
}

impl ApprovedCommitmentWake {
    /// The proposal claim this token was minted from.
    #[must_use]
    pub const fn proposal_claim_id(&self) -> EntityId {
        self.proposal_claim_id
    }

    /// The commitment instance the approved wake is about.
    #[must_use]
    pub const fn instance_id(&self) -> EntityId {
        self.instance_id
    }

    /// Which phase fired.
    #[must_use]
    pub const fn phase(&self) -> CommitmentWakePhase {
        self.phase
    }

    /// The deterministic phase key: run id, inbox group key, and outbound
    /// idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// The proposal-authoring Dreamer agent this token is bound to.
    #[must_use]
    pub const fn bound_actor(&self) -> EntityId {
        self.bound_actor
    }

    /// The canonical commitment receipt reference.
    #[must_use]
    pub fn trigger_ref(&self) -> String {
        commitment_trigger_ref(&self.instance_id)
    }
}

/// Decoded proposal value, before it is checked against its own provenance.
struct ProposalFields {
    instance_id: EntityId,
    phase: CommitmentWakePhase,
    fire_at: u64,
    due_at: u64,
    occurred_at: u64,
    idempotency_key: String,
    trigger_ref: String,
    verb: String,
    channel: String,
    target: String,
    on_behalf_of: Option<String>,
    content_ref: Option<String>,
    dedupe_key: Option<String>,
}

/// Mints the opaque approved token from ONE approved proposal row.
///
/// # Errors
///
/// [`Error::EntityNotFound`] for a missing claim and
/// [`Error::InvalidClaimBody`] for every other refusal: `Proposed`,
/// `Rejected`, a non-active lifecycle, a wrong predicate or source, malformed
/// or disagreeing fields, unrelated provenance, and a commitment that no
/// longer resolves, is no longer `Open`, or is no longer `Commitment` strength.
pub fn approved_commitment_wake(
    vault: &Vault,
    proposal_claim_id: &EntityId,
) -> Result<ApprovedCommitmentWake> {
    let body = vault
        .get_claim(proposal_claim_id)?
        .ok_or(Error::EntityNotFound)?;
    require_approved_proposal_shape(&body)?;
    let fields = decode_commitment_wake_proposal(&body.value)?;
    let run_id = require_proposal_provenance(&body, &fields)?;
    let bound_actor = session_claim_producer(&body).ok_or(Error::InvalidClaimBody(
        "commitment wake proposal carries no envelope actor",
    ))?;
    require_live_commitment(vault, &fields.instance_id)?;
    Ok(ApprovedCommitmentWake {
        proposal_claim_id: *proposal_claim_id,
        instance_id: fields.instance_id,
        phase: fields.phase,
        run_id,
        idempotency_key: fields.idempotency_key,
        verb: fields.verb,
        channel: fields.channel,
        target: fields.target,
        on_behalf_of: fields.on_behalf_of,
        content_ref: fields.content_ref,
        dedupe_key: fields.dedupe_key,
        occurred_at: fields.occurred_at,
        bound_actor,
    })
}

fn require_approved_proposal_shape(body: &ClaimBody) -> Result<()> {
    if body.predicate != PREDICATE_COMMITMENT_WAKE_PROPOSAL {
        return Err(Error::InvalidClaimBody(
            "claim predicate is not commitment.wake_proposal",
        ));
    }
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal is not active",
        ));
    }
    if body.approval != ClaimApprovalStatus::Approved {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal is not approved",
        ));
    }
    if body.source != Some(ClaimSource::Generated) {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal is not generated",
        ));
    }
    Ok(())
}

/// Requires the Dreamer provenance to name this exact wake: surface, an exact
/// `cmt:<32-hex>:lead|due` run agreeing with the value's own key, and a 32-hex
/// originating attempt.
fn require_proposal_provenance(body: &ClaimBody, fields: &ProposalFields) -> Result<String> {
    let provenance = claim_provenance(body).ok_or(Error::InvalidClaimBody(
        "commitment wake proposal carries no provenance",
    ))?;
    let Value::Map(entries) = provenance else {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal provenance is malformed",
        ));
    };
    let entry = |wanted: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(wanted)).then(|| value.as_str())?)
    };
    if entry(PROVENANCE_KEY_SURFACE) != Some(DREAMER_RUNNER_ATTEMPT_KIND) {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal provenance is not a dreamer run",
        ));
    }
    let run = entry(PROVENANCE_KEY_RUN).ok_or(Error::InvalidClaimBody(
        "commitment wake proposal provenance names no run",
    ))?;
    if run != fields.idempotency_key {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal run does not match its phase key",
        ));
    }
    let job_id = entry(PROVENANCE_KEY_JOB_ID).ok_or(Error::InvalidClaimBody(
        "commitment wake proposal provenance names no job",
    ))?;
    if job_id.len() != 32 || !job_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal job id is not an attempt id",
        ));
    }
    Ok(run.to_owned())
}

fn require_live_commitment(vault: &Vault, instance_id: &EntityId) -> Result<()> {
    let record = vault
        .get_commitment_claim(instance_id)?
        .ok_or(Error::InvalidClaimBody(
            "commitment wake proposal names a missing commitment",
        ))?;
    if !matches!(wake_eligibility(&record), WakeEligibility::Eligible) {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal names a closed or ineligible commitment",
        ));
    }
    Ok(())
}

pub(super) fn claim_provenance(body: &ClaimBody) -> Option<Value> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some("provenance")).then(|| value.clone()))
}

fn decode_commitment_wake_proposal(value: &Value) -> Result<ProposalFields> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal value is malformed",
        ));
    };
    let get = |wanted: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(wanted)).then_some(value))
    };
    let missing = || Error::InvalidClaimBody("commitment wake proposal value is incomplete");
    let required = |key: &str| get(key).ok_or_else(missing);
    let optional_string = |key: &str| -> Result<Option<String>> {
        match get(key) {
            None | Some(Value::Nil) => Ok(None),
            Some(value) => required_string(value).map(Some),
        }
    };
    if required(KEY_SCHEMA_VERSION)?.as_u64() != Some(COMMITMENT_WAKE_PROPOSAL_SCHEMA_VERSION) {
        return Err(Error::InvalidClaimBody(
            "unsupported commitment wake proposal schema version",
        ));
    }
    let Value::Binary(instance_bytes) = required(KEY_INSTANCE_REF)? else {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal instance ref is malformed",
        ));
    };
    let instance_bytes: [u8; 16] = instance_bytes.as_slice().try_into().map_err(|_| {
        Error::InvalidClaimBody("commitment wake proposal instance ref is malformed")
    })?;
    let fields = ProposalFields {
        instance_id: EntityId::from_bytes(instance_bytes).map_err(|_| {
            Error::InvalidClaimBody("commitment wake proposal instance ref is malformed")
        })?,
        phase: CommitmentWakePhase::parse(&required_string(required(KEY_PHASE)?)?).ok_or(
            Error::InvalidClaimBody("commitment wake proposal phase is not lead|due"),
        )?,
        fire_at: required_u64(required(KEY_FIRE_AT)?)?,
        due_at: required_u64(required(KEY_DUE_AT)?)?,
        occurred_at: required_u64(required(KEY_OCCURRED_AT)?)?,
        idempotency_key: required_string(required(KEY_IDEMPOTENCY_KEY)?)?,
        trigger_ref: required_string(required(KEY_TRIGGER_REF)?)?,
        verb: required_string(required(KEY_VERB)?)?,
        channel: required_string(required(KEY_CHANNEL)?)?,
        target: required_string(required(KEY_TARGET)?)?,
        on_behalf_of: optional_string(KEY_ON_BEHALF_OF)?,
        content_ref: optional_string(KEY_CONTENT_REF)?,
        dedupe_key: optional_string(KEY_DEDUPE_KEY)?,
    };
    require_proposal_agreement(&fields)?;
    Ok(fields)
}

/// Every derived field must still agree with the instance and phase it claims
/// to be about, and every delivery string must obey the normal bounds.
fn require_proposal_agreement(fields: &ProposalFields) -> Result<()> {
    let due = CommitmentWakeDue {
        instance_id: fields.instance_id,
        phase: fields.phase,
        fire_at: fields.fire_at,
        due_at: fields.due_at,
    };
    due.event().validate()?;
    if fields.idempotency_key != due.idempotency_key()
        || fields.trigger_ref != due.trigger_ref()
        || fields.occurred_at != fields.fire_at
    {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal fields disagree",
        ));
    }
    CommitmentWakeProposalDraft {
        verb: fields.verb.clone(),
        channel: fields.channel.clone(),
        target: fields.target.clone(),
        on_behalf_of: fields.on_behalf_of.clone(),
        content_ref: fields.content_ref.clone(),
        dedupe_key: fields.dedupe_key.clone(),
    }
    .validate()
}

/// Converts ONE approved token into the existing outbound draft and delegates
/// EXACTLY ONCE to [`crate::memory::Memory::schedule_outbound`].
///
/// Two ordered guards run before any draft is constructed or any outbound
/// method is called:
///
/// 0. The token is reconstructed from CURRENT vault state and must compare
///    equal. A revoked proposal, a closed or stale commitment, or a mutated
///    field is refused here — BEFORE actor checking — so a stale token can
///    never reach a connector, gate, task, receipt, or idempotency lookup. The
///    residual read-then-schedule TOCTOU window is accepted, matching every
///    other non-transactional facade verb.
/// 1. The facade must be bound to the proposal's authoring agent. Same-actor
///    replay proceeds into the existing idempotency path and coalesces.
///
/// # Errors
///
/// A typed facade error for either guard, plus every existing
/// `schedule_outbound` refusal — including a planner-supplied channel/verb the
/// outbound door rejects, which leaves the approved proposal inert.
pub fn schedule_approved_commitment_wake(
    facade: &Memory<'_>,
    approved: ApprovedCommitmentWake,
) -> MemoryResult<OutboundIntentReceipt> {
    let current = approved_commitment_wake(facade.vault(), &approved.proposal_claim_id)
        .map_err(|_| stale_commitment_wake_token())?;
    if current != approved {
        return Err(stale_commitment_wake_token());
    }
    if facade.actor() != approved.bound_actor {
        return Err(MemoryError::from(Error::ActorLacksClaimAuthority {
            reason: "commitment wake is bound to its authoring agent actor",
        }));
    }
    facade.schedule_outbound(&OutboundDraftInput {
        verb: approved.verb,
        channel: approved.channel,
        target: approved.target,
        on_behalf_of: approved.on_behalf_of,
        content_ref: approved.content_ref,
        idempotency_key: Some(approved.idempotency_key),
        dedupe_key: approved.dedupe_key,
        trigger: COMMITMENT_WAKE_TRIGGER.to_owned(),
        trigger_ref: commitment_trigger_ref(&approved.instance_id),
        // NOT the phase key: `cmt:...` is not a 32-hex attempt id and must
        // never alias the attempt run index.
        job_ref: None,
        occurred_at: Some(approved.occurred_at),
    })
}

fn stale_commitment_wake_token() -> MemoryError {
    MemoryError::from(Error::InvalidClaimBody(
        "approved commitment wake token is stale",
    ))
}
