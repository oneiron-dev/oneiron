//! Refs-only attempt payload, advisory dedupe key, leader-gated claim, and membership-leg execution.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::detection::{CampaignEnrollmentEvent, campaign_enrollment_event};
use super::home_node::{
    CampaignHomeNodeAdmission, CampaignHomeNodeDesignation, require_campaign_home_node,
};
use super::program::{CampaignProgramStep, campaign_program, campaign_program_step};
use super::storage::{
    CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND, CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, from_row,
    id_from_hex, invalid, pin_schema, to_row,
};
use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, EnqueueAttempt,
    EnqueueOutcome,
};
use crate::campaign::claims::CampaignMemberState;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::outbound_intent_ledger::{IntentId, OutboundCallRequest, derive_intent_id};
use crate::saved_query::{
    EvaluationRequest, MatchVerdict, MembershipCause, MembershipCommitOutcome,
    MembershipTransition, MembershipWritePlan, SavedQueryEvaluator, commit_membership_plan,
    derived_member_value, read_saved_query,
};

// ---------------------------------------------------------------------------
// The attempt payload
// ---------------------------------------------------------------------------

/// The whole queue payload: three refs.
///
/// Resolving them is a CROSS-BINDING, not a lookup — the program must belong to
/// the event's campaign and the step must belong to that program, or execution
/// fails closed. Refs a caller can shuffle are refs a caller can misuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CampaignEnrollmentAttemptPayload {
    /// The persisted [`CampaignEnrollmentEvent`].
    pub membership_event_ref: EntityId,
    /// The persisted [`CampaignProgram`].
    pub campaign_program_ref: EntityId,
    /// The persisted [`CampaignProgramStep`].
    pub program_step_ref: EntityId,
}

/// Encodes the refs-only payload.
///
/// # Errors
///
/// Serialization errors surface as [`Error::InvalidConfig`].
pub fn encode_enrollment_attempt_payload(
    payload: &CampaignEnrollmentAttemptPayload,
) -> Result<Vec<u8>> {
    to_row(&AttemptPayloadRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        membership_event_ref: payload.membership_event_ref.to_hex(),
        campaign_program_ref: payload.campaign_program_ref.to_hex(),
        program_step_ref: payload.program_step_ref.to_hex(),
    })
}

/// Decodes the refs-only payload, rejecting unknown, duplicated, or
/// wrong-version keys.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] for any malformed payload.
pub fn decode_enrollment_attempt_payload(bytes: &[u8]) -> Result<CampaignEnrollmentAttemptPayload> {
    const CONTEXT: &str = "campaign enrollment attempt payload";
    let row: AttemptPayloadRow = from_row(bytes, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    Ok(CampaignEnrollmentAttemptPayload {
        membership_event_ref: id_from_hex(&row.membership_event_ref, CONTEXT)?,
        campaign_program_ref: id_from_hex(&row.campaign_program_ref, CONTEXT)?,
        program_step_ref: id_from_hex(&row.program_step_ref, CONTEXT)?,
    })
}

/// Advisory queue-hygiene key over the persisted transition.
///
/// It coalesces duplicate enqueues and nothing more. Every correctness property
/// this module claims survives this key being wrong, absent, or hostile.
///
/// It covers the whole transition rather than just `(query, entity, epoch)`
/// because the epoch only advances when a COMMIT spends it: every transition
/// detected before the first one lands shares an epoch. Keying on that alone
/// made the coalescer answer "same work" for genuinely different pending
/// transitions, so the newest one would inherit the oldest one's queue row and
/// then never execute — an advisory key silently deciding what gets enrolled.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the membership event ref does not resolve.
pub fn enrollment_dedupe_key(
    vault: &Vault,
    payload: &CampaignEnrollmentAttemptPayload,
) -> Result<String> {
    let event = campaign_enrollment_event(vault, payload.membership_event_ref)?
        .ok_or(Error::EntityNotFound)?;
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.campaign.enrollment.dedupe.v1");
    hasher.update(event.query_ref.as_bytes());
    hasher.update(event.entity_ref.as_bytes());
    hasher.update(event.epoch.to_be_bytes());
    hasher.update(event.transition.as_str().as_bytes());
    hasher.update([0u8]);
    hasher.update(event.cause.as_str().as_bytes());
    hasher.update([0u8]);
    hasher.update(event.evidence_hash);
    Ok(bytes_to_hex_lower(&hasher.finalize()))
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

/// Outcome of a home-gated claim.
// Carrying the queue's own outcome verbatim is the point — a second vocabulary
// for "claimed / empty" would drift from it. `ClaimOutcome` takes the same
// allow at its definition for the same reason.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CampaignEnrollmentClaim {
    /// The local node took (or found nothing to take from) the queue.
    Queue(ClaimOutcome),
    /// Another node is the home node; the row stays available to it.
    NotHomeNode(CampaignHomeNodeDesignation),
    /// No home node is designated; the row stays queued.
    NoHomeNode,
}

/// What one execution of a claimed enrollment attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentExecution {
    /// The cohort row landed. `outbound_intent` is the stable identity the
    /// outward leg will use, derived from the durable attempt id and the
    /// program step's `call_seq` — it is not evidence that a send happened.
    Applied {
        /// Stable outward-leg identity, when the step declares one.
        outbound_intent: Option<IntentId>,
    },
    /// This exact epoch and content had already landed.
    AlreadyApplied {
        /// Stable outward-leg identity, when the step declares one.
        outbound_intent: Option<IntentId>,
    },
    /// The event's epoch is behind the watermark. Distinct from
    /// `AlreadyApplied`: a replayed `Entered` from before an exit must never be
    /// reported as success.
    RejectedStaleEpoch {
        /// Watermark that rejected the plan.
        current_epoch: u64,
    },
    /// The transition no longer describes reality; nothing was written or sent.
    SkippedStale,
    /// A bulk cause needs an owner ruling before it may write.
    ReviewRequired {
        /// The persisted cause that routed here.
        cause: MembershipCause,
    },
    /// Leadership moved between claim and write.
    NotHomeNode(CampaignHomeNodeDesignation),
    /// Leadership vanished between claim and write.
    NoHomeNode,
}

/// Leader-only enrollment runner over the existing attempt queue.
pub struct CampaignEnrollmentRunner<'a> {
    vault: &'a Vault,
    attempts: AttemptQueue<'a>,
}

impl<'a> CampaignEnrollmentRunner<'a> {
    /// Opens a runner over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            attempts: AttemptQueue::new(vault),
        }
    }

    /// Enqueues one enrollment attempt.
    ///
    /// The membership ref must already resolve: a queue row pointing at nothing
    /// is a row whose consequence can never be derived.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for an unresolvable membership ref; queue and
    /// storage errors propagate.
    pub fn enqueue(
        &self,
        payload: &CampaignEnrollmentAttemptPayload,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueOutcome> {
        let dedupe_key = enrollment_dedupe_key(self.vault, payload)?;
        self.attempts.enqueue(EnqueueAttempt {
            kind: CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND.to_owned(),
            payload: encode_enrollment_attempt_payload(payload)?,
            dedupe_key: Some(dedupe_key),
            run_id,
            now,
        })
    }

    /// Claims the oldest queued enrollment attempt, but only on the home node.
    ///
    /// The designation check runs BEFORE the queue is touched, so a non-home
    /// node never leases a row it would not be allowed to finish.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a zero node id; queue errors propagate.
    pub fn claim_if_home(
        &self,
        local_node_id: u64,
        lease_owner: String,
        now: u64,
    ) -> Result<CampaignEnrollmentClaim> {
        match require_campaign_home_node(self.vault, local_node_id)? {
            CampaignHomeNodeAdmission::NoHomeNode => Ok(CampaignEnrollmentClaim::NoHomeNode),
            CampaignHomeNodeAdmission::NotHomeNode(designation) => {
                Ok(CampaignEnrollmentClaim::NotHomeNode(designation))
            }
            CampaignHomeNodeAdmission::Designated(_) => self
                .attempts
                .claim_kind(
                    CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND,
                    ClaimAttempt { lease_owner, now },
                )
                .map(CampaignEnrollmentClaim::Queue),
        }
    }

    /// Executes one claimed attempt: the membership consequence leg.
    ///
    /// Outward firing is deliberately a SECOND leg
    /// (`run_enrollment_outbound_leg`): a crash between the cohort write and
    /// the intent record must resume the send, not redo the write.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a foreign attempt kind or a payload whose
    /// refs do not cross-bind; [`Error::EntityNotFound`] for unresolvable refs;
    /// evaluation, claim-validation, and storage errors propagate.
    pub async fn execute_claimed(
        &self,
        local_node_id: u64,
        record: &AttemptRecord,
        evaluator: &SavedQueryEvaluator<'_>,
        now: u64,
    ) -> Result<EnrollmentExecution> {
        if record.kind != CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND {
            return Err(invalid("attempt kind is not campaign.enrollment.macro"));
        }
        if let Some(refused) = home_node_refusal(self.vault, local_node_id)? {
            return Ok(refused);
        }
        let payload = decode_enrollment_attempt_payload(&record.payload)?;
        let event = campaign_enrollment_event(self.vault, payload.membership_event_ref)?
            .ok_or(Error::EntityNotFound)?;
        let step = resolve_program_step(self.vault, &payload, &event)?;

        // Staleness outranks cause. A transition that no longer describes
        // reality has nothing for the owner to rule on, so asking would park
        // dead work in the review queue instead of dropping it.
        if event.transition != MembershipTransition::Entered {
            return Ok(EnrollmentExecution::SkippedStale);
        }
        if !self.evidence_still_holds(evaluator, &event, now).await? {
            return Ok(EnrollmentExecution::SkippedStale);
        }

        // The ratified routing dial: only ordinary data movement auto-applies.
        // A bulk scope or definition move is the owner's call, and no payload
        // field can reach this decision.
        if event.cause != MembershipCause::DataChange {
            return Ok(EnrollmentExecution::ReviewRequired { cause: event.cause });
        }

        // Re-checked HERE, immediately before the write: a lease proves this
        // node claimed the work, not that it is still allowed to finish it.
        if let Some(refused) = home_node_refusal(self.vault, local_node_id)? {
            return Ok(refused);
        }
        let membership_event = event.membership_event();
        let plan = MembershipWritePlan {
            value: derived_member_value(
                &membership_event,
                CampaignMemberState::Enrolled,
                vec![step.member_channel()],
            ),
            event: membership_event,
        };
        let outbound_intent = enrollment_intent_id(&event, &step)?;
        Ok(match commit_membership_plan(self.vault, &plan, now)? {
            MembershipCommitOutcome::Applied => EnrollmentExecution::Applied { outbound_intent },
            MembershipCommitOutcome::AlreadyApplied => {
                EnrollmentExecution::AlreadyApplied { outbound_intent }
            }
            MembershipCommitOutcome::RejectedStaleEpoch { current_epoch } => {
                EnrollmentExecution::RejectedStaleEpoch { current_epoch }
            }
        })
    }

    /// Re-derives the saved-query result under the query's OWN owner actor and
    /// the evaluator's current grants, and reports whether the persisted event
    /// still describes reality.
    async fn evidence_still_holds(
        &self,
        evaluator: &SavedQueryEvaluator<'_>,
        event: &CampaignEnrollmentEvent,
        now: u64,
    ) -> Result<bool> {
        let record = read_saved_query(self.vault, event.owner_actor, event.query_ref)?
            .ok_or(Error::EntityNotFound)?;
        let outcome = evaluator
            .evaluate_entity(&EvaluationRequest {
                query_ref: event.query_ref,
                campaign_ref: event.campaign_ref,
                entity_ref: event.entity_ref,
                definition: &record.definition,
                cause: event.cause,
                valid_at: event.valid_at,
                detected_at: now,
            })
            .await?;
        Ok(outcome.decision.verdict == MatchVerdict::Match
            && outcome.evidence_hash == event.evidence_hash)
    }
}

fn home_node_refusal(vault: &Vault, local_node_id: u64) -> Result<Option<EnrollmentExecution>> {
    Ok(match require_campaign_home_node(vault, local_node_id)? {
        CampaignHomeNodeAdmission::Designated(_) => None,
        CampaignHomeNodeAdmission::NotHomeNode(designation) => {
            Some(EnrollmentExecution::NotHomeNode(designation))
        }
        CampaignHomeNodeAdmission::NoHomeNode => Some(EnrollmentExecution::NoHomeNode),
    })
}

/// Resolves the program step and proves it belongs to the event's campaign.
pub(super) fn resolve_program_step(
    vault: &Vault,
    payload: &CampaignEnrollmentAttemptPayload,
    event: &CampaignEnrollmentEvent,
) -> Result<CampaignProgramStep> {
    let program =
        campaign_program(vault, payload.campaign_program_ref)?.ok_or(Error::EntityNotFound)?;
    if program.campaign_ref != event.campaign_ref {
        return Err(invalid(
            "campaign program does not belong to the event's campaign",
        ));
    }
    campaign_program_step(vault, program.program_ref, payload.program_step_ref)?
        .ok_or(Error::EntityNotFound)
}

/// The durable identity of ONE enrollment consequence, standing where ONE-1691
/// expects a queue attempt id.
///
/// The ledger derives an intent from `(attempt_id, call_seq, server, tool,
/// payload_hash)` and dedupes sends by that intent, so whatever is handed in as
/// `attempt_id` is the definition of "the same send". The queue row id is the
/// wrong definition here: this module treats duplicate attempts for one
/// transition as tolerable BY DESIGN — the dedupe key is advisory — and an
/// `AlreadyApplied` membership still owes its outward leg. Two rows for one
/// transition would therefore freeze two intents and send the same enrollment
/// twice, putting the advisory key back on the correctness path it was
/// deliberately kept off.
///
/// So the identity is the consequence itself: the `(query, entity, epoch)` the
/// watermark already treats as the unit of membership, the campaign it lands
/// in, and the program step that carries it. Duplicate rows converge on one
/// ledger intent; two genuinely different consequences still diverge.
pub(super) fn enrollment_consequence_id(
    event: &CampaignEnrollmentEvent,
    step: &CampaignProgramStep,
) -> Result<AttemptId> {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.campaign.enrollment.consequence.v1");
    hasher.update(event.query_ref.as_bytes());
    hasher.update(event.entity_ref.as_bytes());
    hasher.update(event.epoch.to_be_bytes());
    hasher.update(event.campaign_ref.as_bytes());
    hasher.update(step.program_ref.as_bytes());
    hasher.update(step.step_ref.as_bytes());
    AttemptId::from_bytes(&hasher.finalize()[..16])
}

/// The stable outward-leg identity for this consequence, derived exactly the
/// way ONE-1691 will derive it at dispatch.
pub(super) fn enrollment_intent_id(
    event: &CampaignEnrollmentEvent,
    step: &CampaignProgramStep,
) -> Result<Option<IntentId>> {
    let Some(outbound) = step.outbound.as_ref() else {
        return Ok(None);
    };
    derive_intent_id(
        enrollment_consequence_id(event, step)?,
        outbound.call_seq,
        &step.channel,
        &outbound.verb,
        &crate::outbound_intent_ledger::hash_frozen_payload(&outbound.payload),
    )
    .map(Some)
    .map_err(|_| invalid("campaign enrollment outbound identity is not derivable"))
}

/// Derives the outward call from PERSISTED program state plus the durable
/// consequence identity. No caller supplies any of it — and nothing about the
/// queue row that happens to be carrying the work reaches the derivation.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the refs do not cross-bind;
/// [`Error::EntityNotFound`] when they do not resolve.
pub fn derive_enrollment_outbound_request(
    vault: &Vault,
    payload: &CampaignEnrollmentAttemptPayload,
    event: &CampaignEnrollmentEvent,
    now_ms: u64,
) -> Result<Option<OutboundCallRequest>> {
    let step = resolve_program_step(vault, payload, event)?;
    let consequence_id = enrollment_consequence_id(event, &step)?;
    let CampaignProgramStep {
        channel, outbound, ..
    } = step;
    Ok(outbound.map(|outbound| {
        OutboundCallRequest::new(
            consequence_id,
            outbound.call_seq,
            channel,
            outbound.verb,
            outbound.payload,
            now_ms,
        )
    }))
}

// ---------------------------------------------------------------------------
// Codecs and small storage helpers
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptPayloadRow {
    schema_version: u32,
    membership_event_ref: String,
    campaign_program_ref: String,
    program_step_ref: String,
}
