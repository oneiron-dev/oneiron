//! Proposal planner, deterministic claim id, and the wrapper executor.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject};
use crate::commitment::CommitmentRecord;
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, DreamerAdmittedAttempt};
use crate::dreamer_wake::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

use super::wake_approval::claim_provenance;
use super::wake_event::{
    COMMITMENT_WAKE_PROPOSAL_CLAIM_ID_DOMAIN, COMMITMENT_WAKE_PROPOSAL_SCHEMA_VERSION,
    CommitmentWakeEvent, KEY_CHANNEL, KEY_CONTENT_REF, KEY_DEDUPE_KEY, KEY_DUE_AT, KEY_FIRE_AT,
    KEY_IDEMPOTENCY_KEY, KEY_INSTANCE_REF, KEY_OCCURRED_AT, KEY_ON_BEHALF_OF, KEY_PHASE,
    KEY_SCHEMA_VERSION, KEY_TARGET, KEY_TRIGGER_REF, KEY_VERB, PREDICATE_COMMITMENT_WAKE_PROPOSAL,
    PROVENANCE_KEY_JOB_ID, PROVENANCE_KEY_RUN, PROVENANCE_KEY_SURFACE,
    decode_commitment_wake_event, validate_optional_wake_string, validate_wake_string,
};
use super::wake_fire::{WakeEligibility, wake_eligibility};

// ---------------------------------------------------------------------------
// 4. Proposal planner, deterministic claim id, and the wrapper executor
// ---------------------------------------------------------------------------

/// The ONLY fields a planner controls.
///
/// Instance, phase, timestamps, trigger reference, approval status, proposal
/// id, and idempotency key are all derived from the event: a planner proposes
/// a delivery, it does not restate the obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentWakeProposalDraft {
    pub verb: String,
    pub channel: String,
    pub target: String,
    pub on_behalf_of: Option<String>,
    pub content_ref: Option<String>,
    pub dedupe_key: Option<String>,
}

impl CommitmentWakeProposalDraft {
    pub(super) fn validate(&self) -> Result<()> {
        validate_wake_string(&self.verb, "commitment wake proposal verb is invalid")?;
        validate_wake_string(&self.channel, "commitment wake proposal channel is invalid")?;
        validate_wake_string(&self.target, "commitment wake proposal target is invalid")?;
        validate_optional_wake_string(
            self.on_behalf_of.as_deref(),
            "commitment wake proposal on_behalf_of is invalid",
        )?;
        validate_optional_wake_string(
            self.content_ref.as_deref(),
            "commitment wake proposal content_ref is invalid",
        )?;
        validate_optional_wake_string(
            self.dedupe_key.as_deref(),
            "commitment wake proposal dedupe_key is invalid",
        )
    }
}

/// Host-injected proposal planner.
///
/// Deliberately SYNCHRONOUS and deterministic in v1: the tagged path satisfies
/// the at-least-once executor contract through deterministic-claim-id
/// idempotency instead of `call_as_step`, which is only sound while replay
/// re-derives an identical proposal at zero chargeable spend. A planner that
/// wants to call a model must pre-materialize its content behind `content_ref`;
/// an async or budgeted planner MUST adopt `call_as_step` first.
pub trait CommitmentWakeProposalPlanner {
    /// Proposes the delivery fields for one wake.
    ///
    /// # Errors
    ///
    /// Any typed reason the host cannot propose a delivery.
    fn plan(
        &mut self,
        event: &CommitmentWakeEvent,
        commitment: &CommitmentRecord,
    ) -> Result<CommitmentWakeProposalDraft>;
}

/// Why a tagged attempt completed without writing a proposal. Every arm is a
/// COMPLETION with zero units, never a park and never a decode error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommitmentWakeProposalSkip {
    /// The host installed no planner. The wrapper is still installed by
    /// default, so the tagged event is logged and retired rather than falling
    /// through to the partition decoder.
    NoPlannerConfigured,
    /// The instance is gone.
    MissingInstance,
    /// The instance is closed or no longer `Commitment` strength.
    IneligibleInstance,
}

impl CommitmentWakeProposalSkip {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoPlannerConfigured => "no_planner_configured",
            Self::MissingInstance => "missing_instance",
            Self::IneligibleInstance => "ineligible_instance",
        }
    }
}

/// The deterministic proposal claim id for one attempt.
///
/// Hashes exactly the domain separator plus the 16 attempt bytes, then takes
/// the first 16 BLAKE3 bytes RAW. A prefix colliding with a reserved sentinel
/// is perturbed deterministically (`raw[0] ^= 1`, `raw[15] ^= 1`), exactly as
/// `dreamer_consolidation` does — no RFC-4122 version or variant bits are
/// rewritten, so the id stays a pure function of the attempt.
#[must_use]
pub fn commitment_wake_proposal_claim_id(attempt_id: AttemptId) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMITMENT_WAKE_PROPOSAL_CLAIM_ID_DOMAIN);
    hasher.update(attempt_id.as_bytes());
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    entity_id_from_digest_prefix(raw)
}

/// The sentinel-safe raw-prefix rule, factored out so the perturb branch is
/// reachable by a fixture: a BLAKE3 prefix landing on a reserved id is roughly
/// a 2^-120 event and would otherwise be untestable.
pub(super) fn entity_id_from_digest_prefix(mut raw: [u8; 16]) -> EntityId {
    EntityId::from_bytes(raw).unwrap_or_else(|_| {
        raw[0] ^= 0x01;
        raw[15] ^= 0x01;
        EntityId::from_bytes(raw).unwrap_or_else(|_| {
            unreachable!("perturbed commitment wake proposal id is non-reserved")
        })
    })
}

/// Wraps the ordinary consolidation executor with the commitment-wake arm.
///
/// The wrapper is installed by the production factory ALWAYS, planner or not:
/// a tagged event reaching the partition decoder is a decode error and a
/// parked driver, and "install the handler only when configured" is exactly
/// the wiring mistake that produces it.
pub struct CommitmentWakeExecutor<'p, E> {
    inner: E,
    planner: Option<&'p mut dyn CommitmentWakeProposalPlanner>,
    agent_actor: WriteActor,
}

impl<'p, E> CommitmentWakeExecutor<'p, E> {
    /// Composes the wrapper.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] when a planner is installed behind a
    /// non-Agent actor. A planner-LESS wrapper never uses the actor and
    /// constructs for every legal existing host, including a System-class one —
    /// which is what keeps the default composition site infallible in practice.
    pub fn new(
        inner: E,
        planner: Option<&'p mut dyn CommitmentWakeProposalPlanner>,
        agent_actor: WriteActor,
    ) -> Result<Self> {
        if planner.is_some() && agent_actor.actor_class() != EdgeActorClass::Agent {
            return Err(Error::InvalidClaimBody(
                "commitment wake planner requires agent actor",
            ));
        }
        Ok(Self {
            inner,
            planner,
            agent_actor,
        })
    }
}

impl<E: DreamerAttemptExecutor> DreamerAttemptExecutor for CommitmentWakeExecutor<'_, E> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        // Step 1-2: an ordinary partition attempt is delegated with its
        // payload, context, result, and error untouched.
        let Some(event) = decode_commitment_wake_event(&attempt.status.payload.input)? else {
            return self.inner.execute(attempt, ctx).await;
        };
        self.execute_commitment_wake(&event, attempt, ctx)
    }
}

impl<E> CommitmentWakeExecutor<'_, E> {
    /// Steps 3-9. Synchronous on purpose: no model call, no `call_as_step`,
    /// and exactly `completed_units: 0` on every terminal path.
    fn execute_commitment_wake(
        &mut self,
        event: &CommitmentWakeEvent,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        let attempt_id = attempt.status.attempt.id;
        // Step 3: re-read the instance through the ORDINARY public read; this
        // executor owns no transaction, so the nested-read hazard of the fire
        // door does not apply here.
        let Some(record) = ctx.vault.get_commitment_claim(&event.instance_id)? else {
            return Ok(skip_completion(
                CommitmentWakeProposalSkip::MissingInstance,
                event,
                attempt_id,
            ));
        };
        if !matches!(wake_eligibility(&record), WakeEligibility::Eligible) {
            return Ok(skip_completion(
                CommitmentWakeProposalSkip::IneligibleInstance,
                event,
                attempt_id,
            ));
        }
        // Step 4: no planner is a typed COMPLETION, never a partition decode.
        let agent_actor = self.agent_actor;
        let Some(planner) = self.planner.as_deref_mut() else {
            return Ok(skip_completion(
                CommitmentWakeProposalSkip::NoPlannerConfigured,
                event,
                attempt_id,
            ));
        };
        // Step 5: the planner supplies the delivery fields and nothing else.
        let draft = planner.plan(event, &record)?;
        draft.validate()?;
        write_commitment_wake_proposal(
            ctx.vault,
            &ProposalWrite {
                event,
                draft: &draft,
                attempt_id,
                run_id: attempt.status.attempt.run_id.as_deref(),
                agent_actor,
            },
        )?;
        Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
    }
}

/// Every tagged-event terminal path that writes nothing. `completed_units: 0`
/// is EXACT, not an estimate: this arm performs no chargeable work at all.
fn skip_completion(
    skip: CommitmentWakeProposalSkip,
    event: &CommitmentWakeEvent,
    attempt_id: AttemptId,
) -> DreamerAttemptExecution {
    tracing::info!(
        skip = skip.as_str(),
        attempt = %bytes_to_hex_lower(attempt_id.as_bytes()),
        run = %event.idempotency_key(),
        "commitment wake attempt completed without a proposal"
    );
    DreamerAttemptExecution::Completed { completed_units: 0 }
}

/// Everything the proposal write needs, gathered so the writer stays one
/// readable transaction rather than a seven-argument function.
struct ProposalWrite<'a> {
    event: &'a CommitmentWakeEvent,
    draft: &'a CommitmentWakeProposalDraft,
    attempt_id: AttemptId,
    run_id: Option<&'a str>,
    agent_actor: WriteActor,
}

/// Steps 6-9: derive the id, require the run to be the phase key, assemble one
/// candidate, then READ BEFORE WRITE.
///
/// The read-first rule is what makes replay idempotent without `call_as_step`:
/// identical immutables are success with NO write — even after the inbox has
/// advanced the row to `Approved` — and differing immutables at the same
/// deterministic id are typed corruption.
fn write_commitment_wake_proposal(vault: &Vault, write: &ProposalWrite<'_>) -> Result<()> {
    let claim_id = commitment_wake_proposal_claim_id(write.attempt_id);
    let expected_run = write.event.idempotency_key();
    if write.run_id != Some(expected_run.as_str()) {
        return Err(Error::InvalidClaimBody(
            "commitment wake attempt run id is not its phase key",
        ));
    }
    let value = encode_commitment_wake_proposal(write.event, write.draft);
    let provenance = proposal_provenance(&expected_run, write.attempt_id);
    let envelope = WriteEnvelope::new(
        write.agent_actor,
        ClaimSource::Generated,
        WriteProvenance::new(provenance.clone())?,
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        PREDICATE_COMMITMENT_WAKE_PROPOSAL,
        ClaimSubject::Entity(write.event.instance_id),
        value.clone(),
        1.0,
    )
    // GATE-12's evidence floor: a Dreamer-authored claim must cite at least one
    // ref that still resolves. The honest citation is the OBLIGATION itself —
    // the commitment instance claim this proposal exists to serve — so the
    // floor is met by the fact that motivated the wake, not by a token entity
    // minted to satisfy it.
    .with_evidence(commitment_wake_evidence(write.event.instance_id));
    let occurred = TimeRange {
        start: write.event.fire_at,
        end: write.event.fire_at,
    };

    vault.with_write_txn(|wtxn| {
        if let Some(landed) = vault.get_claim_in_txn(&*wtxn, &claim_id)? {
            return match_landed_proposal(&landed, write.event, &value, &provenance);
        }
        // The ONE write door: a raw claim write that omits recording gate
        // decisions would omit the pending consent row and remove the inbox
        // approval door entirely.
        vault
            .batch_in()
            .claim_candidate(
                &claim_id,
                candidate,
                &envelope,
                occurred,
                write.event.fire_at,
            )
            .apply_recording_gate_decisions(wtxn)?;
        vault
            .get_claim_in_txn(&*wtxn, &claim_id)?
            .ok_or(Error::InvalidClaimBody(
                "commitment wake proposal is missing inside its own write transaction",
            ))?;
        Ok(())
    })
}

/// Replay comparison. Approval and lifecycle are deliberately NOT compared:
/// an accepted proposal is a proposal that advanced, not a proposal that was
/// corrupted, and rewriting it back to `Proposed` would undo a consent answer.
fn match_landed_proposal(
    landed: &ClaimBody,
    event: &CommitmentWakeEvent,
    value: &Value,
    provenance: &Value,
) -> Result<()> {
    let corrupt = || {
        Err(Error::InvalidClaimBody(
            "commitment wake proposal id holds a different proposal",
        ))
    };
    if landed.predicate != PREDICATE_COMMITMENT_WAKE_PROPOSAL
        || landed.subject != ClaimSubject::Entity(event.instance_id)
        || landed.source != Some(ClaimSource::Generated)
        || &landed.value != value
    {
        return corrupt();
    }
    if claim_provenance(landed).as_ref() != Some(provenance) {
        return corrupt();
    }
    Ok(())
}

/// The proposal's candidate-evidence envelope, in the exact shape GATE-12's
/// floor decodes. `Generated` is the honest meet: a proposal is engine output
/// about an obligation, never a restatement of what the user said.
fn commitment_wake_evidence(instance_id: EntityId) -> Value {
    crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: vec![instance_id],
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    )
}

fn proposal_provenance(run_id: &str, attempt_id: AttemptId) -> Value {
    Value::Map(vec![
        (
            Value::from(PROVENANCE_KEY_SURFACE),
            Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
        ),
        (Value::from(PROVENANCE_KEY_RUN), Value::from(run_id)),
        (
            Value::from(PROVENANCE_KEY_JOB_ID),
            Value::from(bytes_to_hex_lower(attempt_id.as_bytes())),
        ),
    ])
}

fn encode_commitment_wake_proposal(
    event: &CommitmentWakeEvent,
    draft: &CommitmentWakeProposalDraft,
) -> Value {
    let optional =
        |value: Option<&String>| value.map_or(Value::Nil, |value| Value::from(value.as_str()));
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMMITMENT_WAKE_PROPOSAL_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_INSTANCE_REF),
            Value::Binary(event.instance_id.as_bytes().to_vec()),
        ),
        (Value::from(KEY_PHASE), Value::from(event.phase.as_str())),
        (Value::from(KEY_FIRE_AT), Value::from(event.fire_at)),
        (Value::from(KEY_DUE_AT), Value::from(event.due_at)),
        // Replay-deterministic: the event's fire instant, never `now`.
        (Value::from(KEY_OCCURRED_AT), Value::from(event.fire_at)),
        (
            Value::from(KEY_IDEMPOTENCY_KEY),
            Value::from(event.idempotency_key()),
        ),
        (
            Value::from(KEY_TRIGGER_REF),
            Value::from(event.trigger_ref()),
        ),
        (Value::from(KEY_VERB), Value::from(draft.verb.as_str())),
        (
            Value::from(KEY_CHANNEL),
            Value::from(draft.channel.as_str()),
        ),
        (Value::from(KEY_TARGET), Value::from(draft.target.as_str())),
        (
            Value::from(KEY_ON_BEHALF_OF),
            optional(draft.on_behalf_of.as_ref()),
        ),
        (
            Value::from(KEY_CONTENT_REF),
            optional(draft.content_ref.as_ref()),
        ),
        (
            Value::from(KEY_DEDUPE_KEY),
            optional(draft.dedupe_key.as_ref()),
        ),
    ])
}
