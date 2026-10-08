//! A failed workflow step, settled through the engine's typed failure ladder:
//! the one door that may retry or end an agent-dispatch attempt, and the one
//! that carries the step's run tree and authority scope onto a retry.
//!
//! A model call the provider answered with a retryable error is a host
//! tripwire (T1) whose evidence is the failed attempt itself (its
//! `last_error` keeps the reason). It is tried again after a backoff, up to
//! five consecutive tries. Anything else, and a fifth retryable failure,
//! ends the step for a person to look at (escalation `Human`, no healer case),
//! and the workflow stops. The checkpoint and Q&A refs the ladder forwards to
//! that surface name the workflow root: the server keeps no Q&A thread for
//! steps, and neither ref is persisted on these two paths.
use std::num::NonZeroU16;

use oneiron::agent_dispatch::{HealerSlot, decode_agent_dispatch_input};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
use oneiron::failure_ladder::{
    DetectorTier, FailureEscalationMode, FailureLadderOutcome, FailureScope, FailureScopePolicy,
    HandleAttemptFailure, TypedFailureEvidence, TypedFailureVerdict,
};
use oneiron::{DreamerRunnerStore, EntityId, Vault};

/// Consecutive tries of one step before it ends: five.
const MAX_TRIES: NonZeroU16 = NonZeroU16::MIN.saturating_add(4);

/// A step lease this pump holds after the step failed.
pub(super) struct FailedStep {
    pub(super) leaf: AttemptId,
    /// The lease generation: fences the settlement to this lease.
    pub(super) lease_count: u32,
    /// A later try of the same call may succeed.
    pub(super) retryable: bool,
}

/// Leases `lease_owner` holds while none of its steps runs: a claim that
/// committed before the step's context failed to resolve.
pub(super) fn held_leases(vault: &Vault, lease_owner: &str) -> oneiron::Result<Vec<FailedStep>> {
    Ok(AttemptQueue::new(vault)
        .list()?
        .into_iter()
        .filter(|row| {
            row.state == AttemptState::Leased && row.lease_owner.as_deref() == Some(lease_owner)
        })
        .map(|row| FailedStep {
            leaf: row.id,
            lease_count: row.attempt_count,
            retryable: false,
        })
        .collect())
}

/// Hands one failed step to the ladder: a later try, or the end of the step.
pub(super) fn settle(
    vault: &Vault,
    root: AttemptId,
    step: &FailedStep,
    lease_owner: &str,
    backoff_secs: u64,
    now: u64,
) -> oneiron::Result<FailureLadderOutcome> {
    let queue = AttemptQueue::new(vault);
    let record = queue
        .get(step.leaf)?
        .ok_or_else(|| oneiron::Error::InvalidConfig("failed workflow step is missing".into()))?;
    let payload = decode_dreamer_attempt_payload(&record.payload)?;
    let agent = decode_agent_dispatch_input(&payload.input)?
        .target
        .agent_definition_ref()?;
    let as_entity = |id: AttemptId| EntityId::from_bytes(*id.as_bytes());
    let evidence = if step.retryable {
        TypedFailureEvidence {
            evidence_ref: Some(as_entity(step.leaf)?.to_hex()),
            verdict: TypedFailureVerdict::Retryable,
            tier: Some(DetectorTier::T1Tripwire),
            stable_reason: "workflow_step_model_call_failed".to_owned(),
        }
    } else {
        // The host has no detector verdict for this failure; the ladder
        // never infers one from prose.
        TypedFailureEvidence {
            evidence_ref: None,
            verdict: TypedFailureVerdict::Indeterminate,
            tier: None,
            stable_reason: "workflow_step_failed".to_owned(),
        }
    };
    let root_ref = as_entity(root)?;
    // Which try of its step this was: a retry is a fresh row, so the try
    // count is the lineage behind it.
    let tries = queue
        .retry_chain_depth(step.leaf)?
        .saturating_add(1)
        .min(u32::from(MAX_TRIES.get()));
    DreamerRunnerStore::new(vault).fail_agent_dispatch_with_evidence(
        HandleAttemptFailure {
            attempt_id: step.leaf,
            lease_owner: lease_owner.to_owned(),
            attempt_count: step.lease_count,
            evidence,
            blocked_reports: Vec::new(),
            pre_fail_checkpoint_ref: root_ref,
            qa_thread_ref: root_ref,
            retry_at: now.saturating_add(backoff_secs.saturating_mul(u64::from(tries))),
            now,
        },
        FailureScopePolicy {
            scope: FailureScope {
                agent_ref: agent.to_hex(),
                skill_ref: None,
            },
            max_consecutive_transients: MAX_TRIES,
            escalation_mode: FailureEscalationMode::Human,
            healer_slot: HealerSlot::Reserved,
        },
    )
}
