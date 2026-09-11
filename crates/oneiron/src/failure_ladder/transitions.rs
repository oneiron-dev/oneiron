//! Queue-transition guards and single-transition helpers (validate, scope-bind, fail/retry once).

use std::num::NonZeroU16;

use crate::Vault;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchTarget, decode_agent_dispatch_input,
};
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, FailAttempt, FailOutcome, RetryAttempt, RetryOutcome,
};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::blocked_reports::{BlockedReportRef, BlockedReportVerification, verify_blocked_reports};
use super::classify::{TypedFailureEvidence, TypedFailureVerdict};
use super::lineage::{FailureLadderOutcome, HandleAttemptFailure};
use super::scope::FailureScope;
use crate::error::ArtifactError;

/// Step 0: `stable_reason` must be non-empty, and every non-Indeterminate
/// verdict must carry BOTH `evidence_ref` and `tier`. Returns the parsed
/// evidence ref so no later arm re-parses caller text.
pub(super) fn validated_evidence_ref(evidence: &TypedFailureEvidence) -> Result<Option<EntityId>> {
    if evidence.stable_reason.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "typed failure evidence requires a non-empty stable_reason".to_owned(),
        ));
    }
    let indeterminate = evidence.verdict == TypedFailureVerdict::Indeterminate;
    if !indeterminate && (evidence.evidence_ref.is_none() || evidence.tier.is_none()) {
        return Err(Error::InvalidConfig(
            "a determinate failure verdict requires both evidence_ref and tier".to_owned(),
        ));
    }
    evidence
        .evidence_ref
        .as_deref()
        .map(|hex| {
            EntityId::from_hex(hex).map_err(|_| {
                Error::InvalidConfig(
                    "typed failure evidence_ref must be a hex-encoded EntityId string".to_owned(),
                )
            })
        })
        .transpose()
}

pub(super) fn require_evidence_ref(evidence_ref: Option<EntityId>) -> Result<EntityId> {
    evidence_ref.ok_or(Error::InvalidConfig(
        "a healer-bound failure class requires typed evidence_ref".to_owned(),
    ))
}

/// Step 1a: the failing row must be an agent-dispatch row whose dispatched
/// target is exactly the policy scope's agent. `pre_fail_checkpoint_ref` and
/// `qa_thread_ref` stay caller-supplied: the trust basis is the lease fence,
/// because the caller is the authenticated executor of exactly this attempt.
pub(super) fn require_dispatch_scope(record: &AttemptRecord, scope: &FailureScope) -> Result<()> {
    let expected = EntityId::from_hex(&scope.agent_ref).map_err(|_| {
        Error::InvalidConfig(
            "failure scope agent_ref must be a hex-encoded EntityId string".to_owned(),
        )
    })?;
    let Some(dispatched) = dispatched_target_ref(record) else {
        return Err(Error::InvalidConfig(
            "the failing attempt is not an agent dispatch row".to_owned(),
        ));
    };
    if dispatched != expected {
        return Err(Error::InvalidConfig(
            "the failure scope agent does not match the failing row's dispatched agent".to_owned(),
        ));
    }
    Ok(())
}

/// The dispatched AGENT_DEF ref of a queue row, read through the SAME pinned
/// codec the dispatch and landing-successor paths use.
pub(crate) fn dispatched_target_ref(record: &AttemptRecord) -> Option<EntityId> {
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return None;
    }
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    let AgentDispatchTarget::Custom(target) =
        decode_agent_dispatch_input(&payload.input).ok()?.target;
    Some(target)
}

pub(crate) fn verified_blocked_reports(
    vault: &Vault,
    reports: &[BlockedReportRef],
) -> Result<Vec<BlockedReportRef>> {
    Ok(verify_blocked_reports(vault, reports)?
        .into_iter()
        .filter_map(|verification| match verification {
            BlockedReportVerification::Verified(report) => Some(report),
            BlockedReportVerification::Dropped { .. } => None,
        })
        .collect())
}

/// The single terminal transition. `AlreadyFailed` means a concurrent failure
/// input won it, so the loser routes NOTHING — no healer dispatch, no card, no
/// surface — and returns the existing typed transition error.
pub(super) fn fail_once(
    queue: &AttemptQueue<'_>,
    input: &HandleAttemptFailure,
) -> Result<AttemptRecord> {
    match queue.fail(FailAttempt {
        id: input.attempt_id,
        lease_owner: input.lease_owner.clone(),
        attempt_count: input.attempt_count,
        reason: input.evidence.stable_reason.clone(),
        now: input.now,
    })? {
        FailOutcome::Failed(record) => Ok(record),
        FailOutcome::AlreadyFailed(_) => Err(Error::Artifact(
            ArtifactError::InvalidAttemptQueueTransition {
                action: "failure ladder",
                state: "failed",
            },
        )),
    }
}

/// The single retry transition. The schedule is NOT invented here: `retry_at`
/// comes from the caller's existing typed backoff policy and is forwarded to
/// the landed `backoff_until` field, which is the new row's `scheduled_at`.
pub(super) fn retry_once(
    queue: &AttemptQueue<'_>,
    input: HandleAttemptFailure,
    ordinal: NonZeroU16,
) -> Result<FailureLadderOutcome> {
    let source_attempt_id = input.attempt_id;
    let RetryOutcome::Retried(scheduled_attempt) = queue.retry(RetryAttempt {
        id: source_attempt_id,
        lease_owner: input.lease_owner,
        attempt_count: input.attempt_count,
        backoff_until: input.retry_at,
        last_error: Some(input.evidence.stable_reason),
        now: input.now,
    })?;
    Ok(FailureLadderOutcome::Retried {
        source_attempt_id,
        scheduled_attempt: Box::new(scheduled_attempt),
        consecutive_transients: ordinal,
    })
}
