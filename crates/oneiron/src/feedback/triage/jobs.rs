//! A revision's triage job on the Coach's host queue: its input as it rides
//! the queue, its queueing and re-queueing under a sweep, and what a leased
//! job reads. The queue stays the authority on job state; a job parked on
//! its parts (FIX 7549) is the `work_store` child's to wake.
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{
    COACH_FEEDBACK_TRIAGE_FACET, FEEDBACK_TRIAGE_INBOX_SOURCE, FeedbackTriageHandoff,
    FeedbackTriageInput, FeedbackTriageItem, FeedbackTriageJob, FeedbackTriageSourceRef, HANDOFFS,
    binding_in_txn, erased, github, inbox_note, job_handoff_in_txn, work_store,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::maintenance::coach::COACH_HOST_QUEUE_KIND;
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::{EntityId, Error, Result, Vault};

/// A triage job's input as it rides the queue.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobInput {
    source: String,
    id: String,
    revision: String,
    evidence: EntityId,
}

pub(super) fn invalid_job() -> Error {
    Error::InvalidConfig("invalid feedback triage job".into())
}

pub(super) fn attempt_ref(id: AttemptId) -> Result<EntityId> {
    EntityId::from_bytes(*id.as_bytes())
}

pub(super) fn attempt_id(id: &EntityId) -> Result<AttemptId> {
    AttemptId::from_bytes(id.as_bytes())
}

fn job_input(source_ref: &FeedbackTriageSourceRef, evidence: EntityId) -> Result<Value> {
    rmpv::ext::to_value(JobInput {
        source: source_ref.source.clone(),
        id: source_ref.id.clone(),
        revision: source_ref.revision.clone(),
        evidence,
    })
    .map_err(|_| invalid_job())
}

pub(super) fn job_target(input: &Value) -> Result<(FeedbackTriageSourceRef, EntityId)> {
    let job: JobInput = rmpv::ext::from_value(input.clone()).map_err(|_| invalid_job())?;
    Ok((
        FeedbackTriageSourceRef {
            source: job.source,
            id: job.id,
            revision: job.revision,
        },
        job.evidence,
    ))
}

/// Queues one revision's triage job on the Coach's host queue under
/// `sweep`, and answers its attempt. The key holds one live job per
/// revision; a settled job holds none, so a sweep can queue it again.
pub(super) fn enqueue_triage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source_ref: &FeedbackTriageSourceRef,
    evidence: EntityId,
    sweep: AttemptId,
    run_id: Option<&str>,
    now: u64,
) -> Result<EntityId> {
    let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        COACH_HOST_QUEUE_KIND,
        DreamerAttemptPayload {
            attempt_type: COACH_FEEDBACK_TRIAGE_FACET.into(),
            input: job_input(source_ref, evidence)?,
            parent_attempt: Some(sweep),
        },
        Some(format!(
            "{COACH_FEEDBACK_TRIAGE_FACET}:{}:{}:{}",
            source_ref.source, source_ref.id, source_ref.revision
        )),
        run_id.map(str::to_owned),
        now,
    )?;
    let status = match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
    };
    attempt_ref(status.attempt.id)
}

/// Queues again each unacknowledged revision whose job settled without a
/// result or is gone, under `sweep`. A live job keeps its revision, and one
/// whose evidence the owner erased is settled erased instead. A live job
/// parked on its parts has each owed child queued again, or is woken once
/// nothing is owed (FIX 7549).
pub(super) fn requeue_unacknowledged(
    vault: &Vault,
    sweep: AttemptId,
    run_id: Option<&str>,
    now: u64,
) -> Result<usize> {
    let handoffs = {
        let txn = vault.store.env.read_txn()?;
        HANDOFFS.scan(&vault.store, &txn)?
    };
    let sweep_ref = attempt_ref(sweep)?;
    let queue = AttemptQueue::new(vault);
    let mut requeued = 0;
    for (key, read) in handoffs {
        if read.result.is_some() || read.erased_at.is_some() {
            continue;
        }
        // Read again under the writer: the job may have acknowledged since.
        let again = vault.with_write_txn_grouped(|txn| {
            let Some(mut handoff) = HANDOFFS.get(&vault.store, txn, &key)? else {
                return Ok(false);
            };
            if handoff.result.is_some() || handoff.erased_at.is_some() {
                return Ok(false);
            }
            if queue
                .get_in_txn(txn, attempt_id(&handoff.attempt)?)?
                .is_some_and(|record| !record.state.is_terminal())
            {
                if handoff.work.is_some() {
                    return work_store::reconcile_in_txn(vault, txn, &key, &mut handoff, now);
                }
                return Ok(false);
            }
            if erased::settle_erased_in_txn(vault, txn, &key, &mut handoff, now)? {
                return Ok(false);
            }
            handoff.attempt = enqueue_triage_in_txn(
                vault,
                txn,
                &handoff.source_ref,
                handoff.evidence,
                sweep,
                run_id,
                now,
            )?;
            handoff.queued_by = sweep_ref;
            HANDOFFS.put(&vault.store, txn, &key, &handoff)?;
            Ok(true)
        })?;
        requeued += usize::from(again);
    }
    Ok(requeued)
}

/// The item `handoff`'s revision names: an inbox note read back from the
/// inbox, or a GitHub item read back from its evidence, each checked against
/// that revision.
pub(super) fn job_item(
    vault: &Vault,
    handoff: &FeedbackTriageHandoff,
) -> Result<FeedbackTriageItem> {
    Ok(
        if handoff.source_ref.source == FEEDBACK_TRIAGE_INBOX_SOURCE {
            FeedbackTriageItem::Inbox(Box::new(inbox_note(vault, &handoff.source_ref)?))
        } else {
            FeedbackTriageItem::Github(Box::new(github::evidence_issue(vault, handoff)?))
        },
    )
}

impl Vault {
    /// What a leased `coach.feedback_triage` job triages: the item its
    /// revision names, an inbox note read back from the inbox or a GitHub
    /// item read back from its evidence, checked against that revision, with
    /// its evidence, the skill bound now and the part graph a long item's
    /// earlier runs left (FIX 7549); the result committed for it already;
    /// or, once the owner erased its evidence or while no skill is bound,
    /// nothing to triage.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt or not the
    /// revision's current job; a job naming no handoff, or an item that no
    /// longer matches its revision; storage errors.
    pub fn feedback_triage_job(
        &self,
        attempt: &DreamerAdmittedAttempt,
    ) -> Result<FeedbackTriageJob> {
        self.require_coach_attempt(attempt, COACH_FEEDBACK_TRIAGE_FACET)?;
        let (handoff, skill, erased) = {
            let txn = self.store.env.read_txn()?;
            let handoff = job_handoff_in_txn(self, &txn, attempt)?;
            let erased = erased::evidence_erased_in_txn(self, &txn, &handoff)?;
            (handoff, binding_in_txn(self, &txn)?.skill, erased)
        };
        if let Some(result) = handoff.result {
            return Ok(FeedbackTriageJob::Acknowledged(result));
        }
        if handoff.attempt != attempt_ref(attempt.status.attempt.id)? {
            return Err(invalid_job());
        }
        if erased {
            return Ok(FeedbackTriageJob::Erased);
        }
        let Some(skill) = skill else {
            return Ok(FeedbackTriageJob::Unbound);
        };
        let item = job_item(self, &handoff)?;
        Ok(FeedbackTriageJob::Pending(Box::new(FeedbackTriageInput {
            source_ref: handoff.source_ref,
            evidence: handoff.evidence,
            item,
            skill,
            work: handoff.work,
        })))
    }
}
