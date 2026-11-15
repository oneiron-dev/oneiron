//! A saved workflow run's cooperative cancel (L1-03, `vault.workflows.cancel`).
//!
//! The owner asks a run to stop. The run's record keeps the request; the
//! step that waits to run is cancelled, and a step a worker holds is asked to
//! land, as a TASK's soft cancel asks it. The pump then releases no further
//! step and ends the run `Cancelled` once its active step has settled. A step
//! that completed keeps its result: a cancel never undoes committed work.

use super::AgentDispatcher;
use super::widen_record::invalid;
use super::workflow_record::{
    RECORD, WorkflowCancelRequest, WorkflowDispatchStatus, WorkflowStepAsk,
};
use crate::attempt_queue::{
    AttemptCancelReceiptKind, AttemptId, AttemptInterventionEffect, AttemptInterventionKind,
    AttemptQueue, AttemptRecord, AttemptState, CancelRequestOutcome, CancelStanding,
    InterveneAttempt, LandingTrigger, RequestAttemptCancel,
};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::error::Result;

impl AgentDispatcher<'_> {
    /// Asks the workflow run `root` to stop, as `actor` (L1-03). In one
    /// writer the run's record keeps the request, the step that waits to run
    /// (queued, scheduled or paused) is cancelled, and a step a worker holds
    /// is asked once to land. One pump pass follows, so a run whose step was
    /// stopped ends `Cancelled` before this answers; a run whose step still
    /// runs ends when that step settles. An ended run, and a repeated request
    /// with nothing new to stop, write nothing. Answers the run's status.
    ///
    /// # Errors
    ///
    /// A root that is no workflow run; storage errors.
    pub fn cancel_workflow(
        &self,
        root: AttemptId,
        actor: crate::EntityId,
        now: u64,
    ) -> Result<WorkflowDispatchStatus> {
        let queue = AttemptQueue::new(self.vault);
        let mut txn = self.vault.store.env.write_txn()?;
        let wrapper = queue
            .get_in_write_txn(&txn, root)?
            .ok_or_else(|| invalid("workflow root is missing"))?;
        let mut record = self.read_workflow(&txn, &wrapper)?;
        if wrapper.state != AttemptState::Paused {
            // An ended run has nothing left to stop.
            drop(txn);
            return self.workflow_status(root);
        }
        let mut wrote = false;
        let mut request = match record.cancel_request.clone() {
            Some(request) => request,
            None => {
                wrote = true;
                WorkflowCancelRequest {
                    by: actor.to_hex(),
                    at: now,
                    asked: None,
                }
            }
        };
        let active = queue.retry_tip_in_txn(&txn, record.active)?;
        let payload = decode_dreamer_attempt_payload(&active.payload)?;
        if payload.parent_attempt != Some(root) || active.run_id != record.intent.run_id {
            return Err(invalid("workflow step has foreign run-tree lineage"));
        }
        let waits_to_run = matches!(
            active.state,
            AttemptState::Queued | AttemptState::Scheduled | AttemptState::Paused
        );
        let stopped = self.stop_workflow_step_in(&mut txn, &active, &mut request, now)?;
        if wrote || stopped {
            record.active = active.id;
            record.cancel_request = Some(request);
            RECORD.put(self.vault, &mut txn, &root, &record)?;
            txn.commit()?;
            self.vault.store.notify_attempt_observers();
            if stopped && waits_to_run {
                // FIX 11482: the cancelled step's job notice committed here; a
                // step only asked to land has none yet.
                self.vault.store.notify_notification_updates();
            }
        } else {
            drop(txn);
        }
        // The pump ends a run whose step this request stopped. A pass that
        // fails here leaves the request on the record, and the host's next
        // pass ends the run.
        if let Err(error) = self.advance_workflow(root, now) {
            tracing::warn!(kind = ?error.kind(), ?root, "a cancelled workflow run did not advance; the host's pass ends it");
        }
        self.workflow_status(root)
    }

    /// Puts the run's cancel `request` to its active step `step`, in `txn`:
    /// a step that waits to run is cancelled in the requester's name; a step
    /// a worker holds is asked to land, once for this request, and `request`
    /// keeps that ask; a landing or settled step is left as it is. Whether
    /// anything was written: the caller then stores `request` on the run.
    pub(super) fn stop_workflow_step_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        step: &AttemptRecord,
        request: &mut WorkflowCancelRequest,
        now: u64,
    ) -> Result<bool> {
        let queue = AttemptQueue::new(self.vault);
        match step.state {
            AttemptState::Queued | AttemptState::Scheduled | AttemptState::Paused => {
                let outcome = queue.intervene_in_txn(
                    txn,
                    InterveneAttempt {
                        id: step.id,
                        kind: AttemptInterventionKind::Cancel,
                        actor: request.by.clone(),
                        note: None,
                        now,
                    },
                )?;
                Ok(outcome.effect == AttemptInterventionEffect::Cancelled)
            }
            AttemptState::Leased if !asked_by_request(step, request) => {
                let outcome = queue.request_cancel_in_txn(
                    txn,
                    RequestAttemptCancel {
                        id: step.id,
                        actor: request.by.clone(),
                        standing: CancelStanding::Authority,
                        trigger: LandingTrigger::CancelRequest,
                        reason: None,
                        now,
                    },
                )?;
                let CancelRequestOutcome::Requested { record, .. } = outcome else {
                    return Ok(false);
                };
                // The receipt this ask just wrote: the request matches the
                // step's later end against it alone.
                let sequence = record
                    .cancel_receipts()
                    .last()
                    .filter(|receipt| {
                        receipt.kind == AttemptCancelReceiptKind::SoftRequested
                            && receipt.actor == request.by
                    })
                    .map(|receipt| receipt.sequence)
                    .ok_or_else(|| invalid("a landing ask wrote no soft-request receipt"))?;
                request.asked = Some(WorkflowStepAsk {
                    step: step.id,
                    sequence,
                });
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Ends the open run `root` `Cancelled` in the name of the actor whose
    /// `request` it carries, in `txn`. The caller settles the run's leases.
    pub(super) fn end_workflow_cancelled_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        root: AttemptId,
        request: &WorkflowCancelRequest,
        now: u64,
    ) -> Result<()> {
        AttemptQueue::new(self.vault).intervene_in_txn(
            txn,
            InterveneAttempt {
                id: root,
                kind: AttemptInterventionKind::Cancel,
                actor: request.by.clone(),
                note: None,
                now,
            },
        )?;
        Ok(())
    }
}

/// Whether the run's cancel `request` stopped its settled step `step`: the
/// step was cancelled, or this request asked it to land. A step that failed
/// or was abandoned before the request was not stopped by it, even when the
/// same actor had asked it to land before, outside the request.
pub(super) fn stopped_by_request(step: &AttemptRecord, request: &WorkflowCancelRequest) -> bool {
    step.state == AttemptState::Cancelled || asked_by_request(step, request)
}

/// Whether `request` asked the step `step` to land: the ask it keeps names
/// this step, and the step holds that soft-request receipt in the
/// requester's name.
fn asked_by_request(step: &AttemptRecord, request: &WorkflowCancelRequest) -> bool {
    request.asked.as_ref().is_some_and(|ask| {
        ask.step == step.id
            && step.cancel_receipts().iter().any(|receipt| {
                receipt.sequence == ask.sequence
                    && receipt.kind == AttemptCancelReceiptKind::SoftRequested
                    && receipt.actor == request.by
            })
    })
}
