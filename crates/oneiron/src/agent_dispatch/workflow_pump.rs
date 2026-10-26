//! Ordered workflow host pump. Completion and successor release co-commit.

use super::AgentDispatcher;
use super::widen_record::invalid;
use super::workflow_record::{RECORD, WorkflowProgress, WorkflowStepResult};
use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptResultRef, AttemptState, ClaimAttempt,
    ClaimOutcome, CompleteAttempt, FailAttempt, InterveneAttempt, SetAttemptResult,
};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::error::{ArtifactError, Error, Result};

/// The failure a wrapper settles with when its next step's agent was
/// disabled after the run was admitted (FIX 9567).
const STEP_AGENT_DISABLED: &str = "workflow_step_agent_disabled";

impl AgentDispatcher<'_> {
    /// Advance a saved composition after its active leaf settles. Call after
    /// completion or on recovery. Repeated/concurrent calls cannot report a
    /// completed step twice: the writer owns the durable cursor.
    ///
    /// Only one leaf is ever queued. Workers execute ordinary agent dispatches,
    /// attach their result, and complete through the existing lease-fenced doors.
    /// External effects still need idempotency keys across a crash before result
    /// attachment; this pump does not promise exactly-once external I/O.
    pub fn advance_workflow(&self, root: AttemptId, now: u64) -> Result<WorkflowProgress> {
        let queue = AttemptQueue::new(self.vault);
        // FIX 6291: a successor's release re-resolves its real parent's
        // context, whose fold may read a member's grants: they are judged at
        // a grant clock committed before this writer.
        if self.releases_under_parent(&queue, root) {
            self.vault.store.authorization_now()?;
        }
        let mut txn = self.vault.store.env.write_txn()?;
        let wrapper = queue
            .get_in_write_txn(&txn, root)?
            .ok_or_else(|| invalid("workflow wrapper is missing"))?;
        let mut record = self.read_workflow(&txn, &wrapper)?;
        if wrapper.state == AttemptState::Completed {
            if record.results.len() != record.steps.len() {
                return Err(invalid("completed workflow has an incomplete report"));
            }
            return Ok(WorkflowProgress::Completed);
        }
        if wrapper.state != AttemptState::Paused {
            return Ok(WorkflowProgress::Stopped(root));
        }
        let active = queue.retry_tip_in_txn(&txn, record.active)?;
        let payload = decode_dreamer_attempt_payload(&active.payload)?;
        if payload.parent_attempt != Some(root) || active.run_id != record.intent.run_id {
            return Err(invalid("workflow step has foreign run-tree lineage"));
        }
        let dispatched = super::decode_agent_dispatch_input(&payload.input)?;
        record.active = active.id;
        if matches!(
            active.state,
            AttemptState::Queued
                | AttemptState::Scheduled
                | AttemptState::Paused
                | AttemptState::Leased
                | AttemptState::Landing
        ) {
            return Ok(WorkflowProgress::Waiting(active.id));
        }
        if active.state != AttemptState::Completed {
            let lease = self.claim_workflow_wrapper(&mut txn, root, now)?;
            crate::ports::JobQueue::port_job_fail(
                self.vault,
                &mut txn,
                FailAttempt {
                    id: root,
                    lease_owner: "workflow-pump".to_owned(),
                    attempt_count: lease.attempt_count,
                    reason: "workflow_step_stopped".to_owned(),
                    now,
                },
            )?;
            // OF-532: the stopped leaf and the workflow settle their leases;
            // the leaves already settled keep their saved results.
            self.settle_child_in_txn(&mut txn, &active.id, now)?;
            self.settle_child_in_txn(&mut txn, &root, now)?;
            // FIX 2314: through the vault's custody door, as admission wrote it.
            RECORD.put(self.vault, &mut txn, &root, &record)?;
            txn.commit()?;
            self.vault.store.notify_attempt_observers();
            // FIX 4391: a bound run's TASK settles after this commit, in a
            // writer of its own; nothing it does changes this answer.
            if record.intent.task.is_some() {
                self.settle_bound_task_after_commit(root, now);
            }
            return Ok(WorkflowProgress::Stopped(active.id));
        }
        // FIX 10602: a leaf whose result a refused release already saved is
        // never reported or settled twice; only its successor's release is
        // tried again, at the next index.
        let resumed = record
            .results
            .last()
            .is_some_and(|last| last.attempt_id == active.id);
        if !resumed {
            let result = active
                .result_ref
                .as_ref()
                .ok_or_else(|| invalid("completed workflow step has no durable result"))?;
            let definition =
                crate::agent_def::workflow::decode_workflow(&record.intent.definition)?;
            let ordinal = record.results.len();
            let requested = definition
                .steps
                .get(ordinal)
                .ok_or_else(|| invalid("workflow result exceeds the saved composition"))?;
            record.results.push(WorkflowStepResult {
                ordinal,
                requested_agent: requested.to_hex(),
                dispatched_agent: dispatched.target.agent_definition_ref()?.to_hex(),
                attempt_id: active.id,
                result_ref: result.as_str().to_owned(),
            });
            // OF-532: the completed leaf's settlement is its calibration receipt.
            self.settle_child_in_txn(&mut txn, &active.id, now)?;
        }
        let progress = if record.results.len() == record.steps.len() {
            let lease = self.claim_workflow_wrapper(&mut txn, root, now)?;
            queue.set_result_in_txn(
                &mut txn,
                SetAttemptResult {
                    id: root,
                    lease_owner: "workflow-pump".to_owned(),
                    attempt_count: lease.attempt_count,
                    result_ref: AttemptResultRef::new(format!(
                        "workflow-report:{}",
                        crate::entity_id::bytes_to_hex_lower(root.as_bytes())
                    ))?,
                    now,
                },
            )?;
            crate::ports::JobQueue::port_job_complete(
                self.vault,
                &mut txn,
                CompleteAttempt {
                    id: root,
                    lease_owner: "workflow-pump".to_owned(),
                    attempt_count: lease.attempt_count,
                    now,
                },
            )?;
            self.settle_child_in_txn(&mut txn, &root, now)?;
            WorkflowProgress::Completed
        } else {
            // FIX 9567: the successor's admission runs in a savepoint, so a
            // successor whose agent was disabled since rolls back its own
            // writes alone. The completed step's result stays, the wrapper
            // fails durably with that reason, and nothing repeats it.
            let mut savepoint = self.vault.store.env.nested_write_txn(&mut txn)?;
            match self.enqueue_workflow_step(&mut savepoint, &record, record.results.len(), now) {
                Ok(next) => {
                    savepoint.commit()?;
                    record.active = next;
                    record.release_refusal = None;
                    WorkflowProgress::Advanced(next)
                }
                Err(Error::Artifact(ArtifactError::AgentDefinitionDisabled { .. })) => {
                    drop(savepoint);
                    let lease = self.claim_workflow_wrapper(&mut txn, root, now)?;
                    crate::ports::JobQueue::port_job_fail(
                        self.vault,
                        &mut txn,
                        FailAttempt {
                            id: root,
                            lease_owner: "workflow-pump".to_owned(),
                            attempt_count: lease.attempt_count,
                            reason: STEP_AGENT_DISABLED.to_owned(),
                            now,
                        },
                    )?;
                    self.settle_child_in_txn(&mut txn, &root, now)?;
                    WorkflowProgress::Stopped(root)
                }
                // FIX 10602: a successor whose definition is missing, inactive
                // or unapproved now may be admitted later. The completed step
                // stays saved and settled once, the wrapper stays paused with
                // the refusal on its record, and the next pass tries the
                // release again. A refusal already saved changes nothing, so
                // nothing is written and no one is woken.
                Err(error) if release_refused(&error) => {
                    drop(savepoint);
                    let refusal = error.to_string();
                    if resumed && record.release_refusal.as_deref() == Some(refusal.as_str()) {
                        return Ok(WorkflowProgress::Waiting(active.id));
                    }
                    record.release_refusal = Some(refusal);
                    WorkflowProgress::Waiting(active.id)
                }
                Err(error) => return Err(error),
            }
        };
        RECORD.put(self.vault, &mut txn, &root, &record)?;
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        if matches!(
            progress,
            WorkflowProgress::Completed | WorkflowProgress::Stopped(_)
        ) && record.intent.task.is_some()
        {
            self.settle_bound_task_after_commit(root, now);
        }
        Ok(progress)
    }

    /// Whether the wrapper `root` releases its steps under a real parent,
    /// in a snapshot of its own. One whose rows do not read counts as one,
    /// and the writer after answers as it always did.
    fn releases_under_parent(&self, queue: &AttemptQueue<'_>, root: AttemptId) -> bool {
        let read = || -> Result<bool> {
            let txn = self.vault.store.env.read_txn()?;
            Ok(match queue.get_in_txn(&txn, root)? {
                Some(wrapper) => self.read_workflow(&txn, &wrapper)?.intent.parent.is_some(),
                None => false,
            })
        };
        read().unwrap_or(true)
    }

    fn claim_workflow_wrapper(
        &self,
        txn: &mut heed::RwTxn<'_>,
        root: AttemptId,
        now: u64,
    ) -> Result<crate::attempt_queue::AttemptRecord> {
        let queue = AttemptQueue::new(self.vault);
        queue.intervene_in_txn(
            txn,
            InterveneAttempt {
                id: root,
                kind: AttemptInterventionKind::Resume,
                actor: "runtime".to_owned(),
                note: None,
                now,
            },
        )?;
        match crate::ports::JobQueue::port_job_claim_id(
            self.vault,
            txn,
            root,
            ClaimAttempt {
                lease_owner: "workflow-pump".to_owned(),
                now,
            },
        )? {
            ClaimOutcome::Claimed(lease) => Ok(lease),
            ClaimOutcome::Empty => Err(invalid("workflow wrapper is not claimable")),
        }
    }
}

/// Whether `error` is a successor release's refusal that may lift (FIX
/// 10602): its agent definition is missing, inactive or unapproved now.
fn release_refused(error: &Error) -> bool {
    matches!(
        error,
        Error::Artifact(
            ArtifactError::AgentDefinitionNotFound { .. }
                | ArtifactError::AgentNotDispatchable(
                    "agent definition is not active" | "agent definition is not approved"
                )
        )
    )
}
