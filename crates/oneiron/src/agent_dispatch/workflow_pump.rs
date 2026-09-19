//! Ordered workflow host pump. Completion and successor release co-commit.

use super::AgentDispatcher;
use super::widen_record::{invalid, json};
use super::workflow_record::{WorkflowProgress, WorkflowStepResult, record_key};
use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptResultRef, AttemptState, ClaimAttempt,
    CompleteAttempt, FailAttempt, InterveneAttempt, SetAttemptResult,
};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::error::Result;

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
            queue.fail_in_txn(
                &mut txn,
                FailAttempt {
                    id: root,
                    lease_owner: "workflow-pump".to_owned(),
                    attempt_count: lease.attempt_count,
                    reason: "workflow_step_stopped".to_owned(),
                    now,
                },
            )?;
            self.vault
                .store
                .vault_meta
                .put(&mut txn, &record_key(root), &json(&record)?)?;
            txn.commit()?;
            return Ok(WorkflowProgress::Stopped(active.id));
        }
        let result = active
            .result_ref
            .as_ref()
            .ok_or_else(|| invalid("completed workflow step has no durable result"))?;
        let definition = crate::agent_def::workflow::decode_workflow(&record.intent.definition)?;
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
            queue.complete_in_txn(
                &mut txn,
                CompleteAttempt {
                    id: root,
                    lease_owner: "workflow-pump".to_owned(),
                    attempt_count: lease.attempt_count,
                    now,
                },
            )?;
            WorkflowProgress::Completed
        } else {
            record.active = self.enqueue_workflow_step(&mut txn, &record, ordinal + 1, now)?;
            WorkflowProgress::Advanced(record.active)
        };
        self.vault
            .store
            .vault_meta
            .put(&mut txn, &record_key(root), &json(&record)?)?;
        txn.commit()?;
        Ok(progress)
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
        queue.claim_id_in_txn(
            txn,
            root,
            ClaimAttempt {
                lease_owner: "workflow-pump".to_owned(),
                now,
            },
        )
    }
}
