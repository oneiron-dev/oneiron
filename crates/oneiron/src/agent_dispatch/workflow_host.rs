//! Typed headless host door for running the one ready workflow leaf.

use super::widen_record::invalid;
use super::{AgentDispatchStatus, AgentDispatcher, WorkflowProgress};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptResultRef, AttemptState, ClaimAttempt, CompleteAttempt,
    SetAttemptResult,
};
use crate::context_projection::ResolvedContextProjection;
use crate::error::Result;

impl AgentDispatcher<'_> {
    /// Claim the active leaf, resolve its live context, and call the host once.
    /// An already settled leaf is pumped without calling `execute` again.
    /// Concurrent hosts observe the lease and return `Waiting`.
    ///
    /// The callback is ordinary host code, not saved instructions or a DSL. It
    /// must use the real agent actor at write doors and use idempotency keys for
    /// external effects. A callback error leaves its lease for normal recovery;
    /// this door does not turn an uncertain effect into a false completion.
    pub fn run_workflow_step<F>(
        &self,
        root: AttemptId,
        lease_owner: &str,
        now: u64,
        execute: F,
    ) -> Result<WorkflowProgress>
    where
        F: FnOnce(&AgentDispatchStatus, ResolvedContextProjection) -> Result<AttemptResultRef>,
    {
        let queue = AttemptQueue::new(self.vault);
        let mut txn = self.vault.store.env.write_txn()?;
        let wrapper = queue
            .get_in_write_txn(&txn, root)?
            .ok_or_else(|| invalid("workflow wrapper is missing"))?;
        let record = self.read_workflow(&txn, &wrapper)?;
        if wrapper.state != AttemptState::Paused {
            drop(txn);
            return self.advance_workflow(root, now);
        }
        let active = queue.retry_tip_in_txn(&txn, record.active)?;
        match active.state {
            AttemptState::Queued | AttemptState::Scheduled => {}
            AttemptState::Leased | AttemptState::Landing | AttemptState::Paused => {
                return Ok(WorkflowProgress::Waiting(active.id));
            }
            _ => {
                drop(txn);
                return self.advance_workflow(root, now);
            }
        }
        if active
            .scheduled_at
            .or(active.backoff_until)
            .is_some_and(|ready| ready > now)
        {
            return Ok(WorkflowProgress::Waiting(active.id));
        }
        let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&active.payload)?;
        if payload.parent_attempt != Some(root) || active.run_id != record.intent.run_id {
            return Err(invalid("workflow host leaf has foreign lineage"));
        }
        let input = super::decode_agent_dispatch_input(&payload.input)?;
        self.dispatchable_definition_in_txn(&txn, &input.target)?;
        let attempt = queue.claim_id_in_txn(
            &mut txn,
            active.id,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now,
            },
        )?;
        txn.commit()?;
        let status = AgentDispatchStatus { attempt, input };
        let context = self.resolve_attempt_context(status.attempt.id)?;
        let result = execute(&status, context)?;
        let mut txn = self.vault.store.env.write_txn()?;
        queue.set_result_in_txn(
            &mut txn,
            SetAttemptResult {
                id: status.attempt.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: status.attempt.attempt_count,
                result_ref: result,
                now,
            },
        )?;
        queue.complete_in_txn(
            &mut txn,
            CompleteAttempt {
                id: status.attempt.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: status.attempt.attempt_count,
                now,
            },
        )?;
        txn.commit()?;
        self.advance_workflow(root, now)
    }
}
