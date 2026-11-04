//! Typed headless host door for running the one ready workflow leaf.

use super::widen_record::invalid;
use super::{AgentDispatchStatus, AgentDispatcher, WorkflowProgress};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptResultRef, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, SetAttemptResult,
};
use crate::context_projection::ResolvedContextProjection;
use crate::error::Result;
use crate::self_heal::audit::{AttemptConfession, ObjectiveConfession};

impl AgentDispatcher<'_> {
    /// Run a workflow agent whose host produces raw bytes. Persist the exact
    /// result in the vault-local content-addressed store; the workflow and its
    /// successors retain only a stable result handle, never the output body.
    pub fn run_workflow_step_output<F>(
        &self,
        root: AttemptId,
        lease_owner: &str,
        now: u64,
        execute: F,
    ) -> Result<WorkflowProgress>
    where
        F: FnOnce(&AgentDispatchStatus, ResolvedContextProjection) -> Result<Vec<u8>>,
    {
        self.run_workflow_step_output_with_confession(root, lease_owner, now, |status, context| {
            execute(status, context).map(|bytes| (bytes, Vec::new()))
        })
    }

    /// Capture a leaf's raw output and seal its objective confessions in the
    /// transaction that completes that same leased try. A refused seal rolls
    /// back on its own; the successful output and completion stand.
    pub fn run_workflow_step_output_with_confession<F>(
        &self,
        root: AttemptId,
        lease_owner: &str,
        now: u64,
        execute: F,
    ) -> Result<WorkflowProgress>
    where
        F: FnOnce(
            &AgentDispatchStatus,
            ResolvedContextProjection,
        ) -> Result<(Vec<u8>, Vec<ObjectiveConfession>)>,
    {
        self.run_workflow_step_confessed(root, lease_owner, now, |status, context| {
            let (raw, objectives) = execute(status, context)?;
            let entry = crate::compaction::output::OutputContextEntry::capture(
                self.vault,
                &raw,
                now,
                String::new(),
            )?;
            let confession = status
                .input
                .target
                .agent_definition_ref()
                .ok()
                .filter(|_| !objectives.is_empty())
                .map(|subject| AttemptConfession {
                    attempt: status.attempt.id,
                    subject,
                    type_ref: crate::learning::TypeRef::from(&status.input.type_ref),
                    objectives,
                });
            Ok((AttemptResultRef::new(entry.source.handle())?, confession))
        })
    }

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
        self.run_workflow_step_confessed(root, lease_owner, now, |status, context| {
            execute(status, context).map(|result| (result, None))
        })
    }

    fn run_workflow_step_confessed<F>(
        &self,
        root: AttemptId,
        lease_owner: &str,
        now: u64,
        execute: F,
    ) -> Result<WorkflowProgress>
    where
        F: FnOnce(
            &AgentDispatchStatus,
            ResolvedContextProjection,
        ) -> Result<(AttemptResultRef, Option<AttemptConfession>)>,
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
        // FIX 11592: a requester whose authority was withdrawn ends the leaf
        // unrun, and the workflow reads it as any failed leaf.
        if self.requester_withdrawn_in_txn(&txn, &input).is_some() {
            drop(txn);
            self.end_withdrawn(active.id, lease_owner, now)?;
            return self.advance_workflow(root, now);
        }
        // A leaf placed on another worker, or not yet ready at the recorded
        // clock, is not this host's to run.
        let ClaimOutcome::Claimed(attempt) = crate::ports::JobQueue::port_job_claim_id(
            self.vault,
            &mut txn,
            active.id,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now,
            },
        )?
        else {
            return Ok(WorkflowProgress::Waiting(active.id));
        };
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        let status = AgentDispatchStatus { attempt, input };
        // A member's run reads its context on their own grants (FIX 5416),
        // judged at the grant clock persisted here, before that read.
        if let Some(task) = &record.intent.task
            && task.payer_required
        {
            self.vault.store.authorization_now()?;
        }
        let context = self.resolve_attempt_context(status.attempt.id)?;
        let (result, confession) = execute(&status, context)?;
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
        crate::ports::JobQueue::port_job_complete(
            self.vault,
            &mut txn,
            CompleteAttempt {
                id: status.attempt.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: status.attempt.attempt_count,
                now,
            },
        )?;
        if let Some(confession) = confession {
            let sealed = (|| -> Result<()> {
                let mut seal = self.vault.store.env.nested_write_txn(&mut txn)?;
                self.vault
                    .record_attempt_confession_in_txn(&mut seal, &confession, now)?;
                seal.commit()?;
                Ok(())
            })();
            if let Err(error) = sealed {
                tracing::warn!(kind = ?error.kind(), attempt = ?confession.attempt, "a workflow leaf's confession was not sealed");
            }
        }
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        self.advance_workflow(root, now)
    }
}
