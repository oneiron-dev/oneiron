//! Typed headless host door for running the one ready workflow leaf.

use super::widen_record::invalid;
use super::{AgentDispatchStatus, AgentDispatcher, WorkflowProgress};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptResultRef, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, SetAttemptResult,
};
use crate::context_projection::ResolvedContextProjection;
use crate::error::Result;

struct WorkflowOutput {
    id: crate::EntityId,
    source: crate::compaction::output::OutputRef,
    bytes: Vec<u8>,
    held: crate::provenance::body::OwnedBody,
}

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
        self.run_workflow_step_captured(root, lease_owner, now, |status, context| {
            let raw = execute(status, context)?;
            let entry = crate::compaction::output::OutputContextEntry::capture(
                self.vault,
                &raw,
                now,
                String::new(),
            )?;
            Ok((
                AttemptResultRef::new(entry.source.handle())?,
                Some(entry.source),
            ))
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
        self.run_workflow_step_captured(root, lease_owner, now, |status, context| {
            execute(status, context).map(|result| (result, None))
        })
    }

    fn run_workflow_step_captured<F>(
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
        ) -> Result<(
            AttemptResultRef,
            Option<crate::compaction::output::OutputRef>,
        )>,
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
        let (result, output) = execute(&status, context)?;
        if output.is_some() {
            if let Err(error) = crate::skill_attribution::bind_agent_run_attribution(
                self.vault,
                status.attempt.id,
                lease_owner,
            ) {
                tracing::warn!(kind = ?error.kind(), "workflow output attribution did not bind");
            }
        }
        // File custody is read before opening the result/completion writer.
        let output = output
            .map(|source| self.prepare_workflow_output(&status.attempt, source))
            .transpose();
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
        match output {
            Ok(Some(output)) => {
                // Failed attribution rolls back only its stage. A successful
                // stage stays inside the raw result/completion transaction,
                // so a crash cannot leave a root for an uncommitted result.
                let staged = (|| -> Result<()> {
                    let mut stage = self.vault.store.env.nested_write_txn(&mut txn)?;
                    self.put_workflow_output_in_txn(
                        &mut stage,
                        &status.attempt,
                        lease_owner,
                        &output,
                        now,
                    )?;
                    crate::skill_attribution::witness_agent_run_close_in_txn(
                        self.vault,
                        &mut stage,
                        &status.attempt,
                        lease_owner,
                        output.id,
                    )?;
                    stage.commit()?;
                    Ok(())
                })();
                if let Err(error) = staged {
                    tracing::warn!(kind = ?error.kind(), "workflow output close was not recorded");
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "workflow output entity was not prepared");
            }
        }
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
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        self.advance_workflow(root, now)
    }

    /// Attribution sidecar for this live leaf's actual captured bytes. The
    /// attempt and its successors still carry the original output handle.
    fn prepare_workflow_output(
        &self,
        attempt: &crate::attempt_queue::AttemptRecord,
        output: crate::compaction::output::OutputRef,
    ) -> Result<WorkflowOutput> {
        use crate::provenance::body::{BodyLocation, BodyRef, BodyState, OwnedBody};
        use crate::{EntityId, Error};
        use rmpv::Value;

        const RESULT: &[u8] = b"oneiron:workflow-run-result:v1";
        const BODY: &[u8] = b"oneiron:workflow-run-result-body:v1";
        let result = EntityId::derive(RESULT, &[attempt.id.as_bytes().as_slice()])?;
        let inline = {
            let txn = self.vault.store.env.read_txn()?;
            self.vault.code_run_body_inline_in_txn(&txn, &output.hash)?
        };
        // Probe files before the writer, in the native result TURN's lock order.
        let location = if inline {
            BodyLocation::Inline
        } else if self
            .vault
            .store
            .body_file_present(&output.hash, output.byte_len)?
        {
            BodyLocation::File
        } else {
            return Err(Error::CorruptedIndex("workflow output body missing"));
        };
        let field = |key: &str, value: Value| (Value::from(key), value);
        let artifact = Value::Map(vec![
            field("kind", Value::from("workflow.run_result")),
            field(
                "attempt_ref",
                Value::from(crate::entity_id::bytes_to_hex_lower(attempt.id.as_bytes())),
            ),
            // run_id is an opaque scheduling label, not a typed code-run id.
            field("run_ref", Value::Nil),
            field(
                "task_ref",
                attempt.task_ref.clone().map_or(Value::Nil, Value::from),
            ),
            field(
                "answer",
                Value::Map(vec![
                    field("handle", Value::from(output.handle())),
                    field("bytes", Value::from(output.byte_len)),
                ]),
            ),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &artifact)
            .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        let held = OwnedBody {
            owner: result,
            occurrence: EntityId::derive(BODY, &[result.as_bytes().as_slice()])?,
            state: BodyState::Complete {
                body: BodyRef {
                    blake3: output.hash,
                    bytes: output.byte_len,
                    location,
                },
            },
            result: None,
        };
        Ok(WorkflowOutput {
            id: result,
            source: output,
            bytes,
            held,
        })
    }

    fn put_workflow_output_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: &crate::attempt_queue::AttemptRecord,
        lease_owner: &str,
        output: &WorkflowOutput,
        now: u64,
    ) -> Result<()> {
        AttemptQueue::new(self.vault).require_skill_load_lease_in_txn(
            txn,
            attempt.id,
            lease_owner,
            attempt.attempt_count,
        )?;
        if !self
            .vault
            .code_run_body_inline_in_txn(txn, &output.source.hash)?
            && !crate::code_run::code_run_body_held_in_txn(
                &self.vault.store,
                txn,
                &output.source.hash,
            )?
        {
            return Err(crate::Error::CorruptedIndex("workflow output body missing"));
        }
        if self
            .vault
            .get_entity_type_in_txn(txn, &output.id)?
            .is_none()
        {
            self.vault
                .batch_in()
                .put(
                    &output.id,
                    crate::registry::ENTITY_TYPE_TURN,
                    crate::TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &output.bytes,
                )
                .apply(txn)?;
        }
        crate::provenance::body::publish_body_in_txn(&self.vault.store, txn, &output.held)
    }
}
