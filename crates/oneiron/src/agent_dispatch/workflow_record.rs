//! Durable, inert workflow admission and result provenance.

use super::widen_record::{decode, invalid, json};
use crate::agent_def::workflow::WorkflowDefinition;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::context_projection::ContextSpec;
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::error::Result;
use serde::{Deserialize, Serialize};

pub(super) const WORKFLOW_ATTEMPT_TYPE: &str = "agent.workflow";

/// A completed step's stable provenance, independent of queue dedupe retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStepResult {
    pub ordinal: usize,
    pub requested_agent: String,
    pub dispatched_agent: String,
    pub attempt_id: AttemptId,
    pub result_ref: String,
}

/// Host pump result. A stopped step never releases its successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowProgress {
    Waiting(AttemptId),
    Advanced(AttemptId),
    Stopped(AttemptId),
    Completed,
}

/// Durable run-tree wrapper, frozen saved composition, and append-only results.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowDispatchStatus {
    pub attempt: AttemptRecord,
    pub workflow_ref: crate::EntityId,
    pub definition: WorkflowDefinition,
    pub active_step: AttemptId,
    pub results: Vec<WorkflowStepResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkflowIntent {
    pub workflow_ref: String,
    pub definition: Vec<u8>,
    pub parent: Option<AttemptId>,
    pub run_id: Option<String>,
    pub context_spec: Option<ContextSpec>,
    pub context_from: Vec<String>,
    pub depth_remaining: Option<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkflowRecord {
    pub version: u8,
    pub root: AttemptId,
    pub intent: WorkflowIntent,
    /// Encoded AgentDispatchInput values, not instructions or prompt text.
    pub steps: Vec<Vec<u8>>,
    pub active: AttemptId,
    pub results: Vec<WorkflowStepResult>,
}

pub(super) fn record_key(id: AttemptId) -> Vec<u8> {
    let mut key = b"agent.workflow.record.v1\0".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}
pub(super) fn dedupe_key(key: &str) -> Vec<u8> {
    let mut result = b"agent.workflow.dedupe.v1\0".to_vec();
    result.extend_from_slice(blake3::hash(key.as_bytes()).as_bytes());
    result
}
pub(super) fn is_wrapper(row: &AttemptRecord) -> Result<bool> {
    if row.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(false);
    }
    Ok(decode_dreamer_attempt_payload(&row.payload)
        .is_ok_and(|payload| payload.attempt_type == WORKFLOW_ATTEMPT_TYPE))
}
pub(super) fn reject_wrapper_parent(row: &AttemptRecord) -> Result<()> {
    if is_wrapper(row)? {
        return Err(invalid("an inert workflow cannot directly spawn an agent"));
    }
    Ok(())
}

impl super::AgentDispatcher<'_> {
    pub(super) fn read_workflow(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &AttemptRecord,
    ) -> Result<WorkflowRecord> {
        let bytes = self
            .vault
            .store
            .vault_meta
            .get(txn, &record_key(row.id))?
            .ok_or_else(|| invalid("workflow wrapper has no registered admission"))?;
        let record: WorkflowRecord = decode(&bytes)?;
        let payload = decode_dreamer_attempt_payload(&row.payload)?;
        if record.version != 1
            || record.root != row.id
            || payload.attempt_type != WORKFLOW_ATTEMPT_TYPE
            || payload.parent_attempt != record.intent.parent
            || row.run_id != record.intent.run_id
            || payload.input != rmpv::Value::Binary(json(&record.intent)?)
            || record.steps.is_empty()
            || record.steps.len() > 64
            || record.results.len() > record.steps.len()
        {
            return Err(invalid("workflow admission does not match the wrapper"));
        }
        let definition = crate::agent_def::workflow::decode_workflow(&record.intent.definition)?;
        if definition.steps.len() != record.steps.len() {
            return Err(invalid(
                "workflow snapshot length differs from its saved definition",
            ));
        }
        Ok(record)
    }

    /// A wrapper has no authority. Cross only a registered wrapper and require
    /// its recorded real parent to exist and decode. Missing never means root.
    pub(super) fn workflow_authority_parent(
        &self,
        parent: Option<AttemptId>,
    ) -> Result<Option<AttemptId>> {
        let Some(id) = parent else { return Ok(None) };
        let queue = crate::attempt_queue::AttemptQueue::new(self.vault);
        let Some(row) = queue.get(id)? else {
            return Err(invalid("workflow authority parent is missing"));
        };
        if !is_wrapper(&row)? {
            return Ok(parent);
        }
        let txn = self.vault.store.env.read_txn()?;
        let record = self.read_workflow(&txn, &row)?;
        if let Some(real_parent) = record.intent.parent {
            let row = queue
                .get_in_txn(&txn, real_parent)?
                .ok_or_else(|| invalid("workflow real parent is missing"))?;
            super::codec::record_dispatch_input(&row)
                .ok_or_else(|| invalid("workflow real parent has no agent lineage"))?;
        }
        Ok(record.intent.parent)
    }

    /// Reads the durable workflow result report, including after completion.
    pub fn workflow_status(&self, root: AttemptId) -> Result<WorkflowDispatchStatus> {
        let row = crate::attempt_queue::AttemptQueue::new(self.vault)
            .get(root)?
            .ok_or_else(|| invalid("workflow root is missing"))?;
        let txn = self.vault.store.env.read_txn()?;
        let record = self.read_workflow(&txn, &row)?;
        self.workflow_status_from(row, &record)
    }

    pub(super) fn workflow_status_from(
        &self,
        attempt: AttemptRecord,
        record: &WorkflowRecord,
    ) -> Result<WorkflowDispatchStatus> {
        Ok(WorkflowDispatchStatus {
            attempt,
            workflow_ref: crate::EntityId::from_hex(&record.intent.workflow_ref)?,
            definition: crate::agent_def::workflow::decode_workflow(&record.intent.definition)?,
            active_step: record.active,
            results: record.results.clone(),
        })
    }
}
