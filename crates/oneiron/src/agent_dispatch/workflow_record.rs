//! Durable, inert workflow admission and result provenance.

use super::widen_record::{invalid, json};
use crate::agent_def::workflow::WorkflowDefinition;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, AttemptState,
};
use crate::compaction::output::OutputRef;
use crate::context_projection::ContextSpec;
use crate::context_projection::WorkflowOutputContextRef;
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::error::Result;
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use serde::{Deserialize, Serialize};

/// Durable saved-composition record for one inert multi-step workflow wrapper
/// attempt. Key: the root attempt id.
pub(super) const RECORD: SideTable<AttemptId, WorkflowRecord, LegacyJson> =
    SideTable::new(&side_table::AGENT_WORKFLOW_RECORD);
/// Dedupe index from a caller-supplied dedupe key to the workflow root
/// attempt id. Key: `blake3(dedupe key)`.
pub(super) const DEDUPE: SideTable<[u8; 32], AttemptId, Raw> =
    SideTable::new(&side_table::AGENT_WORKFLOW_DEDUPE);

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
    pub project_ref: Option<String>,
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

pub(super) fn dedupe_key_hash(key: &str) -> [u8; 32] {
    *blake3::hash(key.as_bytes()).as_bytes()
}
pub(super) fn is_wrapper(row: &AttemptRecord) -> bool {
    if row.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
        return false;
    }
    decode_dreamer_attempt_payload(&row.payload)
        .is_ok_and(|payload| payload.attempt_type == WORKFLOW_ATTEMPT_TYPE)
}
pub(super) fn reject_wrapper_parent(row: &AttemptRecord) -> Result<()> {
    if is_wrapper(row) {
        return Err(invalid("an inert workflow cannot directly spawn an agent"));
    }
    Ok(())
}

impl super::AgentDispatcher<'_> {
    /// Rebuild only the active workflow leaf's prior output handles from its
    /// durable report and the actual completed producer attempts. Arbitrary
    /// result refs are not output handles; a malformed output handle refuses.
    /// This never alters the unrelated memory/ancestor projection.
    pub(super) fn workflow_output_refs_for_attempt(
        &self,
        attempt: AttemptId,
        parent: Option<AttemptId>,
    ) -> Result<Vec<WorkflowOutputContextRef>> {
        let Some(root) = parent else {
            return Ok(Vec::new());
        };
        let queue = AttemptQueue::new(self.vault);
        // Context resolution can run while a caller owns the writer (widen
        // admission does). It must never acquire a nested write transaction.
        let txn = self.vault.store.env.read_txn()?;
        let Some(wrapper) = queue.get_in_txn(&txn, root)? else {
            return Err(invalid("workflow context parent is missing"));
        };
        if !is_wrapper(&wrapper) {
            return Ok(Vec::new());
        }
        let record = self.read_workflow(&txn, &wrapper)?;
        if record.results.len() >= record.steps.len() {
            return Err(invalid("workflow context is not the active step"));
        }
        let current = queue
            .get_in_txn(&txn, attempt)?
            .ok_or_else(|| invalid("workflow context step is missing"))?;
        // The cursor can lag a retry tip until the pump advances it. Prove
        // the attempted leaf descends from that cursor without taking the
        // queue's write-only retry-tip lock in a read-side context door.
        let mut cursor = current.clone();
        let mut hops = 0;
        while cursor.id != record.active {
            hops += 1;
            if hops > 1024 {
                return Err(invalid("workflow context retry bound"));
            }
            let previous = queue
                .get_in_txn(
                    &txn,
                    cursor
                        .retry_of
                        .ok_or_else(|| invalid("workflow context retry lineage"))?,
                )?
                .ok_or_else(|| invalid("workflow context retry ancestor is missing"))?;
            if previous.state != AttemptState::Failed
                || previous.kind != cursor.kind
                || previous.payload != cursor.payload
                || previous.run_id != cursor.run_id
            {
                return Err(invalid("workflow context retry lineage differs"));
            }
            cursor = previous;
        }
        let payload = decode_dreamer_attempt_payload(&current.payload)?;
        if payload.parent_attempt != Some(root) || current.run_id != record.intent.run_id {
            return Err(invalid("workflow context step has foreign lineage"));
        }
        let mut refs = Vec::new();
        for (ordinal, result) in record.results.iter().enumerate() {
            if result.ordinal != ordinal {
                return Err(invalid("workflow context result order is malformed"));
            }
            let producer = queue
                .get_in_txn(&txn, result.attempt_id)?
                .ok_or_else(|| invalid("workflow context producer is missing"))?;
            let producer_payload = decode_dreamer_attempt_payload(&producer.payload)?;
            if producer.state != AttemptState::Completed
                || producer_payload.parent_attempt != Some(root)
                || producer.run_id != record.intent.run_id
                || producer.result_ref.as_ref().map(AttemptResultRef::as_str)
                    != Some(result.result_ref.as_str())
            {
                return Err(invalid(
                    "workflow context producer does not match its result",
                ));
            }
            if result.result_ref.starts_with("output:blake3:") {
                refs.push(WorkflowOutputContextRef {
                    step_ordinal: ordinal,
                    producing_attempt: producer.id,
                    source: OutputRef::from_handle(&result.result_ref)?,
                });
            }
        }
        Ok(refs)
    }

    pub(super) fn read_workflow(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &AttemptRecord,
    ) -> Result<WorkflowRecord> {
        let record = RECORD
            .get(&self.vault.store, txn, &row.id)?
            .ok_or_else(|| invalid("workflow wrapper has no registered admission"))?;
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
        let txn = self.vault.store.env.read_txn()?;
        self.workflow_authority_parent_in_txn(&txn, parent)
    }

    /// Same registered-wrapper crossing within a caller's admission snapshot.
    pub(super) fn workflow_authority_parent_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent: Option<AttemptId>,
    ) -> Result<Option<AttemptId>> {
        let Some(id) = parent else { return Ok(None) };
        let queue = crate::attempt_queue::AttemptQueue::new(self.vault);
        let row = queue
            .get_in_txn(txn, id)?
            .ok_or_else(|| invalid("workflow authority parent is missing"))?;
        if !is_wrapper(&row) {
            return Ok(parent);
        }
        let record = self.read_workflow(txn, &row)?;
        if let Some(real_parent) = record.intent.parent {
            let row = queue
                .get_in_txn(txn, real_parent)?
                .ok_or_else(|| invalid("workflow real parent is missing"))?;
            super::codec::record_dispatch_input(&row)
                .ok_or_else(|| invalid("workflow real parent has no agent lineage"))?;
        }
        Ok(record.intent.parent)
    }

    /// Saved workflows a host pump may still advance: open (Paused) wrapper
    /// roots in creation order. Completed and stopped roots are not listed.
    pub fn open_workflow_roots(&self) -> Result<Vec<AttemptId>> {
        Ok(AttemptQueue::new(self.vault)
            .list()?
            .into_iter()
            .filter(|row| row.state == AttemptState::Paused && is_wrapper(row))
            .map(|row| row.id)
            .collect())
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
