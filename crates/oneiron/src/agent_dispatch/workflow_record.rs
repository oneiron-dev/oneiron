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
use crate::edge::EdgeActorClass;
use crate::error::{Error, GateError, Result};
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::task_verb::highway_runner::workflow_try::WorkflowTaskBind;
use crate::write_envelope::WriteActor;
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
    /// Each step's dispatch input as admission froze it, in step order: the
    /// definition revision, scope and ceiling the run captured. Release
    /// rechecks live authority; this snapshot is not a grant.
    pub captured_steps: Vec<super::AgentDispatchInput>,
    pub active_step: AttemptId,
    pub results: Vec<WorkflowStepResult>,
    /// The whole workflow's launch statement (OF-532): one agent per leaf,
    /// the sum of their expected spend, and the cap, frozen at admission.
    pub launch: Option<super::LaunchStatement>,
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
    pub depth_remaining: Option<u64>,
    pub project_ref: Option<String>,
    /// OF-543: the type the spawner placed the workflow at, as supplied. None
    /// leaves each leaf to dispatch's own placement. A retry naming another
    /// type is another intent.
    pub type_ref: Option<crate::task_type::TaskTypeRef>,
    /// The spawn's `budget`: a hard carve for the whole workflow.
    #[serde(default)]
    pub budget: Option<u64>,
    /// A root workflow's spend scope.
    #[serde(default)]
    pub spend: Option<super::SpendScopeId>,
    /// The room its leaves work in (OF-531).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<crate::workspace_roster::RoomWork>,
    /// The objectives the caller assigned (OF-544), frozen into each leaf.
    /// A retry naming another list is another intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objectives: Option<Vec<String>>,
    /// The comm reach the caller asked for (FIX 1380). Each leaf resolves
    /// it against the real parent; a retry naming another is another intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<super::CommReach>,
    /// The TASK this run realizes and the actor who bound it (FIX 4391,
    /// FIX 5316). Only the wrapper carries the backlink; a retry naming
    /// another TASK, or none, is another intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<WorkflowTaskBinding>,
}

/// A run's binding to the TASK it realizes: the TASK and the actor whose
/// Owner standing admitted it, as hex, and that actor's class byte, which
/// the wrapper's take, fence, settlement and report run under: an owner's
/// or a member's Human, an agent's Agent. A member's run also requires a
/// payer (FIX 5316): every step's model calls must read one from the root
/// the member funds, and none falls to the owner's account. Only the
/// wrapper keeps the fact; its steps find it through their wrapper. A
/// member's binding keeps the slip their call presented too (FIX 5419), as
/// settlement metadata: the settlement names it revoked or lapsed once it
/// is, and gates nothing on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkflowTaskBinding {
    pub task_ref: String,
    pub bound_by: String,
    pub bound_class: u8,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub payer_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slip: Option<[u8; 32]>,
}

impl WorkflowTaskBinding {
    pub(super) fn new(bind: &WorkflowTaskBind) -> Self {
        Self {
            task_ref: bind.task.to_hex(),
            bound_by: bind.bound_by.entity_ref().to_hex(),
            bound_class: bind.bound_by.actor_class() as u8,
            payer_required: bind.payer_required,
            slip: bind.slip,
        }
    }

    /// The TASK, the actor who bound it under its class, whether its steps
    /// must read a payer, and the slip a member presented.
    pub(super) fn bind(&self) -> Result<WorkflowTaskBind> {
        let class = EdgeActorClass::try_from_u8(self.bound_class)
            .ok_or_else(|| invalid("workflow TASK binding names no actor class"))?;
        Ok(WorkflowTaskBind {
            task: crate::EntityId::from_hex(&self.task_ref)?,
            bound_by: WriteActor::new(crate::EntityId::from_hex(&self.bound_by)?, class),
            payer_required: self.payer_required,
            slip: self.slip,
        })
    }
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
    #[serde(default)]
    pub launch: Option<super::LaunchStatement>,
    /// How the run ended when its TASK's settlement ran (FIX 4391), so a
    /// pass over ended runs settles each once. A TASK-less run never sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_settled: Option<String>,
}

/// A frozen step's dispatch input, as a release reads it.
fn decode_step(bytes: &[u8]) -> Result<super::AgentDispatchInput> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
        .map_err(|_| invalid("workflow step is malformed"))?;
    super::decode_agent_dispatch_input(&value)
}

/// Logs a frozen step whose masking savepoint failed; the step stays frozen.
fn step_kept_frozen(root: &AttemptId, error: &Error) {
    tracing::warn!(
        kind = ?error.kind(),
        %error,
        root = ?root,
        "workflow step masking savepoint failed; the step keeps its frozen bytes"
    );
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

/// The output handles of the wrapper `root`'s completed steps, by producer
/// lineage: each result in order, its producer a completed step of `root`
/// in this run whose own result it is. A result that is no output handle is
/// passed over; a producer that does not match its result, or a malformed
/// handle, refuses.
fn output_refs_in(
    queue: &AttemptQueue<'_>,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
    record: &WorkflowRecord,
) -> Result<Vec<WorkflowOutputContextRef>> {
    let mut refs = Vec::new();
    for (ordinal, result) in record.results.iter().enumerate() {
        if result.ordinal != ordinal {
            return Err(invalid("workflow context result order is malformed"));
        }
        let producer = queue
            .get_in_txn(txn, result.attempt_id)?
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
        let mut seen = std::collections::HashSet::from([cursor.id]);
        while cursor.id != record.active {
            let previous = queue
                .get_in_txn(
                    &txn,
                    cursor
                        .retry_of
                        .ok_or_else(|| invalid("workflow context retry lineage"))?,
                )?
                .ok_or_else(|| invalid("workflow context retry ancestor is missing"))?;
            // FIX 9577: the retry tip's own rule for a superseded try.
            if !previous.continues_retry_lineage()
                || previous.kind != cursor.kind
                || previous.payload != cursor.payload
                || previous.run_id != cursor.run_id
            {
                return Err(invalid("workflow context retry lineage differs"));
            }
            if !seen.insert(previous.id) {
                return Err(invalid("workflow context retry cycle"));
            }
            cursor = previous;
        }
        // A long lineage is read whole and asks through the retry-tip row
        // (Rule 5); only a cycle refuses.
        self.vault
            .limit_watch()
            .measure(EngineLimit::AttemptRetryTipRows, seen.len() as u64);
        let payload = decode_dreamer_attempt_payload(&current.payload)?;
        if payload.parent_attempt != Some(root) || current.run_id != record.intent.run_id {
            return Err(invalid("workflow context step has foreign lineage"));
        }
        output_refs_in(&queue, &txn, root, &record)
    }

    /// The output handles of a completed TASK-bound run's own steps, read by
    /// producer lineage as [`Self::workflow_output_refs_for_attempt`] reads
    /// an active leaf's, for the "Done means met?" its settlement asks
    /// (FIX 6325): only the wrapper `root`'s own completed steps, and only
    /// while `binder` is the actor its TASK binding names. Each comes with
    /// the handle its step result names. No other workflow's output is
    /// reached, and a malformed handle refuses.
    pub(crate) fn workflow_done_output_refs(
        &self,
        root: AttemptId,
        binder: WriteActor,
    ) -> Result<Vec<(String, OutputRef)>> {
        let queue = AttemptQueue::new(self.vault);
        let txn = self.vault.store.env.read_txn()?;
        let Some(wrapper) = queue.get_in_txn(&txn, root)? else {
            return Err(invalid("workflow root is missing"));
        };
        if wrapper.state != AttemptState::Completed || !is_wrapper(&wrapper) {
            return Ok(Vec::new());
        }
        let record = self.read_workflow(&txn, &wrapper)?;
        let Some(binding) = &record.intent.task else {
            return Ok(Vec::new());
        };
        if binding.bind()?.bound_by != binder {
            return Ok(Vec::new());
        }
        Ok(output_refs_in(&queue, &txn, root, &record)?
            .into_iter()
            .map(|output| (output.source.handle(), output.source))
            .collect())
    }

    /// `intent` as [`RECORD`] stores it (FIX 2314): read through the
    /// side-row wall in `txn`, the vault's custody door holding it, so each
    /// secret it carries reads as its custody handle, a value custody
    /// already holds keeping its own. Every compare, wrapper payload, frozen
    /// step and returned status is derived from this reading: equal requests
    /// stay one intent, and two secrets stay two. No wrapper has an id yet,
    /// so the wall's custody records name the nil attempt's place for it.
    pub(super) fn admitted_workflow_intent_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        intent: WorkflowIntent,
    ) -> Result<WorkflowIntent> {
        let unplaced = AttemptId::from_bytes(&[0; 16])?;
        let mut record = WorkflowRecord {
            version: 1,
            root: unplaced,
            intent,
            steps: Vec::new(),
            active: unplaced,
            results: Vec::new(),
            launch: None,
            task_settled: None,
        };
        RECORD.admit(self.vault, txn, &unplaced, &mut record)?;
        Ok(record.intent)
    }

    /// One frozen step as [`RECORD`] keeps it (FIX 6637): the dispatch input
    /// `bytes` encodes, read through the side-row wall in `txn` as a body of
    /// the wrapper `root`'s row, under that row's structural references. A
    /// secret a spawn field carries outside the intent (its healer case, its
    /// scope, team or plan) reads as its custody handle where the door's
    /// rules place one; the ids and labels the engine resolves by their exact
    /// bytes (target, definition, scope, plan and type refs, team, launch,
    /// room and origin ids, context labels and domains) never take a known
    /// value's handle (FIX 6634). The masked step, with the input it
    /// decodes to, when the wall placed a handle. `None` keeps `bytes` as
    /// frozen: nothing placed, a masked copy that no longer decodes as a
    /// dispatch input, or a hit the wall would refuse or could not mask, so
    /// a step that dispatched before still dispatches. A storage error still
    /// fails the write, as the record's own admission would.
    ///
    /// The wall mints its custody records before its last reading, so it
    /// reads in a savepoint of `txn` that commits only with the masked step
    /// (FIX 6667): a step kept as frozen keeps no record or found-key note
    /// of the handles it does not carry. A savepoint that cannot open or
    /// commit logs and keeps the step as frozen.
    pub(super) fn admitted_workflow_step_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        root: &AttemptId,
        bytes: &[u8],
    ) -> Result<Option<(Vec<u8>, super::AgentDispatchInput)>> {
        let mut savepoint = match self.vault.store.env.nested_write_txn(txn) {
            Ok(savepoint) => savepoint,
            Err(error) => {
                step_kept_frozen(root, &Error::from(error));
                return Ok(None);
            }
        };
        let admitted = crate::batch::secret_scan::admit_side_row(
            self.vault,
            &mut savepoint,
            RECORD.decl(),
            &RECORD.key_bytes(root),
            bytes,
            |copy| decode_step(copy).is_ok(),
        );
        let masked = match admitted {
            Ok(Some(masked)) => masked,
            Ok(None)
            | Err(
                Error::Gate(GateError::GateWriteRejected { .. }) | Error::InvariantViolation(_),
            ) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Ok(input) = decode_step(&masked) else {
            return Ok(None);
        };
        match savepoint.commit() {
            Ok(()) => Ok(Some((masked, input))),
            Err(error) => {
                step_kept_frozen(root, &Error::from(error));
                Ok(None)
            }
        }
    }

    /// [`Self::admitted_workflow_intent_in`] in a writer of its own that
    /// commits nothing, for a replay read outside a writer.
    pub(super) fn admitted_workflow_intent(
        &self,
        intent: WorkflowIntent,
    ) -> Result<WorkflowIntent> {
        let mut txn = self.vault.store.env.write_txn()?;
        self.admitted_workflow_intent_in(&mut txn, intent)
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
            || record.results.len() > record.steps.len()
        {
            return Err(invalid("workflow admission does not match the wrapper"));
        }
        // FIX 4391: only a bound run's wrapper carries a TASK backlink, and
        // only a bound one is checked, so a TASK-less run reads as before.
        if let Some(binding) = &record.intent.task
            && row.task_ref.as_deref() != Some(binding.task_ref.as_str())
        {
            return Err(invalid("workflow wrapper does not carry its TASK backlink"));
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
            captured_steps: record
                .steps
                .iter()
                .map(|bytes| {
                    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
                        .map_err(|_| invalid("workflow step is malformed"))?;
                    super::decode_agent_dispatch_input(&value)
                })
                .collect::<Result<_>>()?,
            active_step: record.active,
            results: record.results.clone(),
            launch: record.launch.clone(),
        })
    }
}
