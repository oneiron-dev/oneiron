//! Durable tool-round state of one workflow leaf. The transcript crosses
//! the custody wall in the writer that publishes its body and checkpoint.
//! Queue pause/claim/completion are joined by the workflow host in that writer.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::batch::secret_scan::{SidePart, admit_side_parts};
use crate::code_run::{CodeRunRawOutput, ResultOccurrence};
use crate::compaction::output::OutputRef;
use crate::llm::BudgetCheckpoint;
use crate::provenance::body::{owned_body_in_txn, release_body_in_txn};
use crate::side_table::{self, ErasedForm, Named, SideTable};
use crate::store::result_manifest::StagedSinks;
use crate::{ContentPart, EdgeActorClass, EntityId, Error, LlmRequest, Result, Vault};

use super::super::{AgentDispatcher, SpendScopeId, agent_dispatch_run_actor};

pub(crate) mod checkpoint;
mod lifetime;
pub(crate) use lifetime::{erase_actor_in_txn, erase_source_in_txn};

const TABLE: SideTable<EntityId, CheckpointRow, Named> =
    SideTable::new(&side_table::WORKFLOW_TOOL_CHECKPOINT);
const BODY_PLACE: &str = "side:WORKFLOW_TOOL_CHECKPOINT:transcript";
const BODY_PATH: &str = "workflow/tool-checkpoint";

/// Full admitted request: the assistant's outstanding tool calls and every
/// completed result stay in their original message order. Objectives are
/// user text too, so they share this admitted body, not the metadata row.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowToolTranscript {
    pub request: LlmRequest,
    pub objectives: Vec<String>,
}

/// The next uncompleted call within the original assistant message. The
/// ordinal of a pending self.use is retained, not incremented on resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowToolCursor {
    pub assistant_message: usize,
    pub tool_index: usize,
    pub use_ordinal: u64,
    pub round: u64,
    pub capture_completed: bool,
}

/// Native identity of the pre-hook pause, never a permit to run its body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowToolWait {
    pub invocation: [u8; 16],
    pub ask: EntityId,
}

/// Settled state beside the transcript. Every positive source survives an
/// incomplete read set; false never means an empty or public source set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowToolProgress {
    pub cursor: WorkflowToolCursor,
    pub wait: Option<WorkflowToolWait>,
    pub budget: BudgetCheckpoint,
    pub budget_units: u64,
    pub spend_scope: Option<SpendScopeId>,
    pub known_sources: Vec<EntityId>,
    pub sources_complete: bool,
    pub planner_craft_rows: Option<Vec<EntityId>>,
    pub no_record_at_arrival: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointRow {
    attempt: AttemptId,
    generation: u32,
    content: Option<CheckpointContent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointContent {
    actor: EntityId,
    actor_class: EdgeActorClass,
    room: Option<EntityId>,
    progress: WorkflowToolProgress,
    body_owner: EntityId,
    body: OutputRef,
}

impl ErasedForm for CheckpointRow {
    fn into_erased(mut self) -> Result<Self> {
        self.content = None;
        Ok(self)
    }
}

/// Body instances are minted before opening a writer, even when admission
/// makes a previously small transcript spill. One transcript needs one sink.
pub(crate) struct PreparedTranscript {
    sinks: StagedSinks,
    bytes: Vec<u8>,
}

pub(crate) fn prepare(
    vault: &Vault,
    transcript: &WorkflowToolTranscript,
) -> Result<PreparedTranscript> {
    Ok(PreparedTranscript {
        sinks: vault.staged_result_sinks(1)?,
        bytes: serde_json::to_vec(transcript)
            .map_err(|error| Error::InvalidConfig(format!("workflow transcript: {error}")))?,
    })
}

fn key(attempt: AttemptId) -> Result<EntityId> {
    EntityId::from_bytes(*attempt.as_bytes())
}

fn body_owner(attempt: AttemptId) -> Result<EntityId> {
    EntityId::derive(
        b"oneiron:workflow-tool-checkpoint:v1",
        &[attempt.as_bytes().as_slice()],
    )
}

fn output(content: &CheckpointContent) -> CodeRunRawOutput {
    CodeRunRawOutput {
        path: BODY_PATH.to_owned(),
        ..CodeRunRawOutput::of_ref(content.body)
    }
}

fn release_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    content: &CheckpointContent,
) -> Result<()> {
    let output = output(content);
    let occurrence = ResultOccurrence::of(Some(content.body_owner), &output)?;
    crate::code_run::drop_code_run_result_marks_in_txn(
        store,
        txn,
        &occurrence.mark_key(&output.handle),
    )?;
    release_body_in_txn(store, txn, &content.body_owner, &occurrence.id())?;
    Ok(())
}

/// Same-writer content publication only. The host must join the queue hold
/// or progress update before committing, and must have booked all spend.
pub(crate) fn put_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    leased: &AttemptRecord,
    progress: WorkflowToolProgress,
    prepared: PreparedTranscript,
) -> Result<()> {
    let queue = AttemptQueue::new(vault);
    let lease_owner = leased
        .lease_owner
        .as_deref()
        .ok_or_else(|| invalid("checkpoint has no workflow lease"))?;
    queue.require_skill_load_lease_in_txn(txn, leased.id, lease_owner, leased.attempt_count)?;
    // Derive actor, room and lineage from the actual queue row, not a draft
    // supplied alongside a current lease's id.
    let actual = queue
        .get_in_write_txn(txn, leased.id)?
        .ok_or_else(|| invalid("workflow checkpoint leaf is missing"))?;
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&actual.payload)?;
    let root = payload
        .parent_attempt
        .ok_or_else(|| invalid("workflow checkpoint has no wrapper"))?;
    let wrapper = queue
        .get_in_write_txn(txn, root)?
        .ok_or_else(|| invalid("workflow checkpoint wrapper is missing"))?;
    let dispatcher = AgentDispatcher::new(vault);
    let workflow = dispatcher.read_workflow(txn, &wrapper)?;
    if queue.retry_tip_in_txn(txn, workflow.active)?.id != actual.id
        || actual.run_id != workflow.intent.run_id
    {
        return Err(invalid("workflow checkpoint has foreign lineage"));
    }
    let input = super::super::decode_agent_dispatch_input(&payload.input)?;
    let actor = agent_dispatch_run_actor(&input, actual.id)?;
    if crate::ports::owner_gone_in_txn(&vault.store, txn, &actor.entity_ref())? {
        return Err(invalid("workflow checkpoint actor is erased"));
    }
    let k = key(actual.id)?;
    let prior = TABLE.get(&vault.store, txn, &k)?;
    if prior.as_ref().is_some_and(|row| {
        row.attempt != actual.id || row.generation > actual.attempt_count || row.content.is_none()
    }) {
        return Err(invalid("workflow checkpoint is unavailable"));
    }
    let room = input.room.map(|room| room.room);
    for source in progress.known_sources.iter().copied().chain(room) {
        if crate::ports::owner_gone_in_txn(&vault.store, txn, &source)? {
            return Err(invalid("workflow checkpoint source is erased"));
        }
    }
    let key_bytes = TABLE.key_bytes(&k);
    let mut parts = [SidePart::Body(prepared.bytes)];
    admit_side_parts(
        vault,
        txn,
        (BODY_PLACE, &key_bytes),
        &mut parts,
        reads_transcript,
    )?;
    let [SidePart::Body(bytes)] = parts else {
        return Err(Error::InvariantViolation(
            "workflow transcript is no longer a body",
        ));
    };
    let transcript: WorkflowToolTranscript = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("admitted workflow transcript does not decode"))?;
    let assistant = transcript
        .request
        .messages
        .get(progress.cursor.assistant_message)
        .filter(|message| message.role == crate::LlmMessageRole::Assistant)
        .ok_or_else(|| invalid("workflow checkpoint tool message is missing"))?;
    let calls = assistant
        .content
        .iter()
        .filter(|part| matches!(part, ContentPart::ToolCall { .. }))
        .count();
    if progress.cursor.tool_index > calls
        || (progress.wait.is_some() && pending_call(&transcript, &progress.cursor).is_none())
    {
        return Err(invalid("workflow checkpoint tool cursor is invalid"));
    }
    // The one dedicated owner holds this checkpoint's body only. Release
    // its previous occurrence before replacing it, in this same writer.
    if let Some(content) = prior.and_then(|row| row.content) {
        release_in_txn(&vault.store, txn, &content)?;
    }
    let sink = vault.code_run_output_sink_knowing(prepared.sinks, None)?;
    let finished = vault.stage_code_run_output_from(
        BODY_PATH.to_owned(),
        sink,
        std::io::Cursor::new(bytes),
    )?;
    let owner = body_owner(actual.id)?;
    vault.put_code_run_output_in_txn(txn, &finished, &finished.output, Some(owner))?;
    let content = CheckpointContent {
        actor: actor.entity_ref(),
        actor_class: actor.actor_class(),
        room,
        progress,
        body_owner: owner,
        body: finished.output.output_ref(),
    };
    let mut row = CheckpointRow {
        attempt: actual.id,
        generation: actual.attempt_count,
        content: Some(content.clone()),
    };
    TABLE.admit(vault, txn, &k, &mut row)?;
    // Structural references skip the known-value sweep, not credential
    // shape handling. A mask must never silently change saved meter state.
    if row.content.as_ref() != Some(&content) {
        return Err(invalid(
            "workflow checkpoint metadata changed during admission",
        ));
    }
    TABLE.put(vault, txn, &k, &row)
}

fn pending_call<'a>(
    transcript: &'a WorkflowToolTranscript,
    cursor: &WorkflowToolCursor,
) -> Option<(&'a str, &'a str, &'a serde_json::Value)> {
    transcript
        .request
        .messages
        .get(cursor.assistant_message)?
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::ToolCall {
                call_id,
                name,
                input,
            } => Some((call_id.as_str(), name.as_str(), input)),
            _ => None,
        })
        .nth(cursor.tool_index)
}

fn reads_transcript(parts: &[SidePart]) -> bool {
    matches!(parts, [SidePart::Body(bytes)] if serde_json::from_slice::<WorkflowToolTranscript>(bytes).is_ok())
}

/// Read the still-owned, non-withheld body in the row's own snapshot. An
/// erased row cannot borrow another owner's identical bytes by their hash.
/// The caller holds the custody read guard and pins this body's digest
/// while opening the snapshot and reading a spilled file.
pub(crate) fn transcript_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &CheckpointRow,
) -> Result<Option<WorkflowToolTranscript>> {
    let Some(content) = &row.content else {
        return Ok(None);
    };
    let output = output(content);
    let occurrence = ResultOccurrence::of(Some(content.body_owner), &output)?.id();
    let held = owned_body_in_txn(&vault.store, txn, &content.body_owner, &occurrence)?;
    if held.is_none_or(|held| {
        held.state.held().is_none_or(|body| {
            body.blake3 != content.body.hash || body.bytes != content.body.byte_len
        })
    }) || vault
        .code_run_result_withheld_in_txn(txn, Some(content.body_owner), &output)?
        .is_some()
    {
        return Ok(None);
    }
    vault
        .code_run_result_body_in_txn(txn, &output)?
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|_| invalid("stored workflow transcript does not decode"))
        })
        .transpose()
}

pub(crate) fn accepts_masked(bytes: &[u8]) -> bool {
    side_table::decodes::<CheckpointRow, Named>(bytes)
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
