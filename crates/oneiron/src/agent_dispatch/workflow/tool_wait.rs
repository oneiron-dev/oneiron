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
use crate::{ContentPart, EdgeActorClass, EntityId, Error, LlmRequest, LlmResponse, Result, Vault};

use super::super::{AgentDispatcher, SpendScopeId, agent_dispatch_run_actor};

mod body_sources;
pub(crate) mod checkpoint;
mod erased;
mod fence;
mod lifetime;
mod runtime;
mod session;
pub(crate) use erased::settle_erased_in_txn;
pub(crate) use lifetime::{erase_actor_in_txn, erase_source_in_txn, settle_payloads_in_txn};
pub use runtime::WorkflowToolContinuation;
pub(crate) use runtime::{
    adopt_claim_in_txn, advance_saved_retry_in_txn, clear_in_txn, requeue_failure_in_txn,
};
pub use session::WorkflowToolCheckpointWriter;

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
    pub answer: Option<WorkflowToolAnswer>,
}

/// The paid terminal answer and the exact rung that answered it. These are
/// admitted body content, never reconstructed from the current route.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowToolAnswer {
    pub response: LlmResponse,
    pub rung: crate::code_run::CapsuleRungBinding,
    pub route: Option<crate::code_run::ReplayRoutePin>,
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
    retained: Option<CheckpointBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointContent {
    actor: EntityId,
    #[serde(with = "crate::secret_custody::actor_class_byte")]
    actor_class: EdgeActorClass,
    room: Option<EntityId>,
    progress: WorkflowToolProgress,
    body_owner: EntityId,
    body: OutputRef,
    published_digests: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointBinding {
    actor: EntityId,
    room: Option<EntityId>,
    known_sources: Vec<EntityId>,
    body_owner: EntityId,
    published_digests: Vec<[u8; 32]>,
}

impl CheckpointContent {
    fn binding(&self) -> CheckpointBinding {
        CheckpointBinding {
            actor: self.actor,
            room: self.room,
            known_sources: self.progress.known_sources.clone(),
            body_owner: self.body_owner,
            published_digests: self.published_digests.clone(),
        }
    }
}

impl CheckpointRow {
    fn binding(&self) -> Option<CheckpointBinding> {
        self.content
            .as_ref()
            .map(CheckpointContent::binding)
            .or_else(|| self.retained.clone())
    }
}

impl ErasedForm for CheckpointRow {
    fn into_erased(mut self) -> Result<Self> {
        self.content = None;
        self.retained = None;
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
    mut progress: WorkflowToolProgress,
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
    if actual.state != crate::attempt_queue::AttemptState::Leased {
        return Err(invalid("workflow checkpoint is not a running leaf"));
    }
    let (actor, room) = identity_in_txn(vault, txn, &actual)?;
    if progress.no_record_at_arrival
        || room.is_some_and(|room| vault.room_has_unrecorded_stretch(room))
    {
        return Err(invalid(
            "workflow checkpoint requires its live no-record session",
        ));
    }
    check_progress_in_txn(vault, txn, &actual, actor, &progress)?;
    let k = key(actual.id)?;
    let prior = TABLE.get(&vault.store, txn, &k)?;
    let owner = body_owner(actual.id)?;
    let mut published_digests = match prior.as_ref().and_then(CheckpointRow::binding) {
        Some(binding) if binding.body_owner == owner => binding.published_digests,
        Some(_) => return Err(invalid("workflow checkpoint has foreign body owner")),
        None => Vec::new(),
    };
    let fenced = fence::check(&vault.store, txn, &actual)?;
    if fenced != prior.is_some() {
        return Err(invalid("workflow checkpoint payload is unavailable"));
    }
    if prior.as_ref().is_some_and(|row| {
        row.attempt != actual.id || row.generation > actual.attempt_count || row.content.is_none()
    }) {
        return Err(invalid("workflow checkpoint is unavailable"));
    }
    if let Some(content) = prior.as_ref().and_then(|row| row.content.as_ref()) {
        for source in &content.progress.known_sources {
            if !progress.known_sources.contains(source) {
                progress.known_sources.push(*source);
            }
        }
    }
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
    validate_transcript(&transcript, &progress)?;
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
    vault.put_code_run_output_in_txn(txn, &finished, &finished.output, Some(owner))?;
    let body = finished.output.output_ref();
    if !published_digests.contains(&body.hash) {
        published_digests.push(body.hash);
    }
    let content = CheckpointContent {
        actor: actor.entity_ref(),
        actor_class: actor.actor_class(),
        room,
        progress,
        body_owner: owner,
        body,
        published_digests,
    };
    let mut row = CheckpointRow {
        attempt: actual.id,
        generation: actual.attempt_count,
        content: Some(content.clone()),
        retained: None,
    };
    TABLE.admit(vault, txn, &k, &mut row)?;
    // Structural references skip the known-value sweep, not credential
    // shape handling. A mask must never silently change saved meter state.
    if row.content.as_ref() != Some(&content) {
        return Err(invalid(
            "workflow checkpoint metadata changed during admission",
        ));
    }
    let mut sources = vec![content.actor];
    for source in content
        .progress
        .known_sources
        .iter()
        .copied()
        .chain(content.room)
    {
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    body_sources::record_in_txn(
        &vault.store,
        txn,
        content.body_owner,
        &content.published_digests,
        &sources,
    )?;
    TABLE.put(vault, txn, &k, &row)?;
    fence::put(&vault.store, txn, &actual)
}

fn identity_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    actual: &AttemptRecord,
) -> Result<(crate::WriteActor, Option<EntityId>)> {
    let (actor, room) = lineage_identity_in_txn(vault, txn, actual)?;
    if crate::ports::owner_gone_in_txn(&vault.store, txn, &actor.entity_ref())? {
        return Err(invalid("workflow checkpoint actor is erased"));
    }
    Ok((actor, room))
}

fn lineage_identity_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    actual: &AttemptRecord,
) -> Result<(crate::WriteActor, Option<EntityId>)> {
    let queue = AttemptQueue::new(vault);
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&actual.payload)?;
    let root = payload
        .parent_attempt
        .ok_or_else(|| invalid("workflow checkpoint has no wrapper"))?;
    let wrapper = queue
        .get_in_txn(txn, root)?
        .ok_or_else(|| invalid("workflow checkpoint wrapper is missing"))?;
    let dispatcher = AgentDispatcher::new(vault);
    let workflow = dispatcher.read_workflow(txn, &wrapper)?;
    if wrapper.state != crate::attempt_queue::AttemptState::Paused
        || queue.retry_tip_in_txn(txn, workflow.active)?.id != actual.id
        || actual.run_id != workflow.intent.run_id
    {
        return Err(invalid("workflow checkpoint has foreign lineage"));
    }
    let input = super::super::decode_agent_dispatch_input(&payload.input)?;
    let actor = agent_dispatch_run_actor(&input, actual.id)?;
    Ok((actor, input.room.map(|room| room.room)))
}

fn check_progress_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    actual: &AttemptRecord,
    actor: crate::WriteActor,
    progress: &WorkflowToolProgress,
) -> Result<()> {
    let guard = crate::BudgetGuard::from_checkpoint(progress.budget.clone())
        .map_err(|_| invalid("workflow checkpoint meter is invalid"))?;
    let run = format!("workflow-step:{}", key(actual.id)?.to_hex());
    if guard.read().attempt_id != run
        || guard.actor() != Some(actor.entity_ref())
        || AgentDispatcher::new(vault).scope_for_attempt_in_txn(txn, actual.id)?
            != progress.spend_scope
    {
        return Err(invalid("workflow checkpoint meter has foreign identity"));
    }
    Ok(())
}

fn validate_transcript(
    transcript: &WorkflowToolTranscript,
    progress: &WorkflowToolProgress,
) -> Result<()> {
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
    if transcript.answer.as_ref().is_some_and(|answer| {
        progress.wait.is_some()
            || progress.cursor.tool_index != calls
            || answer
                .response
                .message
                .content
                .iter()
                .any(|part| matches!(part, ContentPart::ToolCall { .. }))
    }) {
        return Err(invalid("workflow checkpoint answer has unfinished tools"));
    }
    Ok(())
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
