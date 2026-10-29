//! Checkpoint read (DOOR-141 B): one page of a code run's committed step
//! checkpoints and the replies its parked calls resumed with, as the
//! executor's own record holds them. It is the owner's read of a stored run,
//! not a live attachment: no lease is held or forged, nothing is resumed or
//! dispatched, and it shows what the existing injector would carry into the
//! next model context, not that a provider call consumed it.

use serde::{Deserialize, Serialize};

use super::record::parked_wait_at;
use super::store::{
    RESULT_REPLY_INLINE_BYTES, clean_for_context, load_utf8_output, resumed_output_wait,
};
use super::types::{EngineExecutorError, EngineExecutorResult};
use crate::code_run::{CodeRunReplayRecord, ExecutorStorage};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{Error, Vault};

/// Steps in a page when the request names no limit.
pub const CHECKPOINT_READ_DEFAULT_LIMIT: u32 = 32;
/// The most steps one page carries; a larger limit reads this many, and
/// `next_step` names where the following page starts.
pub const CHECKPOINT_READ_MAX_LIMIT: u32 = 128;

/// One page of one code run's checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReadRequest {
    /// 32-hex code-run id (the executor run, not an attempt's run
    /// correlation id).
    pub run_ref: String,
    /// First checkpointed step to read, inclusive.
    #[serde(default)]
    pub from_step: u64,
    /// Steps in this page; [`CHECKPOINT_READ_DEFAULT_LIMIT`] when absent,
    /// at most [`CHECKPOINT_READ_MAX_LIMIT`]. Must be positive.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// A page of committed checkpoints and the stored replies resumed at them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointView {
    pub run_ref: String,
    /// Count of checkpointed steps, not an in-flight step.
    pub completed_steps: u64,
    pub steps: Vec<CheckpointStepView>,
    /// The replies parked calls of this page's steps resumed with, in the
    /// order the run recorded them.
    pub resumed: Vec<CheckpointResumeView>,
    /// Where the next page starts; none past the last checkpoint.
    pub next_step: Option<u64>,
}

/// One committed step checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointStepView {
    pub step: u64,
    pub label: String,
    /// 64-hex chained state hash the checkpoint committed.
    pub state_hash: String,
    pub created_at_ms: u64,
}

/// One stored reply a parked call resumed with.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointResumeView {
    /// The step whose call parked.
    pub step: u64,
    /// 32-hex id of the wait the call parked on.
    pub wait_ref: String,
    /// The parked call's effect.
    pub effect: String,
    /// The run's handle on the stored reply (bound as `wait<step>`).
    pub output_handle: String,
    /// The reply itself, exactly when the injector carries it inline: small
    /// enough and clean of secret or taint for this run. Otherwise absent,
    /// and the reply is read by its handle.
    pub reply: Option<serde_json::Value>,
}

/// Reads one page of `run_ref`'s checkpoints for the vault's owner. Every
/// row the run's answers derive from must read on `memory`'s own credential
/// and locality, and is listed as a producer; a page whose source was
/// withdrawn refuses, as history does. An unknown run reads as absent.
pub fn checkpoint_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CheckpointReadRequest,
) -> MemoryResult<Option<CheckpointView>> {
    let vault = memory.vault();
    owner.revalidate(vault)?;
    let run = EntityId::from_hex(input.run_ref.trim())
        .map_err(|_| MemoryError::bad_request("run_ref must be a 32-hex code-run id"))?;
    let limit = match input.limit {
        Some(0) => return Err(MemoryError::bad_request("limit must be positive")),
        Some(limit) => limit.min(CHECKPOINT_READ_MAX_LIMIT),
        None => CHECKPOINT_READ_DEFAULT_LIMIT,
    };
    let Some((view, sources)) = project(vault, run, input.from_step, limit).map_err(engine)? else {
        return Ok(None);
    };
    for source in sources {
        if memory.get_entity(&source.to_hex())?.value.is_none() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a run checkpoint source is no longer readable",
                &[],
            ));
        }
    }
    Ok(Some(view))
}

fn project(
    vault: &Vault,
    run: EntityId,
    from: u64,
    limit: u32,
) -> EngineExecutorResult<Option<(CheckpointView, Vec<EntityId>)>> {
    let storage = ExecutorStorage::Canonical(vault);
    let Some(record) = storage.get_code_run_replay_record(&run)? else {
        return Ok(None);
    };
    let completed_steps = u64::try_from(record.step_checkpoints.len())
        .map_err(|_| Error::ArithmeticOverflow("executor step count"))?;
    let ledger = storage.code_run_folds(run)?;
    let epochs = storage.code_run_compaction_epochs(run)?;
    let mut sources = record.agent_verb_rows().ok_or_else(|| {
        Error::InvalidConfig("run history contains an answer with unlisted sources".into())
    })?;
    sources.extend(
        ledger
            .folds
            .iter()
            .flat_map(|fold| fold.sources.iter().copied()),
    );
    sources.extend(epochs.iter().map(|(row, _)| row.summary_id()));
    sources.sort_unstable();
    sources.dedup();
    let end = from.saturating_add(u64::from(limit)).min(completed_steps);
    let page = from..end;
    // The same withdrawal law as history and an executor unfold: raw turns
    // whose derived fold was withdrawn are not brought back by a read.
    for step in page.clone() {
        if ledger
            .covering(step)
            .is_some_and(|fold| fold.summary.is_none())
            || epochs
                .iter()
                .any(|(row, text)| row.covers(run, step) && text.is_none())
        {
            return Err(Error::InvalidConfig("checkpoint source was withdrawn".into()).into());
        }
    }
    let steps = record
        .step_checkpoints
        .iter()
        .filter(|checkpoint| page.contains(&checkpoint.seq))
        .map(|checkpoint| CheckpointStepView {
            step: checkpoint.seq,
            label: checkpoint.label.clone(),
            state_hash: bytes_to_hex_lower(&checkpoint.state_hash),
            created_at_ms: checkpoint.created_at_ms,
        })
        .collect();
    let mut resumed = Vec::new();
    for output in &record.outputs {
        let Some((step, wait_ref)) = resumed_output_wait(&output.path) else {
            continue;
        };
        if !page.contains(&step) {
            continue;
        }
        resumed.push(resume_view(&storage, &record, step, wait_ref, output)?);
    }
    Ok(Some((
        CheckpointView {
            run_ref: run.to_hex(),
            completed_steps,
            steps,
            resumed,
            next_step: (end < completed_steps).then_some(end),
        },
        sources,
    )))
}

/// One resumed reply as the injector frames it: inline when small and clean
/// for this run, by handle otherwise.
fn resume_view(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    step: u64,
    wait_ref: &str,
    output: &crate::code_run::CodeRunRawOutput,
) -> EngineExecutorResult<CheckpointResumeView> {
    let wait = parked_wait_at(storage, record, step)?.ok_or(Error::CorruptedIndex(
        "executor resumed reply without a wait",
    ))?;
    let inline = output.raw_len <= RESULT_REPLY_INLINE_BYTES as u64
        && clean_for_context(storage, Some(record.run_id), output)?;
    let reply = if inline {
        let body: serde_json::Value =
            serde_json::from_str(&load_utf8_output(storage, record, &output.path)?)
                .map_err(|_| Error::CorruptedIndex("executor resumed reply"))?;
        Some(body["reply"].clone())
    } else {
        None
    };
    Ok(CheckpointResumeView {
        step,
        wait_ref: wait_ref.to_owned(),
        effect: wait.effect.as_str().to_owned(),
        output_handle: output.handle.clone(),
        reply,
    })
}

fn engine(error: EngineExecutorError) -> MemoryError {
    match error {
        EngineExecutorError::Engine(error) => error.into(),
        _ => Error::InvariantViolation("run checkpoint read failed").into(),
    }
}
