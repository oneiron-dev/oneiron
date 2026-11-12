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

#[doc(hidden)]
pub use oneiron_verb_wire::engine_executor::checkpoint_read::{
    CheckpointReadRequest, CheckpointResumeView, CheckpointStepView, CheckpointView,
};

/// Reads one page of `run_ref`'s checkpoints for the vault's owner. Every
/// row the run's answers derive from must read on `memory`'s own credential
/// and locality, and is listed as a producer; a page whose source was
/// withdrawn refuses, as history does. An unknown run reads as absent.
pub fn checkpoint_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CheckpointReadRequest,
) -> MemoryResult<Option<CheckpointView>> {
    owner.revalidate(memory.vault())?;
    checkpoint_projection(memory, input)
}

/// [`checkpoint_as_owner`]'s page once its caller is admitted: the owner on
/// its proof, or the run's own actor (`crate::snapshot_read`, slice 6.4c).
/// Every source is read through `memory`'s own lane, as before.
pub(crate) fn checkpoint_projection(
    memory: &Memory<'_>,
    input: &CheckpointReadRequest,
) -> MemoryResult<Option<CheckpointView>> {
    let vault = memory.vault();
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
    let end = from.saturating_add(u64::from(limit)).min(completed_steps);
    let page = from..end;
    let sources = owner_read_sources(&storage, &record, page.clone(), "checkpoint")?;
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

/// The rows an owner's read of stored run `record` derives from: those its
/// answers were served from, its folds' sources and its compaction epochs'
/// summaries, sorted once. The same withdrawal law as history and an
/// executor unfold applies before any byte is read: a read of a step in
/// `steps` whose derived fold or epoch was withdrawn refuses, so no read
/// brings its raw turn back. `read` names the read in that refusal.
pub(super) fn owner_read_sources(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    steps: impl IntoIterator<Item = u64>,
    read: &str,
) -> crate::Result<Vec<EntityId>> {
    let run = record.run_id;
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
    for step in steps {
        if ledger
            .covering(step)
            .is_some_and(|fold| fold.summary.is_none())
            || epochs
                .iter()
                .any(|(row, text)| row.covers(run, step) && text.is_none())
        {
            return Err(Error::InvalidConfig(format!("{read} source was withdrawn")));
        }
    }
    Ok(sources)
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
