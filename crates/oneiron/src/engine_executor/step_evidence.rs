//! The owner's per-run step evidence (CODE-RUNTIME-02 slice 2: FIX 4414).
//!
//! For each step of one canonical code run: the program the normalization
//! left, the JavaScript a TypeScript program ran as, the observation the
//! step committed, the console a finished program printed beside its
//! answer, and the step's correction records (slice 1). Each body is the
//! run's own stored body, read as model context reads it: the withheld mark
//! while the secret scan marked it or it is under taint for its run, a
//! program's known custody values masked, and past one reply's bytes its
//! head and the line that names the whole body. No body is a raw provider
//! reply or a console the model wrote.
//!
//! It is the owner's read of a stored run, beside `vault.runs.checkpoint`:
//! no lease is held, nothing runs again, and the guest's own result reads
//! admit no path they did not admit before. The rows the run's answers
//! derive from are named for the reader's credential to read, and a step
//! whose derived fold or epoch was withdrawn refuses, as there.

use std::collections::BTreeSet;

use super::checkpoint_read::owner_read_sources;
use super::store::{
    RESULT_REPLY_INLINE_BYTES, clean_for_context, console_output_path, executed_output_path,
    load_observation_window, load_script_context, observation_output_path, script_output_path,
};
use crate::code_run::{CODE_RUN_OUTPUT_PREVIEW_WITHHELD, CodeRunReplayRecord, ExecutorStorage};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::memory::code_run_doors::{CodeRunStepBody, CodeRunStepEvidence};
use crate::{Error, Result, Vault};

/// One page of a run's step evidence, and the rows its bodies derive from.
pub(crate) struct StepEvidencePage {
    /// Count of checkpointed steps, not an in-flight step.
    pub(crate) completed_steps: u64,
    pub(crate) steps: Vec<CodeRunStepEvidence>,
    /// The last step of this page when a later step holds evidence.
    pub(crate) next_after_step: Option<u64>,
    /// Every row the run's answers, folds and epochs derive from. The reader's
    /// credential reads each before any body is released.
    pub(crate) sources: Vec<EntityId>,
}

/// How a step body's text is read once it is clean.
#[derive(Debug, Clone, Copy)]
enum BodyText {
    /// A program, stored unswept: its known custody values are masked.
    Program,
    /// An output, swept as it was written.
    Output,
}

/// One page of canonical run `run`'s step evidence: up to `steps` steps
/// after `after_step` (from step 0 when none), each a step that committed a
/// checkpoint or recorded a correction. The page holds whole steps and
/// stops early, past its first step, at the step whose bodies would take it
/// past one reply's bytes. `None` for a run the vault holds no replay of.
///
/// # Errors
///
/// Storage errors, a run whose answers list no sources, and a page step
/// whose derived fold or epoch was withdrawn.
pub(crate) fn step_evidence_page(
    vault: &Vault,
    run: EntityId,
    after_step: Option<u64>,
    steps: u32,
) -> Result<Option<StepEvidencePage>> {
    let storage = ExecutorStorage::Canonical(vault);
    let Some(record) = storage.get_code_run_replay_record(&run)? else {
        return Ok(None);
    };
    let completed_steps = u64::try_from(record.step_checkpoints.len())
        .map_err(|_| Error::ArithmeticOverflow("executor step count"))?;
    let take = usize::try_from(steps).unwrap_or(usize::MAX);
    let corrections = vault.code_run_corrections(run, after_step, steps)?;
    // The steps after `after_step` that committed a checkpoint or recorded
    // a correction, the first `steps` of them.
    let mut held: BTreeSet<u64> = record
        .step_checkpoints
        .iter()
        .map(|checkpoint| checkpoint.seq)
        .filter(|step| after_step.is_none_or(|after| *step > after))
        .collect();
    held.extend(corrections.records.iter().map(|correction| correction.step));
    let page: Vec<u64> = held.into_iter().take(take).collect();
    let more = page.last().is_some_and(|last| {
        corrections.next_after_step.is_some()
            || corrections
                .records
                .iter()
                .any(|correction| correction.step > *last)
            || record
                .step_checkpoints
                .iter()
                .any(|checkpoint| checkpoint.seq > *last)
    });
    let sources = owner_read_sources(&storage, &record, page.iter().copied(), "step evidence")?;
    let mut next_after_step = if more { page.last().copied() } else { None };
    let mut corrections = corrections.records.into_iter().peekable();
    let mut evidence: Vec<CodeRunStepEvidence> = Vec::with_capacity(page.len());
    let mut reply_bytes = 0_usize;
    for step in page {
        let mut step_view = step_evidence(&storage, &record, step)?;
        let bytes = body_bytes(&step_view);
        if let Some(previous) = evidence.last().map(|held| held.step)
            && reply_bytes.saturating_add(bytes) > RESULT_REPLY_INLINE_BYTES
        {
            next_after_step = Some(previous);
            break;
        }
        reply_bytes = reply_bytes.saturating_add(bytes);
        while let Some(correction) = corrections.next_if(|correction| correction.step == step) {
            step_view.corrections.push(correction);
        }
        evidence.push(step_view);
    }
    Ok(Some(StepEvidencePage {
        completed_steps,
        steps: evidence,
        next_after_step,
        sources,
    }))
}

/// Step `step` of `record` with its bodies and no correction yet. A step
/// that committed no checkpoint holds no body of the run.
fn step_evidence(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    step: u64,
) -> Result<CodeRunStepEvidence> {
    let state_hash = record
        .step_checkpoints
        .iter()
        .find(|checkpoint| checkpoint.seq == step)
        .map(|checkpoint| bytes_to_hex_lower(&checkpoint.state_hash));
    let mut evidence = CodeRunStepEvidence {
        step,
        state_hash,
        source: None,
        executed_js: None,
        observation: None,
        console: None,
        corrections: Vec::new(),
    };
    if evidence.state_hash.is_none() {
        return Ok(evidence);
    }
    evidence.source = step_body(
        storage,
        record,
        &script_output_path(step),
        BodyText::Program,
    )?;
    evidence.executed_js = step_body(
        storage,
        record,
        &executed_output_path(step),
        BodyText::Program,
    )?;
    evidence.observation = step_body(
        storage,
        record,
        &observation_output_path(step),
        BodyText::Output,
    )?;
    evidence.console = step_body(
        storage,
        record,
        &console_output_path(step),
        BodyText::Output,
    )?;
    Ok(evidence)
}

/// The run's body at `path`, `None` when the run kept none there: the
/// withheld mark while it is not clean for its run, else its text within
/// one reply's bytes.
fn step_body(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    path: &str,
    read: BodyText,
) -> Result<Option<CodeRunStepBody>> {
    let Some(output) = record.outputs.iter().find(|output| output.path == path) else {
        return Ok(None);
    };
    let withheld = !clean_for_context(storage, Some(record.run_id), output)?;
    let text = match (withheld, read) {
        (true, _) => CODE_RUN_OUTPUT_PREVIEW_WITHHELD.to_owned(),
        (false, BodyText::Program) => {
            load_script_context(storage, record, path, Some(RESULT_REPLY_INLINE_BYTES))?
        }
        (false, BodyText::Output) => {
            load_observation_window(storage, record, path, RESULT_REPLY_INLINE_BYTES)?
        }
    };
    Ok(Some(CodeRunStepBody {
        handle: output.handle.clone(),
        bytes: output.raw_len,
        complete: output.complete,
        withheld,
        text,
    }))
}

/// The text bytes a step's bodies put in a reply.
fn body_bytes(evidence: &CodeRunStepEvidence) -> usize {
    [
        &evidence.source,
        &evidence.executed_js,
        &evidence.observation,
        &evidence.console,
    ]
    .into_iter()
    .flatten()
    .map(|body| body.text.len())
    .sum()
}
