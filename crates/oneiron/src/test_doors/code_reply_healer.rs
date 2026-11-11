//! Doors for `tests/code_reply_healer.rs` (CODE-RUNTIME-02 ruling B, the lead 10 Nov 10:32): the code-reply healer and the repair-record builder.

use crate::code_run::{
    CodeRunCorrection, CodeRunCorrectionCheckpoint, CodeRunCorrectionDraft, CodeRunReplayRecord,
    ExecutorWireRepairs,
};
use crate::engine_executor::{
    EngineExecutorError, HealedExecutorReply, heal_executor_text_tracking_repairs,
};
use crate::{EntityId, ModelId, Result};

/// Heals a reply while retaining the production repairs, including on rejection.
pub fn heal_code_reply_text_tracking(
    text: &str,
    repairs: &mut ExecutorWireRepairs,
) -> std::result::Result<(String, Option<String>), EngineExecutorError> {
    let healed: HealedExecutorReply = heal_executor_text_tracking_repairs(text, repairs)?;
    Ok((healed.code, healed.trailing_speak))
}

/// Returns owned repairs alongside the production healed program or error.
pub fn heal_code_reply_text(
    text: &str,
) -> (
    ExecutorWireRepairs,
    std::result::Result<(String, Option<String>), EngineExecutorError>,
) {
    let mut repairs = ExecutorWireRepairs::default();
    let outcome = heal_code_reply_text_tracking(text, &mut repairs);
    (repairs, outcome)
}

/// Builds an accepted record and reads the draft's rejection and healed-model facts.
pub fn accepted_correction_record(
    run_id: EntityId,
    step: u64,
    model: &ModelId,
    repairs: ExecutorWireRepairs,
    attempt: u64,
    checkpoint: Option<CodeRunCorrectionCheckpoint>,
) -> (CodeRunCorrection, bool, Option<String>) {
    let draft = CodeRunCorrectionDraft::accepted(run_id, step, model, repairs);
    (
        draft.record(attempt, checkpoint),
        draft.is_rejected(),
        draft.healed_model().map(|model| model.as_str().to_owned()),
    )
}

/// Builds a rejected record and reads the draft's rejection and healed-model facts.
pub fn rejected_correction_record(
    run_id: EntityId,
    step: u64,
    model: &ModelId,
    repairs: ExecutorWireRepairs,
    reason: String,
    attempt: u64,
    checkpoint: Option<CodeRunCorrectionCheckpoint>,
) -> (CodeRunCorrection, bool, Option<String>) {
    let draft = CodeRunCorrectionDraft::rejected(run_id, step, model, repairs, reason);
    (
        draft.record(attempt, checkpoint),
        draft.is_rejected(),
        draft.healed_model().map(|model| model.as_str().to_owned()),
    )
}

/// Derives the correction checkpoint from the production replay record.
pub fn committed_checkpoint(
    record: &CodeRunReplayRecord,
    step: u64,
) -> Result<CodeRunCorrectionCheckpoint> {
    CodeRunCorrectionCheckpoint::committed(record, step)
}
