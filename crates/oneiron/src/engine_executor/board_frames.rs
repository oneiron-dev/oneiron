//! The board frames a step's verb answers carried (FIX 2135): kept beside
//! the step as it ends, and read to the model beside the step's console in
//! a message of the host's own, as an MCP client reads a carrier frame
//! beside a tool result. None of it enters the guest's output, the step's
//! result digests or its state hash; the frames themselves stay on the
//! answers' recorded outcomes. This copy is best effort: one not kept or
//! not read is logged and the step goes on, as it would with no frame.

use serde_json::json;

use super::driver::EngineNativeExecutor;
use super::store::{
    board_frames_output_path, clean_for_context, load_utf8_output, record_text_output,
};
use super::types::EngineExecutorResult;
use crate::code_run::{CodeRunReplayRecord, ExecutorStorage, agent_verb_observations_of};
use crate::{ContentPart, Error, LlmMessage, LlmMessageRole};

/// Keeps the frames the answers of step `seq` carried, its calls those from
/// `bridge_start` on; a step whose answers carried none keeps nothing. A
/// copy that cannot be kept is logged, never the step's failure.
pub(super) fn record_step_board_frames(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    seq: u64,
    bridge_start: usize,
) {
    if let Err(error) = keep_step_board_frames(storage, record, seq, bridge_start) {
        tracing::warn!(?error, step = seq, "a step's board frames were not kept for its view");
    }
}

fn keep_step_board_frames(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    seq: u64,
    bridge_start: usize,
) -> EngineExecutorResult<()> {
    let Some(calls) = record.bridge_calls.get(bridge_start..) else {
        return Ok(());
    };
    let observations = agent_verb_observations_of(calls);
    if observations.is_empty() {
        return Ok(());
    }
    let frames: Vec<_> = observations
        .iter()
        .map(|observation| {
            json!({
                "connection": observation.connection,
                "frame": observation.frame,
            })
        })
        .collect();
    let text = serde_json::to_string(&frames)
        .map_err(|_| Error::CorruptedIndex("executor board frames encoding"))?;
    record_text_output(storage, record, board_frames_output_path(seq), &text)
}

impl EngineNativeExecutor<'_> {
    /// The frames step `seq`'s answers carried, as the model reads them
    /// beside its console; `None` when they carried none, or their copy
    /// could not be read, which is logged. A body that is not clean reaches
    /// the model as the withheld mark.
    pub(super) fn step_board_frames_message(
        &self,
        record: &CodeRunReplayRecord,
        seq: u64,
    ) -> Option<LlmMessage> {
        self.read_step_board_frames(record, seq)
            .unwrap_or_else(|error| {
                tracing::warn!(
                    ?error,
                    step = seq,
                    "a step's board frames were not read for its view"
                );
                None
            })
    }

    fn read_step_board_frames(
        &self,
        record: &CodeRunReplayRecord,
        seq: u64,
    ) -> EngineExecutorResult<Option<LlmMessage>> {
        let path = board_frames_output_path(seq);
        let Some(output) = record.outputs.iter().find(|output| output.path == path) else {
            return Ok(None);
        };
        let head = format!(
            "Board frames delivered beside step {seq}'s verb answers, not program output"
        );
        let text = if clean_for_context(&self.storage, Some(record.run_id), output)? {
            format!("{head}:\n{}", load_utf8_output(&self.storage, record, &path)?)
        } else {
            format!("{head}: {}", crate::code_run::CODE_RUN_OUTPUT_PREVIEW_WITHHELD)
        };
        Ok(Some(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text { text }],
        }))
    }
}
