//! A write receipt's large verb answer, streamed before its replay row.

use super::{
    ByteCount, RESULT_REPLY_INLINE_BYTES, SCRIPT_OUTPUT_DIR, result_handle_json, write_json,
};
use crate::code_run::{
    AgentVerbAnswer, CodeRunReplayGeneration, CodeRunReplayRecord, ExecutorStorage,
};
use crate::{EntityId, Error, Result};

/// The write's stable result path, independent of reads moved before it.
pub(crate) fn write_receipt_result_output_path(receipt: EntityId) -> String {
    format!(
        "{SCRIPT_OUTPUT_DIR}/bridge/write-{}.result.json",
        receipt.to_hex()
    )
}

/// Stores only the output; its rows, observations and hooks stay on the answer.
pub(crate) fn store_agent_verb_write_answer(
    storage: &ExecutorStorage<'_>,
    owner: EntityId,
    receipt: &mut CodeRunReplayRecord,
    generation: &mut CodeRunReplayGeneration,
    answer: &mut AgentVerbAnswer,
) -> Result<()> {
    let mut size = ByteCount::default();
    serde_json::to_writer(&mut size, &answer.output)
        .map_err(|error| Error::InvalidConfig(format!("verb answer encoding failed: {error}")))?;
    if size.0 <= RESULT_REPLY_INLINE_BYTES {
        return Ok(());
    }
    let mut sink = storage.code_run_reply_spool()?;
    write_json(&mut sink, &answer.output)?;
    let output = match storage.publish_code_run_reply(
        write_receipt_result_output_path(receipt.run_id),
        sink,
        owner,
        Some((receipt, generation)),
    )? {
        Ok(output) => output,
        Err(unavailable) => {
            answer.output = unavailable;
            return Ok(());
        }
    };
    answer.output = result_handle_json(owner, &output);
    answer.stored_output = Some(output);
    Ok(())
}
