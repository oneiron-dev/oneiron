//! The write receipt owns the durable descriptor; the answer only lends it.

use crate::code_run::{
    CodeRunReplayGeneration, CodeRunReplayRecord, ExecutorStorage, SelfDispatchOutcome,
};
use crate::engine_executor::{store_agent_verb_write_answer, write_receipt_result_output_path};
use crate::{EntityId, Result};

pub(super) fn store(
    storage: &ExecutorStorage<'_>,
    owner: EntityId,
    receipt: &mut CodeRunReplayRecord,
    generation: &mut CodeRunReplayGeneration,
    outcome: &mut SelfDispatchOutcome,
) -> Result<()> {
    if let SelfDispatchOutcome::AgentVerb(answer) = outcome {
        store_agent_verb_write_answer(storage, owner, receipt, generation, answer)?;
    }
    Ok(())
}

pub(super) fn restore(receipt: &CodeRunReplayRecord, outcome: &mut SelfDispatchOutcome) {
    if let SelfDispatchOutcome::AgentVerb(answer) = outcome {
        let path = write_receipt_result_output_path(receipt.run_id);
        answer.stored_output = receipt
            .outputs
            .iter()
            .find(|output| output.path == path)
            .cloned();
    }
}
