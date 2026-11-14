//! Moved from `crates/oneiron/src/memory/witness/stream/completion.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::witness::stream::*;
use oneiron_model::llm::FinishReason;
use serde::Serialize;

/// A MESSAGE's completion, read from its latest stream receipt and its seed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct MessageCompletion {
    /// The latest generation ended without finishing its answer: cut off at a
    /// length, filtered, stopped for another reason, cancelled, failed, idle
    /// or recovered after a crash. Continue and Retry act on it.
    pub incomplete: bool,
    /// A stream is open on the MESSAGE now.
    pub generating: bool,
    /// Why the model that wrote the latest generation stopped, when one did.
    pub finish_reason: Option<FinishReason>,
}

impl MessageStreamReceipt {
    /// Final, and ended by its model's stop or tool call, or by a writer
    /// that is no model and finalized normally.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.finality == StreamFinality::Final
            && matches!(
                self.finish_reason,
                None | Some(FinishReason::Stop | FinishReason::ToolCalls)
            )
    }
}
