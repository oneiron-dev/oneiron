//! Moved from `crates/oneiron/src/code_run/compaction_fork.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::LlmRequest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// One prompt-cache boundary: the end of one part of the request as its rung
/// sends it, with the rung's prompt already first. A provider that caches by
/// marked blocks marks there and keeps its own cache lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "at", rename_all = "snake_case")]
pub enum CacheBoundary {
    /// The end of part `part` of message `message`. A system message's
    /// part is a system block.
    Message { message: usize, part: usize },
    /// The end of tool definition `tool`.
    Tool { tool: usize },
}

impl CacheBoundary {
    /// The end of `request`'s last part: where a live prefix ends.
    #[must_use]
    pub fn prefix_end(request: &LlmRequest) -> Option<Self> {
        let message = request.messages.len().checked_sub(1)?;
        let part = request.messages[message].content.len().checked_sub(1)?;
        Some(Self::Message { message, part })
    }

    fn holds(self, request: &LlmRequest) -> bool {
        match self {
            Self::Message { message, part } => request
                .messages
                .get(message)
                .is_some_and(|message| part < message.content.len()),
            Self::Tool { tool } => tool < request.tools.len(),
        }
    }
}
