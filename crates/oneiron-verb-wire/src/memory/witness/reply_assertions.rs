//! Moved from `crates/oneiron/src/memory/witness/reply_assertions.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::ReplyAssertions;
use serde::Deserialize;
use serde::Serialize;

/// The reply assertions a MESSAGE born whole (not streamed) keeps beside it
/// (FIX 10260): which MESSAGE, in which TURN and conversation, written by
/// whom, and the records its turn asserts, as admitted when it landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MessageReplyAssertions {
    pub message: EntityId,
    pub conversation: EntityId,
    pub turn: EntityId,
    /// The writer the MESSAGE was witnessed as, and its actor class.
    pub writer: EntityId,
    pub writer_class: u8,
    /// The records its turn asserts it cited or created, each readable by
    /// its writer when it landed: no proof of authorship.
    pub assertions: ReplyAssertions,
}
