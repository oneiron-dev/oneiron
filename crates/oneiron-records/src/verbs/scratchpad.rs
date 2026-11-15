//! Moved from `crates/oneiron/src/verbs/scratchpad.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::verbs::scratchpad::ScratchpadAppendRequest;
pub use oneiron_verb_wire::verbs::scratchpad::ScratchpadRecallMark;
pub use oneiron_verb_wire::verbs::scratchpad::ScratchpadRecallRequest;
pub use oneiron_verb_wire::verbs::scratchpad::ScratchpadSealRequest;
use serde::Deserialize;
use serde::Serialize;

/// What a scratchpad write did to the session's pad.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchpadWriteReply {
    /// The pad NOTE written or sealed; absent when a seal found no pad.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pad: Option<EntityId>,
    /// Whether the pad is now sealed.
    pub sealed: bool,
    /// The actor's prior pad, sealed because this line opened a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_prior: Option<EntityId>,
}

/// One pad line a recall matched, in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchpadRecallReplyLine {
    /// The line's place in the pad, from 0 for the oldest.
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark: Option<ScratchpadRecallMark>,
    pub pin: bool,
    pub text: String,
}

/// What the recall found in the session's pad.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchpadRecallReply {
    /// The pad searched; absent when the session has no pad.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pad: Option<EntityId>,
    /// Whether the pad is sealed.
    pub sealed: bool,
    /// How many lines matched; `lines` holds the newest
    /// `SCRATCHPAD_RECALL_LINES` of them.
    pub matched: usize,
    /// The newest matching lines in full, newest first.
    pub lines: Vec<ScratchpadRecallReplyLine>,
}
