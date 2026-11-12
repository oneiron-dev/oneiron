//! Moved from `crates/oneiron/src/conversation_dag/quote_strips.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One page of a thread's quote replies, grouped by the MESSAGE they quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplyStripsRequest {
    /// Room (conversation) holding the thread.
    pub room_ref: String,
    /// Trunk record whose selected thread is read, as `Vault::thread` selects
    /// it. For an ordinary room, the room itself (`room_ref` again) reads
    /// every quote its TURNs hold, witness quotes included (CALLS OF-460
    /// ordinary-room strips).
    pub thread_ref: String,
    /// The last strip's citer on a preceding page (its `next_after`): the
    /// citing MESSAGE, or a native append's TURN.
    #[serde(default)]
    pub after: Option<String>,
    /// Strips per page, positive (absent: 256). A page holds at most 256;
    /// the rest follow through `next_after`.
    #[serde(default)]
    pub limit: Option<usize>,
}
