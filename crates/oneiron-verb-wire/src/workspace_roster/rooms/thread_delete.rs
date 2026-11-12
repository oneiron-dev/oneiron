//! Moved from `crates/oneiron/src/workspace_roster/rooms/thread_delete.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// `vault.rooms.thread_delete`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateThreadDeleteRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
}

/// What a private thread's delete did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateThreadDeleteReceipt {
    /// The thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// Whether the root was there to delete.
    pub existed: bool,
    /// The delete's receipt, 32-hex, when it wrote one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
}
