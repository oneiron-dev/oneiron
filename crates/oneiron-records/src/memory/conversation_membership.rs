//! Moved from `crates/oneiron/src/memory/conversation_membership.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipWindow {
    pub joined_at: u64,
    pub from: u64,
    pub to: Option<u64>,
}

impl MembershipWindow {
    pub fn contains(&self, at: u64) -> bool {
        self.from <= at && self.to.is_none_or(|end| at < end)
    }
}
