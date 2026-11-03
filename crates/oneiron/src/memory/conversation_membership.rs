//! The time window a conversation membership admits.

use serde::{Deserialize, Serialize};

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
