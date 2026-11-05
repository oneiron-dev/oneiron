//! A live office body's pinned frontier and commit count.

use serde::{Deserialize, Serialize};

/// Where one live office body stood: its head's frontier and the commits on
/// it so far.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LivePin {
    pub frontier: Vec<u8>,
    pub commits: u64,
}
