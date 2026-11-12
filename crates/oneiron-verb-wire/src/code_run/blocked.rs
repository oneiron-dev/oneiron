//! Moved from `crates/oneiron/src/code_run/blocked.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockedCategory {
    Tool,
    Permission,
    Context,
    Environment,
}

impl BlockedCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Permission => "permission",
            Self::Context => "context",
            Self::Environment => "environment",
        }
    }
}
