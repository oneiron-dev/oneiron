//! Moved from `crates/oneiron/src/skill_optimize/tradeoff_route.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Who the route call was handed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeoffRouteChannel {
    /// The leader agent, by the dispatched attempt (32 hex).
    Dispatched { attempt: String },
    /// The person leader, by an Ask in their inbox.
    Asked { person: String },
}

/// One handed-off route call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TradeoffRouteIssue {
    pub proposal: String,
    pub project: String,
    pub question_digest: String,
    /// The TASK the call names.
    pub task: String,
    pub channel: TradeoffRouteChannel,
    pub at: u64,
}
