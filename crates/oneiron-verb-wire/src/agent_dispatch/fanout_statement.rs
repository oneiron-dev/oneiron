//! Moved from `crates/oneiron/src/agent_dispatch/fanout_statement.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// TASK deliveries to one recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PeerCount {
    pub peer: EntityId,
    pub count: u64,
}

/// How the approval ladder classified an exceptional-width check. No arm
/// holds, refuses or narrows the work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WidthCheckClass {
    /// AUTO cleared it; `policy_ref` names the standing policy row that
    /// covered it, when one did.
    AutoClear { policy_ref: Option<String> },
    /// The next authorised role is asked: on a non-blocking question row when
    /// the work proceeds unclassified (full access), or on the run's own
    /// pause row when its approval mode or a pathology holds it.
    Asked { row_ref: String },
}

/// The typed "is everything okay" check a very large count raises. It is a
/// check, never a limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExceptionalWidthCheck {
    pub count: u64,
    pub threshold: u64,
    pub classification: WidthCheckClass,
}

/// `micros` millionths of a dollar as [`ExpectedSpend::dollar_line`] states
/// them.
pub fn usd(micros: u64) -> String {
    format!("${}.{:06}", micros / 1_000_000, micros % 1_000_000)
}
