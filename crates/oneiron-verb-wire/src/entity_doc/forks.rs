//! Moved from `crates/oneiron/src/entity_doc/forks.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A consume-once fork's durable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ForkStatus {
    Pending,
    Merged,
    Switched,
    Rejected,
}

/// Explicit settle verbs. Only SWITCH has a stale-base refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum SettleVerb {
    Merge,
    Switch,
    Reject,
}
