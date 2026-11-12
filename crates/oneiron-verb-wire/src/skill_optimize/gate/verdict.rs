//! Moved from `crates/oneiron/src/skill_optimize/gate/verdict.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::gate::*;
use rmpv::Value;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// The decision on a mixed (non-floor) goal vector: approve the candidate or
/// keep the incumbent.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TradeoffChoice {
    Approve,
    Reject,
}
