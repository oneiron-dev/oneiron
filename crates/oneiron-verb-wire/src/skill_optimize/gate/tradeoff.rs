//! Moved from `crates/oneiron/src/skill_optimize/gate/tradeoff.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::gate::*;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// A rule matches the exact sets of axes gained and lost, not unbound prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TradeoffRule {
    pub gains: BTreeSet<String>,
    pub losses: BTreeSet<String>,
    pub choice: TradeoffChoice,
}
