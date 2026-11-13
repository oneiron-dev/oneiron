//! Moved from `crates/oneiron/src/task_verb/fanout_launch.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// An answer to the width check of a fan-out that already went out. The
/// check held nothing, so there is no deny: ack records the ruling, and
/// ack-and-remember also persists the receipted standing row AUTO reads
/// next time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FanoutCheckChoice {
    Ack,
    AckAndRemember,
}
