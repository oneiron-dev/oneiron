//! Moved from `crates/oneiron/src/verbs/federation_burst.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::sync::federation_burst::*;
use serde::Deserialize;
use serde::Serialize;

/// `vault.sync.retained_work.wait.set`'s input: one retained-work queue and
/// its new wait. `None` (or an absent `secs`) resets that queue to its
/// existing default; no cap or default is invented here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetainedWorkWaitSetRequest {
    pub queue: RetainedWorkQueue,
    #[serde(default)]
    pub secs: Option<u64>,
}
