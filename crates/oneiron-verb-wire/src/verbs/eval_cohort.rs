//! Moved from `crates/oneiron/src/verbs/eval_cohort.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Pin the returned `built_at` and `inventory_digest` when setting up cohorts.
/// An omitted time reads the vault clock; a future inventory is refused.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalInventoryWire {
    #[serde(default)]
    pub at: Option<u64>,
}
