//! Moved from `crates/oneiron/src/vault_shape/run.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// An apply's run tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeApplyRun {
    /// The run id every row carries; it names the apply's journal.
    pub run_id: String,
    /// The root row, hex: the apply's inbox group key.
    pub root: String,
    /// Each item's row, hex, in `seq` order.
    pub items: Vec<String>,
}
