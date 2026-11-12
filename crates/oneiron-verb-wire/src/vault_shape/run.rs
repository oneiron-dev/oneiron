//! Moved from `crates/oneiron/src/vault_shape/run.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::vault_shape::apply::ShapeItemState;
use crate::vault_shape::invalid;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::attempt_inputs::AttemptInterventionKind;
use oneiron_store::attempt_inputs::ClaimAttempt;
use oneiron_store::attempt_inputs::CompleteAttempt;
use oneiron_store::attempt_inputs::EnqueueAttempt;
use oneiron_store::attempt_inputs::SetAttemptResult;
use oneiron_store::attempt_result::AttemptResultRef;
use oneiron_store::attempt_state::AttemptState;
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
