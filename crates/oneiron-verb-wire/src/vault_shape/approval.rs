//! Moved from `crates/oneiron/src/vault_shape/approval.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::vault_shape::apply::ShapeItemState;
use crate::vault_shape::seed::hex;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// The dependencies a waiting item's preview stood on, as one digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeApprovalDependencies {
    /// BLAKE3, hex, over the policy read-frontier and the reach rows.
    pub digest: String,
}
