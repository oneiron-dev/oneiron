//! Moved from `crates/oneiron/src/memory/shape_card_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::inbox::model::InboxBulkVerb;
use serde::Deserialize;
use serde::Serialize;

/// `vault.shape.items.receipt`'s request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapeItemReceiptRequest {
    /// A landed item's `vault_shape:<frontier>#<seq>` reference, as its run
    /// row's result carries it.
    pub reference: String,
}

/// `vault.shape.groups.resolve`'s request: the owner's answer to one
/// apply's inbox group.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapeGroupResolveRequest {
    /// The apply's run-tree root, hex, as `vault.shape.groups` lists it.
    pub group_key: String,
    pub verb: InboxBulkVerb,
}
