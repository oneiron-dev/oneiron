//! Moved from `crates/oneiron/src/snapshot_read/snapshot.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One `vault.snapshot.page` request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPageRequest {
    /// The handle `vault.snapshot.open` returned to this caller.
    pub handle: EntityId,
    /// The `next` of the page before; absent for the first page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// The most rows this page serves, at most the owner's rows per page.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// A row a page does not serve because it is larger than the owner's bytes
/// per page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotOversizedRow {
    /// The row.
    pub entity: EntityId,
    /// Its size as a page row would encode it, in bytes.
    pub bytes: u64,
}
