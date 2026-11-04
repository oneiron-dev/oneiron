//! Inference snapshot catalog facade.

pub use crate::store::snapshot_catalog::{SNAPSHOT_RECORD_SCHEMA, SnapshotId, SnapshotCompatibility, SnapshotManifest, SnapshotDependencies, SnapshotClass, SnapshotPins, SnapshotRecord};
pub(crate) use crate::store::snapshot_catalog::{CATALOG, CONVERSATION_INDEX, put_conversation_entry, delete_conversation_entry, CatalogRow, rows, rows_of_conversation, erase_in_txn, erase_actor_in_txn};
