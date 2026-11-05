//! Inference snapshot catalog facade.

pub(crate) use crate::store::snapshot_catalog::{
    CATALOG, CONVERSATION_INDEX, CatalogRow, delete_conversation_entry, erase_actor_in_txn,
    erase_in_txn, put_conversation_entry, rows, rows_of_conversation,
};
pub use crate::store::snapshot_catalog::{
    SNAPSHOT_RECORD_SCHEMA, SnapshotClass, SnapshotCompatibility, SnapshotDependencies, SnapshotId,
    SnapshotManifest, SnapshotPins, SnapshotRecord,
};
