//! Retained pack-manifest entries for queued work.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::Store;
use crate::store::revision_ref::RevisionRef;

#[doc(hidden)]
pub(crate) use oneiron_verb_wire::store::attempt_manifest::erase_manifest_revision_pins;
#[doc(hidden)]
pub use oneiron_verb_wire::store::attempt_manifest::{ManifestEntry, ManifestKind};

/// A stale writer cannot restore a hard-erased entity's revision witness.
/// An unreadable marker keeps the witness and does not fail the caller's write.
pub(crate) fn scrub_hard_erased_manifest_revisions_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    manifest: &mut [ManifestEntry],
) {
    erase_manifest_revision_pins(manifest, |entity| {
        match store.port_deletion_marked(txn, DeletionMarker::HardDelete, entity) {
            Ok(erased) => erased,
            Err(_) => {
                tracing::warn!("manifest revision fence: a hard-delete marker could not be read");
                false
            }
        }
    });
}
