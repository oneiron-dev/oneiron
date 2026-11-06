//! Whether one retained revision is a version of an entity's common document
//! (FIX 2783, OF-540): the proof a `document:<entity>@<revision>` team submit
//! needs, read in the caller's transaction with the ledger's own namespace
//! proof, never a second revision store.

use heed::RoTxn;

use super::RevisionRef;
use super::storage::{RevisionNamespace, fork_revision_with_namespace};
use crate::EntityId;
use crate::error::{Error, Result};
use crate::store::ManifestDbs;

/// Whether the common document of `id` retains `revision`: one of its
/// frontiers, or its birth alias. A generic revision of the record from
/// before its document was born is not a document version, nor is a
/// revision the ledger does not hold or a purge removed, nor any revision of
/// a record that owns no common document.
pub(crate) fn common_document_retains_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<bool> {
    if !crate::entity_doc::has_record_head(store, txn, id)? {
        return Ok(false);
    }
    match fork_revision_with_namespace(store, txn, id, revision) {
        Ok((_, RevisionNamespace::Common)) => Ok(true),
        Ok((_, RevisionNamespace::Generic)) | Err(Error::EntityNotFound | Error::Artifact(_)) => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
