//! What a delete answer lists as still out of its reach (H5): whether old
//! backups hold the record, and which of the file bodies found in the
//! delete's own writer are still in use after the collect pass.

use std::collections::BTreeSet;

use crate::Vault;
use crate::deletion::DeleteReason;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{RemainingNotice, remaining_after_delete};
use crate::provenance::body::{BodyLocation, owned_bodies_in_txn};
use crate::store::ManifestDbs;

/// Deduplicated digests of every FILE body `id` owns, read in the delete's
/// own writer before it releases the descriptors.
pub(super) fn file_body_digests_in_txn(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<[u8; 32]>> {
    let mut digests = BTreeSet::new();
    for body in owned_bodies_in_txn(store, txn, id)? {
        if let Some(held) = body.state.held() {
            if held.location == BodyLocation::File {
                digests.insert(held.blake3);
            }
        }
    }
    Ok(digests.into_iter().collect())
}

/// Whether old backups still hold a record deleted under `reason`: a user or
/// policy hard delete only (H5, E1).
pub(crate) fn delete_backups_hold_it(reason: DeleteReason) -> bool {
    matches!(
        reason,
        DeleteReason::UserHardDelete | DeleteReason::PolicyDelete
    )
}

/// The delete answer's entries for a delete that queued `sweep_key` under
/// `reason`: what [`remaining_after_delete`] lists for the sweep, old backups
/// and the files of `file_digests` still in use after the collect pass. The
/// count never fails the answer: the delete has committed, so a failed count
/// is logged and lists none.
pub(crate) fn delete_remaining(
    vault: &Vault,
    reason: DeleteReason,
    sweep_key: Option<&[u8]>,
    file_digests: &[[u8; 32]],
) -> Vec<RemainingNotice> {
    #[cfg(unix)]
    let files_left = if file_digests.is_empty() {
        0
    } else {
        match vault.body_files_left(file_digests) {
            Ok(left) => left,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a delete's still-in-use file count failed; its answer lists none"
                );
                0
            }
        }
    };
    #[cfg(not(unix))]
    let files_left = {
        let _ = (vault, file_digests);
        0
    };
    remaining_after_delete(sweep_key, delete_backups_hold_it(reason), files_left)
}
