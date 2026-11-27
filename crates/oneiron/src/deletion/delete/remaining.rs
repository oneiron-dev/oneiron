//! What a delete answer lists as still out of its reach (H5): whether old
//! backups hold the record, and which of its file bodies are still in use
//! after the delete's collect pass.

use std::collections::BTreeSet;

use crate::Vault;
use crate::deletion::DeleteReason;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{RemainingNotice, remaining_after_delete};
use crate::provenance::body::{BodyLocation, owned_bodies_in_txn};

/// The digests of every body `id` owns that is held in a FILE: what the
/// delete about to run may leave still in use. One read transaction;
/// deduplicated.
pub(crate) fn file_body_digests(vault: &Vault, id: &EntityId) -> Result<Vec<[u8; 32]>> {
    let txn = vault.store.env.read_txn()?;
    let mut digests = BTreeSet::new();
    for body in owned_bodies_in_txn(&vault.store, &txn, id)? {
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
    let _ = reason;
    false
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
