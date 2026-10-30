//! The copies an erased source leaves in the view set (FIX 9722).
//!
//! A view is an engine-owned copy of its source holders' files: the base
//! repository and tested revision of an owner's view, or the repository of
//! a run's work. The permanent hard-delete marker of any of them retires
//! the view: its directory goes, copied build outputs included, then each
//! blob no remaining view holds, then its receipt and build outcomes. A blob
//! another live view holds stays. Rows go only after the files, so a
//! removal that fails is found again by the next pass.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{VIEW_BUILD_OUTCOMES, VIEW_RECEIPTS, ViewReceipt};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::{EntityId, Vault};

impl ViewReceipt {
    /// The source holders whose erase retires this view.
    fn source_holders(&self) -> Vec<EntityId> {
        let mut holders: Vec<_> = self
            .base
            .iter()
            .flat_map(|(repo, tested)| [*repo, *tested])
            .collect();
        holders.extend(self.run.as_ref().map(|stamp| stamp.repo));
        holders
    }
}

/// Set by a pass that failed, so the next housekeeping tick retries it.
static COLLECTION_OWED: AtomicBool = AtomicBool::new(false);

/// Runs [`collect_erased_views`] after a committed delete, logging (never
/// raising) a failure: the delete stands, and the next pass retries.
pub fn collect_after_delete(vault: &Vault) {
    COLLECTION_OWED.store(false, Ordering::Relaxed);
    if let Err(error) = collect_erased_views(vault) {
        COLLECTION_OWED.store(true, Ordering::Relaxed);
        tracing::warn!(
            kind = ?error.kind(),
            "working views of an erased source were not removed; the next pass retries"
        );
    }
}

/// [`collect_after_delete`] for a housekeeping tick: it runs only when the
/// tick's sweep erased something or an earlier pass failed, so an idle tick
/// reads no view.
pub fn collect_after_sweep(vault: &Vault, erased: bool) {
    if erased || COLLECTION_OWED.load(Ordering::Relaxed) {
        collect_after_delete(vault);
    }
}

/// Removes every view whose source holder the owner erased, and each blob
/// only those views held; answers how many views it removed.
///
/// # Errors
/// A store failure, or a file the pass could not remove; rows of views
/// whose files remain are kept for the next pass.
pub fn collect_erased_views(vault: &Vault) -> Result<usize> {
    let root = vault.store.env.path().join("code-views");
    let (views, blobs) = (root.join("views"), root.join("blobs"));
    for directory in [&root, &views, &blobs] {
        if !std::fs::symlink_metadata(directory).is_ok_and(|meta| meta.is_dir()) {
            return Ok(0);
        }
    }
    let (erased, held) = {
        let txn = vault.store.env.read_txn()?;
        let mut erased = Vec::new();
        let mut held = BTreeSet::new();
        for row in VIEW_RECEIPTS.iter_from(&vault.store, &txn, &[])? {
            let (_, receipt) = row?;
            let mut gone = false;
            for holder in receipt.source_holders() {
                gone |= vault.local_hard_delete_marker_exists_in_txn(&txn, &holder)?;
            }
            if gone {
                erased.push(receipt);
            } else {
                held.extend(receipt.files.values().copied());
            }
        }
        (erased, held)
    };
    if erased.is_empty() {
        return Ok(0);
    }
    for receipt in &erased {
        remove(&views.join(receipt.view_id.to_hex()), true)?;
    }
    let orphaned: BTreeSet<_> = erased
        .iter()
        .flat_map(|receipt| receipt.files.values().copied())
        .filter(|hash| !held.contains(hash))
        .collect();
    for hash in orphaned {
        remove(&blobs.join(bytes_to_hex_lower(&hash)), false)?;
    }
    vault.with_write_txn_grouped(|txn| {
        for receipt in &erased {
            VIEW_RECEIPTS.delete(&vault.store, txn, &receipt.view_id)?;
            for key in
                VIEW_BUILD_OUTCOMES.scan_keys(&vault.store, txn, receipt.view_id.as_bytes())?
            {
                VIEW_BUILD_OUTCOMES.delete(&vault.store, txn, &key)?;
            }
        }
        Ok(())
    })?;
    Ok(erased.len())
}

/// Removes one view directory or blob without following a symlink; an
/// absent path is already removed.
fn remove(path: &Path, directory: bool) -> Result<()> {
    let removed = if directory {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match removed {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}
