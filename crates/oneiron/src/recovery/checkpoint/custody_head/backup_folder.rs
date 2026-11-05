//! The automatic backup companion's expiry under the Owners' vault deletion.

use std::path::Path;

use crate::store::FolderTarget;
use crate::store::custody_protocol::{AnchorStore, PendingCode, TargetPending, TargetSpec};
use crate::{Result, Vault};

use super::{CustodyOutbox, CustodyStatus};

fn expired_backup_copy() -> TargetPending {
    TargetPending {
        code: PendingCode::Denied,
        detail: "the deleted vault's backup-adjacent custody copy expired; required-target obligations remain pending"
            .into(),
    }
}

impl Vault {
    /// Removes only the automatic backup folder's copy of this lineage once
    /// the Owners' vault-deletion deadline passes and no legal hold keeps it.
    /// Local keys, other lineages and independent targets are untouched. This
    /// is not a member drain or a target acknowledgement.
    ///
    /// # Errors
    ///
    /// The deletion marker, holds, local custody or filesystem did not read,
    /// or the removal or its status could not be made durable.
    pub fn retire_deleted_backup_custody(&self, folder: &Path) -> Result<bool> {
        let folder = FolderTarget::at(folder.to_path_buf());
        let Some(_publication) = self.store.lock_custody_backup_folder(&folder)? else {
            return Ok(false);
        };
        self.retire_deleted_backup_custody_locked(&folder)
    }

    fn retire_deleted_backup_custody_locked(&self, folder: &FolderTarget) -> Result<bool> {
        let Some(deletion) = self.shared_vault_deletion()? else {
            return Ok(false);
        };
        if self.now_recorded_at() < deletion.backup_retain_until
            || self.legal_hold_keeps_backups()?
        {
            return Ok(false);
        }
        let retired = self.with_backup_hold_exclusion(|holds| -> Result<bool> {
            if holds.keeps_backups() {
                return Ok(false);
            }
            self.store.remove_custody_backup_folder(folder)?;
            Ok(true)
        })??;
        if retired {
            self.store
                .note_custody_backup_folder_removed(folder, &expired_backup_copy())?;
        }
        Ok(retired)
    }

    pub(super) fn publish_custody_backup_folder(
        &self,
        folder: FolderTarget,
        declared: &[TargetSpec],
        outbox: Option<&CustodyOutbox>,
        anchor: Option<&dyn AnchorStore>,
    ) -> Result<CustodyStatus> {
        // Covers target publication, ack acceptance and the recorded status,
        // not just the head rename. Expiry cannot be followed by a late ack.
        let Some(_publication) = self.store.lock_custody_backup_folder(&folder)? else {
            return self.publish_custody_pass(folder, declared, outbox, anchor);
        };
        let folder = if self.retire_deleted_backup_custody_locked(&folder)? {
            folder.unavailable(expired_backup_copy())
        } else {
            folder
        };
        self.publish_custody_pass(folder, declared, outbox, anchor)
    }
}
