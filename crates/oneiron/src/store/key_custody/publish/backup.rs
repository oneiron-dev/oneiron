//! Serializes the automatic backup companion's publication and expiry.

use std::fs::File;

use super::{PublicationState, record_status};
use crate::error::Result;
use crate::store::Store;
use crate::store::key_custody::folder::FolderTarget;
use crate::store::key_custody::protocol::{CustodyTarget, Lineage, TargetPending};

impl Store {
    /// Apart from the target's head-switch lock: held through acknowledgement
    /// acceptance and status recording too, and by backup-companion expiry.
    pub(crate) fn lock_custody_backup_folder(&self, folder: &FolderTarget) -> Result<Option<File>> {
        self.core
            .key_custody
            .local()
            .map(|custody| {
                custody
                    .journal()?
                    .backup_publication_lock(folder.spec().id())
            })
            .transpose()
    }

    /// The caller holds the publication lock and the vault's hold exclusion.
    /// This does filesystem work only, never opens an LMDB writer.
    pub(crate) fn remove_custody_backup_folder(&self, folder: &FolderTarget) -> Result<()> {
        if let Some(custody) = self.core.key_custody.local() {
            let journal = custody.journal()?;
            folder.remove_lineage(Lineage::of(&journal.position()?))?;
        }
        Ok(())
    }

    /// A removed copy is no longer an acknowledged current target. Preserve
    /// membership, history and completed obligations; record no deletion ack.
    pub(crate) fn note_custody_backup_folder_removed(
        &self,
        folder: &FolderTarget,
        pending: &TargetPending,
    ) -> Result<()> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        let journal = custody.journal()?;
        journal.forget_backup_ack(folder.spec().id(), pending)?;
        let mut publication = self.custody_publication()?;
        if publication.state != PublicationState::Nothing {
            if publication.state != PublicationState::Fenced {
                publication.state = PublicationState::TargetPending;
            }
            publication.published = None;
            publication.data_key_wrapped = None;
            publication.detail = Some(pending.detail.clone());
            record_status(&journal, &publication)?;
        }
        Ok(())
    }
}
