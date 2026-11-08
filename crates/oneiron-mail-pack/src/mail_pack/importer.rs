//! Lifted half of `oneiron::mail_pack::importer` (core split, `oneiron-mail-pack`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

use super::pack::require_pack_active_in;
use super::source::MailSourceStatus;
use super::source::SOURCES;
use crate::EntityId;
use crate::Result;
use crate::Vault;
#[allow(unused_imports)]
use crate::ext::*;
pub use oneiron::mail_pack::importer::*;

/// Methods of [`Vault`] that moved out of `oneiron` with `mail_pack::importer` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait MailPackImporterVaultExt {
    /// The mailbox sources a host's importer syncs: every connected mailbox
    /// whose status is Active, while the pack is installed Active.
    fn mail_sync_sources(&self) -> Result<Vec<EntityId>>;
}

impl MailPackImporterVaultExt for Vault {
    /// The mailbox sources a host's importer syncs: every connected mailbox
    /// whose status is Active, while the pack is installed Active.
    fn mail_sync_sources(&self) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        if require_pack_active_in(self, &txn).is_err() {
            return Ok(Vec::new());
        }
        let mut sources = Vec::new();
        for row in SOURCES.iter_from(&self.store, &txn, &[])? {
            let (id, row) = row?;
            if row.kind.is_mailbox() && row.status == MailSourceStatus::Active {
                sources.push(id);
            }
        }
        Ok(sources)
    }
}
