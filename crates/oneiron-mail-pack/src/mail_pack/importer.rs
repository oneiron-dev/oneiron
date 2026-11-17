//! Lifted half of `oneiron::mail_pack::importer` (core split, `oneiron-mail-pack`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

use super::source::active_sources;
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
        Ok(active_sources(self)?
            .into_iter()
            .filter_map(|(source, kind)| kind.is_mailbox().then_some(source))
            .collect())
    }
}
