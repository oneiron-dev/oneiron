//! Lifted half of `oneiron::mail_pack::local_sync` (core split, `oneiron-mail-pack`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

use super::source::active_sources;
use crate::EntityId;
use crate::Result;
use crate::Vault;
#[allow(unused_imports)]
use crate::ext::*;
pub use oneiron::mail_pack::local_sync::*;

/// Methods of [`Vault`] that moved out of `oneiron` with `mail_pack::local_sync` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait MailPackLocalSyncVaultExt {
    /// The pack's Active sources a host steps, mailboxes and calendars,
    /// while the pack is installed.
    ///
    /// # Errors
    ///
    /// Storage failures.
    fn mail_sources_due(&self) -> Result<Vec<EntityId>>;
}

impl MailPackLocalSyncVaultExt for Vault {
    /// The pack's Active sources a host steps, mailboxes and calendars,
    /// while the pack is installed.
    ///
    /// # Errors
    ///
    /// Storage failures.
    fn mail_sources_due(&self) -> Result<Vec<EntityId>> {
        Ok(active_sources(self)?
            .into_iter()
            .map(|(source, _)| source)
            .collect())
    }
}
