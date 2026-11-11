//! Lifted half of `oneiron::mail_pack::pack` (core split, `oneiron-mail-pack`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

use crate::Result;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
#[allow(unused_imports)]
use crate::ext::*;
use crate::skill_hub::pack_catalog::PackInstallDisposition;
pub use oneiron::mail_pack::pack::*;

/// Methods of [`Vault`] that moved out of `oneiron` with `mail_pack::pack` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait MailPackPackVaultExt {
    /// Owner door: installs the engine's own Mail & Calendar pack folder
    /// through the ordinary owner install ([`Vault::put_pack`]). Installing
    /// it connects nothing and grants nothing; each source is connected by
    /// its own person, or, for a group address, by an Owner or an Admin.
    fn install_mail_calendar_pack(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<PackInstallDisposition>;
}

impl MailPackPackVaultExt for Vault {
    /// Owner door: installs the engine's own Mail & Calendar pack folder
    /// through the ordinary owner install ([`Vault::put_pack`]). Installing
    /// it connects nothing and grants nothing; each source is connected by
    /// its own person, or, for a group address, by an Owner or an Admin.
    fn install_mail_calendar_pack(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<PackInstallDisposition> {
        self.put_pack(owner, mail_calendar_pack_files())
    }
}
