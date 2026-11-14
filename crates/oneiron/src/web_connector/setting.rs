//! The vault's one switch: which provider serves its web calls, on whose key.
use crate::Vault;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// The owner's web connector setting. Key: ().
const SETTING: SideTable<(), WebConnectorSetting, Named> =
    SideTable::new(&side_table::WEB_CONNECTOR_SETTING);

pub use crate::settings::web_connector::{WebConnectorSetting, WebProviderKey};

impl Vault {
    /// The vault's web connector setting, or the ruled default when the owner
    /// set none. The server reads it for every web call.
    pub fn web_connector_setting(&self) -> Result<WebConnectorSetting> {
        let txn = self.store.env.read_txn()?;
        Ok(SETTING.get(&self.store, &txn, &())?.unwrap_or_default())
    }

    pub fn web_connector_setting_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<WebConnectorSetting> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        Ok(SETTING.get(&self.store, &txn, &())?.unwrap_or_default())
    }

    /// Replaces the switch under the owner proof. The returned setting is the
    /// one this transaction stored.
    pub fn replace_web_connector_setting_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        setting: WebConnectorSetting,
    ) -> Result<WebConnectorSetting> {
        setting.validate()?;
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        SETTING.put(&self.store, &mut txn, &(), &setting)?;
        txn.commit()?;
        Ok(setting)
    }
}

/// Lands one archived `WEB_CONNECTOR_SETTING` envelope: the writer's
/// [`WebConnectorSetting::validate`] rules, then an absent-key exact-bytes install. An unknown
/// secret name or hub connector installs as a choice; every use-time door fails closed while it
/// is missing.
pub(super) fn land_archived_web_connector_setting_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    let (key, value) = match decode_archived_row(&SETTING, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    if value.validate().is_err() {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidValue,
        ));
    }
    install_archived_row(&SETTING, vault, txn, permit, &key, row)
}
