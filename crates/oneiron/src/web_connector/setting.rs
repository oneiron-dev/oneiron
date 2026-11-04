//! The vault's one switch: which provider serves its web calls, on whose key.
use crate::Vault;
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
