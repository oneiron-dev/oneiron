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

    /// The most results a search returns when the owner's own provider key pays: the owner's
    /// `connectors.web.search_max_results` row, a key holder's tighter row within it, or 10 when
    /// no row stands. The server reads it only for such a call; a call on the deploy's backend
    /// key keeps 10.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn web_search_max_results(&self) -> Result<u32> {
        Ok(self
            .page_max_in_force(&super::setting_keys::SEARCH_MAX_RESULTS)?
            .0)
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
