//! The vault's one switch: which provider serves its web calls, on whose key.
use serde::{Deserialize, Serialize};

use super::{WEB_CONNECTOR_NAME, WebProvider};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// The owner's web connector setting. Key: ().
const SETTING: SideTable<(), WebConnectorSetting, Named> =
    SideTable::new(&side_table::WEB_CONNECTOR_SETTING);

/// Whose key pays for a provider's calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebProviderKey {
    /// The deploy's backend key, only for a provider whose profile allows it.
    Backend,
    /// The user's own key: the custody secret by this name, bound to the
    /// `connector:web` effector. Its value is read only at the custody door.
    Secret { name: String },
    /// An installed hub connector that serves the same `search` and `fetch`
    /// tools on its own key, under its own grant and gate.
    Hub { connector: String },
}

/// Which provider serves the vault's web calls, on whose key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebConnectorSetting {
    pub provider: WebProvider,
    pub key: WebProviderKey,
}

impl Default for WebConnectorSetting {
    /// The ruled default (CONN-1 A): Tavily basic on the deploy's backend key.
    fn default() -> Self {
        Self {
            provider: WebProvider::Tavily,
            key: WebProviderKey::Backend,
        }
    }
}

impl WebConnectorSetting {
    /// Refuses a backend key for a provider whose terms keep it on the user's
    /// own key, and a key that names nothing.
    pub fn validate(&self) -> Result<()> {
        match &self.key {
            WebProviderKey::Backend if !self.provider.profile().backend_key => {
                Err(Error::InvalidConfig(format!(
                    "web connector: {} runs only on the user's own key or through the hub",
                    self.provider.as_str()
                )))
            }
            WebProviderKey::Secret { name } if name.trim().is_empty() => Err(Error::InvalidConfig(
                "web connector: a secret key names its custody record".into(),
            )),
            WebProviderKey::Hub { connector }
                if connector.trim().is_empty() || connector == WEB_CONNECTOR_NAME =>
            {
                Err(Error::InvalidConfig(
                    "web connector: a hub key names another installed connector".into(),
                ))
            }
            _ => Ok(()),
        }
    }
}

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
