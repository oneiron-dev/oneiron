//! The vault's one switch: which provider serves its web calls, on whose key. The catalogue key
//! `connectors.web` holds it ([`super::setting_keys::WEB_CONNECTOR`]); the owner sets it through
//! `vault.settings.set`.
use super::setting_keys::WEB_CONNECTOR;
use crate::Vault;
use crate::error::Result;

pub use crate::settings::web_connector::{WebConnectorSetting, WebProviderKey};

impl Vault {
    /// The vault's web connector setting, or the ruled default when the owner
    /// set none. The server reads it for every web call.
    ///
    /// # Errors
    ///
    /// Storage errors; `CorruptedIndex` on a stored switch that does not decode.
    pub fn web_connector_setting(&self) -> Result<WebConnectorSetting> {
        let txn = self.store.env.read_txn()?;
        Ok(WEB_CONNECTOR.read_in_txn(self, &txn, &[], None)?.value)
    }
}
