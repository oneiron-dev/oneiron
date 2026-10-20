//! A sealed vault's page seal from this device's keystore (moved out of
//! `server_config` whole).

use super::server_config::ServeConfig;

impl ServeConfig {
    /// The page seal of a sealed vault (maximum tier), unlocked with this
    /// device's keystore. A failure is logged without any secret, and the
    /// open then refuses. A mirror whose vault's data is missing unlocks
    /// nothing: no vault is created under another's seal. A door that opens
    /// the vault under a config of its own (doctor, an import's dry run)
    /// takes this seal alone, not the rest of [`Self::vault_config`].
    pub(crate) fn device_page_seal(&self) -> Option<oneiron::VaultPageSeal> {
        match oneiron::world_keys::vault_is_sealed(&self.vault_path) {
            Ok(true) if !self.vault_path.join("data.mdb").exists() => {
                tracing::warn!(
                    "the vault's data is missing beside its page-seal mirror; move the mirror \
                     away to create a new vault"
                );
                return None;
            }
            Ok(true) => {}
            Ok(false) => return None,
            Err(error) => {
                tracing::warn!(%error, "the vault's page seal could not be read");
                return None;
            }
        }
        let keystore = match self.keystore.open(&self.vault_path) {
            Ok(Some(keystore)) => keystore,
            Ok(None) => {
                tracing::warn!("the vault is sealed and the keystore backend is off");
                return None;
            }
            Err(error) => {
                tracing::warn!(
                    reason = ?error.downcast_ref::<oneiron_keystore::KeystoreError>(),
                    "the vault is sealed and this device has no keystore"
                );
                return None;
            }
        };
        let unlock = oneiron::world_keys::VaultKeyUnlock::Device(keystore.as_ref());
        match oneiron::world_keys::unlock_page_seal(&self.vault_path, &unlock) {
            Ok(seal) => Some(seal),
            Err(error) => {
                tracing::warn!(%error, "the vault's pages did not unlock with this device");
                None
            }
        }
    }
}
