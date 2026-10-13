//! The vault-handle doors that need neither the machine roster (P1) nor the world
//! settings (P2): installing the keystore and reading this install's encryption key.

use std::sync::Arc;

use oneiron_crypto::HybridPublicKey;
use oneiron_keystore::DeviceKeystore;

use super::refused;
use crate::error::{Error, Result, SecretError};
use crate::vault::Vault;

impl Vault {
    /// Installs this install's this-device-only keystore on the vault handle. The host
    /// calls it after each open, as it does `retain_machine_write_signer`.
    pub fn install_device_keystore(&self, keystore: Arc<dyn DeviceKeystore>) {
        *self
            .store
            .device_keystore
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(keystore);
    }

    /// This install's public encryption key for this vault: what its machine profile
    /// carries. The seed is created in the keystore on first use.
    pub fn machine_encryption_key(&self) -> Result<HybridPublicKey> {
        let keystore = self.device_keystore()?;
        super::machine_encryption_key(keystore.as_ref(), self.authority_vault_id()?)
    }

    pub(crate) fn device_keystore(&self) -> Result<Arc<dyn DeviceKeystore>> {
        self.store
            .device_keystore
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(Error::Secret(SecretError::KeystoreUnavailable(
                "the host installed no keystore on this vault",
            )))
    }

    /// The vault id from this vault's authority genesis.
    pub(crate) fn authority_vault_id(&self) -> Result<[u8; 32]> {
        let txn = self.store.env.read_txn()?;
        self.authority_view_readonly_in_txn(&txn)?
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis"))
    }
}
