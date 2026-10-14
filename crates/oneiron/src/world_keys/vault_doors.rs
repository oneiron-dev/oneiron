//! The vault-handle doors for this install's own keys: installing the keystore and
//! reading this install's encryption key.

use std::sync::Arc;

use oneiron_keystore::DeviceKeystore;

use crate::authority::{MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey};
use crate::entity_id::EntityId;
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

    /// This install's public encryption key for `vault_id`, the vault it holds or asks
    /// to join: what its machine profile carries. The seed's keystore slot is named by
    /// this install's machine id, so this first mints the machine identity when the
    /// install has none, in its own write transaction. A restore that makes a new
    /// machine has a new id, and so a new key (Engine ruling on slot names, R2).
    pub fn machine_encryption_key(&self, vault_id: [u8; 32]) -> Result<MachineEncryptionKey> {
        Ok(self.machine_encryption_key_with_id(vault_id)?.1)
    }

    /// [`Vault::machine_encryption_key`] with the machine id its slot is named by.
    pub(crate) fn machine_encryption_key_with_id(
        &self,
        vault_id: [u8; 32],
    ) -> Result<(EntityId, MachineEncryptionKey)> {
        let keystore = self.device_keystore()?;
        let machine = self.provision_machine_identity()?;
        let public =
            super::machine_encryption_key(keystore.as_ref(), vault_id, *machine.as_bytes())?;
        Ok((
            machine,
            MachineEncryptionKey {
                suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
                key: public.to_bytes(),
            },
        ))
    }

    /// This install's machine id. A missing identity is minted, id and signing key
    /// together, in a write transaction of its own: the keystore is never touched
    /// inside one.
    fn provision_machine_identity(&self) -> Result<EntityId> {
        let txn = self.store.env.read_txn()?;
        if let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? {
            return Ok(machine);
        }
        drop(txn);
        let mut machine = None;
        self.with_write_txn_grouped(|wtxn| {
            machine = Some(crate::identity::load_or_mint_machine_in_txn(self, wtxn)?.0);
            Ok(())
        })?;
        Ok(machine.expect("closure ran on Ok"))
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
}
