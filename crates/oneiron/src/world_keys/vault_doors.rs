//! The vault-handle doors for this install's own keys: installing the keystore,
//! loading this install's signing keys from it, and reading its encryption key.

use std::path::Path;
use std::sync::{Arc, PoisonError};

use oneiron_keystore::{DeviceKeystore, KeystoreSlot, SlotKind};

use crate::authority::{MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::vault::Vault;

impl Vault {
    /// Installs this install's this-device-only keystore on the vault handle. The host
    /// calls it after each open, as it does `retain_machine_write_signer`.
    /// Signing keys loaded from a keystore installed before are dropped: the next
    /// signing door loads them from this one.
    pub fn install_device_keystore(&self, keystore: Arc<dyn DeviceKeystore>) {
        *self
            .world_keys
            .keystore
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(keystore);
        *self
            .world_keys
            .signer
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Installs this platform's keystore at the keystore crate's defaults and loads
    /// this install's signing keys from it: the call for a local host with no
    /// keystore settings of its own. A platform with none, or a keystore that
    /// refuses, is logged and leaves every signing door refusing
    /// `KeystoreUnavailable`; reads and sync go on. True when the keys loaded.
    pub fn install_default_keystore(&self, vault_dir: &Path) -> bool {
        match oneiron_keystore::default_platform_keystore(&[vault_dir]) {
            Ok(keystore) => {
                self.install_device_keystore(keystore);
                self.prepare_install_signing_logged()
            }
            Err(error) => {
                tracing::warn!(
                    reason = %error,
                    "no this-device-only keystore; signing and world-key doors are unavailable"
                );
                false
            }
        }
    }

    /// [`Vault::prepare_install_signing`] for a host that serves on without it: a
    /// failure is logged by kind, never with key material. True when the keys loaded.
    pub fn prepare_install_signing_logged(&self) -> bool {
        match self.prepare_install_signing() {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "this install's signing keys did not load; signing doors refuse"
                );
                false
            }
        }
    }

    /// Loads this install's signing keys from its `DeviceSigning` keystore slot and
    /// returns its machine id (world privacy P6c). Runs outside every transaction;
    /// each signing door calls it before its own, and a signer inside a transaction
    /// reads the copy it leaves on the handle.
    /// - The machine id is minted when the install has none, in a write transaction of
    ///   its own; the slot is named by the store's id and that machine id.
    /// - The slot's seed is created on first use. A slot found empty while the vault
    ///   holds a device key's public half means this install never held that machine's
    ///   seed (a raw copy on another host, a lost keychain): the vault forgets that
    ///   machine and joins as a new one. No seed is ever imported into a slot.
    /// - It writes the device key's public half when absent, and refuses one that
    ///   names another key.
    pub fn prepare_install_signing(&self) -> Result<EntityId> {
        let keystore = self.device_keystore()?;
        for _ in 0..2 {
            let machine = self.provision_machine_identity()?;
            if self
                .loaded_install_signer()
                .is_some_and(|signer| signer.machine == machine)
            {
                return Ok(machine);
            }
            let slot = KeystoreSlot {
                vault_id: *self.vault_id().as_bytes(),
                install: *machine.as_bytes(),
                kind: SlotKind::DeviceSigning,
            };
            // The public half first: a preparer writes it only after its slot exists,
            // so a present half with an empty slot is never a concurrent first use.
            let had_public = {
                let txn = self.store.env.read_txn()?;
                crate::identity::read_device_verifying_key_in_txn(self, &txn)?.is_some()
            };
            let seed = match keystore
                .get(&slot)
                .map_err(super::machine::keystore_error)?
            {
                Some(seed) => seed,
                None if had_public => {
                    self.with_write_txn_grouped(|wtxn| {
                        if crate::identity::read_machine_id_in_txn(self, wtxn)? == Some(machine) {
                            crate::identity::drop_machine_identity_in_txn(&self.store, wtxn)?;
                        }
                        Ok(())
                    })?;
                    continue;
                }
                None => super::machine::slot_seed(keystore.as_ref(), &slot)?,
            };
            let signer = crate::identity::InstallSigner::derive(machine, &seed);
            drop(seed);
            self.with_write_txn_grouped(|wtxn| {
                if crate::identity::read_machine_id_in_txn(self, wtxn)? != Some(machine) {
                    return Err(super::refused(
                        "the machine identity changed while its signing keys loaded",
                    ));
                }
                crate::identity::load_or_mint_client_id_in_txn(self, wtxn)?;
                crate::identity::put_or_check_device_pk_in_txn(self, wtxn, &signer.device_key)
            })?;
            *self
                .world_keys
                .signer
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(signer));
            return Ok(machine);
        }
        Err(super::refused(
            "this install's machine identity changed while its signing keys loaded",
        ))
    }

    /// [`Vault::prepare_install_signing`] for an install that already has a machine
    /// id, so a door that must not mint one can still load its keys. Nothing to do
    /// with no keystore, no id, or keys already loaded for that id.
    pub(crate) fn load_install_signing_if_minted(&self) -> Result<()> {
        let installed = self
            .world_keys
            .keystore
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        if !installed {
            return Ok(());
        }
        let machine = {
            let txn = self.store.env.read_txn()?;
            crate::identity::read_machine_id_in_txn(self, &txn)?
        };
        match machine {
            Some(machine)
                if !self
                    .loaded_install_signer()
                    .is_some_and(|signer| signer.machine == machine) =>
            {
                self.prepare_install_signing().map(|_| ())
            }
            _ => Ok(()),
        }
    }

    /// The signing keys [`Vault::prepare_install_signing`] left on this handle.
    pub(crate) fn loaded_install_signer(&self) -> Option<Arc<crate::identity::InstallSigner>> {
        self.world_keys
            .signer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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
        let machine = self.prepare_install_signing()?;
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

    /// This install's machine id. A missing one is minted in a write transaction of
    /// its own: the keystore is never touched inside one.
    fn provision_machine_identity(&self) -> Result<EntityId> {
        let txn = self.store.env.read_txn()?;
        if let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? {
            return Ok(machine);
        }
        drop(txn);
        let mut machine = None;
        self.with_write_txn_grouped(|wtxn| {
            machine = Some(crate::identity::load_or_mint_machine_id_in_txn(self, wtxn)?);
            Ok(())
        })?;
        Ok(machine.expect("closure ran on Ok"))
    }

    /// What keeps this install's slots at rest, as the owner is told it; `None`
    /// while the host installed no keystore (OF-168).
    pub fn device_keystore_assurance(&self) -> Option<oneiron_keystore::KeystoreAssurance> {
        self.world_keys
            .keystore
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|keystore| keystore.assurance())
    }

    pub(crate) fn device_keystore(&self) -> Result<Arc<dyn DeviceKeystore>> {
        self.world_keys
            .keystore
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(Error::Secret(SecretError::KeystoreUnavailable(
                "the host installed no keystore on this vault",
            )))
    }
}
