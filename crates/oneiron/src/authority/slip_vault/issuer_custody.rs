//! Where a vault's host issuer seed is kept (FIX-LIST 3018): this install's
//! own `HostIssuerSeed` slot for the vault, in the this-device-only keystore
//! the host installed. The seed is drawn once, independently
//! ([`new_host_issuer_seed`]), when this install roots a vault no root,
//! replica or restore has reached; never from auth_secret, the DEK or the
//! vault id, which name the slot and take no part in the key.
//!
//! Four operations, never one load-or-create on every open: a load reads
//! the slot and writes nothing; a bootstrap fills an empty slot only for an
//! unstarted vault, before its signed genesis; an explicit re-root draws its
//! successor; a validated replacement is written in place. A missing seed is
//! key unavailability: nothing falls back to a key derived from a configured
//! secret, and nothing mints a successor silently.

use oneiron_keystore::{KeystoreError, KeystoreSlot, SlotKind};

use super::issuer_seed::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, new_host_issuer_seed};
use crate::Vault;
use crate::error::{Error, Result, SecretError};
use crate::world_keys::keystore_error;

use crate::authority::{HostReRoot, invalid_authority};

/// This install holds no host issuer seed for this vault: it never rooted
/// it, its keystore lost the slot, or the host installed no keystore.
const HOST_ISSUER_SEED_ABSENT: &str = "this install holds no host issuer seed for this vault";

/// The slot an explicit re-root keeps its successor in emptied before the
/// root moved: nothing was re-rooted, and no seed was kept.
const HOST_ISSUER_SEED_SLOT_EMPTIED: &str =
    "this install's host issuer seed slot emptied before the re-root; nothing moved";

fn seed_absent() -> Error {
    Error::Secret(SecretError::KeystoreUnavailable(HOST_ISSUER_SEED_ABSENT))
}

impl Vault {
    /// This install's host issuer for this vault, from its `HostIssuerSeed`
    /// slot. Read-only: an empty slot, an install with no machine identity,
    /// or a host with no keystore is key unavailability, never a new seed.
    pub fn load_host_slip_issuer(&self) -> Result<HostSlipIssuer> {
        let keystore = self.device_keystore()?;
        let slot = self.host_issuer_slot()?;
        let seed = keystore
            .get(&slot)
            .map_err(keystore_error)?
            .ok_or_else(seed_absent)?;
        HostSlipIssuer::from_seed(&seed)
    }

    /// The issuer a start that may root this vault signs with. On a vault
    /// whose authority no root, replica or restore has reached (no log row,
    /// no pin, no adopted checkpoint), this install's empty slot takes one
    /// fresh independent seed first, before the genesis it signs; the slot
    /// is create-only, so a concurrent first use keeps the first seed. On
    /// any other vault it only loads ([`Self::load_host_slip_issuer`]): an
    /// established root is never reminted here.
    pub fn bootstrap_host_slip_issuer(&self) -> Result<HostSlipIssuer> {
        if !self.authority_is_unstarted()? {
            return self.load_host_slip_issuer();
        }
        let keystore = self.device_keystore()?;
        self.prepare_install_signing()?;
        let slot = self.host_issuer_slot()?;
        if keystore.get(&slot).map_err(keystore_error)?.is_none() {
            let seed = new_host_issuer_seed()?;
            match keystore.create(&slot, &seed) {
                Ok(()) | Err(KeystoreError::AlreadyExists) => {}
                Err(error) => return Err(keystore_error(error)),
            }
        }
        self.load_host_slip_issuer()
    }

    /// Moves this vault's root from `current`, this install's loaded issuer,
    /// to a successor seed drawn here (OF-455 through
    /// [`Self::re_root_host`]): the owner's explicit act, never a repair.
    /// The successor takes this install's slot in place first, so a root
    /// that moved always has its seed kept; a re-root that then fails puts
    /// `current` back. A keystore with no in-place replace keeps nothing and
    /// moves nothing.
    pub fn re_root_host_to_new_seed(&self, current: &HostSlipIssuer) -> Result<HostReRoot> {
        let keystore = self.device_keystore()?;
        let slot = self.host_issuer_slot()?;
        let next_seed = new_host_issuer_seed()?;
        let next = HostSlipIssuer::from_seed(&next_seed)?;
        let kept = current.retained_seed()?;
        match keystore.replace(&slot, &next_seed) {
            Ok(true) => {}
            Ok(false) => return Err(seed_absent()),
            Err(error) => return Err(keystore_error(error)),
        }
        match self.re_root_host(current, &next) {
            Ok(moved) => Ok(moved),
            Err(error) => {
                match keystore.replace(&slot, &kept) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(Error::InvariantViolation(HOST_ISSUER_SEED_SLOT_EMPTIED));
                    }
                    Err(restore) => return Err(keystore_error(restore)),
                }
                Err(error)
            }
        }
    }

    /// Writes `seed`, already validated as a live owner key of the settled
    /// root, over this install's filled `HostIssuerSeed` slot in place.
    /// `Ok(false)` when the slot is empty: a replace never fills one.
    pub(in crate::authority) fn replace_host_issuer_seed(
        &self,
        install: crate::EntityId,
        seed: &[u8; HOST_ISSUER_SEED_BYTES],
    ) -> std::result::Result<bool, KeystoreError> {
        let keystore = self
            .device_keystore()
            .map_err(|_| KeystoreError::Unavailable("the host installed no keystore"))?;
        keystore.replace(&self.issuer_slot_for(install), seed)
    }

    /// This install's `HostIssuerSeed` slot for this vault, by the machine
    /// id it holds; none before it holds one.
    fn host_issuer_slot(&self) -> Result<KeystoreSlot> {
        let txn = self.store.env.read_txn()?;
        let install = crate::identity::read_machine_id_in_txn(self, &txn)?.ok_or_else(seed_absent)?;
        Ok(self.issuer_slot_for(install))
    }

    fn issuer_slot_for(&self, install: crate::EntityId) -> KeystoreSlot {
        KeystoreSlot {
            vault_id: *self.vault_id().as_bytes(),
            install: *install.as_bytes(),
            kind: SlotKind::HostIssuerSeed,
        }
    }
}

impl HostSlipIssuer {
    /// The independent seed this issuer was made from, for the slot a
    /// failed re-root puts back.
    fn retained_seed(&self) -> Result<zeroize::Zeroizing<[u8; HOST_ISSUER_SEED_BYTES]>> {
        let seed: [u8; HOST_ISSUER_SEED_BYTES] = self
            .secret()
            .try_into()
            .map_err(|_| invalid_authority())?;
        Ok(zeroize::Zeroizing::new(seed))
    }
}
