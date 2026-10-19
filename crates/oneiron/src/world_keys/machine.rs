//! This install's machine secret: a 32-byte seed in the this-device-only keystore,
//! expanded to the hybrid keypair that world keys are wrapped to.

use oneiron_crypto::{HybridPublicKey, HybridSecretKey};
use oneiron_keystore::{DeviceKeystore, KeystoreError, KeystoreSlot, SlotKind};
use zeroize::Zeroizing;

use super::{os_fill, refused};
use crate::error::{Error, Result, SecretError};

const MACHINE_KEY_LABEL: &[u8] = b"oneiron/machine-encryption/v1";

/// The secret of install `install` (its machine id) for `vault_id`. It is created in
/// the keystore on first use. The keystore is create-only, so a concurrent first use
/// keeps the slot's first seed.
pub fn machine_secret(
    keystore: &dyn DeviceKeystore,
    vault_id: [u8; 32],
    install: [u8; 16],
) -> Result<HybridSecretKey> {
    let slot = KeystoreSlot {
        vault_id,
        install,
        kind: SlotKind::MachineEncryption,
    };
    let seed = slot_seed(keystore, &slot)?;
    HybridSecretKey::from_seed(&seed, MACHINE_KEY_LABEL)
        .map_err(|_| refused("the machine seed does not expand"))
}

/// `slot`'s seed, created from the OS CSPRNG on first use. The keystore is
/// create-only, so a concurrent first use keeps the slot's first seed.
pub(crate) fn slot_seed(
    keystore: &dyn DeviceKeystore,
    slot: &KeystoreSlot,
) -> Result<Zeroizing<[u8; 32]>> {
    if let Some(seed) = keystore.get(slot).map_err(keystore_error)? {
        return Ok(seed);
    }
    let mut fresh = Zeroizing::new([0u8; 32]);
    os_fill(&mut fresh[..])?;
    match keystore.create(slot, &fresh) {
        Ok(()) | Err(KeystoreError::AlreadyExists) => {}
        Err(e) => return Err(keystore_error(e)),
    }
    keystore
        .get(slot)
        .map_err(keystore_error)?
        .ok_or_else(|| refused("the keystore lost a slot it just created"))
}

/// The public half of [`machine_secret`]: what the machine profile carries.
pub fn machine_encryption_key(
    keystore: &dyn DeviceKeystore,
    vault_id: [u8; 32],
    install: [u8; 16],
) -> Result<HybridPublicKey> {
    Ok(machine_secret(keystore, vault_id, install)?
        .public_key()
        .clone())
}

pub(crate) fn keystore_error(e: KeystoreError) -> Error {
    match e {
        KeystoreError::Unavailable(reason) => {
            Error::Secret(SecretError::KeystoreUnavailable(reason))
        }
        KeystoreError::Corrupt(reason) => refused(reason),
        KeystoreError::AlreadyExists => refused("the keystore slot already exists"),
        KeystoreError::Denied => refused("the keystore denied access"),
        KeystoreError::Platform(..) => refused("the keystore failed"),
        KeystoreError::Unsupported(reason) => refused(reason),
    }
}
