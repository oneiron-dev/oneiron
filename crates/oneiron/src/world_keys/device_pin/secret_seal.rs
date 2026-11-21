//! Seals and opens the device PIN key and the slot secrets it protects.
//! Also derives the PIN's auth value for keystores that count wrong tries.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Passphrase, Purpose, SealKey, SealParams,
    SuiteId, WrapType, seal, seal_with_aad,
};
use oneiron_keystore::KeystoreSlot;
use zeroize::Zeroizing;

use super::super::{derive_guarded, refused};
use crate::error::Result;
use crate::recovery::PassphraseCost;

const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const DEVICE_PIN_EPOCH: u64 = 1;

/// The context the hardware's auth value is derived under from the PIN.
const AUTH_VALUE_CONTEXT: &str = "oneiron/device-pin-auth-value/v1";

// The ids the device PIN key's envelope is bound to. The key belongs to the
// device and to no vault, so they are constants.
const PIN_KEY_SCOPE: &[u8] = b"oneiron/this-device";
const PIN_KEY_RECIPIENT: &[u8] = b"oneiron/device-pin";
const PIN_KEY_ID: &[u8] = b"oneiron/device-pin-key/v1";

/// The auth value the keystore's hardware compares: 32 bytes derived from
/// the PIN under a context of their own, so the hardware never holds the PIN
/// itself.
pub(super) fn auth_value(pin: &[u8]) -> Zeroizing<[u8; 32]> {
    derive_guarded(AUTH_VALUE_CONTEXT, &[pin])
}

/// The device PIN key sealed under `pin` as a passphrase, at `cost`, stepping
/// down toward the kit's floor while the device cannot give the memory. The
/// envelope's header records the cost in force.
pub(super) fn seal_pin_key_envelope(
    key: &[u8; 32],
    pin: &[u8],
    mut cost: PassphraseCost,
) -> Result<Vec<u8>> {
    let passphrase = Passphrase::new(pin)
        .map_err(|_| refused("the device PIN is not a passphrase an envelope takes"))?;
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::DevicePinKey,
        epoch: DEVICE_PIN_EPOCH,
        key_id: PIN_KEY_ID,
        recipient: PIN_KEY_RECIPIENT,
        vault_id: PIN_KEY_SCOPE,
    };
    loop {
        let seal_key = SealKey::Passphrase {
            passphrase: &passphrase,
            cost: cost.argon2(),
        };
        match seal(&params, seal_key, &key[..], &mut SysRng) {
            Ok(envelope) => return Ok(envelope.to_bytes()),
            Err(oneiron_crypto::Error::OutOfMemory)
                if cost.memory_mib > PassphraseCost::FLOOR.memory_mib =>
            {
                cost.memory_mib = (cost.memory_mib / 2).max(PassphraseCost::FLOOR.memory_mib);
            }
            Err(_) => return Err(refused("sealing the device PIN key failed")),
        }
    }
}

/// The device PIN key from its passphrase envelope; `None` for a wrong PIN
/// and for an envelope that does not open. A reader spends at most the
/// kit's ceiling on one try.
pub(super) fn open_pin_key_envelope(sealed: &[u8], pin: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let passphrase = Passphrase::new(pin).ok()?;
    let envelope = Envelope::parse(sealed).ok()?;
    let policy = OpenPolicy {
        purpose: Purpose::DevicePinKey,
        vault_id: PIN_KEY_SCOPE,
        recipient: PIN_KEY_RECIPIENT,
        key_id: PIN_KEY_ID,
        wraps: &[WrapType::Passphrase],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: DEVICE_PIN_EPOCH,
        argon2_max: PassphraseCost::CEILING.argon2(),
    };
    let opened = envelope
        .open(OpenKey::Passphrase(&passphrase), &policy)
        .ok()?;
    secret_bytes(&opened)
}

/// One slot's secret sealed under the device PIN key, for exactly `slot`
/// and the public half `public_key`, which the stored envelope shows with no
/// key.
pub(super) fn seal_slot_secret(
    pin_key: &[u8; 32],
    slot: &KeystoreSlot,
    public_key: &[u8; 32],
    secret: &[u8; 32],
) -> Result<Vec<u8>> {
    let kek = Kek::from_bytes_ref(pin_key);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::DevicePinSlotSecret,
        epoch: DEVICE_PIN_EPOCH,
        key_id: public_key,
        recipient: &slot.install,
        vault_id: &slot.vault_id,
    };
    let envelope = seal_with_aad(
        &params,
        SealKey::SymmetricKek(&kek),
        &secret[..],
        slot.name().as_bytes(),
        &mut SysRng,
    )
    .map_err(|_| refused("sealing a slot's secret under the device PIN key failed"))?;
    Ok(envelope.to_bytes())
}

/// The secret of `slot` from `sealed`, opened with the device PIN key;
/// `None` for anything not sealed under that key for exactly `slot` and
/// `public_key`.
pub(super) fn open_slot_secret(
    pin_key: &[u8; 32],
    slot: &KeystoreSlot,
    public_key: &[u8; 32],
    sealed: &[u8],
) -> Option<Zeroizing<[u8; 32]>> {
    let envelope = Envelope::parse(sealed).ok()?;
    let kek = Kek::from_bytes_ref(pin_key);
    let policy = OpenPolicy {
        purpose: Purpose::DevicePinSlotSecret,
        vault_id: &slot.vault_id,
        recipient: &slot.install,
        key_id: public_key,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: DEVICE_PIN_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let opened = envelope
        .open_with_aad(OpenKey::SymmetricKek(&kek), &policy, slot.name().as_bytes())
        .ok()?;
    secret_bytes(&opened)
}

/// The public half a sealed slot secret names, read with no key; `None` for
/// bytes that are no such envelope. It proves nothing until the secret
/// opens.
pub(super) fn sealed_slot_public_key(sealed: &[u8]) -> Option<[u8; 32]> {
    let envelope = Envelope::parse(sealed).ok()?;
    let header = envelope.header();
    if header.purpose != Purpose::DevicePinSlotSecret {
        return None;
    }
    <[u8; 32]>::try_from(header.key_id.as_slice()).ok()
}

/// `opened` as a 32-byte secret in guarded memory; `None` for any other
/// length.
fn secret_bytes(opened: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let mut secret = Zeroizing::new([0u8; 32]);
    if opened.len() != secret.len() {
        return None;
    }
    secret.copy_from_slice(opened);
    Some(secret)
}
