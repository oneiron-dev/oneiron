//! Sets the first device PIN, moving an owner seed out of its slot when
//! one rests there. Undoes a failed set only when the seed is safe.

use oneiron_keystore::{DeviceKeystore, KeystoreSlot};
use zeroize::Zeroizing;

use super::super::secret_seal::seal_slot_secret;
use super::super::{DevicePin, DevicePinStep, device_pin_was_forgotten};
use super::{SEAL_NOT_READ_BACK, open_owner_seed};
use crate::error::Result;
use crate::world_keys::owner_signing::OwnerRootSigner;
use crate::world_keys::{keystore_error, os_fill, refused};

/// The first PIN of a device, for the vault whose owner slot is `slot`: one
/// step, in the order that never leaves the device with a PIN set and no
/// sealed copy of the seed.
/// 1. The seed in the slot, when one rests there, is sealed under the new
///    device PIN key and read back ([`stage_slot_owner_seed`]).
/// 2. The device PIN key is stored under `typed`, and a window opens with
///    the key its home gave back ([`DevicePin::store_first_key`]).
/// 3. The slot is emptied.
///
/// A refusal is undone by [`undo_first_pin`], which removes the sealed seed
/// only while the seed is seen in its slot. A keystore may answer an error
/// for a delete that did remove the seed, so after a refused step 3 the slot
/// is read: a seed that left it means the step is whole.
pub(super) fn set_first_pin(
    step: &DevicePinStep<'_>,
    pin: &DevicePin,
    keystore: &dyn DeviceKeystore,
    slot: &KeystoreSlot,
    typed: &[u8],
) -> Result<()> {
    let mut pin_key = Zeroizing::new([0u8; 32]);
    os_fill(&mut pin_key[..])?;
    let staged = match stage_slot_owner_seed(pin, keystore, slot, &pin_key) {
        Ok(staged) => staged,
        Err(refusal) => {
            // No PIN is set, so nothing opens what the stage left sealed.
            let _removed = pin.delete_sealed_slot(slot);
            return Err(refusal);
        }
    };
    if let Err(refusal) = pin.store_first_key(step, typed, &pin_key) {
        undo_first_pin(step, pin, keystore, slot, staged.as_deref());
        return Err(refusal);
    }
    if staged.is_none() {
        return Ok(());
    }
    let Err(refusal) = DeviceKeystore::delete(keystore, slot) else {
        return Ok(());
    };
    match keystore.get(slot) {
        Ok(None) => {
            tracing::warn!(
                "the owner signing slot was emptied for the device PIN, and its keystore \
                 answered a failure after it"
            );
            Ok(())
        }
        Ok(Some(_)) => {
            undo_first_pin(step, pin, keystore, slot, staged.as_deref());
            Err(keystore_error(refusal))
        }
        // The slot does not answer: the PIN stays set and the sealed seed
        // stays, so nothing is lost whatever the slot holds.
        Err(_) => Err(keystore_error(refusal)),
    }
}

/// Undoes a first PIN that did not finish: removes the device PIN key, and
/// then the seed staged under it. `staged` is the seed step 1 sealed, when
/// it sealed one. Nothing is removed unless that seed is seen in its slot,
/// and the sealed seed stays when the device PIN key cannot be removed: the
/// sealed copy is never removed while it may be the only one, or while a
/// device PIN key that opens it may rest. What is left then is the state the
/// module notes describe: a PIN set, the seed under it, and a copy in the
/// slot that signs nothing.
fn undo_first_pin(
    step: &DevicePinStep<'_>,
    pin: &DevicePin,
    keystore: &dyn DeviceKeystore,
    slot: &KeystoreSlot,
    staged: Option<&[u8; 32]>,
) {
    if let Some(staged) = staged {
        let in_slot = keystore.get(slot).ok().flatten();
        if in_slot.as_deref() != Some(staged) {
            tracing::warn!(
                "a first device PIN did not finish and its owner signing seed is not seen in \
                 its slot; the sealed seed is kept"
            );
            return;
        }
    }
    if pin.remove_pin_key(step).is_err() {
        tracing::warn!(
            "a first device PIN did not finish and its device PIN key could not be removed; \
             the sealed owner signing seed is kept"
        );
        return;
    }
    let _removed = pin.delete_sealed_slot(slot);
}

/// Step 1 of [`set_first_pin`], before any PIN is set: seals the seed in
/// `slot` under `pin_key`, the device PIN key about to be stored, and reads
/// it back. Answers the seed it sealed; `None` when no seed rests in the
/// slot, and then sealed bytes left under `slot`'s name are removed: no
/// device PIN key opens them. On a device that forgot a PIN, a seed left in
/// the slot is no key ([`SlotSeedBar::PinForgotten`]): it is removed first,
/// never sealed.
///
/// [`SlotSeedBar::PinForgotten`]: super::super::SlotSeedBar::PinForgotten
fn stage_slot_owner_seed(
    pin: &DevicePin,
    keystore: &dyn DeviceKeystore,
    slot: &KeystoreSlot,
    pin_key: &[u8; 32],
) -> Result<Option<Zeroizing<[u8; 32]>>> {
    if device_pin_was_forgotten(keystore).map_err(keystore_error)? {
        DeviceKeystore::delete(keystore, slot).map_err(keystore_error)?;
    }
    let Some(seed) = keystore.get(slot).map_err(keystore_error)? else {
        pin.delete_sealed_slot(slot)?;
        return Ok(None);
    };
    let public_key = OwnerRootSigner::from_seed(&seed).public_key();
    let sealed = seal_slot_secret(pin_key, slot, &public_key, &seed)?;
    pin.put_sealed_slot(slot, &sealed)?;
    let read_back = pin
        .sealed_slot(slot)?
        .and_then(|rests| open_owner_seed(pin_key, slot, &rests));
    if read_back.as_ref().map(|rests| &*rests.seed) != Some(&*seed) {
        return Err(refused(SEAL_NOT_READ_BACK));
    }
    Ok(Some(seed))
}
