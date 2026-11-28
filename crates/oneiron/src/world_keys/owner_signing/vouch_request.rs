//! The new device's half of an owner key vouching for its key (pass 27 R2):
//! the request an owner device answers
//! ([`Vault::enrol_vouched_owner_signing_key`]), made with this install's
//! owner signing key where it rests: in its keystore slot, or, on a device
//! with a PIN set, under the device PIN inside the window a right PIN opened
//! (row OWNER-KEY-VOUCH-REQUEST-ON-PIN-DEVICE).

use super::*;
use crate::authority::{
    DeviceOwnerKeyVouch, OwnerKeyVouchRequest, label_is_valid, label_not_valid,
};
use crate::world_keys::device_pin::PinBoundOwnerKey;
use crate::world_keys::keystore_error;

impl Vault {
    /// The new device's half of an owner key vouching for its key (pass 27
    /// R2): this install's owner signing key, made on first use, signs its
    /// challenge for this install's machine and the owner `authority`
    /// proves, this install's own key signs the request, and the request to
    /// hand an owner device comes back
    /// ([`Vault::enrol_vouched_owner_signing_key`] runs there). It writes no
    /// authority row and needs no owner key of its own; it makes the key's
    /// seed, and readying this install's signing identity may run work
    /// already waiting for it. `label` names this device for the owner to
    /// recognise. Once a vouch put the key on the roster and this vault took
    /// that row (sync), it answers the enrollment's receipt and this handle
    /// holds the key. A key the roster revoked gives its place to a fresh
    /// key, whose request comes back.
    ///
    /// On a device with no PIN set the key rests in its keystore slot. On a
    /// device with a PIN set it is made and kept under the PIN, as an
    /// enrollment's key is ([`Vault::enrol_device_owner_signing_key`]), so
    /// the request needs the window a right PIN opened, and it is one step
    /// with a PIN's set, change and forget. A key asked for before the PIN
    /// was set went under the PIN with its seed, and answers here once a
    /// vouch enrolled it (row OWNER-KEY-VOUCH-REQUEST-ON-PIN-DEVICE).
    ///
    /// # Errors
    /// [`crate::error::RecordError::InvalidAuthorityLogBody`] for a label over
    /// [`crate::authority::OWNER_KEY_VOUCH_LABEL_MAX`] bytes or with a control
    /// or invisible format character; `KeystoreUnavailable` while the host
    /// installed no keystore; an agent's act refused, before anything is
    /// readied; an owner refusal when the proof is no longer the vault's live
    /// owner. On a device with a PIN set,
    /// [`crate::error::SecretError::DevicePin`]: `Required` outside a window,
    /// and `Unavailable` where the host installed no device PIN on this
    /// handle. [`crate::error::DevicePinRefusal::NotSet`] on a device whose
    /// PIN was forgotten and that has none now: the owner sets a new PIN
    /// first.
    pub fn device_owner_key_vouch_request(
        &self,
        authority: &ActAuthority,
        label: &str,
    ) -> Result<DeviceOwnerKeyVouch> {
        if !label_is_valid(label) {
            return Err(label_not_valid());
        }
        // The caller is checked first, before this install readies anything.
        self.owner_key_act_owner(authority)?;
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        // The key's seed is made here, so this is one step with a PIN's set,
        // as [`Vault::device_owner_signing_key`] is; under a set PIN the step
        // covers the whole request.
        let pin = self.device_pin();
        let step = pin.as_deref().map(DevicePin::step);
        let (machine, public_key, proof) = if device_pin_is_set(keystore.as_ref())
            .map_err(keystore_error)?
        {
            let (Some(pin), Some(step)) = (pin.as_ref(), step.as_ref()) else {
                return Err(no_device_pin_here());
            };
            match self.pin_bound_owner_key_for_enrollment(step, pin, authority, machine, slot)? {
                PinBoundOwnerKey::Live(receipt) => {
                    return Ok(DeviceOwnerKeyVouch::Enrolled(receipt));
                }
                PinBoundOwnerKey::Unenrolled { public_key, proof } => (machine, public_key, proof),
            }
        } else {
            match self.device_owner_key_for_enrollment(authority, machine, &keystore, slot)? {
                DeviceOwnerKey::Live { signer, receipt } => {
                    self.hold_checkpoint_root_signer(Arc::new(signer));
                    return Ok(DeviceOwnerKeyVouch::Enrolled(receipt));
                }
                DeviceOwnerKey::Unenrolled {
                    signer,
                    machine,
                    challenge,
                } => (
                    machine,
                    signer.public_key(),
                    signer.sign_possession(&challenge),
                ),
            }
        };
        let mut request = OwnerKeyVouchRequest {
            vault_id: self.authority_vault_id()?.ok_or_else(invalid_authority)?,
            machine,
            public_key,
            proof,
            machine_proof: Vec::new(),
            label: label.to_owned(),
        };
        request.machine_proof =
            self.install_key_signature(machine, &request.machine_transcript()?)?;
        Ok(DeviceOwnerKeyVouch::Request(request))
    }

    /// The signature of this install's own key, the install key of
    /// `machine`, over `transcript`.
    ///
    /// # Errors
    /// [`crate::authority::invalid_authority`] when this install's machine
    /// is no longer `machine` or holds no install key; the store's own.
    fn install_key_signature(&self, machine: EntityId, transcript: &[u8]) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        if crate::identity::read_machine_id_in_txn(self, &txn)? != Some(machine) {
            return Err(invalid_authority());
        }
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .ok_or_else(invalid_authority)?;
        Ok(key.sign(transcript).to_bytes().to_vec())
    }
}
