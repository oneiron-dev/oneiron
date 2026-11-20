//! The device PIN's presence backend. It checks typed PINs and keeps the
//! device PIN key while the gate's window is open.

use std::sync::{MutexGuard, PoisonError};

use oneiron_keystore::{
    AuthBoundError, PresenceCapability, PresenceError, SealedBytesName, UserPresence,
};
use zeroize::Zeroizing;

use super::super::keystore_error;
use super::secret_seal::{auth_value, open_pin_key_envelope, seal_pin_key_envelope};
use super::{
    DevicePinBackend, HeldPinKey, NO_PIN_HOME, NO_PIN_SET, PIN_HOME_UNREADABLE, device_pin_is_set,
    pin_refused,
};
use crate::error::{DevicePinRefusal, Result};

impl DevicePinBackend {
    pub(super) fn held_key(&self) -> MutexGuard<'_, HeldPinKey> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes the key a typed PIN opened the one a use reads: the gate took
    /// that PIN's window. It does nothing where that window ended since,
    /// which wiped the key.
    pub(super) fn admit_checked_key(&self) {
        let mut held = self.held_key();
        if let Some(key) = held.checked.take() {
            held.open = Some(key);
        }
    }

    /// Wipes the key a typed PIN opened, where the gate took no window for
    /// that PIN.
    pub(super) fn drop_checked_key(&self) {
        self.held_key().checked = None;
    }

    /// The device PIN key, opened from its home with `pin`.
    fn open_pin_key(&self, pin: &[u8]) -> std::result::Result<Zeroizing<[u8; 32]>, PresenceError> {
        if let Some(hardware) = self.keystore.auth_bound_secret() {
            let auth = auth_value(pin);
            return match hardware.open_auth_bound(&auth[..]) {
                Ok(Some(key)) => Ok(key),
                Ok(None) => Err(PresenceError::NoPrompt(NO_PIN_SET)),
                Err(AuthBoundError::WrongAuth) => Err(PresenceError::WrongPin),
                Err(AuthBoundError::LockedOut { wait_secs }) => {
                    Err(PresenceError::TooManyTries { wait_secs })
                }
                Err(AuthBoundError::Keystore(_)) => {
                    Err(PresenceError::Platform(PIN_HOME_UNREADABLE, 0))
                }
            };
        }
        let home = self
            .keystore
            .sealed_bytes()
            .ok_or(PresenceError::NoPrompt(NO_PIN_HOME))?;
        let sealed = home
            .get_sealed(&SealedBytesName::DevicePinKey)
            .map_err(|_| PresenceError::Platform(PIN_HOME_UNREADABLE, 0))?
            .ok_or(PresenceError::NoPrompt(NO_PIN_SET))?;
        // An envelope that does not open is a wrong PIN: the two are not
        // told apart.
        open_pin_key_envelope(&sealed, pin).ok_or(PresenceError::WrongPin)
    }

    /// Puts `key` to rest under `pin`, in place of any key there, in one
    /// step of its home.
    pub(super) fn store_pin_key(&self, pin: &[u8], key: &[u8; 32]) -> Result<()> {
        if let Some(hardware) = self.keystore.auth_bound_secret() {
            let auth = auth_value(pin);
            return hardware
                .put_auth_bound(&auth[..], key)
                .map_err(keystore_error);
        }
        let home = self
            .keystore
            .sealed_bytes()
            .ok_or_else(|| pin_refused(DevicePinRefusal::Unavailable(NO_PIN_HOME)))?;
        let sealed = seal_pin_key_envelope(key, pin, self.cost)?;
        home.put_sealed(&SealedBytesName::DevicePinKey, &sealed)
            .map_err(keystore_error)
    }
}

impl UserPresence for DevicePinBackend {
    fn capability(&self) -> PresenceCapability {
        if self.keystore.sealed_bytes().is_none() {
            return PresenceCapability::NoPrompt(NO_PIN_HOME);
        }
        match device_pin_is_set(self.keystore.as_ref()) {
            Ok(set) => PresenceCapability::DevicePin { set },
            Err(_) => PresenceCapability::NoPrompt(PIN_HOME_UNREADABLE),
        }
    }

    /// A device PIN has no prompt to show: the host collects the PIN.
    fn confirm(&self, _reason: &str) -> std::result::Result<(), PresenceError> {
        match self.capability() {
            PresenceCapability::DevicePin { set: true } => Err(PresenceError::PinRequired),
            PresenceCapability::DevicePin { set: false } => {
                Err(PresenceError::NoPrompt(NO_PIN_SET))
            }
            PresenceCapability::DevicePrompt => Err(PresenceError::NoPrompt(NO_PIN_HOME)),
            PresenceCapability::NoPrompt(reason) => Err(PresenceError::NoPrompt(reason)),
        }
    }

    fn confirm_with_secret(&self, secret: &[u8]) -> std::result::Result<(), PresenceError> {
        // The key is opened outside its lock: the stretch may take a second.
        // No use reads it yet: the gate has not taken this PIN's window
        // ([`DevicePinBackend::admit_checked_key`]).
        let key = self.open_pin_key(secret)?;
        self.held_key().checked = Some(key);
        Ok(())
    }

    /// Wipes the device PIN key, and one a typed PIN opened that no window
    /// was taken for. It takes one short lock and never calls the gate.
    fn window_ended(&self) {
        *self.held_key() = HeldPinKey::default();
    }
}
