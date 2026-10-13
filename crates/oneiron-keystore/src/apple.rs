//! Apple: the data-protection keychain, one generic-password item per slot.
//!
//! - Items are `AfterFirstUnlockThisDeviceOnly`: they are bound to this device's
//!   hardware key, so neither an encrypted backup nor a restore onto another device
//!   carries them.
//! - Items are not synchronizable, so iCloud Keychain never sees them.
//! - The data-protection keychain needs a signed app with a keychain access group.
//!   An unsigned build gets `errSecMissingEntitlement`, which maps to `Unavailable`.
//!   There is no fallback to the legacy file keychain: it is copied by Time Machine.

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{DeviceKeystore, KeystoreError, KeystoreLocality, KeystoreSlot, Result};

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// Slots under one keychain service name.
#[derive(Debug)]
pub struct AppleKeychain {
    service: String,
}

impl AppleKeychain {
    pub fn new(service: &str) -> Result<Self> {
        if service.is_empty() {
            return Err(KeystoreError::Unavailable("empty keychain service name"));
        }
        Ok(Self {
            service: service.to_owned(),
        })
    }

    /// The query that finds a slot: this service and account, in the
    /// data-protection keychain, among non-synchronizable items only.
    fn lookup(&self, slot: &KeystoreSlot) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(&self.service, &slot.name());
        options.set_access_synchronized(Some(false));
        options.use_protected_keychain();
        options
    }

    /// The lookup plus the item's protection. Every write goes through here.
    fn new_item(&self, slot: &KeystoreSlot) -> Result<PasswordOptions> {
        let mut options = self.lookup(slot);
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )
        .map_err(|e| platform(e.code()))?;
        options.set_access_control(access);
        Ok(options)
    }
}

impl DeviceKeystore for AppleKeychain {
    fn get(&self, slot: &KeystoreSlot) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let mut bytes = match generic_password(self.lookup(slot)) {
            Ok(bytes) => bytes,
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(None),
            Err(e) => return Err(platform(e.code())),
        };
        let secret = <[u8; 32]>::try_from(bytes.as_slice()).map(Zeroizing::new);
        bytes.zeroize();
        secret
            .map(Some)
            .map_err(|_| KeystoreError::Corrupt("the slot is not 32 bytes"))
    }

    /// Create-only: a present item is `AlreadyExists`. The library call would update it.
    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<()> {
        if self.get(slot)?.is_some() {
            return Err(KeystoreError::AlreadyExists);
        }
        set_generic_password_options(secret, self.new_item(slot)?).map_err(|e| platform(e.code()))
    }

    fn delete(&self, slot: &KeystoreSlot) -> Result<()> {
        match delete_generic_password_options(self.lookup(slot)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(platform(e.code())),
        }
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ThisDeviceOnly
    }
}

fn platform(code: i32) -> KeystoreError {
    match code {
        ERR_SEC_MISSING_ENTITLEMENT => KeystoreError::Unavailable(
            "the data-protection keychain needs a signed app with a keychain access group",
        ),
        ERR_SEC_DUPLICATE_ITEM => KeystoreError::AlreadyExists,
        ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => KeystoreError::Denied,
        other => KeystoreError::Platform("keychain", i64::from(other)),
    }
}
