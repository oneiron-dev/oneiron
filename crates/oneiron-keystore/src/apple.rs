//! Apple: the data-protection keychain, one generic-password item per slot.
//!
//! - Items are `AfterFirstUnlockThisDeviceOnly`: they are bound to this device's
//!   hardware key, so neither an encrypted backup nor a restore onto another device
//!   carries them.
//! - Items are not synchronizable, so iCloud Keychain never sees them.
//! - The data-protection keychain needs a signed app with a keychain access group.
//!   An unsigned build gets `errSecMissingEntitlement`, which maps to `Unavailable`.
//!   There is no fallback to the legacy file keychain: it is copied by Time Machine.

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
};
use security_framework_sys::item::kSecValueData;
use security_framework_sys::keychain_item::SecItemAdd;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    DeviceKeystore, KeystoreAssurance, KeystoreError, KeystoreLocality, KeystoreSlot, Result,
};

const ERR_SEC_SUCCESS: i32 = 0;
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

impl AppleKeychain {
    /// The slot's item as stored; `None` when the slot is empty.
    pub(crate) fn read_item(&self, slot: &KeystoreSlot) -> Result<Option<Vec<u8>>> {
        match generic_password(self.lookup(slot)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(platform(e.code())),
        }
    }

    /// Create-only, in one `SecItemAdd`: a present item is `errSecDuplicateItem`,
    /// so `AlreadyExists`. The library's set call falls back to an update, and a
    /// check before it races another first use of the slot.
    pub(crate) fn add_item(&self, slot: &KeystoreSlot, data: &[u8]) -> Result<()> {
        let item = self.new_item(slot)?;
        #[expect(
            deprecated,
            reason = "PasswordOptions has no add-only call; its query is the item"
        )]
        let mut attributes = item.query.clone();
        // SAFETY: `kSecValueData` is an immutable CFString the Security framework
        // exports for the life of the process; the get rule retains it.
        let value_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
        attributes.push((value_key, CFData::from_buffer(data).into_CFType()));
        let attributes = CFDictionary::from_CFType_pairs(&attributes);
        // SAFETY: `attributes` is a valid dictionary that outlives the call, and a
        // null result pointer asks for no returned item.
        let status = unsafe { SecItemAdd(attributes.as_concrete_TypeRef(), std::ptr::null_mut()) };
        match status {
            ERR_SEC_SUCCESS => Ok(()),
            other => Err(platform(other)),
        }
    }
}

impl DeviceKeystore for AppleKeychain {
    fn get(&self, slot: &KeystoreSlot) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let Some(mut bytes) = self.read_item(slot)? else {
            return Ok(None);
        };
        let secret = <[u8; 32]>::try_from(bytes.as_slice()).map(Zeroizing::new);
        bytes.zeroize();
        secret
            .map(Some)
            .map_err(|_| KeystoreError::Corrupt("the slot is not 32 bytes"))
    }

    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<()> {
        self.add_item(slot, secret)
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

    fn assurance(&self) -> KeystoreAssurance {
        KeystoreAssurance::Platform
    }
}

pub(crate) fn platform(code: i32) -> KeystoreError {
    match code {
        ERR_SEC_MISSING_ENTITLEMENT => KeystoreError::Unavailable(
            "the data-protection keychain needs a signed app with a keychain access group",
        ),
        ERR_SEC_DUPLICATE_ITEM => KeystoreError::AlreadyExists,
        ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => KeystoreError::Denied,
        other => KeystoreError::Platform("keychain", i64::from(other)),
    }
}
