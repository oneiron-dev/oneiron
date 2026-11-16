//! Apple: the data-protection keychain, one generic-password item per slot.
//!
//! - Items are `AfterFirstUnlockThisDeviceOnly`: they are bound to this device's
//!   hardware key, so neither an encrypted backup nor a restore onto another device
//!   carries them.
//! - Items are not synchronizable, so iCloud Keychain never sees them.
//! - The data-protection keychain needs a signed app with a keychain access group.
//!   An unsigned build gets `errSecMissingEntitlement`, which maps to `Unavailable`.
//!   There is no fallback to the legacy file keychain: it is copied by Time Machine.
//!
//! The same service keeps the bytes the engine sealed under a device PIN
//! ([`SealedBytesStore`]): one item per name, with a slot item's protection,
//! under an account no slot has (`sealed-bytes:<name>`). So a sealed value's
//! item is never read as a slot, nor a slot's item as a sealed value.

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
};
use security_framework_sys::item::kSecValueData;
use security_framework_sys::keychain_item::{SecItemAdd, SecItemUpdate};
use zeroize::{Zeroize, Zeroizing};

use crate::apple_names::{sealed_account, slot_account};
use crate::sealed_bytes::check_sealed_len;
use crate::{
    DeviceKeystore, KeystoreAssurance, KeystoreError, KeystoreLocality, KeystoreSlot, Result,
    SEALED_BYTES_MAX, SealedBytesName, SealedBytesStore,
};

const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// Slots, and the sealed values beside them, under one keychain service name.
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

    /// The query that finds one item: this service and account, in the
    /// data-protection keychain, among non-synchronizable items only.
    fn lookup_account(&self, account: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(&self.service, account);
        options.set_access_synchronized(Some(false));
        options.use_protected_keychain();
        options
    }

    /// The lookup plus the item's protection. Every write goes through here.
    fn new_item_account(&self, account: &str) -> Result<PasswordOptions> {
        let mut options = self.lookup_account(account);
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
        self.read_item_account(&slot_account(slot))
    }

    pub(crate) fn read_item_account(&self, account: &str) -> Result<Option<Vec<u8>>> {
        match generic_password(self.lookup_account(account)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(platform(e.code())),
        }
    }

    /// Create-only, in one `SecItemAdd`: a present item is `errSecDuplicateItem`,
    /// so `AlreadyExists`. The library's set call falls back to an update, and a
    /// check before it races another first use of the slot.
    pub(crate) fn add_item(&self, slot: &KeystoreSlot, data: &[u8]) -> Result<()> {
        self.add_item_account(&slot_account(slot), data)
    }

    pub(crate) fn add_item_account(&self, account: &str, data: &[u8]) -> Result<()> {
        let item = self.new_item_account(account)?;
        #[expect(
            deprecated,
            reason = "PasswordOptions has no add-only call; its query is the item"
        )]
        let mut attributes = item.query;
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

    /// Update-only, in one `SecItemUpdate` over the slot's lookup: the item
    /// keeps its protection and attributes and only its data changes, so a
    /// reader sees the old bytes or the new ones. An absent item is
    /// `Ok(false)` and nothing is created.
    pub(crate) fn update_item(&self, slot: &KeystoreSlot, data: &[u8]) -> Result<bool> {
        self.update_item_account(&slot_account(slot), data)
    }

    fn update_item_account(&self, account: &str, data: &[u8]) -> Result<bool> {
        let lookup = self.lookup_account(account);
        #[expect(
            deprecated,
            reason = "PasswordOptions has no update call; its query is the item"
        )]
        let query = lookup.query;
        let query = CFDictionary::from_CFType_pairs(&query);
        // SAFETY: `kSecValueData` is an immutable CFString the Security framework
        // exports for the life of the process; the get rule retains it.
        let value_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
        let update = CFDictionary::from_CFType_pairs(&[(
            value_key,
            CFData::from_buffer(data).into_CFType(),
        )]);
        // SAFETY: `query` and `update` are valid dictionaries that outlive the call.
        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) };
        match status {
            ERR_SEC_SUCCESS => Ok(true),
            ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            other => Err(platform(other)),
        }
    }

    /// Removes the item under `account`. None there is not an error.
    fn delete_item_account(&self, account: &str) -> Result<()> {
        match delete_generic_password_options(self.lookup_account(account)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(platform(e.code())),
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
        self.delete_item_account(&slot_account(slot))
    }

    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<bool> {
        self.update_item(slot, secret)
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ThisDeviceOnly
    }

    fn assurance(&self) -> KeystoreAssurance {
        KeystoreAssurance::Platform
    }

    fn sealed_bytes(&self) -> Option<&dyn SealedBytesStore> {
        Some(self)
    }
}

impl SealedBytesStore for AppleKeychain {
    fn get_sealed(&self, name: &SealedBytesName) -> Result<Option<Vec<u8>>> {
        let Some(sealed) = self.read_item_account(&sealed_account(name))? else {
            return Ok(None);
        };
        if sealed.is_empty() || sealed.len() > SEALED_BYTES_MAX {
            return Err(KeystoreError::Corrupt(
                "the sealed item is empty or longer than a home keeps",
            ));
        }
        Ok(Some(sealed))
    }

    /// The keychain has no one call that keeps a value whether or not one is
    /// there, so this takes the two it has, and neither removes anything:
    /// one `SecItemUpdate` changes the data of an item that is there, so a
    /// reader sees the old value or the new one; where there is none, one
    /// `SecItemAdd` makes the item. Another writer of the same name may add
    /// its item between the two. The add then answers a duplicate and makes
    /// nothing, and one more update changes the item that writer made.
    fn put_sealed(&self, name: &SealedBytesName, sealed: &[u8]) -> Result<()> {
        check_sealed_len(sealed)?;
        let account = sealed_account(name);
        if self.update_item_account(&account, sealed)? {
            return Ok(());
        }
        let added = self.add_item_account(&account, sealed);
        if added != Err(KeystoreError::AlreadyExists) {
            return added;
        }
        if self.update_item_account(&account, sealed)? {
            return Ok(());
        }
        // Other writers added the item and removed it again inside this one
        // call. Nothing of this put is kept, and the answer says so.
        Err(platform(ERR_SEC_ITEM_NOT_FOUND))
    }

    fn delete_sealed(&self, name: &SealedBytesName) -> Result<()> {
        self.delete_item_account(&sealed_account(name))
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
