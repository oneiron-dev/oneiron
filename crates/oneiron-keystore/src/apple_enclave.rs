//! Apple, hardware tier: each slot's secret sealed to a P-256 key the Secure
//! Enclave made and holds (ECIES: cofactor X9.63 SHA-256, AES-GCM), the sealed
//! bytes kept as a data-protection keychain item like the platform tier's. The
//! private key never leaves the enclave, so the stored bytes open only here,
//! through it (OF-168).
//!
//! - One enclave key per keychain service, selected on first use by an immutable
//!   keychain record containing its OS application label. Every caller resolves
//!   that exact key before using it: `AfterFirstUnlockThisDeviceOnly`, usable for
//!   private-key operations only. It cannot synchronize or leave the enclave.
//! - Its items sit under the service name with `.enclave` appended, apart from
//!   the platform tier's. Switching tiers reads nothing the other tier wrote: the
//!   install starts empty slots, as a new machine does.
//! - Like the platform tier it needs a signed app with a keychain access group;
//!   an unsigned build gets `Unavailable`.

use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "macos")]
use core_foundation::array::CFArray;
use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
#[cfg(target_os = "macos")]
use core_foundation::string::CFStringRef;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{ItemSearchOptions, KeyClass, Reference, SearchResult};
use security_framework::key::{Algorithm, SecKey};
use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
#[cfg(not(target_os = "macos"))]
use security_framework_sys::item::kSecValueRef;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs, kSecUseDataProtectionKeychain,
};
use security_framework_sys::keychain_item::SecItemDelete;
use zeroize::{Zeroize, Zeroizing};

use crate::apple::{AppleKeychain, platform};
use crate::{
    DeviceKeystore, KeystoreAssurance, KeystoreError, KeystoreLocality, KeystoreSlot, Result,
};

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const SEAL: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
// Slot accounts always start with the vault and install hex ids, unlike this account.
const SELECTOR_ACCOUNT: &str = "enclave-key-selector.v1";
static KEY_SELECTION: Mutex<()> = Mutex::new(());

#[cfg(target_os = "macos")]
unsafe extern "C" {
    // Security/SecItem.h exports this CFString; sys 2.17 does not bind it.
    static kSecMatchItemList: CFStringRef;
}

/// Slots sealed to this service's enclave key.
pub struct SecureEnclaveKeychain {
    items: AppleKeychain,
    key_label: String,
    key: OnceLock<SecKey>,
}

impl std::fmt::Debug for SecureEnclaveKeychain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureEnclaveKeychain")
            .field("key_label", &self.key_label)
            .finish_non_exhaustive()
    }
}

impl SecureEnclaveKeychain {
    pub fn new(service: &str) -> Result<Self> {
        if service.is_empty() {
            return Err(KeystoreError::Unavailable("empty keychain service name"));
        }
        Ok(Self {
            items: AppleKeychain::new(&format!("{service}.enclave"))?,
            key_label: format!("{service}.enclave-key"),
            key: OnceLock::new(),
        })
    }

    /// Resolve the stored winner before caching it; never seal with a candidate.
    fn enclave_key(&self) -> Result<SecKey> {
        if let Some(key) = self.key.get() {
            return Ok(key.clone());
        }
        // The lock protects no Rust state. After a panic, reread the OS record.
        let _selection = KEY_SELECTION.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = self.key.get() {
            return Ok(key.clone());
        }
        let key = self.select_key()?;
        Ok(self.key.get_or_init(|| key).clone())
    }

    fn select_key(&self) -> Result<SecKey> {
        if let Some(winner) = self.items.read_item_account(SELECTOR_ACCOUNT)? {
            return self.resolve_key(&winner);
        }
        let candidate = self.make_key()?;
        let Some(identity) = candidate.application_label() else {
            self.delete_unidentified_candidate(&candidate)?;
            return Err(KeystoreError::Corrupt(
                "the new enclave key has no application label",
            ));
        };
        // SecItemAdd selects one immutable winner across processes. Even its
        // successful writer rereads it rather than using the local candidate.
        let added = match self.items.add_item_account(SELECTOR_ACCOUNT, &identity) {
            Ok(()) | Err(KeystoreError::AlreadyExists) => Ok(()),
            Err(error) => Err(error),
        };
        let winner = match self.items.read_item_account(SELECTOR_ACCOUNT) {
            Ok(Some(winner)) => winner,
            Ok(None) => {
                if added.is_err() {
                    // The add failed and no selector names this fresh key.
                    self.delete_candidate(&identity)?;
                }
                added?;
                return Err(KeystoreError::Corrupt(
                    "the enclave key selector is missing",
                ));
            }
            Err(error) => {
                // Selection is unknown: keep the candidate rather than risk
                // deleting a winner that another process may already use.
                added?;
                return Err(error);
            }
        };
        if identity != winner {
            self.delete_candidate(&identity)?;
        }
        added?;
        self.resolve_key(&winner)
    }

    fn key_query(&self, identity: &[u8]) -> ItemSearchOptions {
        let mut search = ItemSearchOptions::new();
        search
            .key_class(KeyClass::private())
            .label(&self.key_label)
            .application_label(identity);
        #[cfg(target_os = "macos")]
        search.ignore_legacy_keychains();
        search
    }

    fn resolve_key(&self, identity: &[u8]) -> Result<SecKey> {
        let mut search = self.key_query(identity);
        search.load_refs(true);
        let key = match search.search() {
            Ok(found) => found.into_iter().find_map(|result| match result {
                SearchResult::Ref(Reference::Key(key)) => Some(key),
                _ => None,
            }),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => None,
            Err(e) => return Err(platform(e.code())),
        };
        key.ok_or(KeystoreError::Corrupt(
            "the selected enclave key is missing",
        ))
    }

    /// Only a fresh candidate known not to be the selector's winner.
    fn delete_candidate(&self, identity: &[u8]) -> Result<()> {
        match self.key_query(identity).delete() {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(platform(e.code())),
        }
    }

    /// A fresh key with no usable identity has never been offered to the selector.
    fn delete_unidentified_candidate(&self, candidate: &SecKey) -> Result<()> {
        // SAFETY: Security exports immutable CFString constants for the life of
        // the process; the get rule retains them. The array/dictionary retain
        // this exact fresh candidate, and every value outlives SecItemDelete.
        let query = unsafe {
            #[cfg(target_os = "macos")]
            let candidate_pair = (
                CFString::wrap_under_get_rule(kSecMatchItemList),
                CFArray::from_CFTypes(std::slice::from_ref(candidate)).into_CFType(),
            );
            #[cfg(not(target_os = "macos"))]
            let candidate_pair = (
                CFString::wrap_under_get_rule(kSecValueRef),
                candidate.as_CFType(),
            );
            CFDictionary::from_CFType_pairs(&[
                candidate_pair,
                (
                    CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                    CFBoolean::true_value().into_CFType(),
                ),
            ])
        };
        // SAFETY: `query` is an owned dictionary identifying only `candidate`
        // by reference, using SecItem.h's platform-specific deletion form.
        match unsafe { SecItemDelete(query.as_concrete_TypeRef()) } {
            0 | ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            status => Err(platform(status)),
        }
    }

    fn make_key(&self) -> Result<SecKey> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage,
        )
        .map_err(|e| platform(e.code()))?;
        // SAFETY: These are immutable Security CFString exports. The get rule
        // retains them, and the owned dictionary retains every attribute value.
        let private = unsafe {
            CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecAttrIsPermanent),
                    CFBoolean::true_value().into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccessControl),
                    access.into_CFType(),
                ),
            ])
        };
        // Emit private persistence/access control on every Apple target: pinned
        // GenerateKeyOptions only includes its private-attributes dict on macOS.
        // SAFETY: The exported strings are valid for the process lifetime. All
        // values are owned CF objects retained by the dictionary through generate.
        let attributes = unsafe {
            CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyType),
                    CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                    CFNumber::from(256_i32).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrLabel),
                    CFString::new(&self.key_label).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrTokenID),
                    CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                    CFBoolean::true_value().into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecPrivateKeyAttrs),
                    private.into_CFType(),
                ),
            ])
        };
        #[expect(
            deprecated,
            reason = "GenerateKeyOptions drops private-key attributes on non-macOS Apple targets"
        )]
        let key = SecKey::generate(attributes.into_untyped());
        key.map_err(|e| enclave(e.code()))
    }

    /// `secret` sealed to the enclave key's public half.
    fn seal(&self, secret: &[u8; 32]) -> Result<Vec<u8>> {
        let public = self
            .enclave_key()?
            .public_key()
            .ok_or(KeystoreError::Corrupt("the enclave key has no public half"))?;
        public
            .encrypt_data(SEAL, secret)
            .map_err(|e| enclave(e.code()))
    }
}

impl DeviceKeystore for SecureEnclaveKeychain {
    fn get(&self, slot: &KeystoreSlot) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let Some(sealed) = self.items.read_item(slot)? else {
            return Ok(None);
        };
        let mut opened = self
            .enclave_key()?
            .decrypt_data(SEAL, &sealed)
            .map_err(|_| KeystoreError::Corrupt("the slot does not open with this enclave key"))?;
        let secret = <[u8; 32]>::try_from(opened.as_slice()).map(Zeroizing::new);
        opened.zeroize();
        secret
            .map(Some)
            .map_err(|_| KeystoreError::Corrupt("the slot is not 32 bytes"))
    }

    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<()> {
        let sealed = self.seal(secret)?;
        self.items.add_item(slot, &sealed)
    }

    fn delete(&self, slot: &KeystoreSlot) -> Result<()> {
        self.items.delete(slot)
    }

    /// Sealed to the same enclave key, then the item's data updated in place.
    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<bool> {
        let sealed = self.seal(secret)?;
        self.items.update_item(slot, &sealed)
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ThisDeviceOnly
    }

    fn assurance(&self) -> KeystoreAssurance {
        KeystoreAssurance::Hardware
    }
}

/// A `CFError` from a key operation, by its code: the keychain's own codes keep
/// their meaning, an unsigned build among them.
fn enclave(code: isize) -> KeystoreError {
    match i32::try_from(code) {
        Ok(code) => platform(code),
        Err(_) => KeystoreError::Platform("secure enclave", i64::MIN),
    }
}
