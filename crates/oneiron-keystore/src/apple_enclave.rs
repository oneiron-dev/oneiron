//! Apple, hardware tier: each slot's secret sealed to a P-256 key the Secure
//! Enclave made and holds (ECIES: cofactor X9.63 SHA-256, AES-GCM), the sealed
//! bytes kept as a data-protection keychain item like the platform tier's. The
//! private key never leaves the enclave, so the stored bytes open only here,
//! through it (OF-168).
//!
//! - One enclave key per keychain service, found by its label and made on first
//!   use: `AfterFirstUnlockThisDeviceOnly`, usable for private-key operations
//!   only. An enclave key never synchronizes; it cannot leave the enclave.
//! - Its items sit under the service name with `.enclave` appended, apart from
//!   the platform tier's. Switching tiers reads nothing the other tier wrote: the
//!   install starts empty slots, as a new machine does.
//! - Like the platform tier it needs a signed app with a keychain access group;
//!   an unsigned build gets `Unavailable`.

use std::sync::OnceLock;

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{ItemSearchOptions, KeyClass, Location, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
use zeroize::{Zeroize, Zeroizing};

use crate::apple::{AppleKeychain, platform};
use crate::{
    DeviceKeystore, KeystoreAssurance, KeystoreError, KeystoreLocality, KeystoreSlot, Result,
};

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const SEAL: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

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

    /// The enclave key: found by its label, or made in the enclave on first use.
    fn enclave_key(&self) -> Result<SecKey> {
        if let Some(key) = self.key.get() {
            return Ok(key.clone());
        }
        let key = match self.find_key()? {
            Some(key) => key,
            None => self.make_key()?,
        };
        Ok(self.key.get_or_init(|| key).clone())
    }

    fn find_key(&self) -> Result<Option<SecKey>> {
        let mut search = ItemSearchOptions::new();
        search
            .key_class(KeyClass::private())
            .label(&self.key_label)
            .load_refs(true);
        #[cfg(target_os = "macos")]
        search.ignore_legacy_keychains();
        match search.search() {
            Ok(found) => Ok(found.into_iter().find_map(|result| match result {
                SearchResult::Ref(Reference::Key(key)) => Some(key),
                _ => None,
            })),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(platform(e.code())),
        }
    }

    fn make_key(&self) -> Result<SecKey> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage,
        )
        .map_err(|e| platform(e.code()))?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_label(self.key_label.clone())
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(access);
        SecKey::new(&options).map_err(|e| enclave(e.code()))
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
        let public = self
            .enclave_key()?
            .public_key()
            .ok_or(KeystoreError::Corrupt("the enclave key has no public half"))?;
        let sealed = public
            .encrypt_data(SEAL, secret)
            .map_err(|e| enclave(e.code()))?;
        self.items.add_item(slot, &sealed)
    }

    fn delete(&self, slot: &KeystoreSlot) -> Result<()> {
        self.items.delete(slot)
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
