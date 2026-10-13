//! This-device-only key slots for one install.
//!
//! A slot holds one 32-byte secret that must never leave the machine. It must not
//! reach a synced keychain, an OS backup, a vault checkpoint or sync. The engine
//! keeps exactly one secret here: the seed of this machine's hybrid encryption key,
//! which opens the world keys wrapped to this machine. Losing a slot loses nothing
//! else. Another of the owner's machines, or the recovery kit, wraps the keys
//! again for a new seed.
//!
//! Adapters:
//! - Apple: [`AppleKeychain`], the data-protection keychain, with the attributes
//!   `AfterFirstUnlockThisDeviceOnly` and not synchronizable.
//! - Other Unix: [`LocalFileKeystore`], 0600 files in a 0700 directory outside the
//!   vault, tagged so that backup tools skip it.
//! - Windows has no adapter yet: [`platform_keystore`] returns `Unavailable` there.

use zeroize::Zeroizing;

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(all(unix, not(target_vendor = "apple")))]
mod file;
mod memory;

#[cfg(target_vendor = "apple")]
pub use apple::AppleKeychain;
#[cfg(all(unix, not(target_vendor = "apple")))]
pub use file::LocalFileKeystore;
pub use memory::MemoryKeystore;

/// What a slot holds. One variant per secret the engine keeps at rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SlotKind {
    /// The seed of this machine's hybrid encryption key for one vault.
    MachineEncryption,
}

impl SlotKind {
    /// Stable name in the backend: part of the keychain account or the file name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MachineEncryption => "machine-encryption",
        }
    }
}

/// One slot: a vault and what the secret is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeystoreSlot {
    pub vault_id: [u8; 32],
    pub kind: SlotKind,
}

impl KeystoreSlot {
    /// `<vault id hex>.<kind>`: the backend's name for the slot. It carries no secret.
    #[must_use]
    pub fn name(&self) -> String {
        let mut name = String::with_capacity(64 + 1 + self.kind.label().len());
        for byte in self.vault_id {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        name.push('.');
        name.push_str(self.kind.label());
        name
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Where a backend's secrets can travel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeystoreLocality {
    /// Persistent on this machine only: never synced, never restored onto another machine.
    ThisDeviceOnly,
    /// This process's memory only. Lost on exit.
    ProcessOnly,
}

/// No secret appears in these errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeystoreError {
    /// This platform or build has no this-device-only keystore.
    #[error("no this-device-only keystore is available: {0}")]
    Unavailable(&'static str),
    /// `create` found the slot already filled. Slots are never overwritten.
    #[error("key slot already exists")]
    AlreadyExists,
    /// The stored slot is not a 32-byte secret, or its protection is wrong.
    #[error("key slot is corrupt: {0}")]
    Corrupt(&'static str),
    /// The platform refused access.
    #[error("keystore denied access")]
    Denied,
    /// Any other platform failure, by name and code only.
    #[error("keystore failure: {0} ({1})")]
    Platform(&'static str, i64),
}

pub type Result<T> = std::result::Result<T, KeystoreError>;

/// A this-device-only home for 32-byte secrets.
pub trait DeviceKeystore: Send + Sync + 'static {
    /// The slot's secret, or `None` when the slot is empty.
    fn get(&self, slot: &KeystoreSlot) -> Result<Option<Zeroizing<[u8; 32]>>>;
    /// Fills an empty slot. A filled slot is `AlreadyExists` and keeps its secret.
    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<()>;
    /// Empties the slot. An empty slot is not an error.
    fn delete(&self, slot: &KeystoreSlot) -> Result<()>;
    fn locality(&self) -> KeystoreLocality;
}

/// This platform's this-device-only keystore.
/// - `service` names the keychain service on Apple.
/// - `dir` is the key directory on other Unix systems. It must lie outside every
///   vault directory in `vault_dirs`.
#[allow(unused_variables)]
pub fn platform_keystore(
    service: &str,
    dir: &std::path::Path,
    vault_dirs: &[&std::path::Path],
) -> Result<std::sync::Arc<dyn DeviceKeystore>> {
    #[cfg(target_vendor = "apple")]
    {
        Ok(std::sync::Arc::new(AppleKeychain::new(service)?))
    }
    #[cfg(all(unix, not(target_vendor = "apple")))]
    {
        Ok(std::sync::Arc::new(LocalFileKeystore::open(
            dir, vault_dirs,
        )?))
    }
    #[cfg(not(unix))]
    {
        Err(KeystoreError::Unavailable(
            "no adapter for this platform yet",
        ))
    }
}
