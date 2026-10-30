//! This-device-only key slots for one install.
//!
//! A slot holds one 32-byte secret that must never leave the machine. It must not
//! reach a synced keychain, an OS backup, a vault checkpoint or sync. The engine
//! keeps exactly one secret here: the seed of this machine's hybrid encryption key,
//! which opens the world keys wrapped to this machine. Losing a slot loses nothing
//! else. Another of the owner's machines, or the recovery kit, wraps the keys
//! again for a new seed. One slot's secret has a second home the engine owns: a
//! vault's host issuer seed ([`SlotKind::HostIssuerSeed`]) is also escrowed in
//! that vault's protected key custody, never through this crate, so a new install
//! takes the same seed back into its own slot (FIX-LIST 10770).
//!
//! Adapters, each with the assurance it reports ([`KeystoreAssurance`]):
//! - Apple: `AppleKeychain`, the data-protection keychain, with the attributes
//!   `AfterFirstUnlockThisDeviceOnly` and not synchronizable (platform).
//! - Apple, hardware tier: `SecureEnclaveKeychain`, the same items sealed to a
//!   P-256 key the Secure Enclave holds and never releases (hardware).
//! - Windows: `WindowsDpapiKeystore`, one file per slot sealed by DPAPI to this
//!   user on this machine (platform).
//! - Other Unix: `LocalFileKeystore`, 0600 files in a 0700 directory outside the
//!   vault, tagged so that backup tools skip it (software).
//! - Tests: `MemoryKeystore`, process memory only, built under `cfg(test)` or the
//!   `test-keystore` feature and never for a host.
//!
//! [`platform_keystore`] picks the platform tier; [`hardware_keystore`] the
//! hardware one, refused where this platform has none: never a silent downgrade
//! to software (identity, signature suites).

use std::borrow::Cow;

use zeroize::Zeroizing;

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(target_vendor = "apple")]
mod apple_enclave;
#[cfg(all(unix, not(target_vendor = "apple")))]
mod file;
#[cfg(any(test, feature = "test-keystore"))]
mod memory;
#[cfg(windows)]
mod windows;

#[cfg(target_vendor = "apple")]
pub use apple::AppleKeychain;
#[cfg(target_vendor = "apple")]
pub use apple_enclave::SecureEnclaveKeychain;
#[cfg(all(unix, not(target_vendor = "apple")))]
pub use file::LocalFileKeystore;
#[cfg(any(test, feature = "test-keystore"))]
pub use memory::MemoryKeystore;
#[cfg(windows)]
pub use windows::WindowsDpapiKeystore;

/// What a slot holds. One variant per secret the engine keeps at rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SlotKind {
    /// The seed of this machine's hybrid encryption key for one vault.
    MachineEncryption,
    /// The seed this install's signing keys are derived from: the machine key and
    /// the device key that signs receipts.
    DeviceSigning,
    /// The key that unlocks the vault data key on this device (OF-570 E1).
    VaultUnlock,
    /// The seed this install's checkpoint signing keys are remade from: an Ed25519
    /// key and an SLH-DSA-SHA2-256s key (OF-570 (e)).
    CheckpointSigning,
    /// The host root secret of a vault this install rooted itself as a new local
    /// origin with no configured secret, such as the desktop app's own vault
    /// (FIX 4730). The root's recovery material, on this device only.
    HostRoot,
    /// The independent seed this install's host issuer signs with for one
    /// vault (FIX-LIST 3018): drawn once from the OS CSPRNG when the install
    /// roots a new vault, never derived from a shared secret, a data key or
    /// the vault id, and never minted again for a vault already rooted. The
    /// engine escrows the same seed in the vault's protected key custody; a
    /// new install's empty slot takes it back from there only when its issuer
    /// is the vault's live root, and a filled slot is never replaced by it
    /// (FIX-LIST 10770). The slot itself stays this device's.
    HostIssuerSeed,
    /// The seed of this install's own Ed25519 owner signing key for one vault
    /// (FIX 4921): made on first use, put on the roster only by the owner's
    /// enrollment act, and used only to sign checkpoint statements as that
    /// owner root.
    OwnerSigning,
    /// One of the slots that keep this machine's own piece of a vault's
    /// recovery kit (FIX 2063). A piece is longer than one slot, so it spans
    /// a head and a tail slot, and each kit kind has its own pair: issuing
    /// one kind of kit replaces only that kind's piece. Each recovery-root kit
    /// drawn and not yet confirmed also has a pending pair of its own, named
    /// by its kit id (FIX 11977, 12046). One slot more, named by the vault id
    /// alone, names the install that keeps a data-key kit piece (FIX 12054).
    KitPiece(KitPieceSlot),
}

impl SlotKind {
    /// Stable name in the backend: part of the keychain account or the file name.
    #[must_use]
    pub fn label(self) -> Cow<'static, str> {
        let label = match self {
            Self::MachineEncryption => "machine-encryption",
            Self::DeviceSigning => "device-signing",
            Self::VaultUnlock => "vault-unlock",
            Self::CheckpointSigning => "checkpoint-signing",
            Self::HostRoot => "host-root",
            Self::HostIssuerSeed => "host-issuer-seed",
            Self::OwnerSigning => "owner-signing",
            Self::KitPiece(slot) => return slot.label(),
        };
        Cow::Borrowed(label)
    }
}

/// Which slot of this machine's kit pieces: the kit kind, the current pair or
/// one drawn kit's pending pair, then the piece's first 32 bytes (head) or the
/// rest (tail).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KitPieceSlot {
    /// The data-key kit's piece, its first 32 bytes.
    VaultKeyHead,
    /// The data-key kit's piece, its remaining bytes.
    VaultKeyTail,
    /// The recovery-root kit's piece, its first 32 bytes.
    RecoveryRootHead,
    /// The recovery-root kit's piece, its remaining bytes.
    RecoveryRootTail,
    /// The piece of the recovery-root kit whose 4-byte id this holds, drawn
    /// and not yet confirmed, its first 32 bytes (FIX 11977, 12046): each
    /// drawn kit keeps its own. A data-key kit has no confirm, so its issue
    /// fills the current pair and it has no pending one.
    RecoveryRootPendingHead([u8; 4]),
    /// The piece of the recovery-root kit whose id this holds, drawn and not
    /// yet confirmed, its remaining bytes.
    RecoveryRootPendingTail([u8; 4]),
    /// The 16-byte machine id of the install whose slots keep the data-key
    /// kit's piece, then zeros (FIX 12054). Filed under the all-zero install,
    /// so the vault id alone names it: a sealed vault's pages open before its
    /// machine id can be read.
    VaultKeyInstall,
}

impl KitPieceSlot {
    /// Stable name in the backend, as [`SlotKind::label`]. A pending slot's
    /// name carries its kit's id: `kit-piece-recovery-root-pending-<kit id
    /// hex>-head|tail`.
    #[must_use]
    pub fn label(self) -> Cow<'static, str> {
        let (kit, half) = match self {
            Self::VaultKeyHead => return Cow::Borrowed("kit-piece-vault-key-head"),
            Self::VaultKeyTail => return Cow::Borrowed("kit-piece-vault-key-tail"),
            Self::RecoveryRootHead => return Cow::Borrowed("kit-piece-recovery-root-head"),
            Self::RecoveryRootTail => return Cow::Borrowed("kit-piece-recovery-root-tail"),
            Self::VaultKeyInstall => return Cow::Borrowed("kit-piece-vault-key-install"),
            Self::RecoveryRootPendingHead(kit) => (kit, "head"),
            Self::RecoveryRootPendingTail(kit) => (kit, "tail"),
        };
        let mut label = String::from("kit-piece-recovery-root-pending-");
        for byte in kit {
            push_hex(&mut label, byte);
        }
        label.push('-');
        label.push_str(half);
        Cow::Owned(label)
    }
}

/// One slot: a vault, the install that owns the secret, and what it is for.
///
/// `install` is the install's incarnation, the engine's machine id. A restore that
/// makes a new machine gets a new id, so it never opens the slot of the install it
/// was copied from, even on the same host with the same keystore. One slot is
/// filed under the all-zero install, no machine's id:
/// [`KitPieceSlot::VaultKeyInstall`], which the vault id alone names (FIX 12054).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeystoreSlot {
    pub vault_id: [u8; 32],
    pub install: [u8; 16],
    pub kind: SlotKind,
}

impl KeystoreSlot {
    /// `<vault id hex>.<install hex>.<kind>`: the backend's name for the slot. It
    /// carries no secret.
    #[must_use]
    pub fn name(&self) -> String {
        let label = self.kind.label();
        let mut name = String::with_capacity(64 + 1 + 32 + 1 + label.len());
        for byte in self.vault_id {
            push_hex(&mut name, byte);
        }
        name.push('.');
        for byte in self.install {
            push_hex(&mut name, byte);
        }
        name.push('.');
        name.push_str(&label);
        name
    }
}

fn push_hex(name: &mut String, byte: u8) {
    name.push(char::from(HEX[usize::from(byte >> 4)]));
    name.push(char::from(HEX[usize::from(byte & 0x0f)]));
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

/// What keeps a backend's slots at rest, as the owner is told it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeystoreAssurance {
    /// Each slot is sealed to a key this device's secure hardware holds and never
    /// releases; a copy of the stored bytes opens nowhere else.
    Hardware,
    /// The operating system's protected store, bound to this device or to this
    /// user's logon on it.
    Platform,
    /// Files only the owner's account may read.
    Software,
    /// This process's memory.
    Process,
}

impl KeystoreAssurance {
    /// Stable name for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hardware => "hardware",
            Self::Platform => "platform",
            Self::Software => "software",
            Self::Process => "process",
        }
    }
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
    /// This backend cannot do what was asked in one platform operation, so it
    /// did nothing rather than fake it: a [`DeviceKeystore::replace`] where
    /// there is no in-place update.
    #[error("keystore operation not supported: {0}")]
    Unsupported(&'static str),
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
    /// Overwrites a filled slot's secret in place, in one platform operation,
    /// so a reader sees the old secret or the new one and never an empty slot
    /// (FIX 5571: the retained host root a re-key replaces). `Ok(false)` when
    /// the slot is empty: a replace never fills one, which is `create`'s. A
    /// backend with no in-place update answers `Unsupported` and writes
    /// nothing; it never deletes and creates again.
    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<bool> {
        let _ = (slot, secret);
        Err(KeystoreError::Unsupported(
            "this keystore cannot replace a slot in place",
        ))
    }
    fn locality(&self) -> KeystoreLocality;
    /// What keeps the slots at rest. An adapter that claims more than files
    /// says so; nothing else does.
    fn assurance(&self) -> KeystoreAssurance {
        match self.locality() {
            KeystoreLocality::ThisDeviceOnly => KeystoreAssurance::Software,
            KeystoreLocality::ProcessOnly => KeystoreAssurance::Process,
        }
    }
}

/// The keychain service the Apple adapter files slots under by default.
pub const DEFAULT_KEYCHAIN_SERVICE: &str = "oneiron.device-keys";

/// The default key directory on Unix systems other than Apple:
/// `$XDG_STATE_HOME/oneiron/keys`, else `$HOME/.local/state/oneiron/keys`. On
/// Windows, `%LOCALAPPDATA%\Oneiron\keys`, the profile part that never roams.
/// Unset, empty and relative variables name no place a key may be written, so
/// `None`.
#[must_use]
pub fn default_key_dir() -> Option<std::path::PathBuf> {
    let absolute = |key: &str| {
        let path = std::path::PathBuf::from(std::env::var_os(key)?);
        path.is_absolute().then_some(path)
    };
    if cfg!(windows) {
        return absolute("LOCALAPPDATA").map(|local| local.join("Oneiron").join("keys"));
    }
    if let Some(state) = absolute("XDG_STATE_HOME") {
        return Some(state.join("oneiron").join("keys"));
    }
    absolute("HOME").map(|home| {
        home.join(".local")
            .join("state")
            .join("oneiron")
            .join("keys")
    })
}

/// [`platform_keystore`] at the defaults: [`DEFAULT_KEYCHAIN_SERVICE`] and
/// [`default_key_dir`]. For a local host with no keystore settings of its own.
pub fn default_platform_keystore(
    vault_dirs: &[&std::path::Path],
) -> Result<std::sync::Arc<dyn DeviceKeystore>> {
    #[cfg(all(unix, not(target_vendor = "apple")))]
    let dir = default_key_dir().ok_or(KeystoreError::Unavailable(
        "neither XDG_STATE_HOME nor HOME names an absolute key directory",
    ))?;
    #[cfg(windows)]
    let dir = default_key_dir().ok_or(KeystoreError::Unavailable(
        "LOCALAPPDATA names no absolute key directory",
    ))?;
    #[cfg(not(any(all(unix, not(target_vendor = "apple")), windows)))]
    let dir = default_key_dir().unwrap_or_default();
    platform_keystore(DEFAULT_KEYCHAIN_SERVICE, &dir, vault_dirs)
}

/// This platform's this-device-only keystore.
/// - `service` names the keychain service on Apple.
/// - `dir` is the key directory on Windows and on other Unix systems. It must
///   lie outside every vault directory in `vault_dirs`.
pub fn platform_keystore(
    service: &str,
    dir: &std::path::Path,
    vault_dirs: &[&std::path::Path],
) -> Result<std::sync::Arc<dyn DeviceKeystore>> {
    #[cfg(target_vendor = "apple")]
    {
        let _ = (dir, vault_dirs);
        Ok(std::sync::Arc::new(AppleKeychain::new(service)?))
    }
    #[cfg(all(unix, not(target_vendor = "apple")))]
    {
        let _ = service;
        Ok(std::sync::Arc::new(LocalFileKeystore::open(
            dir, vault_dirs,
        )?))
    }
    #[cfg(windows)]
    {
        let _ = service;
        Ok(std::sync::Arc::new(WindowsDpapiKeystore::open(
            dir, vault_dirs,
        )?))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (service, dir, vault_dirs);
        Err(KeystoreError::Unavailable(
            "no adapter for this platform yet",
        ))
    }
}

/// This platform's hardware-wrapped keystore: the Secure Enclave on Apple.
/// Refused where there is none, never answered with a weaker one; the caller
/// picks the platform tier itself if it wants it.
pub fn hardware_keystore(
    service: &str,
    dir: &std::path::Path,
    vault_dirs: &[&std::path::Path],
) -> Result<std::sync::Arc<dyn DeviceKeystore>> {
    let _ = (dir, vault_dirs);
    #[cfg(target_vendor = "apple")]
    {
        Ok(std::sync::Arc::new(SecureEnclaveKeychain::new(service)?))
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let _ = service;
        Err(KeystoreError::Unavailable(
            "no hardware-wrapped keystore on this platform",
        ))
    }
}
