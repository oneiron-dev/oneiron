//! The artifact kinds and the key header's wire form (moved from the engine's
//! `recovery::checkpoint::artifact` and `world_keys::vault_key` whole).

use serde::{Deserialize, Serialize};

use crate::envelope::{Purpose, WrapType};
use crate::error::{Error, Result};

/// The magic every sealed checkpoint or backup artifact starts with.
pub const BACKUP_MAGIC: &[u8; 8] = b"ONEIRONS";
/// Longest key header a reader takes, in bytes.
pub const MAX_KEY_HEADER_LEN: usize = 1 << 20;

/// What a sealed artifact is for, which fixes its envelope purpose. Wire form:
/// one byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    /// A checkpoint, for restore, wake and migrate.
    Checkpoint,
    /// An owner's backup.
    Backup,
}

impl ArtifactKind {
    /// The wire byte.
    pub fn code(self) -> u8 {
        match self {
            Self::Checkpoint => 1,
            Self::Backup => 2,
        }
    }

    /// The kind a wire byte names, if any.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Checkpoint),
            2 => Some(Self::Backup),
            _ => None,
        }
    }

    /// The purpose every sealed frame of an artifact of this kind carries.
    pub fn purpose(self) -> Purpose {
        match self {
            Self::Checkpoint => Purpose::CheckpointArtifact,
            Self::Backup => Purpose::BackupArtifact,
        }
    }
}

/// How one wrap unlocks the vault data key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VaultKeyWrapKind {
    /// This device's keystore slot, for the install named as hex.
    Device { install: String },
    /// The vault password.
    Password,
    /// One passkey, by the host's credential id.
    Passkey { credential: String },
    /// A hybrid capsule to a recovery or transfer key, by the owner's label.
    Escrow { label: String },
}

impl VaultKeyWrapKind {
    /// The wrap's id: one wrap per device, per passkey and per escrow label, and
    /// one password.
    pub fn id(&self) -> String {
        match self {
            Self::Device { install } => format!("device:{install}"),
            Self::Password => "password".to_owned(),
            Self::Passkey { credential } => format!("passkey:{credential}"),
            Self::Escrow { label } => format!("escrow:{label}"),
        }
    }

    /// The envelope wrap type a wrap of this kind is sealed with.
    pub fn wrap_type(&self) -> WrapType {
        match self {
            Self::Device { .. } => WrapType::DeviceKeystore,
            Self::Password => WrapType::Passphrase,
            Self::Passkey { .. } => WrapType::Passkey,
            Self::Escrow { .. } => WrapType::HybridCapsule,
        }
    }
}

/// One wrap's public facts: never the envelope, never a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyWrapInfo {
    pub id: String,
    pub kind: VaultKeyWrapKind,
    /// The vault clock, in seconds, when the wrap was added.
    pub created_at: u64,
}

/// One wrap of the vault data key as it rests: its public facts and its sealed
/// envelope. The engine files each one under its id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHeaderWrap {
    pub info: VaultKeyWrapInfo,
    pub envelope: Vec<u8>,
}

/// The vault data key as a sealed artifact carries it in the clear: the
/// commitment naming the key and every wrap's sealed envelope, never the key.
/// Named MessagePack.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyHeader {
    pub commitment: [u8; 32],
    pub wraps: Vec<KeyHeaderWrap>,
}

impl KeyHeader {
    /// The wire form.
    pub fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|_| Error::BackupMalformed("key header"))
    }

    /// Reads the wire form.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        rmp_serde::from_slice(bytes).map_err(|_| Error::BackupMalformed("key header"))
    }

    /// Each wrap's public facts.
    pub fn wrap_infos(&self) -> Vec<VaultKeyWrapInfo> {
        self.wraps.iter().map(|wrap| wrap.info.clone()).collect()
    }
}
