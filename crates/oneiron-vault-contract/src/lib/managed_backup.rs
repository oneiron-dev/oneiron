//! What a managed vault reports of its backups on every `Ping` (Engine 10-20
//! row (b)): the vault id its checkpoints bind and this install's current
//! public checkpoint signer, which the supervisor forwards for the control
//! plane to pin. Public keys only: never a seed, a data key or an escrow key.
//!
//! The block rides v3 with a build floor and no version move. A vault built
//! before it sends none, and a block that does not parse or validate reads as
//! none too: either way the supervisor knows nothing of this vault's backups
//! or signer, and the `Ping` it rode on still stands.

use serde::{Deserialize, Deserializer, Serialize};

/// The answer to an idle reap's preparation and its backup (B2).
mod idle_reap;

pub use self::idle_reap::{
    BackupCoverageWire, IDLE_REAP_PREPARATION_SECS, IDLE_REAP_SCHEMA_VERSION, IdleBackupFailure,
    IdleBackupState, IdleBackupWire, IdleReapWire,
};

/// The one [`ManagedBackupFacts`] schema this crate reads.
pub const MANAGED_BACKUP_SCHEMA_VERSION: u32 = 1;

/// A vault id's length in bytes.
const VAULT_ID_LEN: usize = 32;
/// A checkpoint signer's install id length in bytes.
const INSTALL_LEN: usize = 16;
/// An Ed25519 public key's length in bytes.
const ED25519_PUBLIC_LEN: usize = 32;
/// An SLH-DSA-SHA2-256s public key's length in bytes.
const SLHDSA_PUBLIC_LEN: usize = 64;

/// What a managed vault reports of its backups on `Ping`
/// ([`CtlResponse::Ping`](crate::CtlResponse::Ping)): read once at boot,
/// before the vault signalled ready, and unchanged while the process runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedBackupFacts {
    /// [`MANAGED_BACKUP_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The vault id its checkpoints and sealed artifacts bind, as 64
    /// lowercase hex digits.
    pub engine_vault_id: String,
    /// How often the vault takes a managed backup, in seconds as a decimal
    /// string; `None` when it takes none of its own, as a build that reports
    /// its signer alone does.
    pub cadence_secs: Option<String>,
    /// Whether the vault takes a backup when its supervisor prepares an idle
    /// reap; `false` in a build that reports its signer alone.
    pub prepare_idle_reap: bool,
    /// This install's current checkpoint signer.
    pub checkpoint_signer: CheckpointSignerObservation,
}

/// This install's current checkpoint signer as the vault read it at boot:
/// its public keys in the pin file's spelling (`oneiron vault-key signer`),
/// or why it could not read them. The algorithms are fixed, Ed25519 and
/// SLH-DSA-SHA2-256s, so neither is named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CheckpointSignerObservation {
    /// Read: this install's public keys.
    Available {
        /// The install's id, as 32 lowercase hex digits.
        install: String,
        /// The Ed25519 public key, 32 bytes as unpadded base64url.
        ed25519: String,
        /// The SLH-DSA-SHA2-256s public key, 64 bytes as unpadded base64url.
        slhdsa: String,
    },
    /// No signer read: the vault serves on, and there is nothing to pin.
    Unavailable { reason: CheckpointSignerUnavailable },
}

/// Why a vault reports no checkpoint signer, in closed names: never a path
/// or an error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointSignerUnavailable {
    /// The vault has no keystore to hold the signer's seed.
    KeystoreUnavailable,
    /// The keystore is there, and the signer did not read from it.
    CheckpointSignerFailed,
}

impl CheckpointSignerUnavailable {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeystoreUnavailable => "keystore_unavailable",
            Self::CheckpointSignerFailed => "checkpoint_signer_failed",
        }
    }
}

impl ManagedBackupFacts {
    /// Shape check on a block a supervisor read: the schema it names, the
    /// vault id, the cadence's spelling, and an available signer's install
    /// id and keys at their decoded lengths. A block that fails it is no
    /// observation.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema_version == MANAGED_BACKUP_SCHEMA_VERSION,
            "unrecognized managed_backup schema_version"
        );
        anyhow::ensure!(
            lower_hex_of(&self.engine_vault_id, VAULT_ID_LEN),
            "engine_vault_id is 64 lowercase hex digits"
        );
        if let Some(cadence) = &self.cadence_secs {
            anyhow::ensure!(
                positive_decimal(cadence),
                "cadence_secs is a positive decimal string"
            );
        }
        if let CheckpointSignerObservation::Available {
            install,
            ed25519,
            slhdsa,
        } = &self.checkpoint_signer
        {
            anyhow::ensure!(
                lower_hex_of(install, INSTALL_LEN),
                "checkpoint_signer.install is 32 lowercase hex digits"
            );
            anyhow::ensure!(
                base64url_of(ed25519, ED25519_PUBLIC_LEN),
                "checkpoint_signer.ed25519 is 32 bytes as unpadded base64url"
            );
            anyhow::ensure!(
                base64url_of(slhdsa, SLHDSA_PUBLIC_LEN),
                "checkpoint_signer.slhdsa is 64 bytes as unpadded base64url"
            );
        }
        Ok(())
    }
}

/// `Ping.managed_backup` as a supervisor reads it: a block that does not
/// parse, names another schema or fails [`ManagedBackupFacts::validate`]
/// reads as `None`, unknown, and never fails the `Ping` it rides.
pub(super) fn observed<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ManagedBackupFacts>, D::Error> {
    let block = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(block
        .and_then(|block| serde_json::from_value::<ManagedBackupFacts>(block).ok())
        .filter(|facts| facts.validate().is_ok()))
}

/// Whether `text` is exactly `len` bytes as lowercase hex.
fn lower_hex_of(text: &str, len: usize) -> bool {
    text.len() == len * 2
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `text` is a positive whole number in decimal, with no sign or
/// leading zero, that a u64 holds.
fn positive_decimal(text: &str) -> bool {
    !text.starts_with('0')
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && text.parse::<u64>().is_ok()
}

/// Whether `text` is exactly `len` bytes as unpadded base64url, spelled the
/// one way an encoder writes them: the last digit's bits past the final
/// byte are zero.
fn base64url_of(text: &str, len: usize) -> bool {
    let digits: Option<Vec<u8>> = text
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        })
        .collect();
    let Some(digits) = digits else {
        return false;
    };
    if digits.len() != (len * 8).div_ceil(6) {
        return false;
    }
    let spare = digits.len() * 6 - len * 8;
    let mask = (1_u8 << spare) - 1;
    digits.last().is_some_and(|last| (last & mask) == 0)
}
