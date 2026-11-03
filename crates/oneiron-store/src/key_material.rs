//! Guarded key derivation, OS entropy, and the world-key refusal constructor.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use oneiron_contracts::error::{Error, Result, SecretError};

pub fn refused(reason: &'static str) -> Error {
    Error::Secret(SecretError::WorldKeyRefused(reason))
}

/// `BLAKE3-derive_key(context, parts…)`, the same 32 bytes, written straight
/// into guarded output (FIX 6334): the output is zero-filled first and the
/// XOF fills it in place, and the hasher's block buffer and the reader's
/// state, which still hold the input key's bytes, are wiped. A secret subkey
/// never passes through a plain array on its way to its guard.
pub fn derive_guarded(context: &str, parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut out[..]);
    zeroize::Zeroize::zeroize(&mut hasher);
    zeroize::Zeroize::zeroize(&mut reader);
    out
}

/// Fills `buf` from the OS CSPRNG. A failure is an error, never a weaker key.
pub fn os_fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| refused("os entropy unavailable"))
}

/// Why a world's keys were destroyed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldKeyDestroyCause {
    /// This vault erased the world through the delete door.
    LocalDelete,
    /// A peer's hard tombstone for the world was applied here.
    ReplayedTombstone,
    /// A batch delete removed the world's row.
    BatchDelete,
}

/// The receipt, and permanent fact, that an erased world's keys were destroyed
/// here. Ids only: never a key, a pad or an envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldKeyDestruction {
    pub receipt_id: String,
    /// The WORLD row, as hex.
    pub world: String,
    pub cause: WorldKeyDestroyCause,
    /// Each key whose pad was erased, as `generation:mint` with the mint in hex.
    pub keys: Vec<String>,
    /// The erased pad rows, as hex. Each also has a queued hard tombstone.
    pub pad_rows: Vec<String>,
    /// The delete request this erasure rode, as hex, when it had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The vault's recorded-at clock when the fact was first written.
    pub at: u64,
}

/// LMDB refuses a sealed file opened without a key, or a plain one with one.
const MDB_ENV_ENCRYPTION: i32 = -30776;

/// LMDB refuses a page that does not open under the key.
const MDB_CRYPTO_FAIL: i32 = -30777;

/// The error of an environment opened with (`keyed`) or without a page key,
/// in the owner's words where LMDB refused the seal.
pub fn page_seal_open_error(error: heed::Error, keyed: bool) -> Error {
    let code = match &error {
        heed::Error::Mdb(heed::MdbError::Other(code)) => Some(*code),
        // heed hands an LMDB code it has no name for over as a raw OS error.
        heed::Error::Io(error) => error.raw_os_error(),
        _ => None,
    };
    match code {
        Some(MDB_ENV_ENCRYPTION) if keyed => {
            refused("this vault is plain: the maximum tier is chosen when the vault is created")
        }
        Some(MDB_ENV_ENCRYPTION) => {
            refused("this vault is sealed (maximum tier): unlock it with its vault key")
        }
        Some(MDB_CRYPTO_FAIL) => refused("this vault's pages do not open with this page key"),
        _ => error.into(),
    }
}
