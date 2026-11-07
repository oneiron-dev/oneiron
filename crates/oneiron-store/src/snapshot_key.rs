//! Wrapped inference-snapshot data keys and their byte grammar.

use oneiron_base::error::{Error, Result};

/// The format version both values' bytes and every chunk key id carry.
pub const VERSION: u8 = 1;

pub const WRAP_NONCE_LEN: usize = 12;
/// A wrapped key's fixed width: version ‖ nonce ‖ 32 key bytes + 16 tag.
pub const WRAPPED_LEN: usize = 1 + WRAP_NONCE_LEN + 48;

pub fn corrupt() -> Error {
    Error::CorruptedIndex("inference snapshot")
}

/// One snapshot's data key, wrapped under the vault's key: `u8` version 1, a
/// fresh 12-byte nonce, then the 32 key bytes sealed under it. The sealed
/// body never carries the key; whoever holds only [`SealedSnapshot`](crate::inference_snapshot::SealedSnapshot) opens
/// nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedSnapshotKey {
    pub bytes: Vec<u8>,
}

impl WrappedSnapshotKey {
    /// Parses wrapped bytes: the version, then nonce and ciphertext, exactly.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WRAPPED_LEN || bytes[0] != VERSION {
            return Err(corrupt());
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        owned.extend_from_slice(bytes);
        Ok(Self { bytes: owned })
    }

    /// The canonical bytes: version, nonce, ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Retires this copy of the wrapped key: its bytes are wiped and dropped,
    /// so this handle never unwraps again. Durable erasure — the stored rows,
    /// copies and backups — is the store's erase wiring, not a filename
    /// delete here.
    pub fn retire(mut self) {
        zeroize::Zeroize::zeroize(&mut self.bytes);
    }
}
