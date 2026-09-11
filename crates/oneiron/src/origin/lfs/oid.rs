//! Object-id type with hex parse/spelling codec and OID length consts.

use sha2::{Digest, Sha256};

use crate::error::{ArtifactError, Error, Result};

/// Raw byte length of a Git-LFS object id (SHA-256).
pub const VAULT_LFS_OID_LEN: usize = 32;

/// Hex-encoded length of a Git-LFS object id.
pub const VAULT_LFS_OID_HEX_LEN: usize = 64;

// ---------------------------------------------------------------------------
// The object id
// ---------------------------------------------------------------------------
/// A Git-LFS object id: the SHA-256 of the object's bytes.
///
/// Deliberately a distinct 32-byte type from the 16-byte [`EntityId`]: an
/// object id addresses BYTES and an entity id addresses an ENTITY, and the two
/// are never interchangeable even though one deterministically derives the
/// other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LfsOid([u8; VAULT_LFS_OID_LEN]);

impl LfsOid {
    /// Wraps raw object-id bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; VAULT_LFS_OID_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses the 64-character lowercase-or-uppercase hex spelling.
    ///
    /// Rejects any other length and any non-hex character; there is no lenient
    /// path, because a mis-parsed object id would address the wrong bytes.
    pub fn parse_hex(value: &str) -> Result<Self> {
        if value.len() != VAULT_LFS_OID_HEX_LEN {
            return Err(Error::Artifact(ArtifactError::InvalidLfsObject(
                "lfs oid must be 64 hex characters",
            )));
        }
        let mut bytes = [0_u8; VAULT_LFS_OID_LEN];
        for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            *slot = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    /// The SHA-256 of `bytes` — the first and only hash of an LFS body.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut oid = [0_u8; VAULT_LFS_OID_LEN];
        oid.copy_from_slice(&digest);
        Self(oid)
    }

    /// The raw object-id bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VAULT_LFS_OID_LEN] {
        &self.0
    }

    /// The 64-character lowercase hex spelling clients send on the wire.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut hex = String::with_capacity(VAULT_LFS_OID_HEX_LEN);
        for byte in self.0 {
            hex.push(hex_digit(byte >> 4));
            hex.push(hex_digit(byte & 0x0f));
        }
        hex
    }
}

const fn hex_digit(nibble: u8) -> char {
    (if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }) as char
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Artifact(ArtifactError::InvalidLfsObject(
            "lfs oid is not hex",
        ))),
    }
}
