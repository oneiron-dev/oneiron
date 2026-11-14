//! Moved from `crates/oneiron/src/compaction/output.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::de;

/// The occurrence path a context output's manifest names. Its body is one of
/// the code-run raw-output family, keyed by its content: inline in its row
/// up to the inline bound, past it a file beside data.mdb.
pub const CONTEXT_OUTPUT_PATH: &str = "context/output";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRef {
    pub hash: [u8; 32],
    pub byte_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputTier {
    Full,
    Overview,
    Stub,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputAffordance {
    Reexpand(OutputRef),
    Summarize(OutputRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputContextView {
    pub source: OutputRef,
    pub tier: OutputTier,
    pub bytes: Vec<u8>,
    pub affordances: [OutputAffordance; 2],
}

impl OutputRef {
    /// Portable handle for an output that stays valid after context compaction.
    #[must_use]
    pub fn handle(self) -> String {
        format!(
            "output:blake3:{}:{}",
            blake3::Hash::from(self.hash).to_hex(),
            self.byte_len
        )
    }

    /// Parse a handle before trying to restore the named bytes.
    pub fn from_handle(handle: &str) -> Result<Self> {
        let invalid = || Error::CorruptedIndex("recoverable output handle");
        let rest = handle.strip_prefix("output:blake3:").ok_or_else(invalid)?;
        let (hex, len) = rest.split_once(':').ok_or_else(invalid)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid());
        }
        let hash = blake3::Hash::from_hex(hex).map_err(|_| invalid())?;
        let byte_len = len.parse::<u64>().map_err(|_| invalid())?;
        if len != byte_len.to_string() {
            return Err(invalid());
        }
        Ok(Self {
            hash: *hash.as_bytes(),
            byte_len,
        })
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            hash: *blake3::hash(bytes).as_bytes(),
            byte_len: bytes.len() as u64,
        }
    }

    pub fn verify(self, bytes: &[u8]) -> Result<()> {
        if Self::from_bytes(bytes) != self {
            return Err(Error::CorruptedIndex("recoverable output integrity"));
        }
        Ok(())
    }
}
