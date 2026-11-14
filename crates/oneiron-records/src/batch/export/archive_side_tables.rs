//! Moved from `crates/oneiron/src/batch/export/archive_side_tables.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Read;
use std::io::Seek;

/// A binary value or byte array longer than this goes in the archive's `files/`
/// as it is stored; ids, hashes and folds stay inline as hex.
pub const SIDE_INLINE_BYTES: usize = 64;

/// One part of a row's key, typed: ids and hashes as lowercase hex, text as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ArchiveSideKeyPart {
    Id(String),
    Hash(String),
    /// A kind byte and 16 bytes: a born-from source or a code-memory payload.
    Source(String),
    U64(u64),
    Text(String),
}

/// An LFS object record: its manifest ASSET, size, creation time and ref owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveLfsObject {
    pub asset: String,
    pub size_bytes: u64,
    pub created_at: u64,
    pub ref_owner: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveSideWithheldReason {
    /// The credential pass would change the row: it carries a secret.
    Credential,
    /// The stored row does not read back through its table's key type and codec.
    NotPortable,
    /// FIX 3681: a carried record's rows of this family do not all travel (one
    /// names a carrier the export does not hold, or does not read), and they go
    /// together, so none go. Named once per record and family.
    Incomplete,
}

pub fn byte_values(items: &[rmpv::Value]) -> Option<Vec<u8>> {
    items
        .iter()
        .map(|item| item.as_u64().and_then(|value| u8::try_from(value).ok()))
        .collect()
}

/// Lowercase hex of exactly `len` bytes.
pub fn hex_exact(text: &str, len: usize) -> Option<Vec<u8>> {
    hex_any(text).ok().filter(|bytes| bytes.len() == len)
}

/// Lowercase hex of any length.
pub fn hex_any(text: &str) -> Result<Vec<u8>> {
    let bytes = text
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .filter(|pair| pair.len() == 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| invalid("side row hex"))?;
    if bytes_to_hex_lower(&bytes) != text {
        return Err(invalid("side row hex must be lowercase"));
    }
    Ok(bytes)
}

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault side row: {reason}"))
}
