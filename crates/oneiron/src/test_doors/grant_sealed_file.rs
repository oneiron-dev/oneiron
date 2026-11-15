//! Doors for `tests/grant_sealed_file.rs` (REVIEW-7708 P1): how many key
//! groups an agent's read of a stored file asks for, so a test can show that
//! no grant reaches a file the write door sealed whole. The groups are
//! crate-private, and a public read only shows the sight they end in.

use crate::Vault;
use crate::error::Result;

/// How many key groups an agent's read of the file whose stored bytes are
/// `bytes` asks for: `None` when no grant can reach it (no mark covers it,
/// a key is not admitted, or the write door sealed it whole).
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub fn marked_key_groups(vault: &Vault, bytes: &[u8]) -> Result<Option<usize>> {
    vault.marked_file_key_groups_for_test(blake3::hash(bytes).as_bytes())
}
