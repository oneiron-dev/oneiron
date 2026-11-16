//! Moved from `crates/oneiron/src/policy_model/binding.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::bytes_to_hex_lower;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyContentBinding {
    pub content_hash: [u8; 32],
    pub read_frontier_hash: [u8; 32],
}

impl PolicyContentBinding {
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        bytes_to_hex_lower(&self.content_hash)
    }

    #[must_use]
    pub fn read_frontier_hash_hex(&self) -> String {
        bytes_to_hex_lower(&self.read_frontier_hash)
    }
}

pub fn hash_binding_str(hasher: &mut Sha256, label: &str, value: &str) {
    hasher.update(label.as_bytes());
    hasher.update([0]);
    // Eight bytes on every architecture. A relay recomputes this hash locally
    // and compares it against one a VAULT produced, so a bare `usize` — four
    // bytes on a 32-bit target, eight on a 64-bit one — would make the two
    // machines disagree about identical content. Same rule as the policy hash.
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    hasher.update([0xff]);
}
