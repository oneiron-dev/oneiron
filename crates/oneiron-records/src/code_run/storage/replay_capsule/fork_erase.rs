//! Moved from `crates/oneiron/src/code_run/storage/replay_capsule/fork_erase.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::ENTITY_ID_LEN;
use oneiron_contracts::entity_id::EntityId;

/// Native full-id spellings anywhere in an opaque receipt, including
/// upper-case hex: the same spelling match used by CHECK's erase pass.
pub fn receipt_entities(receipt: &str) -> impl Iterator<Item = EntityId> + '_ {
    receipt
        .as_bytes()
        .windows(ENTITY_ID_LEN * 2)
        .filter_map(|hex| std::str::from_utf8(hex).ok())
        .filter_map(|hex| EntityId::from_hex(hex).ok())
}
