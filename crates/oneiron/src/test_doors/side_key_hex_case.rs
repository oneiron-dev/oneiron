//! Doors for `tests/side_key_hex_case.rs` (UC-06 PR 0a, HEX-CASE-POLICY = A): what four
//! crate-private side-table key types read from the bytes after their table prefix, or
//! `None` where they refuse them. Compiled only under `--cfg oneiron_test_support`; never API.

use crate::entity_id::EntityId;

/// `authority::ingest_observation::IngestCheckKey`: the peer id and the window start.
pub fn ingest_check_key(bytes: &[u8]) -> Option<(String, u64)> {
    crate::authority::decode_ingest_check_key_for_test(bytes)
}

/// `authority::slip_replay::NonceKey`: the signed timestamp and the digest text.
pub fn nonce_key(bytes: &[u8]) -> Option<(u64, String)> {
    crate::authority::decode_nonce_key_for_test(bytes)
}

/// `deletion::tombstone::PendingTombstoneKey`: the window label and the entity.
pub fn pending_tombstone_key(bytes: &[u8]) -> Option<(String, EntityId)> {
    crate::deletion::decode_pending_tombstone_key_for_test(bytes)
}

/// `sync::lease::LeaseKey`: the vault id and the client id.
#[cfg(feature = "sync")]
pub fn lease_key(bytes: &[u8]) -> Option<(u64, u64)> {
    crate::sync::lease::decode_lease_key_for_test(bytes)
}
