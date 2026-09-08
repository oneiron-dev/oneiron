//! Vault-meta key prefixes, key builders, upper bounds, and key-parsing helpers for pending gate-consent rows.

use crate::error::{Error, Result};

use super::records::decode_pending_gate_consent_sequence;

pub(in crate::store) const PENDING_GATE_CONSENT_KEY_PREFIX: &[u8] = b"gate_pending:v0:";

/// Durable idempotence marker for a critical-confirm attachment invalidated by
/// a replicated overwrite. It is intentionally separate from the pending row:
/// the latter is consumed, while this closure prevents replaying the same peer
/// bytes from restoring `Auto` without a new local ceremony.
const CRITICAL_CONFIRM_INVALIDATION_KEY_PREFIX: &[u8] = b"gate_critical_invalidation:v0:";

pub(in crate::store) const CRITICAL_CONFIRM_EXPIRY_CURSOR_KEY: &[u8] =
    b"gate_pending:critical_confirm_expiry_cursor:v1";

pub(super) const CRITICAL_CONFIRM_LIST_CURSOR_KEY: &[u8] =
    b"gate_pending:critical_confirm_list_cursor:v1";

const CRITICAL_CONFIRM_CONFIRM_INDEX_PREFIX: &[u8] = b"gate_pending:critical_confirm_by_id:v1:";

const PENDING_GATE_CONSENT_SEQUENCE_KEY_PREFIX: &[u8] = b"gate_pending:sequence:v1:";

pub(super) const PENDING_GATE_CONSENT_SEQUENCE_INDEX_PREFIX: &[u8] =
    b"gate_pending:sequence_index:v1:";

pub(super) const PENDING_GATE_CONSENT_SEQUENCE_COUNTER_KEY: &[u8] =
    b"gate_pending:sequence_counter:v1";

pub(in crate::store) const PENDING_GATE_CONSENT_RUN_INDEX_PREFIX: &[u8] =
    b"gate_pending:run_index:v1:";

pub(in crate::store) const PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX: &[u8] =
    b"gate_pending:group_index:v1:";

pub(in crate::store) const PENDING_GATE_CONSENT_HASH_INDEX_PREFIX: &[u8] =
    b"gate_pending:hash_index:v1:";

pub(in crate::store) const PENDING_GATE_CONSENT_INDEX_STATE_PREFIX: &[u8] =
    b"gate_pending:index_state:v1:";

pub(super) fn critical_confirm_invalidation_key(claim_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CRITICAL_CONFIRM_INVALIDATION_KEY_PREFIX.len() + 16);
    key.extend_from_slice(CRITICAL_CONFIRM_INVALIDATION_KEY_PREFIX);
    key.extend_from_slice(claim_id);
    key
}

pub(super) fn critical_confirm_index_key(confirm_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CRITICAL_CONFIRM_CONFIRM_INDEX_PREFIX.len() + 32);
    key.extend_from_slice(CRITICAL_CONFIRM_CONFIRM_INDEX_PREFIX);
    key.extend_from_slice(confirm_id);
    key
}

pub(super) fn pending_gate_consent_sequence_key(claim_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::from(PENDING_GATE_CONSENT_SEQUENCE_KEY_PREFIX);
    key.extend_from_slice(claim_id);
    key
}

pub(super) fn pending_gate_consent_sequence_index_key(sequence: u64) -> Vec<u8> {
    let mut key = Vec::from(PENDING_GATE_CONSENT_SEQUENCE_INDEX_PREFIX);
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

pub(super) fn pending_gate_consent_sequence_index_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(PENDING_GATE_CONSENT_SEQUENCE_INDEX_PREFIX);
    let last = key.last_mut().expect("nonempty prefix");
    *last = last.checked_add(1).expect("prefix upper bound");
    key
}

pub(super) fn pending_gate_consent_sequence_from_index_key(key: &[u8]) -> Result<u64> {
    decode_pending_gate_consent_sequence(
        key.strip_prefix(PENDING_GATE_CONSENT_SEQUENCE_INDEX_PREFIX)
            .ok_or(Error::CorruptedIndex("pending gate consent sequence index"))?,
    )
}

pub(super) fn pending_gate_consent_key(claim_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_GATE_CONSENT_KEY_PREFIX.len() + 16);
    key.extend_from_slice(PENDING_GATE_CONSENT_KEY_PREFIX);
    key.extend_from_slice(claim_id);
    key
}

pub(in crate::store) fn pending_gate_consent_claim_id_from_key(key: &[u8]) -> Result<[u8; 16]> {
    let bytes = key
        .strip_prefix(PENDING_GATE_CONSENT_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("pending gate consent"))?;
    bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("pending gate consent"))
}

pub(in crate::store) fn pending_gate_consent_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(PENDING_GATE_CONSENT_KEY_PREFIX);
    let last = key
        .last_mut()
        .expect("pending gate consent key prefix must be non-empty");
    *last = last
        .checked_add(1)
        .expect("pending gate consent key prefix upper bound must not overflow");
    key
}

pub(super) fn pending_gate_consent_run_index_prefix(run_id: &str) -> Vec<u8> {
    string_index_prefix(PENDING_GATE_CONSENT_RUN_INDEX_PREFIX, run_id)
}

pub(super) fn pending_gate_consent_run_index_key(run_id: &str, claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(&pending_gate_consent_run_index_prefix(run_id), claim_id)
}

pub(super) fn pending_gate_consent_group_index_prefix(group_key: &str) -> Vec<u8> {
    string_index_prefix(PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX, group_key)
}

pub(super) fn pending_gate_consent_group_index_key(
    group_key: &str,
    claim_id: &[u8; 16],
) -> Vec<u8> {
    index_key_with_id(
        &pending_gate_consent_group_index_prefix(group_key),
        claim_id,
    )
}

pub(super) fn pending_gate_consent_hash_index_prefix(semantic_claim_hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_GATE_CONSENT_HASH_INDEX_PREFIX.len() + 32);
    key.extend_from_slice(PENDING_GATE_CONSENT_HASH_INDEX_PREFIX);
    key.extend_from_slice(semantic_claim_hash);
    key
}

pub(super) fn pending_gate_consent_hash_index_key(
    semantic_claim_hash: &[u8; 32],
    claim_id: &[u8; 16],
) -> Vec<u8> {
    index_key_with_id(
        &pending_gate_consent_hash_index_prefix(semantic_claim_hash),
        claim_id,
    )
}

pub(super) fn pending_gate_consent_index_state_key(claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(PENDING_GATE_CONSENT_INDEX_STATE_PREFIX, claim_id)
}

pub(in crate::store) fn string_index_prefix(prefix: &[u8], value: &str) -> Vec<u8> {
    let value = value.as_bytes();
    let mut key = Vec::with_capacity(prefix.len() + std::mem::size_of::<u64>() + value.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(&(value.len() as u64).to_be_bytes());
    key.extend_from_slice(value);
    key
}

pub(in crate::store) fn index_key_with_id(prefix: &[u8], id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + id.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(id);
    key
}

pub(in crate::store) fn index_suffix_id(
    key: &[u8],
    prefix: &[u8],
    index_name: &'static str,
) -> Result<[u8; 16]> {
    key.strip_prefix(prefix)
        .ok_or(Error::CorruptedIndex(index_name))?
        .try_into()
        .map_err(|_| Error::CorruptedIndex(index_name))
}
