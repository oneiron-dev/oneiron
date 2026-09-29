//! Vault-meta key prefixes, key builders, upper bounds, and key-parsing helpers for pending gate-consent rows.

use crate::error::{Error, Result};

pub(in crate::store) const PENDING_GATE_CONSENT_KEY_PREFIX: &[u8] = b"gate_pending:v0:";

/// Production reads/writes of the critical-confirm expiry cursor go through
/// this module's own typed door; the raw key stays only for `store::tests`'
/// corrupt/legacy-row fixtures.
#[cfg(test)]
pub(in crate::store) const CRITICAL_CONFIRM_EXPIRY_CURSOR_KEY: &[u8] =
    b"gate_pending:critical_confirm_expiry_cursor:v1";

pub(in crate::store) const PENDING_GATE_CONSENT_RUN_INDEX_PREFIX: &[u8] =
    b"gate_pending:run_index:v1:";

pub(in crate::store) const PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX: &[u8] =
    b"gate_pending:group_index:v1:";

/// Production reads/writes of the hash index go through this module's own
/// typed door; the raw prefix stays only for `store::tests`' fixtures.
#[cfg(test)]
pub(in crate::store) const PENDING_GATE_CONSENT_HASH_INDEX_PREFIX: &[u8] =
    b"gate_pending:hash_index:v1:";

/// Production reads/writes of the index-state row go through this module's
/// own typed door; the raw prefix stays only for `store::tests`' fixtures.
#[cfg(test)]
pub(in crate::store) const PENDING_GATE_CONSENT_INDEX_STATE_PREFIX: &[u8] =
    b"gate_pending:index_state:v1:";

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

/// Only `store::tests` names this directly now, to unpack a raw index key it
/// wrote itself; production readers reach the id through this module's typed
/// index doors instead.
#[cfg(test)]
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
