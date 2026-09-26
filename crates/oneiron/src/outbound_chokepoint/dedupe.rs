//! OF-327 mechanical semantic cooldown under the effect admission writer lock.

use crate::Vault;
use crate::outbound_intent_ledger::{
    IntentId, IntentLedgerError, IntentState, read_intent_record_in_txn,
};

use super::types::PreparedEffect;

// Initial safety floor. Tuning belongs to OF-327; this is not a provider rate limit.
const DEDUPE_COOLDOWN_S: u64 = 86_400;
const PREFIX: &[u8] = b"outbound:dedupe:v1:";
const INTENT_PREFIX: &[u8] = b"outbound:dedupe_intent:v1:";

/// The semantic key is vault-wide: changing actor, channel or target cannot
/// evade this floor. Producers include any needed recipient scope in the key;
/// the payload binding below prevents supplying a key different from the send.
fn key(prepared: &PreparedEffect) -> Result<Option<Vec<u8>>, IntentLedgerError> {
    let Some(dedupe) = prepared
        .dedupe_key
        .as_deref()
        .filter(|key| !key.trim().is_empty())
    else {
        return Ok(None);
    };
    let frozen: serde_json::Value = serde_json::from_slice(&prepared.payload)
        .map_err(|_| IntentLedgerError::InvalidInput("invalid dedupe payload"))?;
    // FrozenOutboundPayload flattens OutboundIntent at the top level.
    let intent = &frozen;
    if intent.get("dedupe_key").and_then(serde_json::Value::as_str) != Some(dedupe)
        || intent.get("channel").and_then(serde_json::Value::as_str)
            != Some(prepared.server.as_str())
    {
        return Err(IntentLedgerError::InvalidInput(
            "dedupe does not match frozen intent",
        ));
    }
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(blake3::hash(dedupe.as_bytes()).as_bytes());
    Ok(Some(key))
}

/// Called only for a new effect, after gate allow and before any budget debit.
/// The existing pointer must resolve to a real ledger row; corruption fails
/// closed rather than silently letting another send through.
pub(super) fn blocked(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    now_s: u64,
) -> Result<bool, IntentLedgerError> {
    let Some(raw) = vault.store.vault_meta.get(txn, key)? else {
        return Ok(false);
    };
    let bytes: &[u8] = raw.as_ref();
    let (id_bytes, stamp_bytes) = bytes
        .split_at_checked(32)
        .filter(|(_, stamp)| stamp.len() == 8)
        .ok_or(IntentLedgerError::InvalidRecord("invalid dedupe pointer"))?;
    let id: IntentId = id_bytes
        .try_into()
        .map_err(|_| IntentLedgerError::InvalidRecord("invalid dedupe pointer"))?;
    let stamped_at = u64::from_be_bytes(
        stamp_bytes
            .try_into()
            .map_err(|_| IntentLedgerError::InvalidRecord("invalid dedupe timestamp"))?,
    );
    let record = read_intent_record_in_txn(vault, txn, &id)?
        .ok_or(IntentLedgerError::InvalidRecord("dedupe target is missing"))?;
    if intent_key(vault, txn, &id)?.as_deref() != Some(key) {
        return Err(IntentLedgerError::InvalidRecord(
            "dedupe pointer lacks its intent binding",
        ));
    }
    // An uncertain/in-flight attempt cannot be released by elapsed time.
    // A definite no-wire result can be replaced after the provisional window,
    // but its old replay is fenced under that same writer lock (below).
    Ok(
        (record.state == IntentState::Pending && record.recorded_outcome.is_none())
            || now_s < stamped_at.saturating_add(DEDUPE_COOLDOWN_S),
    )
}

pub(super) fn dedupe_key(prepared: &PreparedEffect) -> Result<Option<Vec<u8>>, IntentLedgerError> {
    key(prepared)
}

pub(super) fn reserve(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8],
    id: &IntentId,
    now_s: u64,
) -> Result<(), IntentLedgerError> {
    let mut value = Vec::with_capacity(40);
    value.extend_from_slice(id);
    value.extend_from_slice(&now_s.to_be_bytes());
    vault.store.vault_meta.put(txn, key, &value)?;
    vault
        .store
        .vault_meta
        .put(txn, &intent_binding_key(id), key)?;
    Ok(())
}

fn intent_binding_key(id: &IntentId) -> Vec<u8> {
    let mut key = INTENT_PREFIX.to_vec();
    key.extend_from_slice(id);
    key
}

fn intent_key(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &IntentId,
) -> Result<Option<Vec<u8>>, IntentLedgerError> {
    let raw = vault.store.vault_meta.get(txn, &intent_binding_key(id))?;
    raw.map(|bytes| {
        if bytes.len() != PREFIX.len() + 32 || !bytes.starts_with(PREFIX) {
            return Err(IntentLedgerError::InvalidRecord(
                "invalid dedupe intent binding",
            ));
        }
        Ok(bytes.into_owned())
    })
    .transpose()
}

/// Under the transition's writer lock, only the current reservation can move
/// from known non-delivery back to an in-flight wire attempt.
pub(crate) fn owns_retry(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &IntentId,
) -> Result<bool, IntentLedgerError> {
    let Some(key) = intent_key(vault, txn, id)? else {
        return Ok(true);
    };
    let raw = vault
        .store
        .vault_meta
        .get(txn, &key)?
        .ok_or(IntentLedgerError::InvalidRecord(
            "dedupe reservation is missing",
        ))?;
    if raw.len() != 40 {
        return Err(IntentLedgerError::InvalidRecord(
            "invalid dedupe reservation",
        ));
    }
    Ok(&raw.as_ref()[..32] == id)
}

/// Extend the floor from the actual ACK, not the possibly much earlier
/// admission. This mutates the ledger's sidecar inside its Done transition.
pub(crate) fn delivered_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &IntentId,
) -> Result<(), IntentLedgerError> {
    let Some(key) = intent_key(vault, txn, id)? else {
        return Ok(());
    };
    if !owns_retry(vault, txn, id)? {
        return Err(IntentLedgerError::InvalidRecord(
            "delivered dedupe reservation was replaced",
        ));
    }
    let mut value = Vec::with_capacity(40);
    value.extend_from_slice(id);
    value.extend_from_slice(&vault.store.clock.now_recorded_at().to_be_bytes());
    vault.store.vault_meta.put(txn, &key, &value)?;
    Ok(())
}

/// After retry governance, refresh the conservative wire-start time before
/// transport. A later definite failure cannot erase an older ambiguous send.
pub(crate) fn touch_inflight(vault: &Vault, id: &IntentId) -> Result<(), IntentLedgerError> {
    let mut txn = vault
        .store
        .env
        .write_txn()
        .map_err(crate::error::Error::from)?;
    let Some(key) = intent_key(vault, &txn, id)? else {
        return Ok(());
    };
    if !owns_retry(vault, &txn, id)? {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound semantic retry lost its reservation",
        ));
    }
    let mut value = Vec::with_capacity(40);
    value.extend_from_slice(id);
    value.extend_from_slice(&vault.store.clock.now_recorded_at().to_be_bytes());
    vault.store.vault_meta.put(&mut txn, &key, &value)?;
    txn.commit().map_err(crate::error::Error::from)?;
    crate::outbound_intent_ledger::force_sync(vault)
}
