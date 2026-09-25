//! Durable signer sequence maxima and content-addressed first-observation receipts.
//!
//! A maximum alone is not a fold input: comparing the entire stored history to
//! today's maximum would reject genesis and every accepted predecessor on the
//! next recomputation. Each immutable hash therefore retains the maximum that
//! existed BEFORE its first observation. Re-putting those bytes cannot refresh
//! that receipt. All records still enter the log; only the local fold decides
//! whether a newly observed old sequence can authorize.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::store::Store;

use super::*;

pub(super) struct AuthorityLocalObservations {
    pub(super) sequence_floors: BTreeMap<AuthorityEntryHash, u64>,
    pub(super) policy: AuthorityObservationPolicy,
}

/// Stable signer identity, including the suite to separate key encodings.
pub(super) fn authority_observation_peer_id(signer: &AuthorityKey) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron/authority-observation/v1/peer");
    match signer {
        AuthorityKey::Ed25519(bytes) => {
            hasher.update(b"ed25519");
            hasher.update(bytes);
        }
        AuthorityKey::P256(bytes) => {
            hasher.update(b"p256");
            hasher.update(bytes);
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn sequence_key(signer: &AuthorityKey) -> String {
    format!("authlog:seq_hwm:{}", authority_observation_peer_id(signer))
}

fn receipt_key(hash: &AuthorityEntryHash) -> String {
    format!(
        "authlog:seq_observation:{}",
        crate::entity_id::bytes_to_hex_lower(hash)
    )
}

fn read_u64(raw: &[u8]) -> Result<u64> {
    decode_authority_first_seen_secs(raw)
        .ok_or(Error::CorruptedIndex("authority sequence high-water mark"))
}

fn decode_receipt(raw: &[u8]) -> Result<Option<u64>> {
    match raw {
        [0] => Ok(None),
        [1, rest @ ..] if rest.len() == 8 => read_u64(rest).map(Some),
        _ => Err(Error::CorruptedIndex(
            "authority sequence observation receipt",
        )),
    }
}

/// Called at the shared successful-put site in the row's own transaction.
/// Returns whether this is a new hash, for exactly-once ingest accounting.
pub(crate) fn record_authority_sequence_observation_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    entry: &AuthorityLogEntry,
    hash: &AuthorityEntryHash,
) -> Result<bool> {
    let receipt_key = receipt_key(hash);
    if let Some(raw) = store.sync_state.get(txn, &receipt_key)? {
        decode_receipt(&raw)?;
        return Ok(false);
    }
    let key = sequence_key(entry.signer_key());
    let previous = store
        .sync_state
        .get(txn, &key)?
        .map(|raw| read_u64(&raw))
        .transpose()?;
    let mut receipt = vec![u8::from(previous.is_some())];
    if let Some(previous) = previous {
        receipt.extend_from_slice(&previous.to_be_bytes());
    }
    store.sync_state.put(txn, &receipt_key, &receipt)?;
    let next = previous.map_or(entry.seq, |value| value.max(entry.seq));
    store.sync_state.put(txn, &key, &next.to_be_bytes())?;
    Ok(true)
}

pub(super) fn authority_local_observations_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entries: &[AuthorityLogEntry],
) -> Result<AuthorityLocalObservations> {
    let mut sequence_floors = BTreeMap::new();
    for entry in entries {
        let hash = authority_entry_hash(entry)?;
        let current = store
            .sync_state
            .get(txn, &sequence_key(entry.signer_key()))?
            .map(|raw| read_u64(&raw))
            .transpose()?;
        let receipt = store.sync_state.get(txn, &receipt_key(&hash))?;
        let floor = match receipt {
            Some(raw) => {
                let observed = decode_receipt(&raw)?;
                if current.is_none_or(|current| current < entry.seq)
                    || observed.is_some_and(|floor| current.is_none_or(|now| floor > now))
                {
                    return Err(Error::CorruptedIndex("authority sequence high-water mark"));
                }
                observed
            }
            // A missing receipt is never an exemption from an existing mark.
            None => current,
        };
        if let Some(floor) = floor {
            sequence_floors.insert(hash, floor);
        }
    }
    Ok(AuthorityLocalObservations {
        sequence_floors,
        policy: authority_observation_policy_in_txn(store, txn)?,
    })
}
