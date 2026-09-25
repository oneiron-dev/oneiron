//! Bounded, timestamp-bound replay windows for authenticated slip requests.
use super::invalid_authority;
use crate::{Vault, error::Result};

const WINDOW_SECS: u64 = 60;
const REPLAY_PREFIX: &str = "authority:slip-replay:v2:";

/// The timestamp is part of the signed challenge, never an unsigned eviction hint.
pub(super) fn request_challenge(timestamp: u64, nonce: &[u8], now: u64) -> Result<Vec<u8>> {
    if now.abs_diff(timestamp) > WINDOW_SECS
        || nonce.len() != 32
        || !nonce
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(invalid_authority());
    }
    let nonce = std::str::from_utf8(nonce).map_err(|_| invalid_authority())?;
    Ok(holder_proof_challenge(timestamp, nonce))
}

/// The challenge a slip holder signs, through the slip's binding transcript,
/// to prove it holds the binding key.
#[must_use]
pub fn holder_proof_challenge(timestamp: u64, nonce: &str) -> Vec<u8> {
    format!("oneiron-request:{timestamp}:{nonce}").into_bytes()
}

/// A fresh holder proof for one request: a new nonce, signed through the
/// slip's binding transcript with the connection key. The proof is not a
/// replacement bearer token.
pub fn holder_proof(
    slip: &super::CapabilitySlip,
    key: &ed25519_dalek::SigningKey,
    timestamp: u64,
) -> Result<serde_json::Value> {
    use ed25519_dalek::Signer;
    let nonce = crate::EntityId::now().to_hex();
    let transcript = slip.binding_transcript(&holder_proof_challenge(timestamp, &nonce))?;
    let signature = super::slip::hex(&key.sign(&transcript).to_bytes());
    Ok(serde_json::json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}))
}

/// One row per admitted proof, keyed by its signed timestamp. The timestamp
/// window bounds the table: rows older than the window are evicted in the same
/// transaction, and a crowded table admits every fresh proof.
pub(super) fn record_nonce(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding_key: &[u8; 32],
    nonce: &[u8],
    timestamp: u64,
    now: u64,
) -> Result<()> {
    request_challenge(timestamp, nonce, now)?;
    // An evicted proof already fails `request_challenge`, so eviction opens no
    // replay.
    let floor = now.saturating_sub(WINDOW_SECS);
    let mut expired = Vec::new();
    for row in vault.store.sync_state.prefix_iter(txn, REPLAY_PREFIX)? {
        let (key, _) = row?;
        let signed_at = key
            .get(REPLAY_PREFIX.len()..REPLAY_PREFIX.len() + 16)
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .ok_or_else(invalid_authority)?;
        if signed_at >= floor {
            break;
        }
        expired.push(key.into_owned());
    }
    for key in expired {
        vault.store.sync_state.delete(txn, &key)?;
    }
    let mut material = binding_key.to_vec();
    material.extend_from_slice(nonce);
    let key = format!(
        "{REPLAY_PREFIX}{timestamp:016x}:{}",
        blake3::hash(&material).to_hex()
    );
    if vault.store.sync_state.get(txn, &key)?.is_some() {
        return Err(invalid_authority());
    }
    vault.store.sync_state.put(txn, &key, &[])?;
    Ok(())
}

#[cfg(test)]
mod tests;
