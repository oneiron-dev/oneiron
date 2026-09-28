//! Bounded, timestamp-bound replay windows for authenticated slip requests.
use super::invalid_authority;
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::{Vault, error::Result};

const WINDOW_SECS: u64 = 60;
/// Kept for [`tests`], which seed rows directly under the raw prefix; production code reaches
/// this table only through [`REPLAY_NONCE`] now.
#[cfg(test)]
const REPLAY_PREFIX: &str = "authority:slip-replay:v2:";

/// Key of one admitted replay-nonce marker: the signed timestamp as 16 lowercase hex digits,
/// then `:`, then the keyed digest of (binding key + nonce) as 64 lowercase hex digits — the
/// pre-migration `{timestamp:016x}:{digest_hex}` spelling, minus the shared prefix the table
/// now carries.
struct NonceKey {
    timestamp: u64,
    digest_hex: String,
}

impl SideKey for NonceKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(format!("{:016x}", self.timestamp).as_bytes());
        out.push(b':');
        out.extend_from_slice(self.digest_hex.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let (ts_hex, digest_hex) = text.split_once(':')?;
        if ts_hex.len() != 16 || digest_hex.len() != 64 {
            return None;
        }
        Some(Self {
            timestamp: u64::from_str_radix(ts_hex, 16).ok()?,
            digest_hex: digest_hex.to_owned(),
        })
    }
}

/// Admitted request nonce inside the replay window (empty marker). Key: u64hex16 ":" hex64.
const REPLAY_NONCE: SideTable<NonceKey, (), Raw> =
    SideTable::new(&side_table::AUTHORITY_SLIP_REPLAY_NONCE);

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
    for row in REPLAY_NONCE.iter_from(&vault.store, txn, &[])? {
        let (key, ()) = row?;
        if key.timestamp >= floor {
            break;
        }
        expired.push(key);
    }
    for key in expired {
        REPLAY_NONCE.delete(&vault.store, txn, &key)?;
    }
    let mut material = binding_key.to_vec();
    material.extend_from_slice(nonce);
    let key = NonceKey {
        timestamp,
        digest_hex: blake3::hash(&material).to_hex().to_string(),
    };
    if REPLAY_NONCE.contains(&vault.store, txn, &key)? {
        return Err(invalid_authority());
    }
    REPLAY_NONCE.put(&vault.store, txn, &key, &())?;
    Ok(())
}

#[cfg(test)]
mod tests;
