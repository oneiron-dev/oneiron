//! Bounded, timestamp-bound replay windows for authenticated slip requests.
use super::invalid_authority;
use crate::{Vault, error::Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const WINDOW_SECS: u64 = 60;
const WINDOW_SLOTS: u64 = 3;
const MAX_WINDOW_NONCES: usize = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayWindow {
    bucket: u64,
    nonces: BTreeSet<[u8; 32]>,
}

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

/// Three fixed rows cover the previous/current/next signed minute. A slot can
/// rotate only after every proof in its old bucket has expired (inclusive +60s).
/// Full live buckets refuse, never evict a replay witness to admit another call.
pub(super) fn record_nonce(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding_key: &[u8; 32],
    nonce: &[u8],
    timestamp: u64,
    now: u64,
) -> Result<()> {
    request_challenge(timestamp, nonce, now)?;
    let bucket = timestamp / WINDOW_SECS;
    let key = format!("authority:slip-replay:v1:{}", bucket % WINDOW_SLOTS);
    let mut window = match vault.store.sync_state.get(txn, &key)? {
        Some(raw) => {
            rmp_serde::from_slice::<ReplayWindow>(&raw).map_err(|_| invalid_authority())?
        }
        None => ReplayWindow {
            bucket,
            nonces: BTreeSet::new(),
        },
    };
    if window.nonces.len() > MAX_WINDOW_NONCES {
        return Err(invalid_authority());
    }
    if window.bucket != bucket {
        let expires_at = window.bucket.saturating_add(2).saturating_mul(WINDOW_SECS);
        if now < expires_at {
            return Err(invalid_authority());
        }
        window = ReplayWindow {
            bucket,
            nonces: BTreeSet::new(),
        };
    }
    if window.nonces.len() >= MAX_WINDOW_NONCES {
        return Err(invalid_authority());
    }
    let mut material = binding_key.to_vec();
    material.extend_from_slice(nonce);
    if !window.nonces.insert(*blake3::hash(&material).as_bytes()) {
        return Err(invalid_authority());
    }
    let bytes = rmp_serde::to_vec_named(&window).map_err(|_| invalid_authority())?;
    vault.store.sync_state.put(txn, &key, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests;
