//! Control-plane API keys: HMAC-SHA256 at rest, transactional uniqueness,
//! and a database lookup on every verification. No credential cache exists.

use hmac::{Hmac, Mac};
use oneiron::Vault;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub mod http;

const PREFIX: &str = "auth:control-key:v1:";
const DEFAULT_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;
/// Authentication failures alone pay this minimum wall-clock duration.
pub const FAILURE_FLOOR: Duration = Duration::from_millis(20);

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid control-key configuration")]
    Invalid,
    #[error("control-key digest already exists")]
    Duplicate,
    #[error("unknown, revoked, or expired control key")]
    Rejected,
    #[error("control-key scope denied")]
    ScopeDenied,
    #[error("control-key storage failure")]
    Storage(#[from] oneiron::Error),
    #[error("invalid control-key row")]
    Corrupt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// This is a digest, never the supplied credential or pepper.
    pub digest: String,
    pub scopes: BTreeSet<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_used_at: Option<u64>,
    pub revoked: bool,
}

/// Owned by one server instance. The pepper is zeroized on drop and omitted
/// from Debug; the vault stores only HMAC digests and authorization metadata.
pub struct ControlKeys {
    vault: Arc<Vault>,
    pepper: Zeroizing<Vec<u8>>,
}
impl ControlKeys {
    pub fn new(vault: Arc<Vault>, pepper: Zeroizing<Vec<u8>>) -> Result<Self, KeyError> {
        if pepper.len() < 32 {
            return Err(KeyError::Invalid);
        }
        Ok(Self { vault, pepper })
    }
    fn digest(&self, plaintext: &[u8]) -> String {
        // HMAC accepts arbitrary key lengths. Construction cannot fail.
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.pepper).expect("HMAC key length");
        mac.update(b"oneiron:control-key:v1\0");
        mac.update(plaintext);
        oneiron_vault_contract::hex(&mac.finalize().into_bytes())
    }
    fn row(
        &self,
        plaintext: &[u8],
        scopes: BTreeSet<String>,
        now: u64,
        expires_at: Option<u64>,
    ) -> Result<KeyRecord, KeyError> {
        let expires_at = match expires_at {
            Some(at) => at,
            None => now
                .checked_add(DEFAULT_LIFETIME_SECS)
                .ok_or(KeyError::Invalid)?,
        };
        if plaintext.len() < 32
            || expires_at <= now
            || expires_at == u64::MAX
            || scopes.is_empty()
            || scopes.iter().any(|s| {
                s.is_empty()
                    || s.len() > 128
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-')
            })
        {
            return Err(KeyError::Invalid);
        }
        Ok(KeyRecord {
            digest: self.digest(plaintext),
            scopes,
            created_at: now,
            expires_at,
            last_used_at: None,
            revoked: false,
        })
    }
    /// UNIQUE(hash) is an existence check and insertion in ONE LMDB writer.
    pub fn insert(
        &self,
        plaintext: &[u8],
        scopes: BTreeSet<String>,
        now: u64,
        expires_at: Option<u64>,
    ) -> Result<KeyRecord, KeyError> {
        let row = self.row(plaintext, scopes, now, expires_at)?;
        self.vault.try_with_write_txn(|txn| {
            let key = format!("{PREFIX}{}", row.digest);
            if self.vault.sync_state_get_in_write_txn(txn, &key)?.is_some() {
                return Err(KeyError::Duplicate);
            }
            self.vault
                .sync_state_put_in_write_txn(txn, &key, &encode(&row)?)?;
            Ok(row)
        })
    }
    /// Every call reads the database, checks current scopes/revocation/expiry,
    /// and stamps acceptance atomically. Storage and scope failures pay the
    /// same floor as unknown keys. There is no positive or negative cache.
    pub async fn verify(
        &self,
        plaintext: &[u8],
        scope: &str,
        now: u64,
    ) -> Result<KeyRecord, KeyError> {
        let started = Instant::now();
        let key = format!("{PREFIX}{}", self.digest(plaintext));
        let result = self.vault.try_with_write_txn(|txn| {
            let bytes = self
                .vault
                .sync_state_get_in_write_txn(txn, &key)?
                .ok_or(KeyError::Rejected)?;
            let mut row = decode(&bytes)?;
            validate_lookup(&row, &key)?;
            if row.revoked || now >= row.expires_at || now < row.created_at {
                return Err(KeyError::Rejected);
            }
            if !row.scopes.contains(scope) {
                return Err(KeyError::ScopeDenied);
            }
            row.last_used_at = Some(row.last_used_at.unwrap_or(now).max(now));
            self.vault
                .sync_state_put_in_write_txn(txn, &key, &encode(&row)?)?;
            Ok(row)
        });
        if result.is_err() {
            tokio::time::sleep(FAILURE_FLOOR.saturating_sub(started.elapsed())).await;
        }
        result
    }
    /// Atomic replacement keeps scopes unchanged. Failed insertion leaves the
    /// original live; a successful replacement revokes it in the same commit.
    pub fn rotate(&self, old: &[u8], new: &[u8], now: u64) -> Result<KeyRecord, KeyError> {
        let old_key = format!("{PREFIX}{}", self.digest(old));
        self.vault.try_with_write_txn(|txn| {
            let bytes = self
                .vault
                .sync_state_get_in_write_txn(txn, &old_key)?
                .ok_or(KeyError::Rejected)?;
            let mut old = decode(&bytes)?;
            validate_lookup(&old, &old_key)?;
            if old.revoked || now >= old.expires_at || now < old.created_at {
                return Err(KeyError::Rejected);
            }
            let new = self.row(new, old.scopes.clone(), now, None)?;
            let new_key = format!("{PREFIX}{}", new.digest);
            if self
                .vault
                .sync_state_get_in_write_txn(txn, &new_key)?
                .is_some()
            {
                return Err(KeyError::Duplicate);
            }
            old.revoked = true;
            self.vault
                .sync_state_put_in_write_txn(txn, &new_key, &encode(&new)?)?;
            self.vault
                .sync_state_put_in_write_txn(txn, &old_key, &encode(&old)?)?;
            Ok(new)
        })
    }
    pub fn revoke(&self, plaintext: &[u8]) -> Result<(), KeyError> {
        let key = format!("{PREFIX}{}", self.digest(plaintext));
        self.vault.try_with_write_txn(|txn| {
            let bytes = self
                .vault
                .sync_state_get_in_write_txn(txn, &key)?
                .ok_or(KeyError::Rejected)?;
            let mut row = decode(&bytes)?;
            validate_lookup(&row, &key)?;
            row.revoked = true;
            self.vault
                .sync_state_put_in_write_txn(txn, &key, &encode(&row)?)?;
            Ok(())
        })
    }
    pub fn record(&self, digest: &str) -> Result<Option<KeyRecord>, KeyError> {
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(KeyError::Invalid);
        }
        self.vault
            .sync_state_get(&format!("{PREFIX}{digest}"))?
            .map(|raw| decode(&raw))
            .transpose()
    }
}
fn encode(row: &KeyRecord) -> Result<Vec<u8>, KeyError> {
    rmp_serde::to_vec_named(row).map_err(|_| KeyError::Corrupt)
}
fn decode(raw: &[u8]) -> Result<KeyRecord, KeyError> {
    rmp_serde::from_slice(raw).map_err(|_| KeyError::Corrupt)
}

#[cfg(test)]
mod tests;

fn validate_lookup(row: &KeyRecord, key: &str) -> Result<(), KeyError> {
    if key != format!("{PREFIX}{}", row.digest)
        || row.expires_at <= row.created_at
        || row.expires_at == u64::MAX
        || row.scopes.is_empty()
        || row
            .last_used_at
            .is_some_and(|used| used < row.created_at || used >= row.expires_at)
    {
        return Err(KeyError::Corrupt);
    }
    Ok(())
}
