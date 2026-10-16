//! Managed-host wiring for the node account-key path (OF-448, the node
//! half of CROSS-ARCH-0008 section 4, owner pick B of 2026-10-17).
//!
//! The control plane owns the account-key lifecycle and the pepper. A
//! node holds no digests and pulls nothing: it checks a presented key
//! centrally once, caches the verdict for a short lease
//! ([`crate::auth::account_key`]), and keeps that cache honest with
//! pushed invalidations:
//!
//! - **Revoke propagation is settled as push-then-ack.** A rotate,
//!   revoke, or delete reaches the node as a [`KeyInvalidation`]; the
//!   node punches the verdict cache immediately and returns a
//!   [`KeyInvalidationAck`] in the same call. The pusher retries until
//!   it holds every node's ack; if a push is never delivered, the
//!   verdict lease bounds how long a dead key can still verify.
//! - **Pepper custody stays with the control plane.** Sync carries key
//!   ids only — never plaintext, never digests, never the pepper. The
//!   node-side door to the pepper holder is the host-supplied
//!   [`CentralKeyCheck`]; that transport is the host's to build.
//! - **The lease is a host config row.** The vault's
//!   `managed:account-key-lease:v1` row (u64 big-endian seconds) sets
//!   it; absent, the default is 60 seconds.

use std::sync::Arc;

use oneiron::Vault;
use serde::{Deserialize, Serialize};

pub use crate::auth::account_key::{
    AccountKeyConfig, AccountKeyError, AccountKeys, CentralCheckFuture, CentralKeyCheck,
    CentralKeyVerdict, DEFAULT_VERDICT_LEASE_SECS, MAX_VERDICT_LEASE_SECS, PunchAck,
    VerifiedAccountKey,
};

/// `sync_state` host config row holding the verdict lease in seconds
/// (u64 big-endian). Written by the host; the node only reads it.
pub const LEASE_CONFIG_KEY: &str = "managed:account-key-lease:v1";

/// Which console act a pushed invalidation carries. All three kill the
/// named key's cached verdict identically; the kind is evidence for the
/// node's logs, not a different cache act.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyInvalidationKind {
    /// The key was replaced; the old key is dead.
    Rotated,
    /// The key was revoked.
    Revoked,
    /// The key was deleted.
    Deleted,
}

/// One control-plane push: the named account key no longer lives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInvalidation {
    /// The dead key's console identifier.
    pub key_id: String,
    /// Which console act killed it.
    pub kind: KeyInvalidationKind,
    /// When the console performed the act, unix seconds on its clock.
    /// Evidence only: the node's own clock orders its cache.
    pub issued_at: u64,
}

/// The node's acknowledgement of one applied invalidation.
pub type KeyInvalidationAck = PunchAck;

/// Applies one pushed invalidation now and acknowledges it in the same
/// call. The ack is the pusher's proof this node no longer serves the
/// key from cache; anything not acked is bounded by the verdict lease.
pub fn apply_key_invalidation(
    keys: &AccountKeys,
    invalidation: &KeyInvalidation,
    now: u64,
) -> Result<KeyInvalidationAck, AccountKeyError> {
    keys.punch(&invalidation.key_id, now)
}

/// The verdict lease the host configured for this vault: the
/// `managed:account-key-lease:v1` row when present, else the 60-second
/// default. A malformed or out-of-bar row refuses the verifier rather
/// than silently running an unbounded lease.
pub fn verdict_lease_from_vault(vault: &Vault) -> Result<AccountKeyConfig, AccountKeyError> {
    let Some(bytes) = vault
        .sync_state_get(LEASE_CONFIG_KEY)
        .map_err(|_| AccountKeyError::Unavailable)?
    else {
        return Ok(AccountKeyConfig::default());
    };
    let raw: [u8; 8] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AccountKeyError::Invalid)?;
    AccountKeyConfig::with_lease_secs(u64::from_be_bytes(raw))
}

/// Builds the node verifier from the host's central checker and an
/// explicit config.
pub fn account_keys(checker: Arc<dyn CentralKeyCheck>, config: AccountKeyConfig) -> AccountKeys {
    AccountKeys::new(checker, config)
}

/// Builds the node verifier from the host's central checker and the
/// vault's lease config row.
pub fn account_keys_from_vault_config(
    vault: &Vault,
    checker: Arc<dyn CentralKeyCheck>,
) -> Result<AccountKeys, AccountKeyError> {
    Ok(AccountKeys::new(checker, verdict_lease_from_vault(vault)?))
}
