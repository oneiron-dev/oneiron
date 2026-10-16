//! Node-side account API key verification (OF-448, the M4 node path of
//! CROSS-ARCH-0008 section 4, owner pick B of 2026-10-17).
//!
//! On managed hosting a vault request may carry an account API key. The
//! control plane owns the key lifecycle and the pepper: it stores peppered
//! HMAC digests and verifies by plain database lookup (the hash bar
//! [`crate::control_keys`] implements for the console path). A node never
//! holds the pepper and never pulls digests. Instead:
//!
//! - the first presentation of a key goes to one central check through
//!   [`CentralKeyCheck`], the host-supplied door to the control plane;
//! - a positive verdict is cached in memory for a short lease (default
//!   60 seconds, a host config row — see [`crate::managed::key_sync`]);
//! - a rotate, revoke or delete is pushed to the node and punched out of
//!   the cache at once ([`AccountKeys::punch`], acknowledged to the
//!   pusher); if a push is missed, the lease bounds the lag;
//! - failures are never cached and pay the fixed-time floor; successes
//!   are not padded.
//!
//! The cache index is a node-local SHA-256 fingerprint of the presented
//! key. It is an in-memory lookup key only: it verifies nothing by itself
//! (only a central verdict does), is never stored, and cannot be presented
//! as a credential.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::CoreScope;
use crate::control_keys::FAILURE_FLOOR;

/// Default verdict lease when the host config row names none.
pub const DEFAULT_VERDICT_LEASE_SECS: u64 = 60;
/// Longest verdict lease a host may configure. The lease is the worst
/// revoke lag when a punch push is missed, so it stays short.
pub const MAX_VERDICT_LEASE_SECS: u64 = 300;
/// Presented keys shorter than this are refused before any check.
const MIN_PLAINTEXT_LEN: usize = 32;
/// Presented keys longer than this are refused before any check.
const MAX_PLAINTEXT_LEN: usize = 512;
/// Most positive verdicts cached at once; past this, keys still verify
/// centrally on every call rather than growing the cache unbounded.
const MAX_CACHE_ENTRIES: usize = 4096;
/// How long a punch tombstone is kept, so a central check that started
/// before the punch cannot re-cache its stale verdict afterwards.
const TOMBSTONE_RETENTION_SECS: u64 = 3600;

#[derive(Debug, thiserror::Error)]
pub enum AccountKeyError {
    #[error("invalid account-key configuration or identifier")]
    Invalid,
    #[error("unknown, revoked, or expired account key")]
    Rejected,
    #[error("account-key central check unavailable or malformed")]
    Unavailable,
}

/// One positive central verdict: what the control plane established about
/// a presented key at `checked_at` on its own clock. The node trusts the
/// verdict's identity and scopes, but still enforces the key's expiry and
/// any later punch locally.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CentralKeyVerdict {
    /// Console-issued key identifier, unique per issued key.
    pub key_id: String,
    /// The registered principal this key acts as, when the console binds
    /// one (canonical entity-id hex).
    pub principal_ref: Option<String>,
    /// Granted scopes, in [`CoreScope`] spellings.
    pub scopes: BTreeSet<String>,
    /// The key's own finite expiry, unix seconds.
    pub expires_at: u64,
    /// When the control plane performed the check, unix seconds.
    pub checked_at: u64,
}

/// Boxed future of one central check.
pub type CentralCheckFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<CentralKeyVerdict>, AccountKeyError>> + Send + 'a>>;

/// The host's door to the control plane's key verifier.
///
/// `Ok(Some(verdict))` accepts the key, `Ok(None)` refuses it, and `Err`
/// means no verdict could be reached; the node fails closed on `Err` and
/// never extends a lease to cover an outage. The plaintext crosses only
/// this door, to the holder of the pepper.
pub trait CentralKeyCheck: Send + Sync {
    /// Checks one presented key with the control plane at `now`.
    fn check_account_key<'a>(&'a self, plaintext: &'a [u8], now: u64) -> CentralCheckFuture<'a>;
}

/// Node knobs for the verdict cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountKeyConfig {
    /// How long one positive verdict may be replayed from cache.
    pub verdict_lease: Duration,
}

impl Default for AccountKeyConfig {
    fn default() -> Self {
        Self {
            verdict_lease: Duration::from_secs(DEFAULT_VERDICT_LEASE_SECS),
        }
    }
}

impl AccountKeyConfig {
    /// A config with a lease of `secs` seconds, within the short-lease bar.
    pub fn with_lease_secs(secs: u64) -> Result<Self, AccountKeyError> {
        if secs == 0 || secs > MAX_VERDICT_LEASE_SECS {
            return Err(AccountKeyError::Invalid);
        }
        Ok(Self {
            verdict_lease: Duration::from_secs(secs),
        })
    }

    fn lease_secs(&self) -> u64 {
        self.verdict_lease.as_secs().max(1)
    }
}

/// What a successful verification establishes: identity and granted
/// scopes. Scope enforcement stays with the route, via `CoreAuth::require`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccountKey {
    /// Console-issued key identifier.
    pub key_id: String,
    /// The registered principal the verdict binds, when it binds one.
    pub principal_ref: Option<String>,
    /// Scopes the verdict granted.
    pub scopes: BTreeSet<CoreScope>,
    /// The key's own finite expiry, unix seconds.
    pub expires_at: u64,
    /// Node-clock time of this acceptance, unix seconds.
    pub last_used_at: u64,
    /// Node-local fingerprint of the presented key, as the exact
    /// instrument identity. Stable across cache hits and central checks.
    pub(crate) instrument: [u8; 32],
}

/// The node's receipt for one applied punch: the pushed rotate, revoke or
/// delete has removed the key's cached verdict and barred a stale
/// in-flight verdict from re-caching, as of `acked_at` on the node clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PunchAck {
    /// The punched key identifier.
    pub key_id: String,
    /// Cached verdicts this punch removed (0 when none was cached).
    pub removed: usize,
    /// When the punch was applied, unix seconds on the node clock.
    pub acked_at: u64,
}

struct CachedVerdict {
    key_id: String,
    principal_ref: Option<String>,
    scopes: BTreeSet<CoreScope>,
    key_expires_at: u64,
    /// End of this entry's lease on the node clock, unix seconds.
    lease_until: u64,
    last_used_at: u64,
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<[u8; 32], CachedVerdict>,
    /// Punched key ids and when the punch landed, node clock.
    punched: HashMap<String, u64>,
}

impl CacheState {
    fn prune(&mut self, now: u64) {
        self.entries
            .retain(|_, entry| now < entry.lease_until && now < entry.key_expires_at);
        self.punched
            .retain(|_, at| now.saturating_sub(*at) < TOMBSTONE_RETENTION_SECS);
    }
}

/// The node verifier: one central check per key per lease, an in-memory
/// verdict cache, and push-punched invalidation. Holds no pepper and no
/// credential material beyond presented-key fingerprints.
pub struct AccountKeys {
    checker: Arc<dyn CentralKeyCheck>,
    lease_secs: u64,
    state: Mutex<CacheState>,
}

impl fmt::Debug for AccountKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountKeys")
            .field("lease_secs", &self.lease_secs)
            .finish_non_exhaustive()
    }
}

impl AccountKeys {
    pub fn new(checker: Arc<dyn CentralKeyCheck>, config: AccountKeyConfig) -> Self {
        Self {
            checker,
            lease_secs: config.lease_secs(),
            state: Mutex::new(CacheState::default()),
        }
    }

    /// The configured verdict lease, in seconds.
    pub fn lease_secs(&self) -> u64 {
        self.lease_secs
    }

    /// Verifies one presented key. A live cached verdict answers from
    /// memory; anything else pays one central check. Every failure pays
    /// the fixed-time floor; successes are not padded.
    pub async fn verify(
        &self,
        plaintext: &[u8],
        now: u64,
    ) -> Result<VerifiedAccountKey, AccountKeyError> {
        let started = Instant::now();
        let result = self.verify_inner(plaintext, now).await;
        if result.is_err() {
            tokio::time::sleep(FAILURE_FLOOR.saturating_sub(started.elapsed())).await;
        }
        result
    }

    async fn verify_inner(
        &self,
        plaintext: &[u8],
        now: u64,
    ) -> Result<VerifiedAccountKey, AccountKeyError> {
        if !(MIN_PLAINTEXT_LEN..=MAX_PLAINTEXT_LEN).contains(&plaintext.len()) {
            return Err(AccountKeyError::Rejected);
        }
        let instrument = cache_index(plaintext);
        {
            let mut state = self.lock();
            state.prune(now);
            if let Some(entry) = state.entries.get_mut(&instrument) {
                entry.last_used_at = entry.last_used_at.max(now);
                return Ok(VerifiedAccountKey {
                    key_id: entry.key_id.clone(),
                    principal_ref: entry.principal_ref.clone(),
                    scopes: entry.scopes.clone(),
                    expires_at: entry.key_expires_at,
                    last_used_at: entry.last_used_at,
                    instrument,
                });
            }
        }
        let check_started = now;
        let verdict = self
            .checker
            .check_account_key(plaintext, now)
            .await?
            .ok_or(AccountKeyError::Rejected)?;
        let scopes = validate_verdict(&verdict, now)?;
        let mut state = self.lock();
        state.prune(now);
        // A punch that landed while this check was in flight, or after the
        // control plane judged the key, beats the verdict: the key died
        // after (or while) it was judged live. A punch strictly older
        // than both lets a re-issued key through on the fresh verdict.
        if let Some(punched_at) = state.punched.get(&verdict.key_id)
            && (*punched_at >= check_started || *punched_at >= verdict.checked_at)
        {
            return Err(AccountKeyError::Rejected);
        }
        if state.entries.len() < MAX_CACHE_ENTRIES {
            state.entries.insert(
                instrument,
                CachedVerdict {
                    key_id: verdict.key_id.clone(),
                    principal_ref: verdict.principal_ref.clone(),
                    scopes: scopes.clone(),
                    key_expires_at: verdict.expires_at,
                    lease_until: now.saturating_add(self.lease_secs).min(verdict.expires_at),
                    last_used_at: now,
                },
            );
        }
        Ok(VerifiedAccountKey {
            key_id: verdict.key_id,
            principal_ref: verdict.principal_ref,
            scopes,
            expires_at: verdict.expires_at,
            last_used_at: now,
            instrument,
        })
    }

    /// Punches one key id now: every cached verdict for it is removed and
    /// a tombstone bars stale in-flight verdicts from re-caching. This is
    /// the receiving end of the control plane's rotate/revoke/delete
    /// push; the returned [`PunchAck`] is its acknowledgement.
    pub fn punch(&self, key_id: &str, now: u64) -> Result<PunchAck, AccountKeyError> {
        if !valid_key_id(key_id) {
            return Err(AccountKeyError::Invalid);
        }
        let mut state = self.lock();
        state.prune(now);
        let before = state.entries.len();
        state.entries.retain(|_, entry| entry.key_id != key_id);
        let removed = before - state.entries.len();
        state
            .punched
            .entry(key_id.to_owned())
            .and_modify(|at| *at = (*at).max(now))
            .or_insert(now);
        Ok(PunchAck {
            key_id: key_id.to_owned(),
            removed,
            acked_at: now,
        })
    }

    /// How many positive verdicts are currently cached. Diagnostics only.
    pub fn cached_verdicts(&self) -> usize {
        self.lock().entries.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The in-memory cache index of a presented key. Domain-separated
/// SHA-256; proves nothing without a central verdict behind it.
fn cache_index(plaintext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron:account-key-cache:v1\0");
    hasher.update(plaintext);
    hasher.finalize().into()
}

/// Whether `key_id` is a bounded console key identifier.
pub(crate) fn valid_key_id(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id.len() <= 128
        && key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// Checks a central verdict before it can establish or cache anything. A
/// verdict that fails here authenticates nothing: malformed central
/// output is an outage, not a key the node improvises scopes for.
fn validate_verdict(
    verdict: &CentralKeyVerdict,
    now: u64,
) -> Result<BTreeSet<CoreScope>, AccountKeyError> {
    if !valid_key_id(&verdict.key_id)
        || verdict.expires_at <= now
        || verdict.expires_at == u64::MAX
        || verdict.checked_at == 0
    {
        return Err(AccountKeyError::Unavailable);
    }
    if let Some(principal_ref) = &verdict.principal_ref {
        let canonical = oneiron::EntityId::from_hex(principal_ref)
            .map(|id| id.to_hex())
            .map_err(|_| AccountKeyError::Unavailable)?;
        if &canonical != principal_ref {
            return Err(AccountKeyError::Unavailable);
        }
    }
    // Org-admin scopes are refused: they bind authority to an org and a
    // registered principal together, and a verdict carries no org binding
    // for the node to check them against.
    if verdict.scopes.is_empty() {
        return Err(AccountKeyError::Unavailable);
    }
    verdict
        .scopes
        .iter()
        .map(|scope| match CoreScope::parse(scope) {
            Some(CoreScope::OrgAdmin(_)) | None => Err(AccountKeyError::Unavailable),
            Some(scope) => Ok(scope),
        })
        .collect()
}
