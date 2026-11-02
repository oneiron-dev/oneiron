//! Durable client-named invocation claims (FIX 11889).
//!
//! The live `ClaimSlot` remains the fast path. This store is the restart
//! twin: an intent before the route runs, a settled JSON outcome beside its
//! release, bounded duplicate waits, and no open-intent expiry that can turn
//! into a second run. Its rows, locks and sweep are separate from HTTP keys.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::runtime_hooks::InvocationId;
use oneiron::runtime_hooks::verb::{InvocationOutcome, InvocationRelease};
use oneiron::store::{
    IdempotencyEntry, InvocationClaimEntry, InvocationClaimRelease, ResponseStamps,
    StoredPeerMachine,
};

const INVOCATION_CLAIM_PREFIX: &str = "http:invocation:";
pub(crate) const INVOCATION_CLAIM_TTL: Duration = Duration::from_secs(86_400);
/// A work quantum, not a claim bound: one admission measures one page.
const INVOCATION_CLAIM_SWEEP_ROWS: usize = 128;

/// The durable key for one invocation id.
pub(crate) fn invocation_claim_key(invocation: InvocationId) -> String {
    format!("{INVOCATION_CLAIM_PREFIX}{}", invocation.to_hex())
}

#[derive(Clone)]
pub(crate) struct InvocationClaimStore {
    vault: Arc<oneiron::Vault>,
    locks: Arc<InvocationClaimLockTable>,
}

impl InvocationClaimStore {
    pub(crate) fn new(vault: Arc<oneiron::Vault>) -> Self {
        Self {
            vault,
            locks: Arc::new(InvocationClaimLockTable::default()),
        }
    }

    pub(crate) async fn lock_for(&self, store_key: &str) -> InvocationClaimKeyGuard {
        self.locks.lock(store_key).await
    }

    pub(crate) fn lookup(
        &self,
        store_key: &str,
        request_body: &[u8],
    ) -> Result<InvocationClaimLookup, InvocationClaimStoreError> {
        loop {
            let now = now_secs();
            let Some(raw) = self
                .vault
                .sync_state_get(store_key)
                .map_err(InvocationClaimStoreError::storage)?
            else {
                return Ok(InvocationClaimLookup::Miss);
            };
            let Ok(raw) =
                oneiron::store::invocation_claim_response_read(store_key.as_bytes(), &raw)
            else {
                if oneiron::store::invocation_claim_opaque_retired_at(&raw)
                    .is_some_and(|retired| expired(retired, now))
                {
                    self.vault
                        .invocation_claim_reclaim_expired(
                            store_key,
                            now,
                            INVOCATION_CLAIM_TTL.as_secs(),
                        )
                        .map_err(InvocationClaimStoreError::storage)?;
                    continue;
                }
                return Ok(InvocationClaimLookup::Erased);
            };
            let stored =
                InvocationClaimEntry::decode(raw).map_err(InvocationClaimStoreError::storage)?;
            if expired(stored.created_at_secs, now) {
                self.vault
                    .invocation_claim_reclaim_expired(
                        store_key,
                        now,
                        INVOCATION_CLAIM_TTL.as_secs(),
                    )
                    .map_err(InvocationClaimStoreError::storage)?;
                continue;
            }
            if stored.erased {
                return Ok(InvocationClaimLookup::Erased);
            }
            if stored.request_body != request_body {
                return Ok(InvocationClaimLookup::Conflict);
            }
            if stored.reply_not_kept {
                return Ok(InvocationClaimLookup::ReplyNotKept {
                    committed_writes: stored.committed_writes,
                });
            }
            if stored.is_open_intent() {
                return Ok(InvocationClaimLookup::Interrupted {
                    committed_writes: stored.committed_writes,
                });
            }
            return outcome(stored).map(InvocationClaimLookup::Replay);
        }
    }

    /// Writes the intent before any route effect. The caller is an owner of
    /// the row from this first write, so its erase reaches an open claim too.
    pub(crate) fn insert_intent(
        &self,
        store_key: &str,
        request_body: [u8; 32],
        actor: Option<oneiron::EntityId>,
    ) -> Result<(), InvocationClaimStoreError> {
        let intent = InvocationClaimEntry {
            created_at_secs: now_secs(),
            request_body: request_body.to_vec(),
            status: IdempotencyEntry::INTENT_STATUS,
            stamps: ResponseStamps {
                actor,
                ..Default::default()
            },
            ..Default::default()
        };
        self.vault
            .invocation_claim_put(store_key, &intent)
            .map_err(InvocationClaimStoreError::storage)
    }

    /// Settles the standing open intent with the whole JSON outcome and the
    /// release a later caller judges again. The intent's original caller,
    /// creation and committed-write count stay on the row.
    pub(crate) fn settle(
        &self,
        store_key: &str,
        outcome: &InvocationOutcome,
    ) -> Result<bool, InvocationClaimStoreError> {
        let Some(raw) = self
            .vault
            .sync_state_get(store_key)
            .map_err(InvocationClaimStoreError::storage)?
        else {
            return Ok(false);
        };
        let standing =
            InvocationClaimEntry::decode(&raw).map_err(InvocationClaimStoreError::storage)?;
        if !standing.is_open_intent() {
            return Ok(false);
        }
        let release = outcome
            .release
            .as_ref()
            .map(|release| {
                Ok(InvocationClaimRelease {
                    peer: StoredPeerMachine::from(release.peer),
                    value: serde_json::to_vec(&release.value)
                        .map_err(InvocationClaimStoreError::json)?,
                    rows: release.rows.clone(),
                })
            })
            .transpose()?;
        let stored = InvocationClaimEntry {
            created_at_secs: standing.created_at_secs,
            request_body: standing.request_body,
            status: outcome.status,
            response_body: serde_json::to_vec(&outcome.body)
                .map_err(InvocationClaimStoreError::json)?,
            release,
            stamps: standing.stamps,
            erased: false,
            committed_writes: standing.committed_writes,
            reply_not_kept: false,
        };
        self.vault
            .invocation_claim_settle(store_key, &stored)
            .map_err(InvocationClaimStoreError::storage)
    }

    /// Releases a normally unfinished or failed call. A process crash runs
    /// no destructor, so its intent remains and can never be mistaken for a
    /// released failure.
    pub(crate) fn release_intent(&self, store_key: &str) -> Result<(), InvocationClaimStoreError> {
        self.vault
            .sync_state_delete(store_key)
            .map(|_| ())
            .map_err(InvocationClaimStoreError::storage)
    }

    /// Measures one page and reclaims only expired rows. Open intents are
    /// terminalized by the engine method, never deleted into a fresh run.
    pub(crate) async fn reclaim_expired_page(&self) {
        let mut cursor = self.locks.sweep.0.lock().await;
        let now = now_secs();
        let mut expired_keys = Vec::new();
        let page = self.vault.sync_state_prefix_page(
            INVOCATION_CLAIM_PREFIX,
            cursor.as_deref(),
            INVOCATION_CLAIM_SWEEP_ROWS,
            |key, raw| {
                let expired = InvocationClaimEntry::decode(raw)
                    .ok()
                    .is_some_and(|entry| expired(entry.created_at_secs, now))
                    || oneiron::store::invocation_claim_opaque_retired_at(raw)
                        .is_some_and(|retired| expired(retired, now));
                if expired {
                    expired_keys.push(key.to_owned());
                }
                Ok(())
            },
        );
        let next = match page {
            Ok(next) => next,
            Err(error) => {
                tracing::warn!(
                    reason = "invocation_claim_cleanup_failed",
                    error = %error,
                    "failed to scan expired invocation claims"
                );
                return;
            }
        };
        for key in expired_keys {
            if let Err(error) = self.vault.invocation_claim_reclaim_expired(
                &key,
                now,
                INVOCATION_CLAIM_TTL.as_secs(),
            ) {
                tracing::warn!(
                    reason = "invocation_claim_cleanup_failed",
                    error = %error,
                    "failed to reclaim an expired invocation claim"
                );
                return;
            }
        }
        *cursor = next;
    }
}

fn expired(since: u64, now: u64) -> bool {
    now.saturating_sub(since) >= INVOCATION_CLAIM_TTL.as_secs()
}

fn outcome(stored: InvocationClaimEntry) -> Result<InvocationOutcome, InvocationClaimStoreError> {
    let release = stored
        .release
        .map(|release| {
            Ok(InvocationRelease {
                peer: release.peer.into(),
                value: serde_json::from_slice(&release.value)
                    .map_err(InvocationClaimStoreError::json)?,
                rows: release.rows,
            })
        })
        .transpose()?;
    Ok(InvocationOutcome {
        status: stored.status,
        body: serde_json::from_slice(&stored.response_body)
            .map_err(InvocationClaimStoreError::json)?,
        release,
    })
}

pub(crate) enum InvocationClaimLookup {
    Miss,
    Replay(InvocationOutcome),
    Conflict,
    Erased,
    Interrupted { committed_writes: u32 },
    ReplyNotKept { committed_writes: u32 },
}

#[derive(Default)]
struct InvocationClaimLockTable {
    slots: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    sweep: SweepCursor,
}

impl InvocationClaimLockTable {
    async fn lock(self: &Arc<Self>, store_key: &str) -> InvocationClaimKeyGuard {
        let slot = {
            let mut slots = self.slots.lock().await;
            slots
                .entry(store_key.to_owned())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let guard = slot.clone().lock_owned().await;
        InvocationClaimKeyGuard {
            store_key: store_key.to_owned(),
            slot,
            table: self.clone(),
            guard: Some(guard),
        }
    }
}

pub(crate) struct InvocationClaimKeyGuard {
    store_key: String,
    slot: Arc<tokio::sync::Mutex<()>>,
    table: Arc<InvocationClaimLockTable>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for InvocationClaimKeyGuard {
    fn drop(&mut self) {
        self.guard.take();
        if Arc::strong_count(&self.slot) != 2 {
            return;
        }
        let Ok(mut slots) = self.table.slots.try_lock() else {
            return;
        };
        let Some(slot) = slots.get(&self.store_key) else {
            return;
        };
        if Arc::ptr_eq(slot, &self.slot) && Arc::strong_count(&self.slot) == 2 {
            slots.remove(&self.store_key);
        }
    }
}

#[derive(Default)]
struct SweepCursor(tokio::sync::Mutex<Option<String>>);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Debug)]
pub(crate) struct InvocationClaimStoreError {
    message: String,
}

impl InvocationClaimStoreError {
    fn storage(error: oneiron::Error) -> Self {
        Self {
            message: format!("invocation claim store error: {error}"),
        }
    }

    fn json(error: serde_json::Error) -> Self {
        Self {
            message: format!("invocation claim JSON error: {error}"),
        }
    }
}

impl fmt::Display for InvocationClaimStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
