//! Reclaim of expired idempotency entries (FIX 5951). The cache has no
//! expiry index, so each keyed admission measures one page of the whole
//! cache, from where the last page stopped, and deletes the entries there
//! that a lookup would find expired. A live entry is never deleted, and
//! nothing is capped, evicted or refused; a page that fails is logged and the
//! request goes on.

use super::{
    IDEMPOTENCY_SYNC_STATE_PREFIX, IDEMPOTENCY_TTL, IdempotencyStore, StoredIdempotencyEntry,
};

/// The rows of the whole cache one keyed admission measures (CALLS: FIX 5951
/// idempotency sweep quantum). A work quantum, not a cache limit: a page that
/// reaches it keeps its place for the next admission.
const IDEMPOTENCY_SWEEP_ROWS: usize = 128;

/// Where the next page starts: after this key, or at the cache's start. It
/// wraps at the cache's end, and a restart starts it over.
#[derive(Default)]
pub(super) struct SweepCursor(tokio::sync::Mutex<Option<String>>);

impl IdempotencyStore {
    /// Measures one page of the cache and deletes the entries expired in it.
    pub(super) async fn reclaim_expired_page(&self) {
        let mut cursor = self.locks.sweep.0.lock().await;
        let now = self.now_secs();
        let page = self.vault.sync_state_reclaim_prefix_page(
            IDEMPOTENCY_SYNC_STATE_PREFIX,
            cursor.as_deref(),
            IDEMPOTENCY_SWEEP_ROWS,
            |raw| Ok(expired_at(raw, now)),
        );
        match page {
            Ok(next) => *cursor = next,
            Err(error) => tracing::warn!(
                reason = "idempotency_cleanup_failed",
                error = %error,
                "failed to reclaim expired idempotency entries"
            ),
        }
    }
}

/// Whether `raw` is an entry a lookup at `now` finds expired. A row that does
/// not decode is not judged here, and stays.
fn expired_at(raw: &[u8], now: u64) -> bool {
    rmp_serde::from_slice::<StoredIdempotencyEntry>(raw)
        .is_ok_and(|stored| now.saturating_sub(stored.created_at_secs) >= IDEMPOTENCY_TTL.as_secs())
}
