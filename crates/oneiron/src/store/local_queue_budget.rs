//! Byte accounting for bounded device-local queues, separate from verdict/rate policy.
use crate::Result;
use crate::overlay_db::OverlayDb;

/// Bound keys plus encoded values. An existing key is replaced, not double-counted.
/// Passing `budget` is a threshold observation, counted and logged, never a refusal:
/// accepted work is kept, and the write itself meets the store's real floor (FIX 8852).
pub(crate) fn check_queue_capacity(
    db: &OverlayDb,
    txn: &heed::RoTxn<'_>,
    prefix: &[u8],
    key: &[u8],
    value_len: usize,
    budget: usize,
) -> Result<()> {
    let mut used = key.len().saturating_add(value_len);
    for row in db.prefix_iter(txn, prefix)? {
        let (stored_key, value) = row?;
        if stored_key.as_ref() != key {
            used = used
                .saturating_add(stored_key.len())
                .saturating_add(value.len());
        }
        if used > budget {
            break;
        }
    }
    if used > budget {
        tracing::warn!(
            prefix = %String::from_utf8_lossy(prefix),
            used,
            threshold = budget,
            "local queue passed its byte threshold; the work is kept"
        );
    }
    Ok(())
}
