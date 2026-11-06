//! The canonical settlement of a code-run wait, in the caller's writer: the
//! settled row installed once, and the settled reply delivered to every run
//! parked on the wait.

use super::{
    SETTLED, SETTLED_TAG, WAITERS, WaitDelivery, WaitKey, deliver_in_txn, reply_text,
    settled_in_txn, waiter_prefix,
};
use crate::{EntityId, Result, Vault};

/// Settles `wait_id` with `reply` in the caller's transaction: records the
/// reply unless the wait already settled, then delivers the settled reply to
/// every run parked on it that has none, waking each one's bound trap in the
/// same commit. Returns how many runs this call delivered to.
pub(crate) fn deliver_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    reply: &serde_json::Value,
    now_ms: u64,
) -> Result<usize> {
    deliver_wait_listing_in_txn(vault, txn, wait_id, reply, None, now_ms)
}

/// [`deliver_wait_in_txn`], `reply` kept beside `rows`, the rows its settler
/// listed it derived from (FIX 5455), when it lists them.
pub(crate) fn deliver_wait_listing_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    reply: &serde_json::Value,
    rows: Option<&[EntityId]>,
    now_ms: u64,
) -> Result<usize> {
    let settled = match settled_in_txn(&vault.store, txn, wait_id)? {
        Some(settled) => settled,
        None => {
            let mut settled = WaitDelivery {
                reply: reply_text(reply)?,
                delivered_at_ms: now_ms,
                source_rows: rows.map(<[EntityId]>::to_vec),
                erased: false,
            };
            SETTLED.admit(vault, txn, &(SETTLED_TAG, wait_id), &mut settled)?;
            SETTLED.put(&vault.store, txn, &(SETTLED_TAG, wait_id), &settled)?;
            settled
        }
    };
    let mut delivered = 0;
    for ((_, _, run), generation) in
        WAITERS.scan_from(&vault.store, txn, &waiter_prefix(wait_id))?
    {
        let key = WaitKey {
            run,
            wait_id,
            generation,
        };
        if deliver_in_txn(vault, txn, &key, &settled)? {
            delivered += 1;
        }
    }
    Ok(delivered)
}
