//! The canonical settlement of a code-run wait, in the caller's writer: the
//! settled row installed once, and the settled reply delivered to every run
//! parked on the wait.
//!
//! A connector call's wait also holds its settled reply for the call's
//! caller (FIX 6656). Every canonical settle writes that membership in its
//! own writer, whichever wrapper settles the wait.

use super::super::wait_holders::hold_settled_for_caller_in_txn;
use super::{
    SETTLED, SETTLED_TAG, WAITERS, WaitDelivery, WaitKey, deliver_in_txn, reply_text,
    settled_in_txn, waiter_prefix,
};
use crate::code_run::ResultOrigins;
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
    deliver_wait_listing_in_txn(vault, txn, wait_id, reply, None, None, now_ms)
}

/// [`deliver_wait_in_txn`], `reply` kept beside `rows`, the rows its settler
/// listed it derived from (FIX 5455), when it lists them, and beside
/// `origins`, the origins its settler froze with it (FIX 7083), when it
/// froze them. A wait that already settled keeps its first reply whole,
/// its rows and origins with it. When `wait_id` is a connector call's
/// wait, the call's caller joins the wait's holders in this writer, after
/// every parked run joined (FIX 6656). So the membership commits with the
/// settled row, before any post-commit observer runs.
pub(crate) fn deliver_wait_listing_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    reply: &serde_json::Value,
    rows: Option<&[EntityId]>,
    origins: Option<&ResultOrigins>,
    now_ms: u64,
) -> Result<usize> {
    let settled = match settled_in_txn(&vault.store, txn, wait_id)? {
        Some(settled) => settled,
        None => {
            let mut settled = WaitDelivery {
                reply: reply_text(reply)?,
                delivered_at_ms: now_ms,
                source_rows: rows.map(<[EntityId]>::to_vec),
                origins: origins.cloned(),
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
    if let Some(caller) = connector_call_caller_in_txn(vault, txn, wait_id)? {
        hold_settled_for_caller_in_txn(vault, txn, wait_id, caller)?;
    }
    Ok(delivered)
}

/// The actor whose connector call `wait_id` is (FIX 6656), read in the
/// settling writer `txn` from the call's held or acknowledged row. It is the
/// actor whose hex id is exactly the row's `principal_ref`: the caller that
/// `connector.call_status` admits, and the actor whose erase drops the row.
/// It is never the settler's actor. A principal that is no actor's hex id is
/// not an actor: it has no actor to erase, so it holds no membership, and
/// only the owner reads its status. `None` for a wait that is no connector
/// call's.
fn connector_call_caller_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wait_id: EntityId,
) -> Result<Option<EntityId>> {
    let Some(state) = vault.connector_call_state_in_txn(txn, &wait_id)? else {
        return Ok(None);
    };
    Ok(EntityId::from_hex(&state.principal_ref)
        .ok()
        .filter(|actor| actor.to_hex() == state.principal_ref))
}
