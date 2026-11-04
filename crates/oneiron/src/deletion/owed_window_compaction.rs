//! Window-compaction obligations written by an erase.

use std::collections::BTreeSet;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::window_key::WindowKey;

/// Sweep-queue prefix of an owed window compaction, `hc:{window}`. Its value
/// is a fresh id per raise, so a pass settles only the raise it read, then
/// the receipts waiting on it.
pub(crate) const OWED_COMPACTION_PREFIX: &[u8] = b"hc:";

/// The bytes of one id in an owed row's value.
const ID_LEN: usize = 16;

/// Owes the erasure sweep a compaction of `window`, in the caller's
/// transaction: an erase, or a hold release, whose scrub changed the window's
/// stored state without compacting it. The next sweep pass compacts the
/// window once nothing holds it open. A raise while a pass is under way waits
/// for the pass after.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn owe_window_compaction_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window: &WindowKey,
) -> Result<()> {
    raise_in_txn(vault, wtxn, window, None).map(drop)
}

/// [`owe_window_compaction_in_txn`] for the erase receipt `receipt` that
/// waits on the compaction (FIX 10234): the row names it, beside any receipt
/// an earlier raise named, and its settlement completes each. Returns the
/// row's key.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn owe_window_compaction_for_receipt_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window: &WindowKey,
    receipt: &EntityId,
) -> Result<Vec<u8>> {
    raise_in_txn(vault, wtxn, window, Some(receipt))
}

/// Raises `window`'s owed compaction afresh, keeping each receipt the row
/// already names and adding `receipt`. Returns the row's key.
fn raise_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window: &WindowKey,
    receipt: Option<&EntityId>,
) -> Result<Vec<u8>> {
    let key = [OWED_COMPACTION_PREFIX, window.as_str().as_bytes()].concat();
    let raise = vault.store.clock.entity_id()?;
    let mut waiting = vault
        .store
        .sync_queue
        .get(&*wtxn, &key)?
        .map(|value| waiting_receipts(&value))
        .unwrap_or_default();
    waiting.extend(receipt.copied());
    let mut value = raise.as_bytes().to_vec();
    for receipt in &waiting {
        value.extend_from_slice(receipt.as_bytes());
    }
    vault.store.sync_queue.put(wtxn, &key, &value)?;
    Ok(key)
}

/// The receipts an owed row's `value` names after its raise; a tail that is
/// no whole id names none past it.
pub(crate) fn waiting_receipts(value: &[u8]) -> BTreeSet<EntityId> {
    value
        .get(ID_LEN..)
        .unwrap_or_default()
        .chunks_exact(ID_LEN)
        .filter_map(|bytes| EntityId::from_bytes(bytes.try_into().ok()?).ok())
        .collect()
}

