//! Window compactions an erase owes (FIX 6387).
//!
//! A scrub that drops a carrier from a stored window in its own transaction
//! leaves the operation that put the carrier there in the window's stored
//! history until the window is compacted. It owes the erasure sweep that
//! compaction: one `hc:{window}` row in the sweep queue, written in its
//! transaction. A pass that compacts every window settles each row. Any other
//! pass compacts each owed window on its own and settles it once it has; a
//! window still open, raced or held, or whose cut was not proved to root at
//! its tip (FIX 6520), keeps its row for the next pass.
//!
//! A row may also name the erase receipts that wait on its compaction (FIX
//! 10234): an audience edit erased in place leaves its earlier revisions in
//! the window's history, and its receipt completes once the row settles.
//! The row's value is the raise, then each such receipt's id.

use std::collections::BTreeSet;

use super::compact::{CompactOutcome, compact_window_with};
use super::run::{HardEraseSweepRun, WindowSweepState, WithdrawnSweep};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::sync::types::WindowKey;

/// Sweep-queue prefix of an owed window compaction, `hc:{window}`. Its value
/// is a fresh id per raise, so a pass settles only the raise it read, then
/// the receipts waiting on it.
const OWED_COMPACTION_PREFIX: &[u8] = b"hc:";

/// The bytes of one id in an owed row's value.
const ID_LEN: usize = 16;

/// One owed compaction, as a pass read it before compacting anything.
pub(super) struct OwedCompaction {
    key: Vec<u8>,
    raise: Vec<u8>,
    window: WindowKey,
}

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
fn waiting_receipts(value: &[u8]) -> BTreeSet<EntityId> {
    value
        .get(ID_LEN..)
        .unwrap_or_default()
        .chunks_exact(ID_LEN)
        .filter_map(|bytes| EntityId::from_bytes(bytes.try_into().ok()?).ok())
        .collect()
}

/// The owed compactions, read before the pass compacts anything. A row whose
/// label is no window key can never be compacted: it is kept and reported,
/// never settled.
pub(super) fn owed_compactions(vault: &Vault) -> Result<Vec<OwedCompaction>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut owed = Vec::new();
    for row in vault
        .store
        .sync_queue
        .prefix_iter(&rtxn, OWED_COMPACTION_PREFIX)?
    {
        let (key, raise) = row?;
        let window = key
            .strip_prefix(OWED_COMPACTION_PREFIX)
            .and_then(|label| std::str::from_utf8(label).ok())
            .and_then(WindowKey::try_new);
        match window {
            Some(window) => owed.push(OwedCompaction {
                key: key.to_vec(),
                raise: raise.to_vec(),
                window,
            }),
            None => tracing::error!(
                key_len = key.len(),
                "sweep: hc: row names no window — obligation kept, cannot execute"
            ),
        }
    }
    Ok(owed)
}

/// The erase receipts the owed compactions in `txn` name (FIX 11082): each
/// completes when its row settles, so the sweep's audit counts it owed, not
/// dropped. A row that names no window never settles and covers none, as an
/// undecodable `h:` row covers none.
pub(super) fn receipts_owed_compaction_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let mut receipts = BTreeSet::new();
    for row in vault
        .store
        .sync_queue
        .prefix_iter(txn, OWED_COMPACTION_PREFIX)?
    {
        let (key, value) = row?;
        let names_window = key
            .strip_prefix(OWED_COMPACTION_PREFIX)
            .and_then(|label| std::str::from_utf8(label).ok())
            .and_then(WindowKey::try_new)
            .is_some();
        if names_window {
            receipts.extend(waiting_receipts(&value));
        }
    }
    Ok(receipts)
}

/// Settles what this pass owed. A pass that compacted every window settles
/// each row. A pass no obligation started compacts each owed window on its
/// own and settles the ones it compacted or found without state. Any other
/// pass already compacted each closed window, and its rows settle with the
/// pass that compacts them all. A row raised again since it was read stays.
pub(super) fn settle_owed_compactions(
    vault: &Vault,
    owed: &[OwedCompaction],
    state: &WindowSweepState,
    erased: &BTreeSet<EntityId>,
    withdrawn: &mut WithdrawnSweep,
    run: &mut HardEraseSweepRun,
) -> Result<()> {
    for owed in owed {
        let compacted = match state {
            WindowSweepState::AllCompacted => true,
            WindowSweepState::NoObligation => {
                compact_owed_window(vault, &owed.window, erased, withdrawn, run)
            }
            WindowSweepState::Deferred | WindowSweepState::Failed(_) => false,
        };
        if compacted {
            let receipts = waiting_receipts(&owed.raise);
            if !receipts.is_empty() {
                // Each receipt row is signed in its transaction: the device
                // key first (P6c). One that cannot load keeps the row.
                let _ = vault.prepare_install_signing();
            }
            let settled = vault.with_write_txn_grouped(|wtxn| {
                let current = vault.store.sync_queue.get(&*wtxn, &owed.key)?;
                if current.is_some_and(|raise| *raise == *owed.raise) {
                    vault.store.sync_queue.delete(wtxn, &owed.key)?;
                    complete_receipts_in_txn(vault, wtxn, &receipts)?;
                }
                Ok(())
            });
            match settled {
                Ok(()) => {}
                // A receipt that did not complete keeps the row, and its
                // compaction, for the next pass.
                Err(error) if !receipts.is_empty() => tracing::warn!(
                    kind = ?error.kind(),
                    "sweep: an owed compaction's receipts did not complete; the row stays"
                ),
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

/// Completes each erase receipt in `receipts` whose compaction just settled:
/// its sweep completion row, then its final row once nothing else it binds
/// is owed. A receipt already completed, or no initial receipt, is passed.
fn complete_receipts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipts: &BTreeSet<EntityId>,
) -> Result<()> {
    let now = vault.store.clock.now_recorded_at();
    for id in receipts {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &*wtxn, id)?
        else {
            continue;
        };
        let Some(body) = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .filter(|_| raw.first() == Some(&crate::registry::ENTITY_TYPE_REDACTION_AUDIT))
        else {
            continue;
        };
        let receipt = crate::deletion::decode_redaction_audit_receipt(body)?;
        if !receipt.is_initial() {
            continue;
        }
        crate::deletion::append_redaction_sweep_completion_in_txn(vault, wtxn, id, &receipt, now)?;
        crate::deletion::finish_redaction_erase_in_txn(vault, wtxn, id, &receipt, now)?;
    }
    Ok(())
}

/// Compacts the owed window `key` alone, first unloading it when no caller
/// holds it, as the housekeeping pass unloads each idle window before a pass
/// an obligation starts: a host keeps every window it served registered.
/// Whether it compacted or holds no state. An unload that is refused or fails
/// leaves the window as it was, and it waits as an open one does.
fn compact_owed_window(
    vault: &Vault,
    key: &WindowKey,
    erased: &BTreeSet<EntityId>,
    withdrawn: &mut WithdrawnSweep,
    run: &mut HardEraseSweepRun,
) -> bool {
    let manager = vault
        .live_window_manager
        .lock()
        .ok()
        .and_then(|manager| manager.upgrade());
    if let Some(manager) = manager
        && let Err(error) = manager.unload_window(key)
    {
        tracing::debug!(error = %error, "sweep: owed window not unloaded");
    }
    let compact = || compact_window_with(vault, key, erased, withdrawn, false);
    let compacted = vault.while_window_closed(key, compact);
    match compacted {
        Some(Ok(CompactOutcome::Compacted)) => {
            run.windows_compacted += 1;
            true
        }
        Some(Ok(CompactOutcome::Empty)) => true,
        None => {
            tracing::warn!("sweep: owed window live or retained — deferred");
            run.windows_deferred_live += 1;
            false
        }
        Some(Ok(CompactOutcome::RacedDefer)) => {
            tracing::warn!("sweep: owed window raced before its compaction write — deferred");
            run.windows_deferred_raced += 1;
            false
        }
        Some(Ok(CompactOutcome::HeldDefer)) => {
            tracing::warn!(
                "sweep: a legal hold names a row the owed window would erase — deferred"
            );
            run.windows_deferred_held += 1;
            false
        }
        // Nothing was written: the row stays until a cut is proved.
        Some(Ok(CompactOutcome::UnprovedDefer)) => {
            run.windows_deferred_unproved += 1;
            false
        }
        Some(Err(err)) => {
            tracing::error!(
                kind = ?err.kind(),
                "sweep: owed window compaction FAILED — obligation kept"
            );
            false
        }
    }
}
