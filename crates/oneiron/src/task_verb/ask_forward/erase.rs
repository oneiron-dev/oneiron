//! A hard-erased person's relayed ask words leave with them (FIX 7494).
//!
//! An intent keeps its holder, the whole act, and the holder's slip and
//! signature. Its result answers that act. Both are immutable TASK authority
//! facts, which no ordinary delete removes. The accepted erase of the holder
//! retires them here, in the erase's own writer: each intent whose holder is
//! the erased person, and the result of each, whose id derives from the
//! intent before the intent goes. Every other authority fact stays.
//!
//! Each retired id takes the erase's `dt:` fence, so a replica's later copy
//! is never materialized here again, and a tombstone that the window's next
//! load publishes. Each id joins the scope of the erase's redaction receipt
//! and historical sweep, and leaves the vault's arrivals. A repeated erase
//! finds none.
//!
//! A held intent or result keeps both rows (FIX 20468). The erase then
//! records, in its writer, that it owes the pair their retirement, and it is
//! not complete while it does. Each due legal-hold pass retires every owed
//! pair that no hold keeps any more, as the erase retires an unheld pair.
//!
//! A replica can take an intent before it learns of the erase, so the
//! intent, or its result, can land here after it (FIX 7494). The erase never
//! met that pair. Its put admits it, and the same writer retires it as that
//! pass retires an owed pair, or owes it its retirement while a hold keeps
//! it.

use super::*;
use crate::deletion::ActorErasureWriter;
use crate::ports::EntityStoreRead;
use crate::scan_check::{EngineScan, ScanCount};

/// Retires, in `erase`'s writer, every relayed intent whose holder it
/// erases, and the result of each (FIX 7494). A pair a legal hold keeps
/// stays, and the erase owes it its retirement (FIX 20468). Only this erase
/// context reaches it; it grants no ordinary delete.
///
/// # Errors
/// A storage error; the erase's writer then commits nothing.
pub(crate) fn retire_holder_ask_forward_rows_in_txn(
    erase: &mut ActorErasureWriter<'_, '_>,
) -> Result<()> {
    let (retired, held) = {
        let (vault, wtxn, holder) = erase.parts();
        if crate::deletion::names_no_actor(vault, wtxn, &holder)? {
            return Ok(());
        }
        let mut retired = BTreeSet::new();
        let mut held = BTreeSet::new();
        for (intent, intent_at) in holder_intents_in_txn(vault, wtxn, holder)? {
            // The result's id derives from the intent, read before it goes.
            let result = result_id(intent)?;
            // A hold keeps the word and its result together, and the erase
            // owes both their retirement until it lifts (FIX 20468).
            if pair_held_in_txn(vault, wtxn, intent, result)? {
                held.insert(intent);
                continue;
            }
            retire_pair_in_txn(vault, wtxn, intent, result, intent_at)?;
            retired.extend([intent, result]);
        }
        // An erased intent is never consumed.
        drop_arrivals(vault, &retired);
        (retired, held)
    };
    erase.stage_retired_rows(&retired)?;
    erase.owe_held_ask_forward_intents(&held)
}

/// Retires, in a due legal-hold pass's writer, each relayed intent a hold
/// kept from its holder's erase, and its result, once no hold keeps either
/// (FIX 20468). Each row retires as the erase retires an unheld pair: its
/// stored copy and indexes go, it takes its `dt:` fence and its tombstone,
/// and the intent leaves the arrivals. The erase's receipt never changes.
/// So the pass does here what that receipt's scope does for its ids: the
/// archives kept for removed Owners lose both rows, and the sweep is owed
/// the compaction of each row's window. A pair whose rows are both gone
/// only clears its record. A held pair keeps its record. A repeated pass
/// finds nothing owed.
///
/// # Errors
/// A storage error; the pass's writer then commits nothing.
pub(crate) fn settle_held_ask_forward_rows_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let mut settled = BTreeSet::new();
    for (holder, intent) in crate::deletion::held_ask_forward_intents_in_txn(vault, wtxn)? {
        let result = result_id(intent)?;
        if pair_held_in_txn(vault, wtxn, intent, result)? {
            continue;
        }
        retire_pair_after_erase_in_txn(vault, wtxn, holder, intent, result)?;
        settled.extend([intent, result]);
    }
    drop_arrivals(vault, &settled);
    Ok(())
}

/// Retires, in the writer that puts it, a relayed intent or its result that
/// lands after the hard erase of `holder` here, and the other row of the pair
/// (FIX 7494). `intent` names the pair. The pair retires as a due legal-hold
/// pass retires an owed pair, and the intent leaves the arrivals: it is
/// never consumed, and its result is never delivered. A pair a legal hold
/// keeps stays, and the erase of `holder` owes it its retirement, with the
/// record its erase makes for a held pair (FIX 20468). A repeated arrival
/// meets its row's `dt:` fence, or finds that record already made.
///
/// # Errors
/// A storage error; the writer then commits nothing.
pub(super) fn retire_erased_holder_pair_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    holder: EntityId,
    intent: EntityId,
) -> Result<()> {
    let result = result_id(intent)?;
    if pair_held_in_txn(vault, wtxn, intent, result)? {
        return crate::deletion::owe_held_ask_forward_intents_in_txn(
            vault,
            wtxn,
            &holder,
            &BTreeSet::from([intent]),
        );
    }
    retire_pair_after_erase_in_txn(vault, wtxn, holder, intent, result)?;
    drop_arrivals(vault, &BTreeSet::from([intent, result]));
    Ok(())
}

/// Retires a pair after the writer of its holder's erase: through
/// [`retire_pair_in_txn`], when a row of it is here, and then as that
/// erase's receipt scope retires its ids, since that receipt never changes.
/// The archives kept for removed Owners lose both rows, and the sweep is owed
/// the compaction of each row's window. Last, `holder`'s record that the
/// pair is owed its retirement goes, if it has one (FIX 20468).
fn retire_pair_after_erase_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    holder: EntityId,
    intent: EntityId,
    result: EntityId,
) -> Result<()> {
    if let Some(intent_at) = held_pair_time_in_txn(vault, wtxn, intent, result)? {
        let fenced_at = retire_pair_in_txn(vault, wtxn, intent, result, intent_at)?;
        vault.scrub_removal_exports_in_txn(wtxn, &[intent, result])?;
        #[cfg(feature = "sync")]
        owe_window_compactions_in_txn(vault, wtxn, fenced_at)?;
        #[cfg(not(feature = "sync"))]
        let _ = fenced_at;
    }
    crate::deletion::clear_held_ask_forward_intent_in_txn(vault, wtxn, &holder, &intent)
}

/// The intents stored here whose holder is `holder`, each with its time: one
/// read of the TASK rows. A row that does not decode names no holder.
fn holder_intents_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    holder: EntityId,
) -> Result<Vec<(EntityId, u64)>> {
    let mut count = ScanCount::start(
        &vault.store,
        txn,
        EngineScan::TypeIndexRows,
        &[ENTITY_TYPE_TASK],
    )?;
    let mut ids = Vec::new();
    for row in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_TASK, None)?
    {
        count.row();
        ids.push(row?);
    }
    count.finish(vault);
    let mut intents = Vec::new();
    for id in ids {
        let Some(raw) = vault.get_raw_in(txn, &id)? else {
            continue;
        };
        if subkind(&raw) != Some(INTENT) {
            continue;
        }
        if let Ok(Some(intent)) = read_intent(vault, txn, id)
            && intent.holder == holder
        {
            intents.push((id, intent.at));
        }
    }
    Ok(intents)
}

/// Whether a legal hold keeps the intent or its result: a hold on either
/// keeps both.
fn pair_held_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent: EntityId,
    result: EntityId,
) -> Result<bool> {
    Ok(
        crate::store::legal_hold::held_in_txn(&vault.store, txn, intent.as_bytes())?
            || crate::store::legal_hold::held_in_txn(&vault.store, txn, result.as_bytes())?,
    )
}

/// The time an owed pair is fenced in once no hold keeps it: its intent's,
/// as the erase reads it, else the stored intent's or result's own. `None`
/// when neither row is here any more.
fn held_pair_time_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent: EntityId,
    result: EntityId,
) -> Result<Option<u64>> {
    if let Ok(Some(stored)) = read_intent(vault, txn, intent) {
        return Ok(Some(stored.at));
    }
    for row in [intent, result] {
        if let Some(record) = vault.store.port_entity_record(txn, &row)? {
            return Ok(Some(record.learned_at));
        }
    }
    Ok(None)
}

/// Retires the intent and its result through [`retire_row_in_txn`]: the
/// intent in the window of `intent_at`, the result in its own, or in its
/// intent's while it is not here yet. The times each was fenced in, intent
/// first.
fn retire_pair_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    intent: EntityId,
    result: EntityId,
    intent_at: u64,
) -> Result<[u64; 2]> {
    let result_at = vault
        .store
        .port_entity_record(&*wtxn, &result)?
        .map_or(intent_at, |row| row.learned_at);
    retire_row_in_txn(vault, wtxn, intent, intent_at)?;
    retire_row_in_txn(vault, wtxn, result, result_at)?;
    Ok([intent_at, result_at])
}

/// Retires one row: its stored copy and its indexes go when it is here, and
/// its `dt:` fence and tombstone are staged in the window of `learned_at`,
/// as an erase stages each engine row it hard-erases.
fn retire_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: EntityId,
    learned_at: u64,
) -> Result<()> {
    if vault.get_raw_in(wtxn, &row)?.is_some() {
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(
            &crate::secret_custody::CustodyWrite::of(vault),
            wtxn,
            &row,
        )?;
        crate::ppr::invalidate_ppr_for_delete(&vault.store, wtxn, &row, &neighbors)?;
        if graph {
            crate::store::graph_version::increment_graph_version(&vault.store, wtxn)?;
        }
        if vector {
            crate::store::vector_index::increment_vector_version(&vault.store, wtxn)?;
        }
    }
    let erased_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    crate::deletion::stage_engine_row_hard_erasure_in_txn(
        &vault.store,
        wtxn,
        &row,
        learned_at,
        &crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::UserHardDelete,
            deleted_at: erased_at,
            request_id: *row.as_bytes(),
        },
    )
}

/// Owes the erasure sweep the compaction of each window a settled pair's
/// tombstones are staged in, `fenced_at` naming their times: the history
/// there goes as the erase's own sweep takes an unheld pair's (FIX 20468).
#[cfg(feature = "sync")]
fn owe_window_compactions_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fenced_at: [u64; 2],
) -> Result<()> {
    let [intent_window, result_window] =
        fenced_at.map(crate::window_key::WindowKey::from_timestamp);
    crate::deletion::owed_window_compaction::owe_window_compaction_in_txn(
        vault,
        wtxn,
        &intent_window,
    )?;
    if result_window != intent_window {
        crate::deletion::owed_window_compaction::owe_window_compaction_in_txn(
            vault,
            wtxn,
            &result_window,
        )?;
    }
    Ok(())
}

/// Drops `rows` from the vault's arrivals: an erased intent is never
/// consumed.
fn drop_arrivals(vault: &Vault, rows: &BTreeSet<EntityId>) {
    with_arrivals(vault, |arrivals| {
        arrivals.intents.retain(|intent| !rows.contains(intent));
    });
}
