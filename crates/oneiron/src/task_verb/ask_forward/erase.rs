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
//! and historical sweep, and leaves the vault's arrivals. A held intent or
//! result keeps both rows. A repeated erase finds none.

use super::*;
use crate::deletion::ActorErasureWriter;
use crate::ports::EntityStoreRead;
use crate::scan_check::{EngineScan, ScanCount};

/// Retires, in `erase`'s writer, every relayed intent whose holder it
/// erases, and the result of each (FIX 7494). Only this erase context
/// reaches it; it grants no ordinary delete.
///
/// # Errors
/// A storage error; the erase's writer then commits nothing.
pub(crate) fn retire_holder_ask_forward_rows_in_txn(
    erase: &mut ActorErasureWriter<'_, '_>,
) -> Result<()> {
    let retired = {
        let (vault, wtxn, holder) = erase.parts();
        if crate::deletion::names_no_actor(vault, wtxn, &holder)? {
            return Ok(());
        }
        let mut retired = BTreeSet::new();
        for (intent, intent_at) in holder_intents_in_txn(vault, wtxn, holder)? {
            // The result's id derives from the intent, read before it goes.
            let result = result_id(intent)?;
            // A hold keeps the word and its result together.
            if crate::store::legal_hold::held_in_txn(&vault.store, wtxn, intent.as_bytes())?
                || crate::store::legal_hold::held_in_txn(&vault.store, wtxn, result.as_bytes())?
            {
                continue;
            }
            // A result not here yet is fenced in its intent's window.
            let result_at = vault
                .store
                .port_entity_record(&*wtxn, &result)?
                .map_or(intent_at, |row| row.learned_at);
            retire_row_in_txn(vault, wtxn, intent, intent_at)?;
            retire_row_in_txn(vault, wtxn, result, result_at)?;
            retired.extend([intent, result]);
        }
        // An erased intent is never consumed.
        with_arrivals(vault, |arrivals| {
            arrivals.intents.retain(|intent| !retired.contains(intent));
        });
        retired
    };
    erase.stage_retired_rows(&retired)
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
