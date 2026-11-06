//! A person's hard erase reaches the forward rows they hold (FIX 20468).
//!
//! A relayed intent names its holder and carries the holder's slip token and
//! signature. Its result names the intent. Both are task authority facts, so
//! no ordinary delete removes them. Only the accepted erase of the holder
//! retires them, in the erase's own writer (`deletion::actor_fields`), which
//! the live erase, the marker-only erase, the replayed erase and the
//! checkpoint restore sweep all reach. It takes each intent the person holds
//! and the result of each such intent, and nothing else: every other
//! authority fact stays. The retired ids ride the erase's redaction receipt
//! as erased with the person ([`ask_forward_rows_retired_with`]). An erase
//! that finds none retires nothing, so a repeated erase is harmless.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use super::{AskForwardResult, INTENT, RESULT, read_intent, result_id, subkind};
use crate::deletion::ActorErasureWriter;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_TASK;
use crate::task_verb::ask_record;
use crate::{EntityId, Vault};

thread_local! {
    /// The forward rows this thread's erases retired with each erased
    /// person, until the erase's receipt reads them in the same transaction.
    static RETIRED: RefCell<BTreeMap<EntityId, BTreeSet<EntityId>>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// Retires, under the accepted erase `erase`, every relayed intent its
/// erased person holds and the result of each (FIX 20468). Each row is torn
/// as a cascade tears a row: its indexes and side rows go, its id gets the
/// permanent local hard-delete marker, so a late copy does not land again,
/// and its replicas get its tombstone. A row a legal hold keeps stays, as
/// every tear keeps it. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a stored intent or result that does not decode.
pub(crate) fn retire_holder_ask_forward_rows_in_txn(
    erase: &mut ActorErasureWriter<'_, '_>,
) -> Result<()> {
    let (vault, wtxn, holder) = erase.parts();
    if crate::deletion::names_no_actor(vault, wtxn, &holder)? {
        return Ok(());
    }
    let mut retired = BTreeSet::new();
    for row in holder_rows_in_txn(vault, wtxn, holder)? {
        if retire_row_in_txn(vault, wtxn, &row)? {
            retired.insert(row);
        }
    }
    if !retired.is_empty() {
        RETIRED.with(|held| held.borrow_mut().entry(holder).or_default().extend(retired));
    }
    Ok(())
}

/// The forward rows an erase of `holder` retired in this thread, for its
/// redaction receipt to bind as erased with them (FIX 20468); each is handed
/// over once.
pub(crate) fn ask_forward_rows_retired_with(holder: &EntityId) -> Vec<EntityId> {
    RETIRED.with(|held| {
        held.borrow_mut()
            .remove(holder)
            .map(|rows| rows.into_iter().collect())
            .unwrap_or_default()
    })
}

/// Each stored intent `holder` holds, and before it the result stored for
/// that intent, which names it. The result's id derives from the intent's,
/// so it is read while the intent still stands.
fn holder_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    holder: EntityId,
) -> Result<Vec<EntityId>> {
    let mut rows = Vec::new();
    for task in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_TASK, None)?
    {
        let id = task?;
        let Some(raw) = vault.get_raw_in(txn, &id)? else {
            continue;
        };
        if subkind(&raw) != Some(INTENT) {
            continue;
        }
        let Some(intent) = read_intent(vault, txn, id)? else {
            continue;
        };
        if intent.holder != holder {
            continue;
        }
        let result = result_id(id)?;
        if ask_record::read::<AskForwardResult>(vault, txn, result, RESULT)?
            .is_some_and(|stored| stored.intent == id)
        {
            rows.push(result);
        }
        rows.push(id);
    }
    Ok(rows)
}

/// Tears the forward row `id` in the erase's transaction. `false` when a
/// legal hold keeps it, or no row was stored under it.
fn retire_row_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<bool> {
    if crate::store::legal_hold::held_in_txn(&vault.store, wtxn, id.as_bytes())? {
        return Ok(false);
    }
    let write = crate::secret_custody::CustodyWrite::of(vault);
    crate::provenance::erase_row_provenance_in_txn(&write, wtxn, id, true)?;
    let (existed, vector, graph, neighbors) = crate::batch::deindex_entity(&write, wtxn, id)?;
    if !existed {
        return Ok(false);
    }
    crate::batch::stage_cascade_tombstone_in_txn(&vault.store, wtxn, id)?;
    crate::ppr::invalidate_ppr_for_delete(&vault.store, wtxn, id, &neighbors)?;
    if graph {
        crate::ppr::increment_graph_version(&vault.store, wtxn)?;
    }
    if vector {
        crate::hnsw::increment_vector_version(&vault.store, wtxn)?;
    }
    Ok(true)
}
