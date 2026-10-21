//! The MESSAGE rows a kept TURN lacks after a window demotion (OF-534, FIX
//! 3859).
//!
//! A demotion that removes a MESSAGE and keeps its TURN leaves the turn's
//! words partly here. A tagged turn's saved set lists the rows it was read
//! from, but an untagged one keeps no list, so the demotion records what each
//! kept turn lost, in its own transaction before any row or edge goes, and
//! adds it to what an earlier demotion recorded. Queued work on the turn
//! waits while one of those MESSAGEs lacks its row or its `PartOf` edge to
//! the turn ([`crate::tagging::tagged_messages_absent_in_txn`]).
//!
//! The marker is derived and local: it lives in `vault_meta`, which sync
//! never reads. It is read against the rows and edges this replica holds,
//! never an import's word or a promoted-window marker. A promotion clears a
//! turn's entry once every MESSAGE it lists is back with its edge, and owes
//! the turn the tag pass and sieve read it held back then. A deletion takes
//! the MESSAGE it removes out of every entry, whether or not its row is
//! here, and a TURN's own entry goes with the turn.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// The MESSAGE ids a kept TURN lacks. Key: the turn id. An entry is never
/// empty: the last id out takes the row with it.
const MISSING: SideTable<EntityId, BTreeSet<EntityId>, Named> =
    SideTable::new(&side_table::TURN_MISSING_MESSAGES);

/// The demotion's write, in its transaction after the final plan and before
/// any row or edge goes: each kept TURN with the MESSAGEs the call removes
/// from it, added to what its entry lists already, never in place of it. A
/// tagged turn and an untagged one are recorded alike.
#[cfg(feature = "sync")]
pub(crate) fn record_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    lost: &std::collections::BTreeMap<EntityId, BTreeSet<EntityId>>,
) -> Result<()> {
    for (turn, messages) in lost {
        let mut missing = MISSING.get(store, txn, turn)?.unwrap_or_default();
        missing.extend(messages);
        if !missing.is_empty() {
            MISSING.put(store, txn, turn, &missing)?;
        }
    }
    Ok(())
}

/// Whether `turn` lacks a MESSAGE a demotion took from it: one its entry
/// lists is not back with its `PartOf` edge to the turn. A row back without
/// its edge still lacks. A turn with no entry lacks none.
pub(crate) fn absent_in_txn(store: &Store, txn: &RoTxn<'_>, turn: &EntityId) -> Result<bool> {
    let Some(missing) = MISSING.get(store, txn, turn)? else {
        return Ok(false);
    };
    for message in &missing {
        if !returned_in_txn(store, txn, turn, message)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `message` is here as part of `turn`: its row stored and its
/// `PartOf` edge to the turn standing.
fn returned_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    message: &EntityId,
) -> Result<bool> {
    Ok(store.port_entity_present(txn, message)?
        && store.port_edge_present(txn, message, EdgeDirection::Out, EdgeKind::PartOf, turn)?)
}

/// Clears the entry of each kept turn whose MESSAGEs are all back with their
/// `PartOf` edges, as `txn` holds the rows and edges now, and owes a stored
/// turn the tag pass and sieve read its partial words held back
/// ([`crate::store::local_replica::owe_promoted_turn_in_txn`]). An entry
/// with only some of its MESSAGEs back keeps the others, so one window or
/// one MESSAGE arriving never clears a turn that still lacks another.
///
/// `returned` is a row a promotion just landed: only the entries that list
/// it are read, and only when it is a MESSAGE. `None` reads every entry, for
/// a promotion's completion. Returns how many entries it cleared.
#[cfg(feature = "sync")]
pub(crate) fn reconcile_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    returned: Option<&EntityId>,
) -> Result<usize> {
    let store = &vault.store;
    if let Some(id) = returned
        && !message_in_txn(store, txn, id)?
    {
        return Ok(0);
    }
    let mut cleared = 0;
    for (turn, missing) in MISSING.scan(store, txn)? {
        if returned.is_some_and(|id| !missing.contains(id)) {
            continue;
        }
        let mut away = BTreeSet::new();
        for message in &missing {
            if !returned_in_txn(store, txn, &turn, message)? {
                away.insert(*message);
            }
        }
        if away.is_empty() {
            MISSING.delete(store, txn, &turn)?;
            if store.port_entity_present(txn, &turn)? {
                crate::store::local_replica::owe_promoted_turn_in_txn(vault, txn, &turn)?;
            }
            cleared += 1;
        } else if away.len() < missing.len() {
            MISSING.put(store, txn, &turn, &away)?;
        }
    }
    Ok(cleared)
}

/// [`reconcile_in_txn`] over every entry, in a short write of its own once a
/// promotion's rows and edges have landed or been tried, its sealed mirror's
/// among them. A failure keeps every entry for the next promotion.
#[cfg(feature = "sync")]
pub(crate) fn reconcile_after_promotion(vault: &Vault) {
    if let Err(error) = vault.with_write_txn_grouped(|txn| reconcile_in_txn(vault, txn, None)) {
        tracing::warn!(%error, "partial-turn markers not reconciled after promotion");
    }
}

/// Whether the row stored at `id` is a MESSAGE.
#[cfg(feature = "sync")]
fn message_in_txn(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store
        .port_entity_record(txn, id)?
        .is_some_and(|row| row.entity_type == crate::registry::ENTITY_TYPE_MESSAGE))
}

/// The erase doors' hook, beside tagging's: [`forget_in_txn`], then each
/// stored turn whose entry it emptied is owed the tag pass and sieve read
/// its partial words held back. Returns whether an entry named `id`.
pub(crate) fn erase_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<bool> {
    let (named, emptied) = forget_in_txn(&vault.store, txn, id)?;
    for turn in emptied {
        if vault.store.port_entity_present(txn, &turn)? {
            crate::tagging::mark_turn_in_txn(
                vault,
                txn,
                turn,
                crate::memory::extraction::ExtractionWork::Bulk,
            )?;
            crate::dreamer_wake::owe_sieve_read_in_txn(&vault.store, txn, &turn)?;
        }
    }
    Ok(named)
}

/// The physical tear's hook, beside tagging's, with no vault in hand:
/// [`forget_in_txn`], then each stored turn whose entry it emptied is owed
/// its sieve read. The tag pass is the erase doors' to owe: they run
/// [`erase_in_txn`] first, and a bare tear owes none.
pub(crate) fn tear_in_txn(store: &Store, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    for turn in forget_in_txn(store, txn, id)?.1 {
        if store.port_entity_present(txn, &turn)? {
            crate::dreamer_wake::owe_sieve_read_in_txn(store, txn, &turn)?;
        }
    }
    Ok(())
}

/// Takes `id` out of every entry that lists it, whether or not its row and
/// edges are here, and drops its own entry when it is a TURN, before the
/// graph goes. Every entry is read: no index leads from a MESSAGE to the
/// turns that list it. Returns whether an entry named `id`, and the turns
/// whose entry it emptied, which lack nothing now.
fn forget_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, Vec<EntityId>)> {
    let mut named = MISSING.delete(store, txn, id)?;
    let mut emptied = Vec::new();
    for (turn, mut missing) in MISSING.scan(store, txn)? {
        if !missing.remove(id) {
            continue;
        }
        named = true;
        if missing.is_empty() {
            MISSING.delete(store, txn, &turn)?;
            emptied.push(turn);
        } else {
            MISSING.put(store, txn, &turn, &missing)?;
        }
    }
    Ok((named, emptied))
}

/// Whether deleting `id` has an entry to change: its own, as a TURN, or one
/// that lists it, so a headerless delete of a MESSAGE a demotion took, which
/// only an untagged turn's entry may name, still reaches the hooks.
pub(crate) fn delete_scope_exists_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if MISSING.contains(store, txn, id)? {
        return Ok(true);
    }
    for row in MISSING.iter_from(store, txn, &[])? {
        if row?.1.contains(id) {
            return Ok(true);
        }
    }
    Ok(false)
}
