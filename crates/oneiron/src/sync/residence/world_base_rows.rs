//! The owner's discard of a world copy takes the world's rows that sit in
//! BASE windows too (FIX 14534, Engine 11-06 08:34 call 1 = A): a NOTE whose
//! live `InWorld` edges name that world alone, and a TASK, SUMMARY, ASSET,
//! ASSET_TEXT or BLOB_ARTIFACT its stamp places there alone
//! ([`content_world_in`]). A shared, base or unknown row stays. Each goes
//! through the tear's own rules for its BASE window, held closed
//! ([`remove_local_members_in_txn`]); the window's document rows, and every
//! other member, stay.
//!
//! That document still carries a removed row, so the discard keeps a
//! payload-free mark of it (`wd:e:{id}` -> the world). The ingest ladder
//! reads the mark only as a cue: it judges the arriving body itself, and
//! leaves it out while it is still that world's alone and the owner keeps
//! the world on another machine (`sync::ingest::entity`). No tombstone,
//! marker that travels or Loro operation is written.

use std::collections::HashMap;

use heed::{RoTxn, RwTxn};

use super::content_world::{ContentWorld, content_world_in};
use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use crate::store::local_replica::{KeepControls, remove_local_members_in_txn};
use crate::sync::WindowKey;

/// A BASE row the owner's discard took as one world's alone, by its id: the
/// world's id. Key: hex32 (entity id).
const DISCARDED_WORLD_ROW: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_DISCARDED_WORLD_ROW);

/// The kinds a stamp places in a world, which a BASE window carries.
const STAMPED_KINDS: [u8; 5] = [
    registry::ENTITY_TYPE_TASK,
    registry::ENTITY_TYPE_SUMMARY,
    registry::ENTITY_TYPE_ASSET,
    registry::ENTITY_TYPE_ASSET_TEXT,
    registry::ENTITY_TYPE_BLOB_ARTIFACT,
];

/// Rows one removing write takes.
const BASE_ROW_BATCH: usize = 256;

/// What the discard took from BASE windows.
#[derive(Default)]
pub(super) struct BaseRows {
    /// The rows removed.
    pub(super) removed: Vec<EntityId>,
    pub(super) kept: usize,
    pub(super) windows_busy: usize,
}

/// Takes the rows of `world` that sit in BASE windows, window by window. A
/// window a handle holds open, whose outbox queues a write, or whose local
/// writes a mirror still owes, waits for the next discard, whole.
pub(super) fn discard_base_rows(vault: &Vault, world: EntityId) -> Result<BaseRows> {
    let by_window = {
        let txn = vault.store.env.read_txn()?;
        base_rows_of_world(&vault.store, &txn, world)?
    };
    let keep = KeepControls {
        defer_on_queued_writes: true,
        defer_on_local_members: false,
        release_local_members: true,
        keep_birth_facets: true,
        ..KeepControls::default()
    };
    let mut rows = BaseRows::default();
    for (window, ids) in by_window {
        for batch in ids.chunks(BASE_ROW_BATCH) {
            vault.unload_idle_window(&window)?;
            let step = vault.while_window_closed(&window, || {
                vault.with_write_txn_grouped(|txn| {
                    if crate::sync::manager::window_owes_mirror_in_txn(vault, txn, &window)? {
                        return Ok(None);
                    }
                    // The census read before the window closed is not this
                    // write's: each row is judged again here.
                    let mut exclusive = Vec::with_capacity(batch.len());
                    for id in batch {
                        if content_world_in(&vault.store, txn, *id)?
                            == ContentWorld::Exclusive(world)
                        {
                            exclusive.push(*id);
                        }
                    }
                    let step = remove_local_members_in_txn(
                        &vault.store,
                        txn,
                        &window,
                        &exclusive,
                        keep.clone(),
                    )?;
                    for id in &step.removed {
                        mark_discarded_in_txn(&vault.store, txn, *id, world)?;
                    }
                    Ok(Some(step))
                })
            });
            let Some(step) = step else {
                rows.windows_busy += 1;
                break;
            };
            let Some(step) = step? else {
                rows.windows_busy += 1;
                break;
            };
            // A queued write deferred the call: the outbox holds what only
            // this install has of the month.
            if keep.defer_on_queued_writes && step.queued_writes > 0 {
                rows.windows_busy += 1;
                break;
            }
            rows.removed.extend_from_slice(&step.removed);
            rows.kept += step.kept.len();
        }
    }
    Ok(rows)
}

/// Every stored row of `world` alone whose canonical window is a BASE one,
/// by that window: NOTEs by the `InWorld` edges that reach the world, the
/// stamped kinds by their type index.
fn base_rows_of_world(
    store: &Store,
    txn: &RoTxn<'_>,
    world: EntityId,
) -> Result<HashMap<WindowKey, Vec<EntityId>>> {
    let mut by_window: HashMap<WindowKey, Vec<EntityId>> = HashMap::new();
    let mut notes = Vec::new();
    for row in store.port_edges(
        txn,
        &world,
        EdgeDirection::In,
        Some(EdgeKind::InWorld),
        None,
    )? {
        notes.push(row?.target);
    }
    for id in notes {
        place(store, txn, world, id, &mut by_window)?;
    }
    for kind in STAMPED_KINDS {
        let ids = store
            .port_entity_ids_by_type(txn, kind, None)?
            .collect::<Result<Vec<_>>>()?;
        for id in ids {
            place(store, txn, world, id, &mut by_window)?;
        }
    }
    Ok(by_window)
}

/// Files `id` under its BASE window when its row is `world`'s alone.
fn place(
    store: &Store,
    txn: &RoTxn<'_>,
    world: EntityId,
    id: EntityId,
    by_window: &mut HashMap<WindowKey, Vec<EntityId>>,
) -> Result<()> {
    if content_world_in(store, txn, id)? != ContentWorld::Exclusive(world) {
        return Ok(());
    }
    let Some(raw) = store.port_entity_raw(txn, &id)? else {
        return Ok(());
    };
    if let Ok(window) = super::residence_window_for_blob(&raw)
        && window.world().is_none()
    {
        by_window.entry(window).or_default().push(id);
    }
    Ok(())
}

fn mark_discarded_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: EntityId,
    world: EntityId,
) -> Result<()> {
    DISCARDED_WORLD_ROW.put(store, txn, &HexId(id), &world.as_bytes().to_vec())
}

/// The world the owner's discard took the BASE row `id` as, if it did.
pub(crate) fn discarded_world_in(
    store: &Store,
    txn: &RoTxn<'_>,
    id: EntityId,
) -> Result<Option<EntityId>> {
    Ok(DISCARDED_WORLD_ROW
        .get(store, txn, &HexId(id))?
        .and_then(|raw| <[u8; 16]>::try_from(raw.as_slice()).ok())
        .and_then(|bytes| EntityId::from_bytes(bytes).ok()))
}

/// Forgets the discard's mark of `id`: its row may come back.
pub(crate) fn forget_discarded_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    DISCARDED_WORLD_ROW.delete(store, txn, &HexId(id))?;
    Ok(())
}
