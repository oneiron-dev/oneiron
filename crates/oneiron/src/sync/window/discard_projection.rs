//! The owner's discard of a world copy, carried into the persisted BASE
//! windows (FIX 14534 part E, Engine 11-06 23:52 E1-E4 = A).
//!
//! The discard takes the world's exclusive rows from LMDB, but a BASE
//! month's document still holds their carriers and history: entity rows,
//! incident edges, births, NOTE carriers and the rest. A Loro delete would
//! sync, and this discard is local. So the window is projected in place:
//! the vendored root-map checkpoint splits the document into its payload
//! free skeleton and one atom per value (`loro::checkpoint`), every atom a
//! discarded row owns is erased, a NOTE bundle that keeps other members is
//! rewritten redacted (`sync::note::discard`), and the join writes each
//! erased value as a delete at its own operation id. No operation is
//! authored; the version vector, frontiers and every other value stay, and
//! the join proves it before anything is written.
//!
//! A projected history differs, at the same operation ids, from the one
//! the owner's other machines hold. So it is installed only while the home,
//! as this device last exchanged with it, holds every operation the window
//! does (E2 = A): the home never takes a rewritten delete for content it
//! still holds. The version vector the projection kept is filed as the
//! window's floor (`SYNC_BASE_WINDOW_DISCARD`), and a send to a home below
//! it waits. A shared value stays whole; what the projection cannot place
//! (a NOTE carrier that does not decode, a root outside the window's maps,
//! a parted row whose parts join to a row its key does not name, a whole
//! row filed under a key it does not name) defers the window, never counts
//! as erased. Bytes that read as no row prove no other row: a parted one
//! places by its key, and a whole one is kept under no one, as before. A
//! room turn in parts goes as the same turn stored whole does: once the
//! capture has met every part, its manifest is decided by its joined row's
//! holders (FIX SYNC-DISCARD-PARTED-TURN-HOLDERS-NARROW).

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;
use loro::checkpoint::{Atom, AtomId, Capture, Classify, Field, OwnerId, Payload, Skeleton};
use loro::{LoroDoc, LoroValue, VersionVector};

use super::super::bridge::parse_edge_key;
use super::super::carrier_parts::{Parts, assembly_fits, join_parts_from, part_key};
use super::super::checkpoint_payload::{
    Holder, KindPlacement, PartedRows, Placement, SyncPayloadOwners, SyncUnclassified,
    WINDOW_ROOTS, root_entry,
};
use super::super::loro_support::{doc_from_snapshot, import_doc};
use super::super::note::discard::{NoteAtom, is_note_carrier_map, project_atom, project_current};
use super::super::room_turns::ROOM_TURNS_MAP;
use super::super::room_turns::checkpoint::entry_joined;
use super::super::schema::{ASSET_BODY_REFS_MAP, create_window_doc};
use super::super::types::WindowKey;
use super::super::window_rows::{
    WINDOW_FULL_RESYNC_MARKER, WINDOW_SHALLOW_FENCE, WINDOW_SNAPSHOT, WINDOW_STATE_VECTOR,
    WINDOW_UPDATE, WINDOW_UPDATE_SEQ,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::store::checkpoint_payload::rows::OwnerRef;

mod classifier;
pub(crate) use classifier::{Projected, project_window_doc};

/// A BASE window the owner's discard touched, by its key: a first byte of
/// 1 while its persisted document still waits for its projection, 0 once
/// installed, then the version vector the last projection kept, the floor
/// below which no send of the window goes. Key: window key.
const BASE_WINDOW_DISCARD: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_BASE_WINDOW_DISCARD);

/// What installing one window's projection came to.
pub(crate) enum DiscardInstall {
    /// The window holds no persisted state, or nothing the rows own.
    Unchanged,
    /// The projected document replaced the window's persisted state.
    Installed { erased: usize, rewritten: usize },
    /// The window waits, and why.
    Deferred(&'static str),
}

/// Projects the persisted state of BASE window `key`, which the caller
/// holds closed, for every row the owner's discard marks (read once the
/// window is closed, and read again in the write), and installs it: the
/// snapshot replaced by the projected one, its update rows folded in, its
/// version vector unchanged, and the floor filed. Nothing is written unless
/// the home, as this device last exchanged with it, holds every operation
/// the window does, no send of the window is queued, the rows read first
/// are still the window's, and no row the projection took has come back
/// since (a NOTE accepted again as shared clears its mark).
///
/// # Errors
///
/// Store errors, and a stored document or update that does not open.
pub(crate) fn install_discard_projection(vault: &Vault, key: &WindowKey) -> Result<DiscardInstall> {
    let window = key.to_string();
    let address = WindowAddress::new(&window);
    let (discarded, snapshot, updates) = {
        let txn = vault.store.env.read_txn()?;
        let discarded = crate::sync::residence::discarded_rows_in(&vault.store, &txn)?;
        let snapshot = vault
            .store
            .port_window_doc_with_raw(&txn, address, |raw| Ok(raw.to_vec()))?;
        let updates = vault
            .store
            .port_window_updates(&txn, address, |row, bytes| (row, bytes.to_vec()))?
            .collect::<Result<Vec<_>>>()?;
        (discarded, snapshot, updates)
    };
    if snapshot.is_none() && updates.is_empty() {
        return Ok(DiscardInstall::Unchanged);
    }
    let doc = match &snapshot {
        Some(bytes) => doc_from_snapshot(bytes)?,
        None => create_window_doc("local", key),
    };
    for (_, bytes) in &updates {
        import_doc(&doc, bytes)?;
    }
    // Every operation is the home's: the write checks it.
    let (bytes, erased, rewritten) = match project_window_doc(&doc, &discarded, None)? {
        Projected::Unchanged => return Ok(DiscardInstall::Unchanged),
        Projected::Deferred(why) => return Ok(DiscardInstall::Deferred(why)),
        Projected::Joined {
            bytes,
            erased,
            rewritten,
            ..
        } => (bytes, erased, rewritten),
    };
    let held = doc.oplog_vv();
    if doc_from_snapshot(&bytes)?.oplog_vv() != held {
        return Ok(DiscardInstall::Deferred(
            "a projection that moved the window's version",
        ));
    }
    let floor = held.encode();
    let read_keys: BTreeSet<Vec<u8>> = updates
        .iter()
        .map(|(row, _)| WINDOW_UPDATE.key_bytes(row))
        .collect();
    let update_prefix = format!("{window}:");
    let mut deferred = None;
    vault.with_write_txn_grouped(|txn| {
        // The rows read first must still be the window's whole state.
        let current = vault
            .store
            .port_window_doc_with_raw(txn, address, |raw| Ok(raw.to_vec()))?;
        let current_keys: BTreeSet<Vec<u8>> = vault
            .store
            .port_window_updates(txn, address, |row, _| row)?
            .collect::<Result<Vec<_>>>()?
            .iter()
            .map(|row| WINDOW_UPDATE.key_bytes(row))
            .collect();
        if current != snapshot || current_keys != read_keys {
            deferred = Some("a window written since its projection was read");
            return Ok(());
        }
        if !discarded.is_subset(&crate::sync::residence::discarded_rows_in(
            &vault.store,
            txn,
        )?) {
            deferred = Some("a discarded row accepted back since its projection was read");
            return Ok(());
        }
        if !home_holds_in_txn(&vault.store, txn, &window, &held)? {
            deferred = Some("a window whose operations the home does not all hold");
            return Ok(());
        }
        if vault
            .store
            .sync_hooks
            .queued_window_update_count_in_txn(&vault.store, txn, &window)?
            > 0
        {
            deferred = Some("a window with a queued send");
            return Ok(());
        }
        WINDOW_SNAPSHOT.put(&vault.store, txn, &window, &bytes)?;
        WINDOW_STATE_VECTOR.put(&vault.store, txn, &window, &floor)?;
        WINDOW_UPDATE.delete_from(&vault.store, txn, update_prefix.as_bytes())?;
        WINDOW_SHALLOW_FENCE.put(&vault.store, txn, &window, &[1u8])?;
        file_floor_in_txn(&vault.store, txn, &window, &floor)
    })?;
    Ok(match deferred {
        Some(why) => DiscardInstall::Deferred(why),
        None => DiscardInstall::Installed { erased, rewritten },
    })
}

/// Whether the home's version vector of `window`, as this device last
/// exchanged it, holds `held`.
fn home_holds_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    window: &str,
    held: &VersionVector,
) -> Result<bool> {
    Ok(
        crate::sync::residence::home_window_vv_in_txn(store, txn, window)?
            .is_some_and(|home| home.includes_vv(held)),
    )
}

/// Marks BASE window `window` as waiting for its projection, in the write
/// that took rows from it; a floor an earlier projection filed stays.
pub(crate) fn mark_projection_owed_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &str,
) -> Result<()> {
    let key = window.to_owned();
    let mut record = BASE_WINDOW_DISCARD
        .get(store, txn, &key)?
        .filter(|record| !record.is_empty())
        .unwrap_or_else(|| vec![0]);
    if record.first() == Some(&1) {
        return Ok(());
    }
    record[0] = 1;
    BASE_WINDOW_DISCARD.put(store, txn, &key, &record)
}

/// Marks every persisted BASE window as waiting for its projection, in the
/// write that took rows: a row's values ride off its own month too (a review
/// bundle carries the rows of each member NOTE beside every NOTE it holds a
/// member of), so each window is projected once and the pass lets go of the
/// ones that hold nothing the marks own (`forget_unprojected_in_txn`).
pub(crate) fn mark_base_windows_owed_in_txn(store: &Store, txn: &mut RwTxn<'_>) -> Result<()> {
    let mut windows: BTreeSet<String> = WINDOW_SNAPSHOT
        .scan_keys(store, txn, &[])?
        .into_iter()
        .collect();
    windows.extend(WINDOW_UPDATE_SEQ.scan_keys(store, txn, &[])?);
    for window in windows {
        if WindowKey::try_new(&window).is_some_and(|key| key.world().is_none()) {
            mark_projection_owed_in_txn(store, txn, &window)?;
        }
    }
    Ok(())
}

/// Settles BASE window `window`'s owed projection, found to hold nothing the
/// marks own: one no projection ever rewrote is no longer watched, and one
/// with a floor keeps it.
pub(crate) fn forget_unprojected_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &str,
) -> Result<()> {
    let key = window.to_owned();
    match BASE_WINDOW_DISCARD.get(store, txn, &key)? {
        Some(record) if record.len() <= 1 => {
            BASE_WINDOW_DISCARD.delete(store, txn, &key)?;
            Ok(())
        }
        Some(_) => settle_projection_in_txn(store, txn, window),
        None => Ok(()),
    }
}

/// Files `floor` as BASE window `window`'s, its projection installed.
fn file_floor_in_txn(store: &Store, txn: &mut RwTxn<'_>, window: &str, floor: &[u8]) -> Result<()> {
    let mut record = Vec::with_capacity(1 + floor.len());
    record.push(0);
    record.extend_from_slice(floor);
    BASE_WINDOW_DISCARD.put(store, txn, &window.to_owned(), &record)
}

/// Raises BASE window `window`'s floor to hold `part`, operations the home
/// holds that a projection of an arrival rewrote; its owed state stays.
pub(super) fn raise_floor_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &str,
    part: &VersionVector,
) -> Result<()> {
    let key = window.to_owned();
    let record = BASE_WINDOW_DISCARD
        .get(store, txn, &key)?
        .unwrap_or_default();
    let mut floor = record
        .get(1..)
        .and_then(|bytes| VersionVector::decode(bytes).ok())
        .unwrap_or_default();
    floor.merge(part);
    let mut raised = vec![record.first().copied().unwrap_or(0)];
    raised.extend_from_slice(&floor.encode());
    BASE_WINDOW_DISCARD.put(store, txn, &key, &raised)
}

/// Marks for a full resync every BASE window a projection already rewrote,
/// once a row the discard took is accepted back: each holds deletes where
/// the home holds that row's values, and its replacement from the home is
/// projected anew for the rows the discard still marks.
pub(crate) fn resync_projected_windows_in_txn(store: &Store, txn: &mut RwTxn<'_>) -> Result<()> {
    for (window, record) in BASE_WINDOW_DISCARD.scan(store, txn)? {
        if record.len() > 1 {
            WINDOW_FULL_RESYNC_MARKER.put(store, txn, &window, &[1u8])?;
        }
    }
    Ok(())
}

/// Settles BASE window `window`'s owed projection with nothing to install:
/// its floor, if any, stays.
fn settle_projection_in_txn(store: &Store, txn: &mut RwTxn<'_>, window: &str) -> Result<()> {
    let key = window.to_owned();
    if let Some(mut record) = BASE_WINDOW_DISCARD.get(store, txn, &key)?
        && record.first() == Some(&1)
    {
        record[0] = 0;
        BASE_WINDOW_DISCARD.put(store, txn, &key, &record)?;
    }
    Ok(())
}

/// Every BASE window whose projection is owed.
pub(crate) fn owed_projections_in(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Vec<String>> {
    Ok(BASE_WINDOW_DISCARD
        .scan(store, txn)?
        .into_iter()
        .filter(|(_, record)| record.first() == Some(&1))
        .map(|(window, _)| window)
        .collect())
}

/// Whether the owner's discard touched BASE window `window`: its home's
/// version vector is kept beside it from then on.
pub(crate) fn discard_touched_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    window: &str,
) -> Result<bool> {
    BASE_WINDOW_DISCARD.contains(store, txn, &window.to_owned())
}

/// The floor BASE window `window`'s last projection filed: no send of the
/// window goes to a home whose version vector does not hold it.
pub(crate) fn projection_floor_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    window: &str,
) -> Result<Option<VersionVector>> {
    Ok(BASE_WINDOW_DISCARD
        .get(store, txn, &window.to_owned())?
        .and_then(|record| VersionVector::decode(record.get(1..)?).ok())
        .filter(|floor| !floor.is_empty()))
}
