//! The owner's discard of a world copy, carried into what arrives for a
//! BASE window it took rows from (FIX 14534 part E, Engine 11-06 23:52,
//! E1 = A: every ingress is projected before it persists). A snapshot that
//! any path persists (an unload, a bulk transfer, a replacement, a
//! re-bootstrap) and an update that the home sent are projected in the
//! write that persists them, for every row the discard marks in that write.
//!
//! Only operations that the home holds are rewritten (E2 = A): the update the
//! home sent, and what the home's version vector holds, as this device last
//! exchanged it. The floor rises to those operations. A value that any other
//! operation wrote persists whole and the window's projection stays owed, as
//! does a document the projection cannot place. The pass at the next
//! eviction projects it once the home holds it
//! (`sync::residence::base_projection`).

use std::borrow::Cow;
use std::collections::BTreeSet;

use heed::RwTxn;
use loro::{LoroDoc, VersionVector};

use super::super::bridge::{persist_window_update, persist_window_update_in_txn};
use super::super::loro_support::{doc_from_snapshot, export_updates_from, import_doc};
use super::super::schema::create_window_doc;
use super::super::types::WindowKey;
use super::discard_projection::{
    Projected, discard_touched_in, mark_projection_owed_in_txn, project_window_doc,
    projection_floor_in, raise_floor_in_txn,
};
use super::pad_custody::persisted_window_pads;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

/// The rows that the owner's discard marks, when `key` is a BASE window and
/// some are marked; with `watched`, only when the discard touched the window
/// (an arrival's cost stays on the windows that held the rows' values).
fn discarded_for_in_txn(
    store: &Store,
    txn: &RwTxn<'_>,
    key: &WindowKey,
    watched: bool,
) -> Result<Option<BTreeSet<EntityId>>> {
    if key.world().is_some() || (watched && !discard_touched_in(store, txn, key.as_str())?) {
        return Ok(None);
    }
    let discarded = crate::sync::residence::discarded_rows_in(store, txn)?;
    Ok((!discarded.is_empty()).then_some(discarded))
}

/// The operations of `key` that the home holds: its version vector, as this
/// device last exchanged it, and the floor, which only operations the home
/// held ever raised.
fn home_held_in_txn(store: &Store, txn: &RwTxn<'_>, key: &WindowKey) -> Result<VersionVector> {
    let window = key.as_str();
    let mut held =
        crate::sync::residence::home_window_vv_in_txn(store, txn, window)?.unwrap_or_default();
    if let Some(floor) = projection_floor_in(store, txn, window)? {
        held.merge(&floor);
    }
    Ok(held)
}

/// `snapshot`, the state of window `key` that persists in `txn`, projected
/// for the rows that the owner's discard marks there. Every BASE window's
/// snapshot is, touched or not: a carrier of the rows that arrived since in
/// a window that held none of them leaves at its next snapshot, and the
/// window is watched from then on.
///
/// # Errors
///
/// Store errors; a snapshot that does not open.
pub(super) fn project_snapshot_in_txn<'a>(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    key: &WindowKey,
    snapshot: &'a [u8],
) -> Result<Cow<'a, [u8]>> {
    let store = &vault.store;
    let Some(discarded) = discarded_for_in_txn(store, txn, key, false)? else {
        return Ok(Cow::Borrowed(snapshot));
    };
    let doc = doc_from_snapshot(snapshot)?;
    let held = home_held_in_txn(store, txn, key)?;
    Ok(
        match project_in_txn(store, txn, key, &doc, &discarded, &held)? {
            Some(bytes) => Cow::Owned(bytes),
            None => Cow::Borrowed(snapshot),
        },
    )
}

/// Persists `update`, the operations of window `key` that its live
/// document `doc` took past `base`, as one `u:w` row. For a BASE window that
/// the owner's discard took rows from, the row holds those operations as
/// `doc`, projected in that write, holds them. `from_home`: the home sent
/// `update`, so it holds the operations `update` itself carries; any other
/// operation `doc` took meanwhile, a local write among them, is not.
///
/// # Errors
///
/// Store errors; a projection that does not export.
pub(crate) fn persist_window_arrival(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    base: &VersionVector,
    update: &[u8],
    from_home: bool,
) -> Result<()> {
    if key.world().is_some() {
        // Its pads persist by reference where custody here holds them (FIX 7107).
        let persisted = persisted_window_pads(vault, key, update, Some(doc));
        return persist_window_update(vault, key.as_str(), &persisted);
    }
    // The live document keeps its observers: the projection reads a copy,
    // taken before the write. A discard that touches the window after this
    // read owes the window a projection of its own.
    let touched = {
        let txn = vault.store.env.read_txn()?;
        discard_touched_in(&vault.store, &txn, key.as_str())?
    };
    let copy = touched.then(|| doc.fork());
    // A BASE window holds no pad row: its bytes persist as they are.
    vault.with_write_txn_grouped(|txn| {
        let store = &vault.store;
        let projected = match (&copy, discarded_for_in_txn(store, txn, key, true)?) {
            (Some(copy), Some(discarded)) => {
                let mut held = home_held_in_txn(store, txn, key)?;
                if from_home {
                    held.merge(&sent_end(update));
                }
                match project_in_txn(store, txn, key, copy, &discarded, &held)? {
                    Some(bytes) => Some(export_updates_from(&doc_from_snapshot(&bytes)?, base)?),
                    None => None,
                }
            }
            _ => None,
        };
        persist_window_update_in_txn(
            vault,
            txn,
            key.as_str(),
            projected.as_deref().unwrap_or(update),
        )
    })
}

/// Whether `update`, a self-contained update of window `key`, holds a value
/// the rows in `discarded` own, or cannot be shown not to.
pub(crate) fn update_holds_discarded(
    key: &WindowKey,
    update: &[u8],
    discarded: &BTreeSet<EntityId>,
) -> bool {
    let doc = create_window_doc("discard-census", key);
    import_doc(&doc, update).is_err()
        || !matches!(
            project_window_doc(&doc, discarded, None),
            Ok(Projected::Unchanged)
        )
}

/// `update`, a self-contained update of window `key` that no peer holds,
/// with every value the rows in `discarded` own erased at its own operation
/// (E3 = A); `None` when it holds none. A staged foreign import is projected
/// so before its content persists (E4 = A).
///
/// # Errors
///
/// An update that does not open; one the projection cannot place, refused
/// retryably as configuration.
pub(crate) fn project_unsent_update(
    key: &WindowKey,
    update: &[u8],
    discarded: &BTreeSet<EntityId>,
) -> Result<Option<Vec<u8>>> {
    if discarded.is_empty() {
        return Ok(None);
    }
    let doc = create_window_doc("discard-stage", key);
    import_doc(&doc, update)?;
    match project_window_doc(&doc, discarded, None)? {
        Projected::Unchanged => Ok(None),
        Projected::Deferred(why) => Err(Error::InvalidConfig(format!(
            "an update that holds discarded rows the projection cannot place: {why}"
        ))),
        Projected::Joined { bytes, .. } => Ok(Some(export_updates_from(
            &doc_from_snapshot(&bytes)?,
            &VersionVector::default(),
        )?)),
    }
}

/// `doc` as the projection for `discarded` leaves it, with only the
/// operations in `held` rewritten, and the floor raised to hold them.
/// Returns `None` when nothing changed. A value left whole, or a document
/// the projection cannot place, keeps the window's projection owed.
fn project_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    key: &WindowKey,
    doc: &LoroDoc,
    discarded: &BTreeSet<EntityId>,
    held: &VersionVector,
) -> Result<Option<Vec<u8>>> {
    let window = key.as_str();
    match project_window_doc(doc, discarded, Some(held))? {
        Projected::Unchanged => Ok(None),
        Projected::Deferred(why) => {
            tracing::info!(%window, why, "BASE window arrival persists before its projection");
            mark_projection_owed_in_txn(store, txn, window)?;
            Ok(None)
        }
        Projected::Joined { bytes, waiting, .. } => {
            raise_floor_in_txn(store, txn, window, &held_of(&doc.oplog_vv(), held))?;
            if waiting > 0 {
                mark_projection_owed_in_txn(store, txn, window)?;
            }
            Ok(Some(bytes))
        }
    }
}

/// Where each peer's operations in `update` end: the home, having sent it,
/// holds every operation of those peers up to there. An update that does not
/// decode proves nothing.
fn sent_end(update: &[u8]) -> VersionVector {
    LoroDoc::decode_import_blob_meta(update, true)
        .map(|meta| meta.partial_end_vv)
        .unwrap_or_default()
}

/// The operations of `version` that `held` holds: each peer at the lesser
/// of its two ends.
fn held_of(version: &VersionVector, held: &VersionVector) -> VersionVector {
    version
        .iter()
        .filter_map(|(peer, end)| {
            let held_end = held.get(peer).copied().unwrap_or(0).min(*end);
            (held_end > 0).then_some((*peer, held_end))
        })
        .collect()
}
