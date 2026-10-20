//! An erased actor's births leave the window carriers (FIX 6279).
//!
//! A window's `row_births` map carries each replicated row's birth beside its
//! row, and a birth names the actor that made it. When this vault hard-erases
//! that actor, the actor's scrub drops, in the erase's own transaction, every
//! carrier of a birth it made from every window this vault stores, but for a
//! born row a legal hold keeps: that carrier stays with its birth until the
//! hold lifts (FIX 6280). An unknown birth stays too: a row with no birth here
//! is not erased provenance.
//!
//! The scrub never touches a loaded window. It rebuilds each stored window in
//! a document no observer watches, from the erase's own transaction, and
//! stores its removals as one more pending update of that window, so a loaded
//! copy takes them when it next merges its stored state. The window is pinned
//! history-free, since a removed carrier stays in its history until the erase
//! sweep compacts it, and the erase owes the sweep that compaction (FIX 6387);
//! its queued sends go but the delete-bearing, and it owes a full resync. Until a loaded copy merges, and whenever a peer's copy
//! brings a carrier back, every export, persist and mirror drops it first
//! ([`scrub_erased_actor_births`], [`drop_erased_carrier`]), and the birth
//! itself never lands again (`stamp_replicated_row_birth_in_txn`).

use std::collections::{BTreeMap, BTreeSet};

use loro::{CommitOptions, LoroDoc};

use super::births;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::provenance::birth::{RowBirth, birth_held_in_txn};
use crate::sync::bridge::{BRIDGE_ORIGIN, persist_window_update_in_txn};
use crate::sync::loro_support::{
    doc_from_snapshot, export_updates_from, import_doc, map_delete, map_for_each_bytes,
    map_get_bytes,
};
use crate::sync::residence::residence_window_for_blob;
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::sync::window_rows::{HISTORY_FREE_WINDOW, WINDOW_FULL_RESYNC_MARKER};

/// Drops, in the erase's own transaction, every stored window carrier of a
/// birth one of `actors` made, but for a born row a legal hold keeps. A window
/// whose stored bytes do not rebuild keeps its carriers, with a warning: the
/// erase stands, and nothing ships from that window before its next export
/// drops them.
///
/// # Errors
///
/// Storage errors, or a removal that cannot be written.
pub(crate) fn erase_birth_carriers_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actors: &BTreeSet<EntityId>,
) -> Result<()> {
    if actors.is_empty() {
        return Ok(());
    }
    let named = |actor: &EntityId| Ok(actors.contains(actor));
    for key in stored_windows_in_txn(vault, wtxn)? {
        let doc = match stored_window_in_txn(vault, wtxn, &key)? {
            Some(Ok(doc)) => doc,
            Some(Err(error)) => {
                tracing::warn!(
                    window = %key,
                    error = %error,
                    "erased actor's birth carriers: stored window does not rebuild; left \
                     for its next export"
                );
                continue;
            }
            None => continue,
        };
        let doomed = doomed_carriers_in_txn(vault, wtxn, &doc, named)?;
        if !doomed.is_empty() {
            drop_from_stored_window_in_txn(vault, wtxn, &key, &doc, &doomed)?;
        }
    }
    Ok(())
}

/// Drops from `doc` each birth carrier whose maker this vault erased, by its
/// own `dt:` marker, but for a born row a legal hold keeps. Every export and
/// persist runs it, so neither a loaded window that has not merged the
/// erase's removals nor a carrier a peer's copy brought back ever ships. The
/// window `history_free` names is pinned history-free first. Whether anything
/// changed.
///
/// # Errors
///
/// Storage errors, or the pin's write.
pub(in crate::sync) fn scrub_erased_actor_births(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    let doomed = {
        let rtxn = vault.store.env.read_txn()?;
        let mut seen: BTreeMap<EntityId, bool> = BTreeMap::new();
        doomed_carriers_in_txn(vault, &rtxn, doc, |actor| {
            if let Some(erased) = seen.get(actor) {
                return Ok(*erased);
            }
            let erased = vault.carrier_actor_erased_in_txn(&rtxn, actor)?;
            seen.insert(*actor, erased);
            Ok(erased)
        })?
    };
    if doomed.is_empty() {
        return Ok(false);
    }
    // Pin BEFORE the removal: the operation that put each carrier in still
    // names its maker.
    if let Some(key) = history_free {
        crate::sync::window::require_history_free_window(vault, key)?;
    }
    let map = births(doc);
    for key in &doomed {
        map_delete(&map, key)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}

/// `mirror_local_birth` for a row with no birth here: the carrier `doc` holds
/// for `id` goes when this vault erased its maker and no legal hold keeps the
/// row, once the window the row's carrier names is pinned history-free. A row
/// with no birth is not erased provenance: an unknown birth, or one that has
/// not landed yet, keeps its carrier, and so does one whose window this
/// cannot name (the next export drops it). Whether the map changed.
///
/// # Errors
///
/// Storage errors, or the pin's write.
pub(super) fn drop_erased_carrier(vault: &Vault, doc: &LoroDoc, id: &EntityId) -> Result<bool> {
    let map = births(doc);
    let key = id.to_hex();
    let Some(actor) = map_get_bytes(&map, &key).as_deref().and_then(maker) else {
        return Ok(false);
    };
    let entities = doc.get_map("entities");
    let Some(carrier) = map_get_bytes(&entities, &key) else {
        return Ok(false);
    };
    let Ok(window) = residence_window_for_blob(&carrier) else {
        return Ok(false);
    };
    {
        let rtxn = vault.store.env.read_txn()?;
        if !vault.carrier_actor_erased_in_txn(&rtxn, &actor)?
            || birth_held_in_txn(&vault.store, &rtxn, id)?
        {
            return Ok(false);
        }
    }
    crate::sync::window::require_history_free_window(vault, &window)?;
    map_delete(&map, &key)?;
    Ok(true)
}

/// The keys of `doc`'s birth carriers whose maker `erased` says this vault
/// erased, but for a born row a legal hold keeps. A carrier whose bytes do
/// not decode names no maker, and stays.
fn doomed_carriers_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    doc: &LoroDoc,
    mut erased: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<Vec<String>> {
    let mut carried = Vec::new();
    map_for_each_bytes(&births(doc), |key, bytes| {
        if let Some(actor) = maker(bytes) {
            carried.push((key.to_owned(), actor));
        }
    });
    let mut doomed = Vec::new();
    for (key, actor) in carried {
        if !erased(&actor)? {
            continue;
        }
        // A key that spells no row names nothing a hold keeps.
        let held = match EntityId::from_hex(&key) {
            Ok(row) => birth_held_in_txn(&vault.store, txn, &row)?,
            Err(_) => false,
        };
        if !held {
            doomed.push(key);
        }
    }
    Ok(doomed)
}

/// The actor a carried birth names as its maker, whatever its encoding.
fn maker(bytes: &[u8]) -> Option<EntityId> {
    rmp_serde::from_slice::<RowBirth>(bytes)
        .ok()
        .map(|birth| birth.made_by.process.actor)
}

/// Deletes the carriers under `doomed` from `doc`, the stored window `key`
/// rebuilt, and stores the removal in `wtxn` as one more pending update of
/// the window, which it pins history-free and marks for a full resync: the
/// removed carriers stay in its history, and a queued send may carry one, so
/// every queued send of it goes but the delete-bearing. The history goes when
/// the erasure sweep compacts the window, which this owes it (FIX 6387).
fn drop_from_stored_window_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &WindowKey,
    doc: &LoroDoc,
    doomed: &[String],
) -> Result<()> {
    let before = doc.oplog_vv();
    let map = births(doc);
    for map_key in doomed {
        map_delete(&map, map_key)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    let removal = export_updates_from(doc, &before)?;
    let label = key.as_str().to_owned();
    HISTORY_FREE_WINDOW.put(&vault.store, wtxn, &label, &[1u8])?;
    crate::sync::queue::scrub_window_updates_in_txn(vault, wtxn, &label)?;
    WINDOW_FULL_RESYNC_MARKER.put(&vault.store, wtxn, &label, &[1u8])?;
    crate::sweep::owed::owe_window_compaction_in_txn(vault, wtxn, key)?;
    // Last: the pending update marks the stored state vector stale too.
    persist_window_update_in_txn(vault, wtxn, &label, &removal)
}

/// Every window this vault stores state for, read in `txn`: each snapshot's
/// label and each pending update's window. A label that is no window key is
/// no window a load opens either.
fn stored_windows_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<WindowKey>> {
    let mut labels: BTreeSet<String> = vault
        .store
        .port_window_doc_rows_raw(txn, |window, _| window.as_str().to_owned())?
        .collect::<Result<_>>()?;
    for label in vault
        .store
        .port_window_update_keys(txn, None, update_window)?
    {
        labels.extend(label?);
    }
    let windows = labels.into_iter().filter_map(WindowKey::try_new);
    Ok(windows.collect())
}

/// The window a pending update's full key (`u:w:{window}:{seq}`) names.
fn update_window(key: &str) -> Option<String> {
    let (window, _) = key.strip_prefix("u:w:")?.rsplit_once(':')?;
    Some(window.to_owned())
}

/// The window `key` as `txn` stores it, rebuilt in a document no observer
/// watches: its snapshot with each pending update on top. `None` when it
/// stores nothing; the inner error when its bytes do not rebuild.
fn stored_window_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &WindowKey,
) -> Result<Option<Result<LoroDoc>>> {
    let address = WindowAddress::new(key.as_str());
    let snapshot = vault
        .store
        .port_window_doc_with_raw(txn, address, |raw| Ok(doc_from_snapshot(raw)))?;
    let mut stored = snapshot.is_some();
    let doc = match snapshot {
        Some(Ok(doc)) => doc,
        Some(Err(error)) => return Ok(Some(Err(error))),
        None => create_window_doc("local", key),
    };
    for imported in vault
        .store
        .port_window_updates(txn, address, |_, update| import_doc(&doc, update))?
    {
        if let Err(error) = imported? {
            return Ok(Some(Err(error)));
        }
        stored = true;
    }
    Ok(stored.then_some(Ok(doc)))
}
