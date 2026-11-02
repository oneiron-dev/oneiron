//! Re-bootstrap of a window from its canonical rebuild (OF-005, ARCH-0038
//! `#recover-window-built`): the rebuilt state becomes the window's durable
//! CRDT state with no history behind it, and every peer resyncs through the
//! history-free door.
//!
//! The rebuilt state lands as the history-free successor of the window's own
//! lineage, not as the rebuild's unrelated history. A rebuilt document shares
//! no operation with any peer: a peer would merge it as concurrent history,
//! and a replacement's carry-over could not order the peer's writes against
//! it, so a value the peer saw superseded would come back over it. So the
//! window's durable document takes the rebuilt value of every root-map key it
//! differs on, as one change, and is cut to a shallow snapshot at its newest
//! operation, as the HardErase compaction cuts it:
//!
//! - a peer holding the whole window keeps taking ordinary updates;
//! - a peer behind the cut holds no vector covering its root, so the export
//!   door answers it with a [`WindowExport::Replacement`](super::WindowExport),
//!   which it installs, writing its own unseen writes back on top;
//! - an update built on history the cut dropped reaches below the root
//!   ([`update_reaches_below_root`](super::update_reaches_below_root)): the
//!   home answers it with its replacement, and a device asks for one.
//!
//! The version vector stays the lineage's own, extended by at most the one
//! barrier operation a cut of a window with several heads takes (FIX 6520); a
//! fresh one would need every peer to learn which writes the rebuild already
//! held.

use std::collections::{BTreeMap, BTreeSet};

use loro::{LoroDoc, LoroValue};

use super::super::loro_support::{doc_from_snapshot, doc_version_vector, import_doc, map_delete};
use super::super::types::WindowKey;
use super::super::window_rows::{WINDOW_FULL_RESYNC_MARKER, WINDOW_UPDATE};
use super::{persist_window_doc_in_txn, write_window_svf_in_txn};
use crate::Vault;
use crate::error::{ArtifactError, Error, Result, SyncEngineContext};
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::store::legal_hold::{HoldActor, is_hold_refusal};
use crate::sync::carrier_holds::CarrierInventory;

/// A rebuilt window cut and ready to install; nothing is persisted yet.
pub(crate) struct PreparedRebootstrap {
    key: WindowKey,
    /// The window as it will stand: the rebuilt state at its new root, with
    /// no history behind it.
    pub(crate) doc: LoroDoc,
    state: Vec<u8>,
    version: Vec<u8>,
    /// The durable carriers the cut was built from, checked again in the
    /// install transaction.
    read_snapshot: Option<Vec<u8>>,
    read_updates: BTreeSet<Vec<u8>>,
    /// Every row id and pad the window's carriers held before the cut, its
    /// history's too: the cut drops each one's bytes (FIX 3061).
    holds: CarrierInventory,
    /// Root-map keys whose value the rebuilt state changed or removed.
    pub(crate) rewritten: usize,
    /// Whether the cut failed its proof (FIX 6520): the install then owes the
    /// erasure sweep a compaction of the window.
    owes_compaction: bool,
}

/// Cuts window `key`'s durable state (its snapshot and every pending update)
/// to `rebuilt`'s state: the rebuilt value of each root-map key the two
/// differ on, and no key `rebuilt` lacks, written as one change of the
/// window's own lineage, then a shallow snapshot at its newest operation.
pub(crate) fn prepare_rebootstrap(
    vault: &Vault,
    key: &WindowKey,
    rebuilt: &LoroDoc,
) -> Result<PreparedRebootstrap> {
    let window = key.as_str().to_owned();
    let (read_snapshot, rows) = {
        let rtxn = vault.store.env.read_txn()?;
        let address = WindowAddress::new(&window);
        let rows = vault
            .store
            .port_window_updates(&rtxn, address, |row, bytes| (row, bytes.to_vec()))?
            .collect::<Result<Vec<_>>>()?;
        let snapshot = vault
            .store
            .port_window_doc_with_raw(&rtxn, address, |raw| Ok(raw.to_vec()))?;
        (snapshot, rows)
    };
    if rows.iter().any(|(row, _)| row.window != window) {
        return Err(not_installable("pending update outside the window"));
    }
    if read_snapshot.is_none() && rows.is_empty() {
        return Err(not_installable("window has no durable CRDT state"));
    }
    let doc = match &read_snapshot {
        Some(bytes) => doc_from_snapshot(bytes)?,
        None => crate::sync::schema::create_window_doc("", key),
    };
    for (_, bytes) in &rows {
        import_doc(&doc, bytes)?;
    }
    let holds = CarrierInventory::of_window(&doc);
    let rewritten = write_rebuilt_state(&doc, rebuilt)?;
    // With no key rewritten the window can keep several heads: the strict cut
    // merges them first, so the root is still its newest operation (FIX 6520).
    let cut = super::shallow::strict_window_cut(&doc)?;
    let doc = doc_from_snapshot(&cut.bytes)?;
    Ok(PreparedRebootstrap {
        key: key.clone(),
        version: doc_version_vector(&doc),
        doc,
        state: cut.bytes,
        owes_compaction: !cut.proved,
        read_snapshot,
        read_updates: rows
            .iter()
            .map(|(row, _)| WINDOW_UPDATE.key_bytes(row))
            .collect(),
        holds,
        rewritten,
    })
}

impl PreparedRebootstrap {
    /// Installs the cut as the window's durable state in one transaction: its
    /// snapshot and version, every pending update it folded in retired, the
    /// state vector fresh and the full-resync marker a shallow cut sets.
    /// Refused with nothing written when the window's carriers changed since
    /// the cut read them, or a legal hold names a row whose history it drops,
    /// or the world of a pad it drops (OF-470, as the compaction refuses). A
    /// cut that failed its proof owes the erasure sweep the window, in the
    /// same transaction.
    pub(crate) fn install(self, vault: &Vault, actor: &HoldActor) -> Result<LoroDoc> {
        let window = self.key.as_str().to_owned();
        let prefix = format!("{window}:");
        vault.with_write_txn_grouped(|wtxn| {
            let address = WindowAddress::new(&window);
            if vault
                .store
                .port_window_doc_with_raw(wtxn, address, |raw| Ok(raw.to_vec()))?
                != self.read_snapshot
            {
                return Err(Error::ConcurrentWrite(
                    "window snapshot changed during re-bootstrap",
                ));
            }
            let updates: BTreeSet<Vec<u8>> = vault
                .store
                .port_window_updates(wtxn, address, |row, _| row)?
                .collect::<Result<Vec<_>>>()?
                .iter()
                .map(|row| WINDOW_UPDATE.key_bytes(row))
                .collect();
            if updates != self.read_updates {
                return Err(Error::ConcurrentWrite(
                    "window updates changed during re-bootstrap",
                ));
            }
            self.holds.reject_held_in_txn(&vault.store, wtxn, actor)?;
            persist_window_doc_in_txn(vault, wtxn, &self.key, &self.state, &self.version)?;
            WINDOW_UPDATE.delete_from(&vault.store, wtxn, prefix.as_bytes())?;
            WINDOW_FULL_RESYNC_MARKER.put(&vault.store, wtxn, &window, &[1u8])?;
            if self.owes_compaction {
                crate::sweep::owed::owe_window_compaction_in_txn(vault, wtxn, &self.key)?;
            }
            write_window_svf_in_txn(vault, wtxn, &self.key)
        })?;
        Ok(self.doc)
    }
}

/// Refuses, before any work, a re-bootstrap whose cut a legal hold would
/// stop: one naming any row `doc` carries or carried, or the world of a pad
/// it holds or held (FIX 3061). A held refusal is in its hold log before
/// this returns: once the read snapshot ended, and only then, it takes a
/// writer of its own (FIX 2433). No materializer lock is held here.
pub(crate) fn reject_held_rebootstrap(
    vault: &Vault,
    doc: &LoroDoc,
    actor: &HoldActor,
) -> Result<()> {
    let holds = CarrierInventory::of_window(doc);
    let refusals = vault.store.begin_refusal_attempt();
    let checked = vault
        .store
        .env
        .read_txn()
        .map_err(Error::from)
        .and_then(|rtxn| holds.reject_held_in_txn(&vault.store, &rtxn, actor));
    let refusals = refusals.finish();
    if checked.as_ref().is_err_and(is_hold_refusal) {
        refusals.settle_now();
    }
    checked
}

/// Writes into `doc` the rebuilt value of every root-map key it differs on,
/// and removes every key `rebuilt` lacks. Returns how many keys it touched.
fn write_rebuilt_state(doc: &LoroDoc, rebuilt: &LoroDoc) -> Result<usize> {
    let held = root_rows(doc)?;
    let target = root_rows(rebuilt)?;
    let mut rewritten = 0;
    for name in held.keys().chain(target.keys()).collect::<BTreeSet<_>>() {
        let (held, target) = (held.get(name), target.get(name));
        if held.is_none_or(BTreeMap::is_empty) && target.is_none_or(BTreeMap::is_empty) {
            continue;
        }
        let map = doc.get_map(name.as_str());
        for (key, value) in target.into_iter().flatten() {
            if held.and_then(|rows| rows.get(key)) != Some(value) {
                map.insert(key, value.clone())
                    .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
                rewritten += 1;
            }
        }
        for key in held.into_iter().flat_map(BTreeMap::keys) {
            if target.is_none_or(|rows| !rows.contains_key(key)) {
                map_delete(&map, key)?;
                rewritten += 1;
            }
        }
    }
    Ok(rewritten)
}

/// Every root map of `doc` and its rows. A window row is bytes: no window
/// writer nests a container or writes another value.
fn root_rows(doc: &LoroDoc) -> Result<BTreeMap<String, BTreeMap<String, LoroValue>>> {
    let LoroValue::Map(roots) = doc.get_deep_value() else {
        return Err(not_installable("window root"));
    };
    let mut maps = BTreeMap::new();
    for (name, value) in roots.iter() {
        let LoroValue::Map(rows) = value else {
            return Err(not_installable("non-map window root"));
        };
        let mut kept = BTreeMap::new();
        for (key, value) in rows.iter() {
            if !matches!(value, LoroValue::Binary(_)) {
                return Err(not_installable("non-binary window row"));
            }
            kept.insert(key.clone(), value.clone());
        }
        maps.insert(name.clone(), kept);
    }
    Ok(maps)
}

fn not_installable(reason: &'static str) -> Error {
    ArtifactError::InvalidRecoveryArtifact(reason).into()
}
