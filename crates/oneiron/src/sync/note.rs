//! Native NOTE carriers for ordinary window sync, distinct from history-free recovery.
//!
//! Proposal carriers contain text values, never nested CRDT history or active
//! document authority. Canonical live NOTE sync uses the authenticated socket.
//! A review bundle is no month's: `workflows` carries it beside each NOTE
//! it holds a member of.

pub(super) mod checkpoint;
mod codec;
mod materialize;
mod mirror;
mod scrub;
mod workflows;
pub(crate) use scrub::{deleted, deleted_elsewhere, deleted_elsewhere_under_lock};

pub(crate) use materialize::apply;
pub(crate) use mirror::{copy_judged, copy_selected, refresh, refresh_for};
use workflows::BundleCarrier;
pub(crate) use workflows::NoteSelection;

use crate::note::documents::{doc_key, invalid};
use crate::note::{NoteFork, NoteLandingReceipt, NoteReviewBundle};
use crate::sync::loro_support::TombstoneIndex;
use crate::{EntityId, Vault, error::Result};
use loro::{LoroDoc, LoroValue, ValueOrContainer};
use std::collections::{BTreeMap, BTreeSet};

const FORMAT_KEY: &str = "@note-sync";
const FORMAT: &[u8] = b"proposal-values-v3";
/// The explainer a bundle that lost a member keeps, as the erase leaves it:
/// it can quote what left.
const REDACTED: &str = "redacted";
const MAPS: [&str; 5] = [
    "documents",
    "document_heads",
    "head_move_receipts",
    "note_forks",
    "note_proposals",
];

#[derive(Default, Clone)]
pub(crate) struct State {
    cores: BTreeMap<EntityId, Vec<u8>>,
    docs: BTreeMap<(EntityId, EntityId), String>,
    heads: BTreeMap<EntityId, EntityId>,
    forks: BTreeMap<EntityId, NoteFork>,
    receipts: BTreeMap<EntityId, NoteLandingReceipt>,
    bundles: BTreeMap<EntityId, BundleCarrier>,
}

pub(crate) fn is_native(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key("documents"))
        && doc.get_map("documents").get(FORMAT_KEY).is_some()
}

pub(crate) fn validate(doc: &LoroDoc) -> Result<State> {
    let mut state = codec::read(doc)?;
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    let dropped: BTreeSet<_> = state
        .notes()
        .into_iter()
        .filter(|note| tombstones.contains(note))
        .collect();
    state.drop_deleted(&dropped);
    state.validate()?;
    Ok(state)
}

fn pack<T: serde::Serialize>(row: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| invalid("NOTE carrier encode"))
}
fn unpack<T: serde::de::DeserializeOwned + serde::Serialize>(bytes: &[u8]) -> Result<T> {
    let row = rmp_serde::from_slice(bytes).map_err(|_| invalid("NOTE carrier decode"))?;
    if pack(&row)? != bytes {
        return Err(invalid("noncanonical NOTE carrier"));
    }
    Ok(row)
}
fn id(key: &str) -> Result<EntityId> {
    let id = EntityId::from_hex(key)?;
    if id.to_hex() != key {
        return Err(invalid("NOTE carrier id"));
    }
    Ok(id)
}
fn rows(doc: &LoroDoc, name: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let mut rows = Vec::new();
    let mut bad = false;
    doc.get_map(name).for_each(|key, value| match value {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => {
            rows.push((key.to_owned(), bytes.to_vec()));
        }
        _ => bad = true,
    });
    if bad {
        return Err(invalid("NOTE carrier must be binary"));
    }
    Ok(rows)
}
fn bundle_notes(bundle: &NoteReviewBundle) -> BTreeSet<EntityId> {
    bundle
        .waiting
        .iter()
        .map(|row| row.note)
        .chain(bundle.landed.iter().map(|row| row.note))
        .collect()
}
/// Whether a device-only world keeps `note` on this device. Unlike a blocked
/// NOTE it is never removed from a window that already carries it: a removal
/// would delete a receiver's copy once the flag clears. The export doors
/// withhold such a window whole instead.
fn held(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    flagged: &BTreeSet<EntityId>,
    note: &EntityId,
) -> Result<bool> {
    crate::settings::device_only_withholds(&vault.store, txn, flagged, note)
}
/// Whether no export of the document `tombstones` indexes carries `note`: it
/// is tombstoned there, deleted here, off the record, or an erased shell.
pub(crate) fn blocked(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    tombstones: &TombstoneIndex,
    note: &EntityId,
) -> Result<bool> {
    if tombstones.contains(note)
        || vault.local_hard_delete_marker_exists_in_txn(txn, note)?
        || vault.store.off_record_sessions.contains_entity(note)?
    {
        return Ok(true);
    }
    Ok(
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, note)?
            .is_some_and(|row| row.len() == crate::batch::ENTITY_METADATA_HEADER_LEN),
    )
}

impl State {
    fn drop_deleted(&mut self, dropped: &BTreeSet<EntityId>) {
        self.cores.retain(|note, _| !dropped.contains(note));
        self.docs.retain(|(note, _), _| !dropped.contains(note));
        self.heads.retain(|note, _| !dropped.contains(note));
        self.forks.retain(|_, row| !dropped.contains(&row.note));
        self.receipts.retain(|_, row| !dropped.contains(&row.note));
        self.bundles.retain(|_, row| {
            if bundle_notes(&row.bundle).is_disjoint(dropped) {
                return true;
            }
            row.bundle
                .waiting
                .retain(|fork| !dropped.contains(&fork.note));
            row.bundle
                .landed
                .retain(|receipt| !dropped.contains(&receipt.note));
            row.redact();
            !row.bundle.waiting.is_empty() || !row.bundle.landed.is_empty()
        });
        self.prune_attachments();
    }
    /// Each actor this vault erased out of the workflow rows this state
    /// carries, as the erase takes it out of this vault's own (FIX 3878): a
    /// decided fork, a landing and a receipt name no one, and a fork no one
    /// decided goes with its proposal value and its place in a bundle.
    fn erase_actors_here(&mut self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        for (id, fork) in std::mem::take(&mut self.forks) {
            let place = (fork.note, fork.fork);
            match fork.carried_here(vault, txn)? {
                Some(fork) => {
                    self.forks.insert(id, fork);
                }
                None => {
                    self.docs.remove(&place);
                }
            }
        }
        for receipt in self.receipts.values_mut() {
            receipt.actor = receipt.actor.erased_here(vault, txn)?;
        }
        for (id, mut row) in std::mem::take(&mut self.bundles) {
            let members = row.bundle.waiting.len();
            if let Some(bundle) = row.bundle.carried_here(vault, txn)? {
                let left = bundle.waiting.len() != members;
                row.bundle = bundle;
                if left {
                    row.redact();
                }
                self.bundles.insert(id, row);
            }
        }
        self.prune_attachments();
        Ok(())
    }
}
