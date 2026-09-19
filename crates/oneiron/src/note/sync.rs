//! Native NOTE carriers for ordinary window sync, distinct from history-free recovery.
//!
//! The existing documents map carries a format discriminator. Native snapshots
//! retain CRDT ancestry (and cursors); canonical recovery deliberately does not.

mod codec;
mod materialize;
mod merge;
mod mirror;
mod scrub;
pub(crate) use scrub::deleted;

pub(crate) use materialize::apply;
pub(crate) use mirror::{copy_selected, refresh};

use super::documents::{doc_key, invalid};
use super::{NoteFork, NoteLandingReceipt, NoteReviewBundle};
use crate::{EntityId, Vault, error::Result};
use loro::{LoroDoc, LoroValue, ValueOrContainer};
use std::collections::{BTreeMap, BTreeSet};

const FORMAT_KEY: &str = "@note-sync";
const FORMAT: &[u8] = b"native-v1";
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
    docs: BTreeMap<(EntityId, EntityId), Vec<u8>>,
    heads: BTreeMap<EntityId, EntityId>,
    forks: BTreeMap<EntityId, NoteFork>,
    receipts: BTreeMap<EntityId, NoteLandingReceipt>,
    bundles: BTreeMap<EntityId, NoteReviewBundle>,
}

pub(crate) fn is_native(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key("documents"))
        && doc.get_map("documents").get(FORMAT_KEY).is_some()
}

pub(crate) fn validate(doc: &LoroDoc) -> Result<State> {
    let mut state = codec::read(doc)?;
    let dropped: BTreeSet<_> = state
        .cores
        .keys()
        .chain(state.heads.keys())
        .copied()
        .chain(state.docs.keys().map(|(note, _)| *note))
        .filter(|note| {
            crate::sync::loro_support::tombstone_map_contains_id(&doc.get_map("tombstones"), note)
        })
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
            rows.push((key.to_owned(), bytes.to_vec()))
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
fn metadata_key(prefix: &[u8], id: EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
}
fn blocked(vault: &Vault, txn: &heed::RoTxn<'_>, doc: &LoroDoc, note: &EntityId) -> Result<bool> {
    if crate::sync::loro_support::tombstone_map_contains_id(&doc.get_map("tombstones"), note)
        || vault.local_hard_delete_marker_exists_in_txn(txn, note)?
        || vault.store.off_record_sessions.contains_entity(note)?
    {
        return Ok(true);
    }
    Ok(vault
        .store
        .entities
        .get(txn, note.as_bytes())?
        .is_some_and(|row| row.len() == crate::batch::ENTITY_METADATA_HEADER_LEN))
}

impl State {
    fn drop_deleted(&mut self, dropped: &BTreeSet<EntityId>) {
        self.cores.retain(|note, _| !dropped.contains(note));
        self.docs.retain(|(note, _), _| !dropped.contains(note));
        self.heads.retain(|note, _| !dropped.contains(note));
        self.forks.retain(|_, row| !dropped.contains(&row.note));
        self.receipts.retain(|_, row| !dropped.contains(&row.note));
        self.bundles.retain(|_, row| {
            if bundle_notes(row).is_disjoint(dropped) {
                return true;
            }
            row.waiting.retain(|fork| !dropped.contains(&fork.note));
            row.landed
                .retain(|receipt| !dropped.contains(&receipt.note));
            row.explainer = "redacted".to_owned();
            !row.waiting.is_empty() || !row.landed.is_empty()
        });
    }
    fn retain(&mut self, keep: &BTreeSet<EntityId>) -> Result<()> {
        for bundle in self.bundles.values() {
            let notes = bundle_notes(bundle);
            if !notes.is_disjoint(keep) && !notes.is_subset(keep) {
                return Err(invalid("NOTE proposal crosses export scope"));
            }
        }
        self.cores.retain(|note, _| keep.contains(note));
        self.docs.retain(|(note, _), _| keep.contains(note));
        self.heads.retain(|note, _| keep.contains(note));
        self.forks.retain(|_, row| keep.contains(&row.note));
        self.receipts.retain(|_, row| keep.contains(&row.note));
        self.bundles
            .retain(|_, row| bundle_notes(row).is_subset(keep));
        Ok(())
    }
}

fn merge_document(local: &[u8], incoming: &[u8]) -> Result<Vec<u8>> {
    let merged = LoroDoc::from_snapshot(local).map_err(|_| invalid("NOTE local snapshot"))?;
    let remote = LoroDoc::from_snapshot(incoming).map_err(|_| invalid("NOTE incoming snapshot"))?;
    let local_vv = merged.oplog_vv();
    let remote_vv = remote.oplog_vv();
    if !local_vv
        .iter()
        .any(|(peer, count)| *count > 0 && remote_vv.get(peer).is_some_and(|count| *count > 0))
    {
        return Err(invalid(
            "unrelated NOTE histories require canonical recovery",
        ));
    }
    merged
        .import(incoming)
        .map_err(|_| invalid("NOTE CRDT merge"))?;
    super::documents::snapshot(&merged)
}
