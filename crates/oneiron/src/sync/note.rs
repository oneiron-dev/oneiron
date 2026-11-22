//! Native NOTE carriers for ordinary window sync, distinct from history-free recovery.
//!
//! Proposal carriers contain text values, never nested CRDT history or active
//! document authority. Canonical live NOTE sync uses the authenticated socket.
//! A review bundle is no month's: `workflows` carries it beside each NOTE
//! it holds a member of.

pub(super) mod checkpoint;
mod codec;
pub(crate) mod discard;
mod materialize;
mod mirror;
mod scrub;
mod workflows;
#[cfg(oneiron_test_support)]
pub(crate) use scrub::{arm_scrub_entry_hook, seed_waiting_bundle};
pub(crate) use scrub::{deleted, deleted_elsewhere, scrub_missed_note_deletes};

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

use crate::deletion::window_document_format::FORMAT_KEY;
const FORMAT: &[u8] = b"proposal-values-v3";
#[doc(hidden)]
use oneiron_records::sync::note::REDACTED;

pub(in crate::sync) const MAPS: [&str; 5] = [
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

pub(crate) use crate::deletion::window_document_format::is_native;

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
/// Whether `note` is withheld here: a record use limit keeps it for storage
/// only on this vault (a privacy erase a customer hold refused, C6, or a
/// cooperative review restriction), or the vault it came from withheld it
/// after it travelled, so it reads to no one here (`HeldBack::Withheld`, as
/// a device holds such a NOTE back; REVIEW-9846 round 2). No window gains
/// its core from this vault's store, no workflow of it is packed, and it
/// rides as no other NOTE's attachment. Unlike a blocked NOTE its carrier is
/// not removed here: the withholding pass takes a use-limited one out under
/// a marker (`window::withhold_use_limited_carriers`), so a receiver holds it
/// back rather than deleting it (Engine ANSWER
/// SERVING-DOORS-OWNER-WINDOW-USE-LIMIT = B).
fn withheld_here(vault: &Vault, txn: &heed::RoTxn<'_>, note: &EntityId) -> Result<bool> {
    Ok(
        crate::store::legal_hold::use_limit_in_txn(&vault.store, txn, note)?.is_some()
            || crate::source_audience::held_back_in(vault, txn, note)?
                == Some(crate::source_audience::HeldBack::Withheld),
    )
}
/// Whether this vault withholds any NOTE ([`withheld_here`]): it holds a
/// record use limit or a row held back.
fn any_withheld(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(
        crate::store::legal_hold::any_record_use_limit_in_txn(&vault.store, txn)?
            || crate::source_audience::any_held_in(vault, txn)?,
    )
}
/// The NOTEs whose workflow rows `doc` carries, as a core or as a bundle's
/// attachment; none for a document with no NOTE maps.
///
/// # Errors
///
/// Codec failures of the document's NOTE maps.
pub(crate) fn workflow_notes(doc: &LoroDoc) -> Result<BTreeSet<EntityId>> {
    if !is_native(doc) {
        return Ok(BTreeSet::new());
    }
    Ok(codec::read(doc)?.notes())
}
/// Takes every workflow row of each of `notes` out of `doc` (its proposal
/// documents, head, forks, receipts and place in a bundle), as a dropped
/// NOTE's go. The caller commits. Whether anything went.
///
/// # Errors
///
/// Codec failures of the document's NOTE maps.
pub(crate) fn drop_workflows(doc: &LoroDoc, notes: &BTreeSet<EntityId>) -> Result<bool> {
    if notes.is_empty() || !is_native(doc) {
        return Ok(false);
    }
    let mut state = codec::read(doc)?;
    if state.notes().is_disjoint(notes) {
        return Ok(false);
    }
    state.drop_deleted(notes);
    state.validate()?;
    state.write(doc)
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

#[cfg(oneiron_test_support)]
pub(crate) use workflows::note_fork_key_pin_for_test;
