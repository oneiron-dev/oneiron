//! What an adopted checkpoint image gives the store doors in place of the raw
//! history it covers (OF-469, slice C).
//!
//! A vault that adopted an image (`checkpoint_adopt`) may hold none of the
//! covered rows' raw bytes, yet its doors judge each new row against that
//! history: the consent structure, each signer's rows and revocations, the
//! counted and slip rows, the slip issuers' handoffs, the strangers' rows,
//! the order a local write stages its rows in, and the ancestry a
//! retired-standing walk reads. Each comes from the image here: its row
//! summaries (signer, sequence, parents, world, slip op) and the canonical
//! signed bodies it carries, decoded by hash. The fold the doors read beside
//! it already holds the image's retired keys, closed handoffs and valid rows.
//!
//! Nothing here makes a row resident: a resident row still means its raw
//! bytes are stored, so a door's "already stored, lands" rule never reaches a
//! covered row the vault does not store. A vault with no adoption reads raw
//! history alone, exactly as before.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::checkpoint_adopt::adopted_authority_checkpoint_in_txn;
use super::*;
use crate::error::{Error, Result};
use crate::store::Store;

/// The image this vault adopted, verified, with its carried bodies decoded by
/// hash and the store id each covered row would have.
#[derive(Debug)]
pub(crate) struct AdoptedEvidence {
    checkpoint: VerifiedAuthorityCheckpoint,
    bodies: BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ids: BTreeSet<crate::EntityId>,
}

impl AdoptedEvidence {
    /// The evidence of the image this vault adopted, verified again in `txn`;
    /// None when it adopted none. A stored adoption that no longer verifies is
    /// corruption, never "not adopted".
    pub(super) fn read_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Option<Self>> {
        let Some(checkpoint) = adopted_authority_checkpoint_in_txn(store, txn)? else {
            return Ok(None);
        };
        let mut bodies = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for (hash, row) in &checkpoint.image().rows {
            ids.insert(authority_log_entity_id_from_hash(hash)?);
            if let Some(body) = &row.body {
                bodies.insert(*hash, decode_authority_log_entry_body(body)?);
            }
        }
        Ok(Some(Self {
            checkpoint,
            bodies,
            ids,
        }))
    }

    /// Each covered row's summary, by hash.
    pub(super) fn rows(&self) -> &BTreeMap<AuthorityEntryHash, AuthorityCheckpointRow> {
        &self.checkpoint.image().rows
    }

    /// Every carried body, decoded, by hash.
    pub(super) fn bodies(&self) -> &BTreeMap<AuthorityEntryHash, AuthorityLogEntry> {
        &self.bodies
    }

    /// The carried body of the covered row `hash`, decoded.
    pub(super) fn body(&self, hash: &AuthorityEntryHash) -> Option<&AuthorityLogEntry> {
        self.bodies.get(hash)
    }

    /// Whether the image covers the row stored at `id`.
    pub(super) fn covers_id(&self, id: &crate::EntityId) -> bool {
        self.ids.contains(id)
    }

    /// Each carried body of a covered row whose hash `stored` does not hold,
    /// ascending by hash: what a reader of the whole log reads past the rows
    /// this vault stores (OF-469, slice E). A stored row stands first and
    /// wins over the image's copy of it, as in
    /// [`super::import_order::write_stage_order`].
    pub(super) fn carried_past<'a>(
        &'a self,
        stored: &'a BTreeSet<AuthorityEntryHash>,
    ) -> impl Iterator<Item = (&'a AuthorityEntryHash, &'a AuthorityLogEntry)> {
        self.bodies
            .iter()
            .filter(move |(hash, _)| !stored.contains(*hash))
    }

    /// The row at `hash`, which this vault does not store, as a door's
    /// retired-standing walk reads it: the carried body of a covered row;
    /// none for a covered row the image holds valid, where the walk stops as
    /// at any valid row; and for any other row, a covered one the image
    /// rejected and carries no body of or one it does not cover, a refusal
    /// naming that history, never a row skipped.
    pub(super) fn ancestor(&self, hash: &AuthorityEntryHash) -> Result<Option<AuthorityLogEntry>> {
        if let Some(entry) = self.bodies.get(hash) {
            return Ok(Some(entry.clone()));
        }
        if self.checkpoint.image().fold().valid_entries.contains(hash) {
            return Ok(None);
        }
        Err(self.history_refusal(hash))
    }

    /// The refusal a door gives on this adopted vault for a row whose
    /// ancestry runs through `missing`, history it neither stores nor reads
    /// whole from the image. It is the fold's own refusal for history this
    /// vault does not hold, which `readonly_fold::is_history_incomplete`
    /// reads as one, so a fetch of that history closes it (CALLS: OF-469 v2
    /// door history refusal).
    fn history_refusal(&self, missing: &AuthorityEntryHash) -> Error {
        tracing::debug!(
            target: "oneiron::authority::adopted",
            checkpoint = ?self.checkpoint.id(),
            missing = ?missing,
            "a door needs authority history the adopted image does not carry"
        );
        super::readonly_fold::history_required(&AuthorityHistoryRequest {
            vault_id: Some(self.checkpoint.image().vault_id),
            checkpoint: Some(self.checkpoint.id()),
            missing: BTreeSet::from([*missing]),
        })
    }
}

/// The evidence of the image this vault adopted, as the store doors' view of
/// `txn`'s authority generation read it; None when it adopted none.
pub(crate) fn adopted_evidence_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<Arc<AdoptedEvidence>>> {
    Ok(super::log_budget::door_view(store, txn)?.evidence.clone())
}

/// What a reader that wants one authority row whole reads where this vault
/// does not store it (OF-469, slice E): on a vault that adopted a checkpoint
/// image, the body the image carries of that covered row. The reader keeps
/// its own stored lookup, with its own errors, and asks here only when that
/// lookup finds no row; it then judges the carried body by the same
/// predicate. The evidence is read once, at the first such miss. With no
/// adoption nothing is found, so the reader's miss stands as before.
#[derive(Default)]
pub(super) struct CarriedRows(Option<Option<Arc<AdoptedEvidence>>>);

impl CarriedRows {
    /// The carried body of the covered row `hash`, decoded; None with no
    /// adoption, for a row the image does not cover, and for a covered row
    /// it carries no body of.
    pub(super) fn get(
        &mut self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        hash: &AuthorityEntryHash,
    ) -> Result<Option<AuthorityLogEntry>> {
        if self.0.is_none() {
            self.0 = Some(adopted_evidence_in_txn(store, txn)?);
        }
        Ok(self
            .0
            .iter()
            .flatten()
            .find_map(|evidence| evidence.body(hash))
            .cloned())
    }
}
