//! A centroid snapshot's sources and their erase (FIX 10094). A snapshot
//! copies its candidate's and every label's vector and its retrieval run
//! whole, so each of those, and every row the run names, is a source of it.
//! The set is read off the stored row itself, which is content-addressed:
//! no index and no second table. A source's erase leaves every snapshot that
//! copied it the content-free erased marker, live and in every image, so its
//! replay answers the erase with no copy of the run (FIX 10822); a snapshot
//! with an erased source is not stored, does not read live and does not
//! replay. Only the permanent hard-delete marker is an erase here: an
//! ordinary delete keeps every snapshot, so a soft delete stays restorable.

use std::collections::BTreeSet;

use super::{CentroidEvidence, EVIDENCE};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::{ResponseCarriage, ResponseFamily, ResponseScan, RetrievalRunRecord, Store};
use crate::{EntityId, Error, Result, Vault};

impl CentroidEvidence {
    /// Every source this snapshot copied: its candidate, every label, and
    /// every row its run names.
    pub(super) fn sources(&self) -> BTreeSet<[u8; 16]> {
        let mut sources = run_sources(&self.run);
        sources.insert(self.candidate.id);
        sources.extend(self.labeled.iter().map(|label| label.id));
        sources
    }
}

/// Every row a retrieval run names: its results, its scored results, every
/// trace stage's candidates, its turn, and its query and corpus refs. A heal
/// context admits a run record against the same set.
pub(in crate::self_heal) fn run_sources(run: &RetrievalRunRecord) -> BTreeSet<[u8; 16]> {
    let mut sources: BTreeSet<[u8; 16]> = run.result_ids.iter().copied().collect();
    sources.extend(run.score_breakdown.iter().map(|row| row.result_id));
    if let Some(trace) = &run.trace {
        let stages = trace
            .per_channel
            .iter()
            .map(|channel| &channel.candidates)
            .chain([
                &trace.fused.candidates,
                &trace.blended.candidates,
                &trace.reranked.candidates,
                &trace.final_stage.candidates,
            ]);
        sources.extend(stages.flatten().map(|candidate| candidate.result_id));
    }
    if let Some(turn) = &run.turn {
        sources.insert(turn.turn_id);
    }
    if let Some(inputs) = &run.replay_inputs {
        for at in [&inputs.query_ref, &inputs.corpus_snapshot_ref]
            .into_iter()
            .flatten()
        {
            if let Ok(id) = EntityId::from_hex(at) {
                sources.insert(*id.as_bytes());
            }
        }
    }
    sources
}

/// What a checkpoint carries of the snapshot row `value`: the whole row,
/// the content-free erased marker in its place, which a retired snapshot
/// keeps, in images and live alike, as its source's erase leaves it. A row
/// that does not decode is carried whole as an opaque response.
pub(crate) fn centroid_evidence_carriage(value: &[u8]) -> ResponseScan {
    if EVIDENCE.decode_value(value).is_err() {
        return ResponseScan::opaque_row();
    }
    ResponseScan::decoded(erased_carriage())
}

/// The carriage of a snapshot row: the whole row, its erased marker in its
/// place, kept whole once retired.
fn erased_carriage() -> Option<ResponseCarriage> {
    ResponseScan::opaque_row()
        .carriage()
        .map(|(carriage, _)| carriage)
}

/// Who owns the snapshot row `value`: every source it copied, so any one's
/// erase retires every image's copy; none for a row that does not decode.
pub(crate) fn centroid_evidence_owners(value: &[u8]) -> Vec<EntityId> {
    EVIDENCE
        .decode_value(value)
        .map(|evidence| {
            evidence
                .sources()
                .into_iter()
                .filter_map(|source| EntityId::from_bytes(source).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The first of `sources` erased in `txn`, by its permanent hard-delete
/// marker; `None` when none is.
pub(super) fn erased_source_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    sources: &BTreeSet<[u8; 16]>,
) -> Result<Option<EntityId>> {
    for source in sources {
        let Ok(id) = EntityId::from_bytes(*source) else {
            continue;
        };
        if store.port_deletion_marked(txn, DeletionMarker::HardDelete, &id)? {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// Leaves every centroid snapshot that copied `id` its erased marker, in the
/// erase's own transaction, once `id` is erased: its hard-delete marker
/// stands. A delete without the marker keeps every snapshot. The table is
/// scanned whole; a row that does not decode is left as it is.
pub(crate) fn erase_centroid_source_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if !vault
        .store
        .port_deletion_marked(&*txn, DeletionMarker::HardDelete, id)?
    {
        return Ok(());
    }
    let mut dependent = Vec::new();
    for row in EVIDENCE.iter_from(&vault.store, &*txn, &[])? {
        let Ok((key, evidence)) = row else {
            continue;
        };
        if evidence.sources().contains(id.as_bytes()) {
            dependent.push(EVIDENCE.key_bytes(&key));
        }
    }
    // The same erased disposition a retired image's copy takes (FIX 10822).
    let carriage = erased_carriage().ok_or(Error::InvariantViolation("centroid erased marker"))?;
    for key in dependent {
        ResponseFamily::CentroidEvidence.retire_in_txn(&vault.store, txn, &key, &carriage)?;
    }
    Ok(())
}
