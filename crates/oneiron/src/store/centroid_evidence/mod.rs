//! Immutable centroid evidence rows and source-erasure custody.

mod erase;

use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::store::{ResponseFamily, ResponseRead, RetrievalRunRecord};
use crate::{Error, Result};

pub(crate) use erase::{
    centroid_evidence_carriage, centroid_evidence_owners, erase_centroid_source_as_in_txn,
    erase_centroid_source_in_txn, erased_source_in_txn, run_sources,
};

pub(crate) const EVIDENCE: SideTable<[u8; 32], CentroidEvidence, Named> =
    SideTable::new(&side_table::SELF_HEAL_CENTROID_EVIDENCE);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct VectorEvidence {
    pub(crate) id: [u8; 16],
    pub(crate) vector: Vec<f32>,
}

/// A versioned, immutable copy of every byte used by the centroid verdict.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct CentroidEvidence {
    pub(crate) version: u8,
    pub(crate) run: RetrievalRunRecord,
    pub(crate) candidate: VectorEvidence,
    pub(crate) labeled: Vec<VectorEvidence>,
    pub(crate) min_similarity: f32,
    pub(crate) similarity: f64,
}

/// Read-time custody of the immutable centroid inputs used by a tier-1
/// observation. The producer performs the full replay check before minting.
/// A snapshot with an erased source is not live.
pub(crate) fn snapshot_live_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    hash: &[u8; 32],
) -> Result<bool> {
    let Some(raw) = EVIDENCE.get_bytes(store, txn, hash)? else {
        return Ok(false);
    };
    // A snapshot a source's erase reached holds its erased marker, live or
    // restored from an image.
    let ResponseRead::Present(raw) = ResponseRead::of(
        ResponseFamily::CentroidEvidence,
        &EVIDENCE.key_bytes(hash),
        &raw,
    ) else {
        return Ok(false);
    };
    if blake3::hash(raw).as_bytes() != hash {
        return Ok(false);
    }
    let evidence: CentroidEvidence =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("centroid evidence body"))?;
    let canonical = rmp_serde::to_vec_named(&evidence)
        .map_err(|_| Error::CorruptedIndex("centroid evidence body"))?;
    Ok(evidence.version == 1
        && raw == canonical.as_slice()
        && erase::erased_source_in_txn(store, txn, &evidence.sources())?.is_none())
}
