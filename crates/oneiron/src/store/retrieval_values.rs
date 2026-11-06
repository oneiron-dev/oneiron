//! Core half of `store::retrieval_values`: its store-layer items live in `oneiron_store::retrieval_values` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::retrieval_values::*;

use crate::entity_id::EntityId;
use crate::retrieval_quality::RetrievalQualityReport;
use crate::store::RetrievalRunId;

pub(crate) type CandidateFilter<'a> = dyn Fn(&crate::store::StoreRead<'_>, &heed::RoTxn<'_>, &EntityId) -> crate::Result<bool>
    + Send
    + Sync
    + 'a;

/// A [`CandidateFilter`] for one retrieval snapshot, used on the thread that
/// opened its transaction, so it need be neither `Send` nor `Sync`.
pub(crate) type SnapshotCandidateFilter<'a> =
    dyn Fn(&crate::store::StoreRead<'_>, &heed::RoTxn<'_>, &EntityId) -> crate::Result<bool> + 'a;

/// A candidate admission that holds state for one read transaction (FIX
/// 11648): a run asks it once for each snapshot it opens, beside that
/// snapshot's transaction, and judges every candidate of the snapshot with
/// the filter it returns. What the filter holds is dropped with the
/// snapshot, so it never serves another transaction.
pub(crate) trait CandidateGate: Send + Sync {
    fn in_txn<'t>(&'t self, txn: &'t heed::RoTxn<'t>) -> Box<SnapshotCandidateFilter<'t>>;
}

#[derive(Debug, Clone)]
pub struct RetrievalWithTelemetry<T> {
    /// Execution quality; independent of result counts and scores.
    pub retrieval_quality: RetrievalQualityReport,
    pub value: T,
    pub run_id: Option<RetrievalRunId>,
}

#[derive(Debug, Clone)]
pub struct RetrievalWithPendingVectors<T> {
    /// Execution quality; pending embedding state does not imply a timeout.
    pub retrieval_quality: RetrievalQualityReport,
    pub value: T,
    pub pending_vector_ids: Vec<EntityId>,
    pub pending_vectors: Vec<PendingVectorEmbedding>,
    pub run_id: Option<RetrievalRunId>,
}
