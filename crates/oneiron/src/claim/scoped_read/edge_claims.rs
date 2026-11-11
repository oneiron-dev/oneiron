//! The audit read of the Claims about one directed edge (FIX 3959): exact
//! pair admission, the Claims a cohort names, and their point reads, in one
//! snapshot under one receipt.
use super::{ScopedRead, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeStoreRead, PointRead, ReadRow};
use crate::provenance::EdgeRef;
use oneiron_contracts::gate::RetrievalFilter;

impl ScopedRead<'_> {
    /// Reads the Claims about the directed `edge` in one snapshot under one
    /// receipt. The edge passes first: it is stored, and its endpoints and
    /// exact pair pass the same admission a neighbourhood row does, so
    /// endpoint readability alone is not pair authority. A retracted stamp
    /// does not withhold it here: a withdrawn assertion stays readable truth
    /// for its audit. `cohort` then names the Claims about the edge in that
    /// snapshot, and each is read as an ordinary point read under
    /// `requested`, so a Claim this reader may not read is withheld as any
    /// row is. A missing or withheld edge, and `None` for an edge whose
    /// endpoint names resolve to no record, name no Claim and answer empty,
    /// with the same receipt. `project` takes each named Claim with its
    /// admitted row, in the order `cohort` named them, in the same snapshot.
    pub(crate) fn edge_claims_projected<T, E: From<Error>>(
        &self,
        edge: Option<&EdgeRef>,
        requested: Option<&RetrievalFilter>,
        cohort: impl FnOnce(&heed::RoTxn<'_>, &EdgeRef) -> std::result::Result<Vec<EntityId>, E>,
        project: impl FnOnce(
            &heed::RoTxn<'_>,
            Vec<(EntityId, Option<ReadRow>)>,
        ) -> std::result::Result<T, E>,
    ) -> std::result::Result<ScopedReadResult<T>, E> {
        let _bodies = crate::store::ASSET_FILE_PLANE.then(|| self.vault.pin_all_result_bodies());
        let txn = self.grant_read_txn()?;
        let admitted = match edge {
            Some(edge) => self.edge_pair_admitted_in(&txn, edge)?,
            None => false,
        };
        let ids = match edge {
            Some(edge) if admitted => cohort(&txn, edge)?,
            _ => Vec::new(),
        };
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        self.read_projected_in_txn(&txn, &reads, requested, |txn, rows| {
            project(txn, ids.iter().copied().zip(rows).collect())
        })
    }

    /// Whether this reader may audit the stored `edge` in `txn`: it exists,
    /// whatever its stamp, and passes endpoint and exact-pair admission.
    fn edge_pair_admitted_in(&self, txn: &heed::RoTxn<'_>, edge: &EdgeRef) -> Result<bool> {
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        let stored = match self.session_view {
            Some(view) => view.port_edge_get(txn, &edge.source, edge.kind, &edge.target)?,
            None => self
                .vault
                .port_edge_get(txn, &edge.source, edge.kind, &edge.target)?,
        };
        let Some(stored) = stored else {
            return Ok(false);
        };
        Ok(self
            .admit_stored_edge_in(txn, &policy, &filter, edge.source, stored)?
            .visible())
    }
}
