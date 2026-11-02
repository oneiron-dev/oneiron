//! The backlog a move's swap reads again in its own writer (FIX 9833).

use heed::RoTxn;

use super::super::EgressPredicate;
use super::super::media::{MediaEgressGate, MediaEmbedReport};
use super::super::space::embedding_space_in_txn;
use super::SpaceMove;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

impl Vault {
    /// A moving document the candidate of `moving` still lacks a vector of, read in the writer
    /// that would swap it in, through the host's media egress gate `egress` as the move's check
    /// reads it (FIX 9833): one that arrived while the probes ran keeps the move open and the
    /// incumbent serving until the backfill fills it, the filling check the move began with.
    /// `None` when the candidate holds every moving document, or is no longer declared. No
    /// model is called here.
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn swap_backlog_in_txn(
        &self,
        txn: &RoTxn<'_>,
        moving: &SpaceMove,
        egress: Option<&dyn EgressPredicate>,
    ) -> Result<Option<EntityId>> {
        let Some(space) = embedding_space_in_txn(&self.store, txn, &moving.candidate)? else {
            return Ok(None);
        };
        let gate = egress
            .map(|egress| MediaEgressGate::read(self, txn, egress))
            .transpose()?;
        let mut report = MediaEmbedReport::default();
        Ok(self
            .media_backlog_where_in_txn(txn, &space, &moving.kinds, 1, &mut report, gate.as_ref())?
            .first()
            .map(|pending| pending.id))
    }
}
