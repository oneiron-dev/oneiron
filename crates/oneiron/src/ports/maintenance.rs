//! Narrow operational writes of the entity and edge ports.
//!
//! These preserve existing domain gates. They are not generic row put/delete doors:
//! each operation names the record field or derived cache it is allowed to change.
use super::Transactions;
use crate::{EntityId, error::Result};
pub(crate) trait EntityStoreMaintenance: Transactions {
    fn port_contact_cache_evict(&self, txn: &mut Self::Write<'_>, id: &EntityId) -> Result<()>;
    fn port_connector_key_rewrite(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        record: &crate::connector_key::ConnectorKeyRecord,
    ) -> Result<()>;
    fn port_outbound_grant_touch(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        grant: crate::outbound_grant::StandingOutboundGrant,
        used_at: u64,
    ) -> Result<()>;
    fn port_habit_streak_materialize(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        streak: crate::habit::HabitStreak,
    ) -> Result<()>;
    /// FloorWrites is the only durable session crossing; it authorizes this append.
    fn port_redaction_audit_append(
        &self,
        permit: &crate::off_record::FloorWrites<'_>,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        learned_at: u64,
        body: &[u8],
    ) -> Result<()>;
}
pub(crate) trait EdgeStoreMaintenance: Transactions {
    /// Revision writer has already proved endpoint, session, ancestry and cardinality laws.
    /// Return whether the caller's graph-version batch must advance.
    fn port_revision_link(
        &self,
        txn: &mut Self::Write<'_>,
        source: &EntityId,
        kind: crate::EdgeKind,
        target: &EntityId,
        created_at: u64,
    ) -> Result<bool>;

    fn port_edge_stamp_provenance(
        &self,
        txn: &mut Self::Write<'_>,
        subject: &crate::provenance::EdgeRef,
        flags: crate::edge::EdgeProvenanceFlags,
    ) -> Result<()>;
    fn port_edge_clear_provenance(
        &self,
        txn: &mut Self::Write<'_>,
        subject: &crate::provenance::EdgeRef,
    ) -> Result<bool>;
}

pub(crate) trait EdgeStoreReadiness: Transactions {
    fn port_blocks_insert(
        &self,
        txn: &mut Self::Write<'_>,
        from: EntityId,
        to: EntityId,
        context: crate::code_memory::BlocksWriteContext<'_>,
    ) -> Result<()>;
    fn port_blocks_remove(
        &self,
        txn: &mut Self::Write<'_>,
        from: EntityId,
        to: EntityId,
        context: crate::code_memory::BlocksWriteContext<'_>,
    ) -> Result<bool>;
}

pub(crate) trait RetrievalIndexMaintenance: Transactions {
    fn port_retrieval_validate_rebuild(&self, txn: &Self::Read<'_>) -> Result<()>;
    /// Remove the text projection before entity-revision cleanup.
    fn port_retrieval_clear_text_for_soft_erase(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
    ) -> Result<()>;
    /// Remove phonetic postings after entity-revision cleanup.
    fn port_retrieval_clear_phonetic_for_soft_erase(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
    ) -> Result<()>;
    /// Remove vector and HNSW projections after domain-specific deletion cleanup.
    /// Returns whether a vector was present (the caller owns the version bump).
    fn port_retrieval_clear_vector_for_soft_erase(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
    ) -> Result<bool>;
    /// Probe index residue without requiring a live entity row.
    fn port_retrieval_delete_scope_exists(
        &self,
        txn: &Self::Read<'_>,
        id: &EntityId,
    ) -> Result<bool>;
}

/// Transactional repair of the backend's short-id forward/reverse projections.
pub(crate) trait ShortIdStoreMaintenance: Transactions {
    fn port_short_id_recompute_hashes(&self, txn: &mut Self::Write<'_>) -> Result<(u64, u64)>;
    fn port_short_id_mapping_exists(&self, txn: &Self::Read<'_>, id: &EntityId) -> Result<bool>;
}
