//! Narrow operational writes of the entity and edge ports.
//!
//! These preserve existing domain gates. They are not generic row put/delete doors:
//! each operation names the record field or derived cache it is allowed to change.
use super::Transactions;
use crate::{EntityId, error::Result};
pub(crate) trait EntityStoreMaintenance: Transactions {
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
}
