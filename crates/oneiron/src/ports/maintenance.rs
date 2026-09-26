//! Narrow operational writes of the entity and edge ports.
//!
//! These preserve existing domain gates. They are not generic row put/delete doors:
//! each operation names the record field or derived cache it is allowed to change.
use super::Transactions;
use crate::{EntityId, error::Result};

/// What an ARCH-0038 erase leaves of a record. The header is kept byte-exact either way.
#[derive(Debug)]
pub(crate) enum ScrubbedRecord {
    /// SoftErase: the body goes and the header stays.
    Shell,
    /// An identity-topology event body re-encoded without its author stamp.
    AuthorStampRemoved(Vec<u8>),
}

pub(crate) trait EntityStoreMaintenance: Transactions {
    /// Replaces a record's body with what erasure leaves of it. Writes one `ChangeOp::Redact`
    /// mutation audit row, occurring at `recorded_at`, when the stored bytes change, and returns
    /// whether they did. Retained revisions are the caller's to remove.
    fn port_entity_scrub(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        record: ScrubbedRecord,
        recorded_at: u64,
    ) -> Result<bool>;
    /// Replaces a record's body with its entity-document pointer form. The header is kept
    /// byte-exact; the body must be a map carrying exactly one `entity_doc_ref` string.
    #[cfg(feature = "sync")]
    fn port_entity_document_pointer_put(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        body: &[u8],
    ) -> Result<()>;
    /// Stamps a pending REDACTION_AUDIT receipt's `sweep_complete_at`, the one field a stored
    /// receipt may change (None to Some). The envelope is kept byte-exact and the body is
    /// validated before the put.
    fn port_redaction_receipt_sweep_complete(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        completed_at: u64,
    ) -> Result<()>;
    /// Installs the header of a retained soft-delete shell, never a body. The index rows stay the
    /// caller's.
    #[cfg(feature = "sync")]
    fn port_retained_shell_restore(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        header: &[u8],
    ) -> Result<()>;
    /// Plants record bytes as given, with no index row: for fixtures that race a divergent local
    /// row against a replayed one, or build a store shape no write door builds at their scale.
    #[cfg(any(test, all(feature = "sync", feature = "test-hooks")))]
    fn port_raw_record_seed(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<()>;
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
    /// Plants one outgoing edge row as given, with no incoming twin, for fixtures that build a
    /// graph shape no write door builds at their scale.
    #[cfg(test)]
    fn port_raw_outgoing_edge_seed(
        &self,
        txn: &mut Self::Write<'_>,
        source: &EntityId,
        kind: crate::EdgeKind,
        target: &EntityId,
        value: &[u8],
    ) -> Result<()>;
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
