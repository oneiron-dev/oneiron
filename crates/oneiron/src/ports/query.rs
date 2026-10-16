//! Read halves of the storage ports. Cursors are lazy and never collect a table.
use super::{EntityRecord, Transactions};
use crate::{EntityId, error::Result};

/// Backend-independent fallible stream over one caller-owned snapshot.
pub type PortRows<'a, T> = Box<dyn Iterator<Item = Result<T>> + 'a>;

/// Historical entity reads are deliberately separate from safe text hydration.
/// Admission, history and repair need to distinguish a shell from an absent row.
/// No deletion or stale filter is applied here; user-visible text uses EntityStore::get.
pub trait EntityStoreRead: Transactions {
    /// Unvalidated entity envelope for repair and corruption diagnostics only.
    /// This is not a text hydration door; malformed bytes remain observable.
    fn port_entity_raw(&self, txn: &Self::Read<'_>, id: &EntityId) -> Result<Option<Vec<u8>>>;
    /// [`port_entity_raw`](Self::port_entity_raw) for a reader that may meet a
    /// custody record, whose body carries its value (ARCH-0069 S1): the copy
    /// is wiped when it drops.
    fn port_entity_raw_wiped(
        &self,
        txn: &Self::Read<'_>,
        id: &EntityId,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
        Ok(self.port_entity_raw(txn, id)?.map(zeroize::Zeroizing::new))
    }
    fn port_entity_record(
        &self,
        txn: &Self::Read<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityRecord>>;
    fn port_entity_ids_by_type<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        kind: u8,
        after: Option<EntityId>,
    ) -> Result<PortRows<'a, EntityId>>;
    fn port_entity_timeline<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        query: TimelineQuery,
    ) -> Result<PortRows<'a, EntityTime>>;

    /// Raw rows for export, repair, and fail-closed inventory scans. The
    /// adapter checks keys but leaves corrupt bodies visible to the caller.
    fn port_entity_raw_records<'a>(
        &self,
        txn: &'a Self::Read<'_>,
    ) -> Result<PortRows<'a, (EntityId, Vec<u8>)>>;
    fn port_entity_records<'a>(
        &self,
        txn: &'a Self::Read<'_>,
    ) -> Result<PortRows<'a, (EntityId, EntityRecord)>>;
    fn port_entity_count(&self, txn: &Self::Read<'_>) -> Result<u64>;
    fn port_entity_ids_by_type_descending<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        kind: u8,
    ) -> Result<PortRows<'a, EntityId>>;
    /// Every long interval ending after `ended_after`, in end order; the
    /// caller keeps those that span its window, so it counts every row read.
    fn port_entity_long_ending_after<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        ended_after: u64,
    ) -> Result<PortRows<'a, (EntityId, crate::TimeRange)>>;
}

/// Adjacency reads in storage order. The caller may stop after its own budget.
/// The adapter decodes every visited row; no raw edge key or database escapes.
pub trait EdgeStoreRead: Transactions {
    /// Key-only presence; a malformed value still occupies graph topology.
    fn port_edge_has_any(
        &self,
        txn: &Self::Read<'_>,
        center: &EntityId,
        direction: super::EdgeDirection,
    ) -> Result<bool>;
    /// Key-only peer enumeration for mutation resolution. Corrupt values stay
    /// unread until the caller actually needs the edge metadata.
    fn port_edge_peers<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        center: &EntityId,
        direction: super::EdgeDirection,
        kind: crate::EdgeKind,
    ) -> Result<PortRows<'a, EntityId>>;
    fn port_edges<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        center: &EntityId,
        direction: super::EdgeDirection,
        kind: Option<crate::EdgeKind>,
        after: Option<EntityId>,
    ) -> Result<PortRows<'a, crate::edge::EdgeInfo>>;
    fn port_edge_get(
        &self,
        txn: &Self::Read<'_>,
        source: &EntityId,
        kind: crate::EdgeKind,
        target: &EntityId,
    ) -> Result<Option<crate::edge::EdgeInfo>>;
    /// Key-only presence of one adjacency row: `Out` asks for
    /// `center -kind-> peer`, `In` for `peer -kind-> center` on the center's
    /// side, `Both` for either. A malformed value still occupies graph topology.
    fn port_edge_present(
        &self,
        txn: &Self::Read<'_>,
        center: &EntityId,
        direction: super::EdgeDirection,
        kind: crate::EdgeKind,
        peer: &EntityId,
    ) -> Result<bool>;
    /// The reverse row of `peer -kind-> center`, read on the center's side and
    /// decoded fail-closed. Its target is `peer`, as in an `In` stream.
    fn port_edge_get_incoming(
        &self,
        txn: &Self::Read<'_>,
        center: &EntityId,
        kind: crate::EdgeKind,
        peer: &EntityId,
    ) -> Result<Option<crate::edge::EdgeInfo>>;
    /// Both directions must contain the same semantic edge. None means both absent.
    fn port_edge_consistent(
        &self,
        txn: &Self::Read<'_>,
        source: &EntityId,
        kind: crate::EdgeKind,
        target: &EntityId,
    ) -> Result<bool>;
    fn port_edge_cursor<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        center: &EntityId,
        direction: super::EdgeDirection,
        after: Option<(u8, EntityId)>,
    ) -> Result<PortRows<'a, crate::edge::EdgeInfo>>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeletionState {
    pub archived: bool,
    pub deleted: bool,
    pub stale: bool,
}
/// Visibility state without opening a read transaction or decoding secret bodies.
pub trait TombstoneStoreRead: Transactions {
    fn port_deletion_state(&self, txn: &Self::Read<'_>, id: &EntityId) -> Result<DeletionState>;
    fn port_tombstone_records<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        family: DeletionFamily,
    ) -> Result<PortRows<'a, (EntityId, crate::deletion::DecodedTombstoneValue)>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeAxis {
    Learned,
    OccurredStart,
    OccurredEnd,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntityTime {
    pub id: EntityId,
    pub timestamp: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct TimelineQuery {
    pub axis: TimeAxis,
    pub start: std::ops::Bound<u64>,
    pub end: std::ops::Bound<u64>,
    /// Exclusive compound cursor, in the requested traversal direction.
    pub after: Option<EntityTime>,
    pub reverse: bool,
}
impl Default for TimelineQuery {
    fn default() -> Self {
        Self {
            axis: TimeAxis::Learned,
            start: std::ops::Bound::Unbounded,
            end: std::ops::Bound::Unbounded,
            after: None,
            reverse: false,
        }
    }
}

/// Current versioned short reference, without hydration or a write transaction.
pub trait ShortIdStoreRead: Transactions {
    fn port_short_id_reference(
        &self,
        txn: &Self::Read<'_>,
        id: &EntityId,
    ) -> Result<Option<(String, u8)>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletionFamily {
    Archive,
    HardDelete,
}

/// Stored job rows without a queue transition, for cleanup, admission and
/// index rebuilds. The caller decodes; no lease, clock or ready entry moves.
pub trait JobQueueRead: Transactions {
    fn port_job_row(
        &self,
        txn: &Self::Read<'_>,
        id: &crate::attempt_queue::AttemptId,
    ) -> Result<Option<Vec<u8>>>;
    /// Rows in id order after `after`. A malformed key fails as the id parser does.
    fn port_job_rows<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        after: Option<crate::attempt_queue::AttemptId>,
    ) -> Result<PortRows<'a, (crate::attempt_queue::AttemptId, Vec<u8>)>>;
}

/// The global change stream in id order, for a consumer that resumes after
/// the last id it processed. Each row is its stored id and record, with the
/// change table's own key and codec errors.
pub trait ChangeLogStoreRead: Transactions {
    fn port_changelog_after<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        after: Option<[u8; 16]>,
    ) -> Result<PortRows<'a, ([u8; 16], super::ChangeLogRecord)>>;
    /// The newest change, or None while the log is empty.
    fn port_changelog_head(
        &self,
        txn: &Self::Read<'_>,
    ) -> Result<Option<([u8; 16], super::ChangeLogRecord)>>;
}

/// Read half used by retrieval pipelines that hold only a storage snapshot.
pub trait RetrievalIndexRead: Transactions {
    fn port_retrieval_phonetic_search(
        &self,
        txn: &Self::Read<'_>,
        codes: &[String],
    ) -> Result<Vec<crate::pipeline::ScoredEntity>>;
}
