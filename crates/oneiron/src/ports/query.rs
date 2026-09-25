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
    fn port_entity_long_spanning<'a>(
        &self,
        txn: &'a Self::Read<'_>,
        started_before: u64,
        ended_after: u64,
    ) -> Result<PortRows<'a, (EntityId, crate::TimeRange)>>;
}

/// Adjacency reads in storage order. The caller may stop after its own budget.
/// The adapter decodes every visited row; no raw edge key or database escapes.
pub trait EdgeStoreRead: Transactions {
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

/// Read half used by retrieval pipelines that hold only a storage snapshot.
pub trait RetrievalIndexRead: Transactions {
    fn port_retrieval_phonetic_search(
        &self,
        txn: &Self::Read<'_>,
        codes: &[String],
    ) -> Result<Vec<crate::pipeline::ScoredEntity>>;
}
