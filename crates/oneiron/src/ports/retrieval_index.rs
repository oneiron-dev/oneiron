//! The retrieval-index inventory port: the physical rows of the vector, HNSW, BM25 and phonetic
//! projections, read as stored.
//!
//! This is not retrieval. No deletion or staleness filter applies, no vector is decoded and no
//! key is parsed: each caller keeps its own decoder and its own error policy. The read runs on
//! the receiver it is called on, so a base store and a composed session view each answer for
//! themselves.
use super::{PortRows, Transactions};
use crate::EntityId;
use crate::error::Result;

/// One retrieval-index table, chosen by name. No database handle leaves the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IndexRows {
    Vectors,
    HnswNeighbors,
    HnswMeta,
    TextPostings,
    TextMeta,
    TextForward,
    TextBm25FieldStats,
    TextDocFieldLengths,
    PhoneticIndex,
    PhoneticForward,
}

/// One fixed `hnsw_meta` row. The key is chosen here and the stored bytes go to the caller,
/// because one key is decoded under different error policies by different readers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IndexMetaKey {
    /// `count`: the HNSW node count, a little-endian u64.
    Count,
    /// `model_id`: the embedding model identity, UTF-8.
    ModelId,
    /// `embedding_transform`: the host's transform descriptor, UTF-8.
    EmbeddingTransform,
    /// `cold_attach_pending`: present while a first model's backfill is owed; any value counts.
    ColdAttachPending,
    /// `graph_version`: the PPR graph version, a little-endian u64.
    GraphVersion,
    /// `hnsw_config`: the persisted HNSW compatibility record.
    HnswConfig,
    /// `temporal_long_intervals_schema_version`: one byte.
    TemporalLongIntervalsSchemaVersion,
}

pub(crate) trait RetrievalIndexInventory: Transactions {
    /// The stored vector of `id`, lent to `read` in place. `None` when no row exists. A
    /// malformed vector is still a row.
    fn port_vector_with_raw<R, F>(
        &self,
        txn: &Self::Read<'_>,
        id: &EntityId,
        read: F,
    ) -> Result<Option<R>>
    where
        F: FnOnce(&[u8]) -> Result<R>;
    /// Whether `id` holds an HNSW neighbor row, by key alone. A malformed row is present.
    fn port_hnsw_node_present(&self, txn: &Self::Read<'_>, id: &EntityId) -> Result<bool>;
    /// One `hnsw_meta` row, lent to `read` in place. `None` when no row exists.
    fn port_index_meta_with_raw<R, F>(
        &self,
        txn: &Self::Read<'_>,
        key: IndexMetaKey,
        read: F,
    ) -> Result<Option<R>>
    where
        F: FnOnce(&[u8]) -> Result<R>;
    /// The row count of one table, as the table itself counts it.
    fn port_index_row_count(&self, txn: &Self::Read<'_>, rows: IndexRows) -> Result<u64>;
    /// Whether one table holds a row. Reads no further than the first.
    fn port_index_has_rows(&self, txn: &Self::Read<'_>, rows: IndexRows) -> Result<bool>;
    /// Every row of one table in key order, duplicates included. `inspect` sees each stored key
    /// and value in place; a cursor failure is the stream's error, and what `inspect` returns
    /// is the caller's own.
    fn port_index_rows<'a, R, F>(
        &self,
        txn: &'a Self::Read<'_>,
        rows: IndexRows,
        inspect: F,
    ) -> Result<PortRows<'a, R>>
    where
        R: 'a,
        F: FnMut(&[u8], &[u8]) -> R + 'a;
    /// [`port_index_rows`](Self::port_index_rows) over the vectors.
    fn port_vector_rows<'a, R, F>(
        &self,
        txn: &'a Self::Read<'_>,
        inspect: F,
    ) -> Result<PortRows<'a, R>>
    where
        R: 'a,
        F: FnMut(&[u8], &[u8]) -> R + 'a,
    {
        self.port_index_rows(txn, IndexRows::Vectors, inspect)
    }
}
