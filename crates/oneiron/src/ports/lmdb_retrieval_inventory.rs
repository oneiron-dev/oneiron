//! LMDB/session adapter of the retrieval-index inventory port, over the receiver's own tables.
use super::{IndexMetaKey, IndexRows, PortRows, RetrievalIndexInventory};
use crate::EntityId;
use crate::error::Result;
use crate::overlay_db::OverlayDb;
use crate::store::ManifestDbs;
use heed::RoTxn;

fn table(dbs: &impl ManifestDbs, rows: IndexRows) -> &OverlayDb {
    match rows {
        IndexRows::Vectors => dbs.vectors(),
        IndexRows::HnswNeighbors => dbs.hnsw_neighbors(),
        IndexRows::TextPostings => dbs.text_postings(),
        IndexRows::TextMeta => dbs.text_meta(),
        IndexRows::TextForward => dbs.text_forward(),
        IndexRows::TextBm25FieldStats => dbs.text_bm25_field_stats(),
        IndexRows::TextDocFieldLengths => dbs.text_doc_field_lengths(),
        IndexRows::PhoneticForward => dbs.phonetic_forward(),
    }
}

fn meta_key(key: IndexMetaKey) -> &'static [u8] {
    match key {
        IndexMetaKey::Count => crate::hnsw::COUNT_KEY,
        IndexMetaKey::ModelId => crate::store::MODEL_ID_KEY,
        IndexMetaKey::EmbeddingTransform => crate::store::EMBEDDING_TRANSFORM_KEY,
        IndexMetaKey::ColdAttachPending => crate::embed::COLD_ATTACH_PENDING_KEY,
        IndexMetaKey::GraphVersion => crate::store::GRAPH_VERSION_KEY,
        IndexMetaKey::HnswConfig => crate::store::HNSW_CONFIG_KEY,
        IndexMetaKey::TemporalLongIntervalsSchemaVersion => {
            crate::store::TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY
        }
    }
}

impl<T: ManifestDbs> RetrievalIndexInventory for T {
    fn port_vector_with_raw<R, F>(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        read: F,
    ) -> Result<Option<R>>
    where
        F: FnOnce(&[u8]) -> Result<R>,
    {
        self.vectors()
            .get(txn, id.as_bytes())?
            .map(|raw| read(&raw))
            .transpose()
    }

    fn port_hnsw_node_present(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        Ok(self.hnsw_neighbors().get(txn, id.as_bytes())?.is_some())
    }

    fn port_index_meta_with_raw<R, F>(
        &self,
        txn: &RoTxn<'_>,
        key: IndexMetaKey,
        read: F,
    ) -> Result<Option<R>>
    where
        F: FnOnce(&[u8]) -> Result<R>,
    {
        self.hnsw_meta()
            .get(txn, meta_key(key))?
            .map(|raw| read(&raw))
            .transpose()
    }

    fn port_index_row_count(&self, txn: &RoTxn<'_>, rows: IndexRows) -> Result<u64> {
        table(self, rows).len(txn)
    }

    fn port_index_has_rows(&self, txn: &RoTxn<'_>, rows: IndexRows) -> Result<bool> {
        Ok(table(self, rows).iter(txn)?.next().transpose()?.is_some())
    }

    fn port_index_rows<'a, R, F>(
        &self,
        txn: &'a RoTxn<'_>,
        rows: IndexRows,
        mut inspect: F,
    ) -> Result<PortRows<'a, R>>
    where
        R: 'a,
        F: FnMut(&[u8], &[u8]) -> R + 'a,
    {
        Ok(Box::new(table(self, rows).iter(txn)?.map(move |row| {
            let (key, value) = row?;
            Ok(inspect(&key, &value))
        })))
    }
}
