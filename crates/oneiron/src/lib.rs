use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use heed::types::Bytes;
use heed::Database;

pub mod batch;
pub(crate) mod bm25;
pub mod context_pack;
pub(crate) mod distance;
pub mod error;
pub(crate) mod fusion;
pub(crate) mod hnsw;
pub mod maintain;
pub mod pipeline;
pub(crate) mod ppr;
pub mod serialize;
pub mod store;
pub mod types;

pub use crate::batch::BatchBuilder;
use crate::batch::{deindex_entity, EntityMetadataHeader, ENTITY_METADATA_HEADER_LEN};
pub use crate::context_pack::ContextPackBuilder;
pub use crate::error::{Error, Result};
pub use crate::maintain::{MaintenanceBuilder, MaintenanceReport};
pub use crate::pipeline::PipelineBuilder;
use crate::store::Store;
use crate::types::{parse_vad, EDGE_KEY_LEN, EDGE_VALUE_LEN};
pub use crate::types::{
    ContextEntity, ContextPack, EdgeInfo, EdgeKind, EntityId, FieldProfile, HnswConfig, PackFormat,
    PackStats, ScoredEntity, Signal, SignalHit, TemporalAnchorMode, TemporalGranularity, TimeRange,
    TokenAllocation, Vad, VaultConfig,
};

const MIN_MAP_SIZE_BYTES: usize = 1 << 20;

/// Main vault API wrapping LMDB storage and configuration.
pub struct Vault {
    pub(crate) store: Store,
    pub(crate) config: VaultConfig,
}

impl Vault {
    /// Opens or creates a vault at `path`.
    pub fn open(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self> {
        if config.dimensions == 0 {
            return Err(Error::InvalidConfig(
                "dimensions must be greater than zero".to_owned(),
            ));
        }
        if config.map_size < MIN_MAP_SIZE_BYTES {
            return Err(Error::InvalidConfig(format!(
                "map_size must be at least {MIN_MAP_SIZE_BYTES} bytes"
            )));
        }

        let store = Store::open(path, &config)?;
        Ok(Self { store, config })
    }

    /// Stores an entity blob.
    pub fn put_entity(
        &self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Result<()> {
        self.batch()
            .put(id, entity_type, occurred, learned_at, data)
            .commit()
    }

    /// Retrieves an entity blob by ID.
    pub fn get(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        let value = self.store.entities.get(&rtxn, id.as_bytes())?;
        let Some(bytes) = value else {
            return Ok(None);
        };

        if EntityMetadataHeader::parse(bytes).is_none() {
            return Err(Error::InvalidKey);
        }

        Ok(Some(bytes[ENTITY_METADATA_HEADER_LEN..].to_vec()))
    }

    /// Deletes an entity blob by ID.
    pub fn delete_entity(&self, id: &EntityId) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let (existed, neighbors) = deindex_entity(&self.store, &mut wtxn, id)?;
        ppr::invalidate_ppr_for_delete(&self.store, &mut wtxn, id, &neighbors)?;
        wtxn.commit()?;
        Ok(existed)
    }

    /// Stores a vector for an entity.
    pub fn put_vector(&self, id: &EntityId, vector: &[f32]) -> Result<()> {
        self.batch().vector(id, vector).commit()
    }

    /// Retrieves a vector for an entity.
    pub fn get_vector(&self, id: &EntityId) -> Result<Option<Vec<f32>>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self.store.vectors.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };

        let vector = le_bytes_to_f32_vec(bytes)?;
        if vector.len() != self.config.dimensions {
            return Err(Error::DimensionMismatch {
                expected: self.config.dimensions,
                got: vector.len(),
            });
        }

        Ok(Some(vector))
    }

    /// Searches nearest neighbors by cosine similarity using the HNSW index.
    pub fn search_vector(&self, query: &[f32], limit: usize) -> Result<Vec<ScoredEntity>> {
        if query.len() != self.config.dimensions {
            return Err(Error::DimensionMismatch {
                expected: self.config.dimensions,
                got: query.len(),
            });
        }
        if query.iter().any(|v| !v.is_finite()) {
            return Err(Error::InvalidVector);
        }

        let rtxn = self.store.env.read_txn()?;
        hnsw::hnsw_search(&self.store, &self.config, &rtxn, query, limit)
    }

    /// Stores a directed edge and its reverse index entry.
    pub fn put_edge(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
    ) -> Result<()> {
        self.batch().edge(src, kind, tgt, weight).commit()
    }

    /// Stores a directed edge with explicit VAD scores.
    pub fn put_edge_with_vad(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        vad: Vad,
    ) -> Result<()> {
        self.batch()
            .edge_with_vad(src, kind, tgt, weight, vad)
            .commit()
    }

    /// Deletes a directed edge and its reverse index entry.
    pub fn delete_edge(&self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Result<bool> {
        let key_out = Store::encode_edge_key(src, kind, tgt);
        let rtxn = self.store.env.read_txn()?;
        let existed = self.store.edges_out.get(&rtxn, &key_out)?.is_some();
        drop(rtxn);

        if !existed {
            return Ok(false);
        }

        self.batch().delete_edge(src, kind, tgt).commit()?;
        Ok(true)
    }

    /// Returns outbound edges for `src`.
    pub fn edges_out(&self, src: &EntityId) -> Result<Vec<EdgeInfo>> {
        let rtxn = self.store.env.read_txn()?;
        scan_edges(&self.store.edges_out, &rtxn, src.as_bytes())
    }

    /// Returns inbound edges for `tgt`.
    pub fn edges_in(&self, tgt: &EntityId) -> Result<Vec<EdgeInfo>> {
        let rtxn = self.store.env.read_txn()?;
        scan_edges(&self.store.edges_in, &rtxn, tgt.as_bytes())
    }

    /// Returns BM25 text matches for a query.
    pub fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        let rtxn = self.store.env.read_txn()?;
        bm25::search_text(&self.store, &rtxn, query, limit)
    }

    /// Creates a new write batch builder bound to this vault.
    pub fn batch(&self) -> BatchBuilder<'_> {
        BatchBuilder::new(self)
    }

    /// Creates a query pipeline builder for multi-signal retrieval.
    pub fn query(&self) -> PipelineBuilder<'_> {
        PipelineBuilder::new(self)
    }

    /// Creates a context pack builder for retrieval + hydration + serialization.
    pub fn context_pack(&self) -> ContextPackBuilder<'_> {
        ContextPackBuilder::new(self)
    }

    /// Creates a maintenance builder for index and cache upkeep operations.
    pub fn maintain(&self) -> MaintenanceBuilder<'_> {
        MaintenanceBuilder::new(self)
    }
}

pub(crate) fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(crate) fn le_bytes_to_f32_vec(bytes: &[u8]) -> Result<Vec<f32>> {
    if !bytes.len().is_multiple_of(4) {
        return Err(Error::InvalidKey);
    }

    Ok(bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
        .collect())
}

fn scan_edges(
    database: &Database<Bytes, Bytes>,
    rtxn: &heed::RoTxn<'_>,
    prefix: &[u8; 16],
) -> Result<Vec<EdgeInfo>> {
    database
        .prefix_iter(rtxn, prefix.as_slice())?
        .map(|entry| {
            let (key, value) = entry?;
            parse_edge_record(key, value)
        })
        .collect()
}

fn parse_edge_record(key: &[u8], value: &[u8]) -> Result<EdgeInfo> {
    if key.len() != EDGE_KEY_LEN || value.len() != EDGE_VALUE_LEN {
        return Err(Error::InvalidKey);
    }

    let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::InvalidKey)?;
    let target = EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?);
    let weight = f32::from_le_bytes(value[..4].try_into().map_err(|_| Error::InvalidKey)?);
    let created_at = u64::from_le_bytes(value[4..12].try_into().map_err(|_| Error::InvalidKey)?);
    let vad = parse_vad(value);
    if !weight.is_finite() {
        return Err(Error::InvalidEdgeWeight);
    }
    if !vad.is_finite() || !vad.is_in_range() {
        return Err(Error::InvalidVad);
    }

    Ok(EdgeInfo {
        kind,
        target,
        target_short_id: None,
        weight,
        created_at,
        vad,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::str;
    use std::time::Instant;

    use heed::types::Bytes;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use xxhash_rust::xxh32::xxh32;

    use super::*;

    const DB_NAMES: [&str; 19] = [
        "entities",
        "edges_out",
        "edges_in",
        "vectors",
        "hnsw_neighbors",
        "hnsw_meta",
        "text_postings",
        "text_meta",
        "text_forward",
        "ppr_cache",
        "ppr_cache_deps",
        "type_index",
        "temporal_occurred_start",
        "temporal_occurred_end",
        "temporal_learned",
        "temporal_long_intervals",
        "phonetic_index",
        "short_ids",
        "short_ids_reverse",
    ];

    fn test_config() -> VaultConfig {
        VaultConfig {
            map_size: 16 * 1024 * 1024,
            dimensions: 4,
            embedding_model: None,
            max_readers: 16,
            hnsw: HnswConfig {
                m_max_0: 64,
                ef_construction: 200,
                ef_search: 128,
            },
        }
    }

    fn test_time_range(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    fn content_hash(data: &[u8]) -> u8 {
        (xxh32(data, 0) % 256) as u8
    }

    fn decode_short_id_value(value: &[u8]) -> Result<(String, u8)> {
        if value.len() < 2 {
            return Err(Error::InvalidKey);
        }

        let (short_id, hash) = value.split_at(value.len() - 1);
        let short_id = str::from_utf8(short_id)
            .map_err(|_| Error::InvalidKey)?
            .to_owned();
        Ok((short_id, hash[0]))
    }

    fn read_short_id_value(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids
            .get(&rtxn, id.as_bytes())?
            .map(|bytes| bytes.to_vec())
            .ok_or(Error::EntityNotFound)
    }

    #[test]
    fn encode_edge_key_has_exact_layout() {
        let src = EntityId::from_bytes([0x11; 16]);
        let tgt = EntityId::from_bytes([0x22; 16]);
        let kind = EdgeKind::DerivedFrom;

        let key = Store::encode_edge_key(&src, kind, &tgt);

        assert_eq!(key.len(), 33);
        assert_eq!(&key[..16], src.as_bytes());
        assert_eq!(key[16], kind as u8);
        assert_eq!(&key[17..], tgt.as_bytes());
    }

    #[test]
    fn open_put_get_delete_entities() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let data = b"entity-payload";

        vault.put_entity(&id, 0, test_time_range(10, 20), 30, data)?;
        let got = vault.get(&id)?.ok_or(Error::EntityNotFound)?;
        assert_eq!(got, data);

        assert!(vault.delete_entity(&id)?);
        assert!(vault.get(&id)?.is_none());
        assert!(!vault.delete_entity(&id)?);

        Ok(())
    }

    #[test]
    fn put_get_vectors_and_validate_dimensions() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let vector = [0.1_f32, 0.2, 0.3, 0.4];

        vault.put_vector(&id, &vector)?;
        let got = vault.get_vector(&id)?.ok_or(Error::EntityNotFound)?;
        assert_eq!(got, vector);

        let bad = [1.0_f32, 2.0, 3.0];
        let err = vault
            .put_vector(&EntityId::now(), &bad)
            .expect_err("expected dimension mismatch");
        assert!(matches!(
            err,
            Error::DimensionMismatch {
                expected: 4,
                got: 3
            }
        ));

        Ok(())
    }

    #[test]
    fn put_vector_routes_through_hnsw_insert() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let vector = [0.1_f32, 0.2, 0.3, 0.4];

        vault.put_vector(&id, &vector)?;

        let rtxn = vault.store.env.read_txn()?;
        let count_raw = vault
            .store
            .hnsw_meta
            .get(&rtxn, b"count")?
            .ok_or(Error::EntityNotFound)?;
        let count = u64::from_le_bytes(count_raw.try_into().map_err(|_| Error::InvalidKey)?);
        assert_eq!(count, 1);

        let entry_point = vault
            .store
            .hnsw_meta
            .get(&rtxn, b"entry_point")?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(entry_point, id.as_bytes());

        assert!(vault
            .store
            .hnsw_neighbors
            .get(&rtxn, id.as_bytes())?
            .is_some());
        Ok(())
    }

    #[test]
    fn search_vector_empty_graph_and_dimension_validation() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let empty = vault.search_vector(&[0.1_f32, 0.2, 0.3, 0.4], 10)?;
        assert!(empty.is_empty());

        let err = vault
            .search_vector(&[1.0_f32, 2.0, 3.0], 5)
            .expect_err("expected dimension mismatch");
        assert!(matches!(
            err,
            Error::DimensionMismatch {
                expected: 4,
                got: 3
            }
        ));
        Ok(())
    }

    #[test]
    fn search_vector_skips_deleted_nodes() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let entry = EntityId::now();
        let deleted = EntityId::now();
        let live = EntityId::now();

        for id in [entry, deleted, live] {
            vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"vector-node")?;
        }

        vault.put_vector(&entry, &[1.0_f32, 0.0, 0.0, 0.0])?;
        vault.put_vector(&deleted, &[0.98_f32, 0.05, 0.0, 0.0])?;
        vault.put_vector(&live, &[0.0_f32, 1.0, 0.0, 0.0])?;

        assert!(vault.delete_entity(&deleted)?);

        let results = vault.search_vector(&[0.98_f32, 0.05, 0.0, 0.0], 3)?;
        assert!(!results.iter().any(|item| item.id == deleted));
        assert!(results.iter().any(|item| item.id == entry));
        Ok(())
    }

    #[test]
    fn search_after_entry_point_deleted() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let entry = EntityId::now();
        let survivor = EntityId::now();

        vault.put_entity(&entry, 0, test_time_range(1, 1), 1, b"entry")?;
        vault.put_entity(&survivor, 0, test_time_range(1, 1), 1, b"survivor")?;
        vault.put_vector(&entry, &[1.0_f32, 0.0, 0.0, 0.0])?;
        vault.put_vector(&survivor, &[0.0_f32, 1.0, 0.0, 0.0])?;

        assert_eq!(vault.search_vector(&[1.0_f32, 0.0, 0.0, 0.0], 5)?.len(), 2);
        assert!(vault.delete_entity(&entry)?);

        let results = vault.search_vector(&[0.0_f32, 1.0, 0.0, 0.0], 5)?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, survivor);

        Ok(())
    }

    #[test]
    fn validates_non_finite_vector_and_edge_weights() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let vector_err = vault
            .put_vector(&EntityId::now(), &[1.0_f32, f32::NAN, 2.0, 3.0])
            .expect_err("expected invalid vector");
        assert!(matches!(vector_err, Error::InvalidVector));

        let edge_err = vault
            .put_edge(
                &EntityId::now(),
                EdgeKind::Supports,
                &EntityId::now(),
                f32::INFINITY,
            )
            .expect_err("expected invalid edge weight");
        assert!(matches!(edge_err, Error::InvalidEdgeWeight));
        Ok(())
    }

    #[test]
    fn hnsw_recall_at_10_vs_bruteforce() -> Result<()> {
        const DIMENSIONS: usize = 128;
        const NODE_COUNT: usize = 1_000;
        const LIMIT: usize = 10;
        const QUERY_COUNT: usize = 25;

        let temp_dir = tempfile::tempdir()?;
        let mut config = test_config();
        config.dimensions = DIMENSIONS;
        config.map_size = 128 * 1024 * 1024;
        config.hnsw.m_max_0 = 64;
        config.hnsw.ef_construction = 256;
        config.hnsw.ef_search = 256;

        let vault = Vault::open(temp_dir.path(), config)?;
        let mut rng = StdRng::seed_from_u64(42);
        let mut corpus = Vec::with_capacity(NODE_COUNT);

        let insert_started = Instant::now();
        for _ in 0..NODE_COUNT {
            let id = EntityId::now();
            let vector: Vec<f32> = (0..DIMENSIONS)
                .map(|_| rng.gen_range(-1.0_f32..1.0_f32))
                .collect();

            vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"recall-node")?;
            vault.put_vector(&id, &vector)?;
            corpus.push((id, vector));
        }
        let insert_elapsed = insert_started.elapsed();

        let search_started = Instant::now();
        let mut recall_sum = 0.0_f32;
        for query_idx in 0..QUERY_COUNT {
            let stride = NODE_COUNT / QUERY_COUNT;
            let query_vector = &corpus[query_idx * stride].1;

            let ann = vault.search_vector(query_vector, LIMIT)?;
            let ann_ids: HashSet<EntityId> = ann.iter().map(|item| item.id).collect();

            let mut brute_force: Vec<(EntityId, f32)> = corpus
                .iter()
                .map(|(id, vector)| (*id, crate::distance::cosine_distance(query_vector, vector)))
                .collect();
            brute_force.sort_by(|left, right| {
                left.1
                    .total_cmp(&right.1)
                    .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
            });

            let brute_ids: HashSet<EntityId> =
                brute_force.iter().take(LIMIT).map(|(id, _)| *id).collect();
            let hits = brute_ids.intersection(&ann_ids).count();
            recall_sum += hits as f32 / LIMIT as f32;
        }
        let search_elapsed = search_started.elapsed();

        let recall_at_10 = recall_sum / QUERY_COUNT as f32;
        eprintln!(
            "hnsw recall@10={recall_at_10:.4}, insert_ms={}, search_ms={}",
            insert_elapsed.as_millis(),
            search_elapsed.as_millis()
        );

        assert!(
            recall_at_10 > 0.95,
            "expected recall@10 > 0.95, got {recall_at_10:.4}"
        );

        Ok(())
    }

    #[test]
    fn put_query_and_delete_edges() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let src = EntityId::now();
        let tgt = EntityId::now();
        let kind = EdgeKind::Supports;
        let weight = 0.75_f32;

        vault.put_edge(&src, kind, &tgt, weight)?;

        let out = vault.edges_out(&src)?;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, kind);
        assert_eq!(out[0].target, tgt);
        assert!((out[0].weight - weight).abs() < f32::EPSILON);

        let inbound = vault.edges_in(&tgt)?;
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].kind, kind);
        assert_eq!(inbound[0].target, src);
        assert!((inbound[0].weight - weight).abs() < f32::EPSILON);

        assert!(vault.delete_edge(&src, kind, &tgt)?);
        assert!(vault.edges_out(&src)?.is_empty());
        assert!(vault.edges_in(&tgt)?.is_empty());
        assert!(!vault.delete_edge(&src, kind, &tgt)?);

        Ok(())
    }

    #[test]
    fn batch_put_multiple_entities_atomically() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id_a = EntityId::now();
        let id_b = EntityId::now();
        let id_c = EntityId::now();

        vault
            .batch()
            .put(&id_a, 0, test_time_range(100, 100), 101, b"a")
            .put(&id_b, 1, test_time_range(200, 201), 202, b"b")
            .put(&id_c, 6, test_time_range(300, 400), 401, b"c")
            .commit()?;

        assert_eq!(vault.get(&id_a)?.ok_or(Error::EntityNotFound)?, b"a");
        assert_eq!(vault.get(&id_b)?.ok_or(Error::EntityNotFound)?, b"b");
        assert_eq!(vault.get(&id_c)?.ok_or(Error::EntityNotFound)?, b"c");
        Ok(())
    }

    #[test]
    fn batch_put_writes_type_index() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let entity_type = 0_u8;

        vault
            .batch()
            .put(&id, entity_type, test_time_range(10, 20), 30, b"type-index")
            .commit()?;

        let key = Store::encode_type_key(entity_type, &id);
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.type_index.get(&rtxn, &key)?.is_some());

        let mut hits = 0_usize;
        for entry in vault.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
            let (found_key, _) = entry?;
            if found_key == key {
                hits += 1;
            }
        }
        assert_eq!(hits, 1);
        Ok(())
    }

    #[test]
    fn batch_put_writes_temporal_indexes() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        vault
            .batch()
            .put(&id, 6, test_time_range(1_000, 2_000), 3_000, b"range")
            .commit()?;

        {
            let rtxn = vault.store.env.read_txn()?;
            let start_key = Store::encode_temporal_key(1_000, &id);
            let end_key = Store::encode_temporal_key(2_000, &id);
            let learned_key = Store::encode_temporal_key(3_000, &id);
            assert!(vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &start_key)?
                .is_some());
            assert!(vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &end_key)?
                .is_some());
            assert!(vault
                .store
                .temporal_learned
                .get(&rtxn, &learned_key)?
                .is_some());
        }

        let point_id = EntityId::now();
        vault
            .batch()
            .put(
                &point_id,
                6,
                test_time_range(7_777, 7_777),
                8_888,
                b"point-event",
            )
            .commit()?;
        let point_end_key = Store::encode_temporal_key(7_777, &point_id);
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &point_end_key)?
            .is_none());

        Ok(())
    }

    #[test]
    fn batch_put_assigns_short_id() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id1 = EntityId::now();
        let id2 = EntityId::now();
        let data1 = b"entity-one";
        let data2 = b"entity-two";

        vault
            .batch()
            .put(&id1, 0, test_time_range(1, 1), 2, data1)
            .put(&id2, 0, test_time_range(3, 3), 4, data2)
            .commit()?;

        let (short_id1, hash1) = decode_short_id_value(&read_short_id_value(&vault, &id1)?)?;
        let (short_id2, hash2) = decode_short_id_value(&read_short_id_value(&vault, &id2)?)?;
        assert_eq!(short_id1, "cl1");
        assert_eq!(short_id2, "cl2");
        assert_eq!(hash1, content_hash(data1));
        assert_eq!(hash2, content_hash(data2));
        Ok(())
    }

    #[test]
    fn batch_put_short_id_reverse_lookup() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let data = b"reverse";

        vault
            .batch()
            .put(&id, 0, test_time_range(100, 100), 101, data)
            .commit()?;

        let short_id_value = read_short_id_value(&vault, &id)?;
        let (short_id, _) = decode_short_id_value(&short_id_value)?;

        let rtxn = vault.store.env.read_txn()?;
        let reverse = vault
            .store
            .short_ids_reverse
            .get(&rtxn, short_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(reverse, id.as_bytes());
        Ok(())
    }

    #[test]
    fn batch_put_updates_content_hash_on_reput() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let data1 = b"initial";
        let mut data2 = b"updated".to_vec();
        while content_hash(data1) == content_hash(&data2) {
            data2.push(0_u8);
        }

        vault
            .batch()
            .put(&id, 0, test_time_range(10, 10), 11, data1)
            .commit()?;
        let (short_id1, hash1) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

        vault
            .batch()
            .put(&id, 0, test_time_range(10, 10), 11, &data2)
            .commit()?;
        let (short_id2, hash2) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

        assert_eq!(short_id1, short_id2);
        assert_eq!(hash1, content_hash(data1));
        assert_eq!(hash2, content_hash(&data2));
        assert_ne!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn reput_deindexes_stale_secondary_indexes() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let old_type = 0_u8;
        let old_occurred = test_time_range(100, 200);
        let old_learned = 300_u64;
        let old_data = b"old-data";
        let new_type = 1_u8;
        let new_occurred = test_time_range(400, 500);
        let new_learned = 600_u64;
        let mut new_data = b"new-data".to_vec();
        while content_hash(old_data) == content_hash(&new_data) {
            new_data.push(0_u8);
        }

        vault
            .batch()
            .put(&id, old_type, old_occurred, old_learned, old_data)
            .commit()?;

        let old_type_key = Store::encode_type_key(old_type, &id);
        let old_start_key = Store::encode_temporal_key(old_occurred.start, &id);
        let old_end_key = Store::encode_temporal_key(old_occurred.end, &id);
        let old_learned_key = Store::encode_temporal_key(old_learned, &id);

        {
            let rtxn = vault.store.env.read_txn()?;
            assert!(vault.store.type_index.get(&rtxn, &old_type_key)?.is_some());
            assert!(vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &old_start_key)?
                .is_some());
            assert!(vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_some());
            assert!(vault
                .store
                .temporal_learned
                .get(&rtxn, &old_learned_key)?
                .is_some());
        }

        let (short_id_before, hash_before) =
            decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

        vault
            .batch()
            .put(&id, new_type, new_occurred, new_learned, &new_data)
            .commit()?;

        let new_type_key = Store::encode_type_key(new_type, &id);
        let new_start_key = Store::encode_temporal_key(new_occurred.start, &id);
        let new_end_key = Store::encode_temporal_key(new_occurred.end, &id);
        let new_learned_key = Store::encode_temporal_key(new_learned, &id);

        {
            let rtxn = vault.store.env.read_txn()?;
            assert!(vault.store.type_index.get(&rtxn, &old_type_key)?.is_none());
            assert!(vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &old_start_key)?
                .is_none());
            assert!(vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_none());
            assert!(vault
                .store
                .temporal_learned
                .get(&rtxn, &old_learned_key)?
                .is_none());
            assert!(vault.store.type_index.get(&rtxn, &new_type_key)?.is_some());
            assert!(vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &new_start_key)?
                .is_some());
            assert!(vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &new_end_key)?
                .is_some());
            assert!(vault
                .store
                .temporal_learned
                .get(&rtxn, &new_learned_key)?
                .is_some());
        }

        assert_eq!(vault.get(&id)?.ok_or(Error::EntityNotFound)?, new_data);
        let (short_id_after, hash_after) =
            decode_short_id_value(&read_short_id_value(&vault, &id)?)?;
        assert_eq!(short_id_before, short_id_after);
        assert_eq!(hash_before, content_hash(old_data));
        assert_eq!(hash_after, content_hash(&new_data));
        assert_ne!(hash_before, hash_after);

        Ok(())
    }

    #[test]
    fn reput_range_to_point_deindexes_stale_end_key() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        vault
            .batch()
            .put(&id, 0, test_time_range(100, 200), 300, b"range")
            .commit()?;

        let old_end_key = Store::encode_temporal_key(200, &id);
        {
            let rtxn = vault.store.env.read_txn()?;
            assert!(vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_some());
        }

        vault
            .batch()
            .put(&id, 0, test_time_range(200, 200), 300, b"point")
            .commit()?;

        {
            let rtxn = vault.store.env.read_txn()?;
            assert!(
                vault
                    .store
                    .temporal_occurred_end
                    .get(&rtxn, &old_end_key)?
                    .is_none(),
                "stale occurred_end key should be deleted on range→point transition"
            );
        }

        assert!(vault.delete_entity(&id)?);
        Ok(())
    }

    #[test]
    fn batch_phonetic_index() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        vault
            .batch()
            .put(&id, 0, test_time_range(1, 1), 2, b"phonetic")
            .phonetic(&id, &["SMTH", "SMT"])
            .commit()?;

        let rtxn = vault.store.env.read_txn()?;
        for code in ["SMTH", "SMT"] {
            let posting = vault
                .store
                .phonetic_index
                .get(&rtxn, code.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            assert!(posting.len().is_multiple_of(16));
            assert!(posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()));
        }
        Ok(())
    }

    #[test]
    fn phonetic_dedup_on_reindex() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        vault
            .batch()
            .put(&id, 0, test_time_range(1, 2), 3, b"dedup")
            .phonetic(&id, &["ABC"])
            .commit()?;

        vault.batch().phonetic(&id, &["ABC"]).commit()?;

        let rtxn = vault.store.env.read_txn()?;
        let posting = vault
            .store
            .phonetic_index
            .get(&rtxn, b"ABC")?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(posting.len(), 16);
        let count = posting
            .chunks_exact(16)
            .filter(|chunk| *chunk == id.as_bytes())
            .count();
        assert_eq!(count, 1);
        Ok(())
    }

    #[test]
    fn full_delete_deindexes_everything() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let out_target = EntityId::now();
        let in_source = EntityId::now();
        let occurred = test_time_range(10_000, 20_000);
        let learned_at = 30_000;

        vault
            .batch()
            .put(&id, 0, occurred, learned_at, b"delete-me")
            .put(&out_target, 4, test_time_range(1, 1), 2, b"target")
            .put(&in_source, 4, test_time_range(3, 3), 4, b"source")
            .vector(&id, &[0.1, 0.2, 0.3, 0.4])
            .edge(&id, EdgeKind::Supports, &out_target, 0.9)
            .edge(&in_source, EdgeKind::Mentions, &id, 0.7)
            .phonetic(&id, &["SMTH", "SMT"])
            .commit()?;

        let short_id_before_delete = {
            let value = read_short_id_value(&vault, &id)?;
            let (short_id, _) = decode_short_id_value(&value)?;
            short_id
        };

        assert!(vault.delete_entity(&id)?);
        assert!(vault.get(&id)?.is_none());
        assert!(vault.get_vector(&id)?.is_none());
        assert!(vault.edges_out(&id)?.is_empty());
        assert!(vault.edges_in(&id)?.is_empty());
        assert!(vault.edges_in(&out_target)?.is_empty());
        assert!(vault.edges_out(&in_source)?.is_empty());

        let type_key = Store::encode_type_key(0, &id);
        let start_key = Store::encode_temporal_key(occurred.start, &id);
        let end_key = Store::encode_temporal_key(occurred.end, &id);
        let learned_key = Store::encode_temporal_key(learned_at, &id);
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_none());
        assert!(vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &start_key)?
            .is_none());
        assert!(vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_none());
        assert!(vault
            .store
            .temporal_learned
            .get(&rtxn, &learned_key)?
            .is_none());

        for code in ["SMTH", "SMT"] {
            if let Some(posting) = vault.store.phonetic_index.get(&rtxn, code.as_bytes())? {
                assert!(!posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()));
            }
        }

        assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_none());
        assert!(vault
            .store
            .short_ids_reverse
            .get(&rtxn, short_id_before_delete.as_bytes())?
            .is_none());
        Ok(())
    }

    #[test]
    fn delete_entity_returns_bool() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        vault
            .batch()
            .put(&id, 0, test_time_range(1, 2), 3, b"exists")
            .commit()?;

        assert!(vault.delete_entity(&id)?);
        assert!(!vault.delete_entity(&id)?);
        Ok(())
    }

    #[test]
    fn put_entity_simple_api_uses_batch() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let occurred = test_time_range(123, 456);
        let learned_at = 789;
        let data = b"simple-api";

        vault.put_entity(&id, 0, occurred, learned_at, data)?;
        assert_eq!(vault.get(&id)?.ok_or(Error::EntityNotFound)?, data);

        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .entities
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(raw.len(), ENTITY_METADATA_HEADER_LEN + data.len());
        assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], data);

        let type_key = Store::encode_type_key(0, &id);
        let start_key = Store::encode_temporal_key(occurred.start, &id);
        let end_key = Store::encode_temporal_key(occurred.end, &id);
        let learned_key = Store::encode_temporal_key(learned_at, &id);
        assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_some());
        assert!(vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &start_key)?
            .is_some());
        assert!(vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_some());
        assert!(vault
            .store
            .temporal_learned
            .get(&rtxn, &learned_key)?
            .is_some());
        assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_some());

        Ok(())
    }

    #[test]
    fn validates_dimensions_and_map_size() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;

        let mut invalid_dims = test_config();
        invalid_dims.dimensions = 0;
        let err = match Vault::open(temp_dir.path(), invalid_dims) {
            Ok(_) => panic!("expected invalid config"),
            Err(err) => err,
        };
        assert!(matches!(err, Error::InvalidConfig(_)));

        let mut invalid_map = test_config();
        invalid_map.map_size = 0;
        let err = match Vault::open(temp_dir.path(), invalid_map) {
            Ok(_) => panic!("expected invalid config"),
            Err(err) => err,
        };
        assert!(matches!(err, Error::InvalidConfig(_)));
        Ok(())
    }

    #[test]
    fn batch_with_edges_and_entities() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let src = EntityId::now();
        let tgt = EntityId::now();
        let vector = [0.9_f32, 0.8, 0.7, 0.6];

        vault
            .batch()
            .put(&src, 0, test_time_range(1, 2), 3, b"src")
            .put(&tgt, 4, test_time_range(4, 5), 6, b"tgt")
            .vector(&src, &vector)
            .edge(&src, EdgeKind::BelongsTo, &tgt, 0.5)
            .commit()?;

        assert_eq!(vault.get(&src)?.ok_or(Error::EntityNotFound)?, b"src");
        assert_eq!(vault.get(&tgt)?.ok_or(Error::EntityNotFound)?, b"tgt");
        assert_eq!(
            vault.get_vector(&src)?.ok_or(Error::EntityNotFound)?,
            vector
        );

        let out = vault.edges_out(&src)?;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EdgeKind::BelongsTo);
        assert_eq!(out[0].target, tgt);
        Ok(())
    }

    #[test]
    fn edges_out_returns_all_edges_for_same_source() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let src = EntityId::now();
        let tgt_a = EntityId::now();
        let tgt_b = EntityId::now();
        let tgt_c = EntityId::now();
        let expected = [
            (EdgeKind::BelongsTo, tgt_a, 1.0_f32),
            (EdgeKind::Mentions, tgt_b, 0.6_f32),
            (EdgeKind::Supports, tgt_c, 0.9_f32),
        ];

        vault.put_edge(&src, expected[0].0, &expected[0].1, expected[0].2)?;
        vault.put_edge(&src, expected[1].0, &expected[1].1, expected[1].2)?;
        vault.put_edge(&src, expected[2].0, &expected[2].1, expected[2].2)?;

        let out = vault.edges_out(&src)?;
        assert_eq!(out.len(), expected.len());
        for (kind, target, weight) in expected {
            assert!(
                out.iter().any(|e| {
                    e.kind == kind && e.target == target && (e.weight - weight).abs() < f32::EPSILON
                }),
                "missing edge ({kind:?}, {target:?}, {weight})"
            );
        }

        Ok(())
    }

    #[test]
    fn detects_embedding_model_mismatch_on_open() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let mut cfg = test_config();
        cfg.embedding_model = Some("model-a".to_owned());
        let vault = Vault::open(temp_dir.path(), cfg)?;
        drop(vault);

        let mut cfg = test_config();
        cfg.embedding_model = Some("model-b".to_owned());
        let Err(err) = Vault::open(temp_dir.path(), cfg) else {
            panic!("expected mismatch");
        };
        assert!(matches!(
            err,
            Error::EmbeddingModelChanged {
                ref stored,
                ref requested
            } if stored == "model-a" && requested == "model-b"
        ));

        Ok(())
    }

    #[test]
    fn embedding_model_first_write_is_atomic() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let mut cfg = test_config();
        cfg.embedding_model = Some("model-x".to_owned());

        let vault = Vault::open(temp_dir.path(), cfg.clone())?;
        drop(vault);

        let vault = Vault::open(temp_dir.path(), cfg)?;
        drop(vault);

        let mut cfg2 = test_config();
        cfg2.embedding_model = Some("model-y".to_owned());
        assert!(matches!(
            Vault::open(temp_dir.path(), cfg2),
            Err(Error::EmbeddingModelChanged { .. })
        ));

        Ok(())
    }

    #[test]
    fn creates_all_databases() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let rtxn = vault.store.env.read_txn()?;

        for name in DB_NAMES {
            let db = vault
                .store
                .env
                .open_database::<Bytes, Bytes>(&rtxn, Some(name))?;
            assert!(db.is_some(), "missing database: {name}");
        }

        Ok(())
    }

    #[test]
    fn context_pack_run_serialized_toon_end_to_end() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = EntityId::now();
        let b = EntityId::now();

        let payload_a = rmp_serde::to_vec_named(&serde_json::json!({
            "pred": "goal.learning",
            "val": "Learn Japanese by June"
        }))
        .map_err(|_| Error::InvalidKey)?;
        let payload_b = rmp_serde::to_vec_named(&serde_json::json!({ "name": "Alice" }))
            .map_err(|_| Error::InvalidKey)?;

        vault
            .batch()
            .put(&a, 0, test_time_range(100, 100), 101, &payload_a)
            .text(&a, &[("body", "learn japanese")])
            .put(&b, 4, test_time_range(102, 102), 103, &payload_b)
            .edge(&a, EdgeKind::Mentions, &b, 1.0)
            .commit()?;

        let output = vault
            .context_pack()
            .search_text("japanese", 10)
            .edge_hop(1)
            .format(PackFormat::Toon)
            .run_serialized()?;
        assert!(!output.is_empty());

        let text = String::from_utf8(output).map_err(|_| Error::InvalidKey)?;
        assert!(text.contains("claims"));
        Ok(())
    }

    #[test]
    fn entity_id_now_is_monotonic_lexicographically() {
        for _ in 0..128 {
            let a = EntityId::now();
            let b = EntityId::now();
            if a < b {
                return;
            }
        }

        panic!("expected two consecutive EntityId::now() values to increase");
    }

    #[test]
    fn new_edge_kinds_round_trip_through_u8() {
        let new_kinds = [
            (13_u8, EdgeKind::EmployedBy),
            (14, EdgeKind::HasFacet),
            (15, EdgeKind::InWorld),
            (16, EdgeKind::FacetOf),
            (17, EdgeKind::SetIn),
        ];
        for (disc, expected) in new_kinds {
            let kind = EdgeKind::try_from_u8(disc).expect("valid discriminant");
            assert_eq!(kind, expected);
            assert_eq!(kind as u8, disc);
        }
        assert!(EdgeKind::try_from_u8(18).is_none());
    }

    #[test]
    fn new_edge_kinds_have_default_weights() {
        assert_eq!(EdgeKind::EmployedBy.default_weight(), 0.8);
        assert_eq!(EdgeKind::HasFacet.default_weight(), 0.7);
        assert_eq!(EdgeKind::InWorld.default_weight(), 0.7);
        assert_eq!(EdgeKind::FacetOf.default_weight(), 0.7);
        assert_eq!(EdgeKind::SetIn.default_weight(), 0.7);
    }

    #[test]
    fn new_entity_type_prefixes() {
        use crate::types::short_id_prefix;
        assert_eq!(short_id_prefix(12), "og");
        assert_eq!(short_id_prefix(13), "fc");
        assert_eq!(short_id_prefix(14), "wd");
        assert_eq!(short_id_prefix(15), "xx");
    }

    #[test]
    fn put_edge_with_vad_round_trip() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let src = EntityId::now();
        let tgt = EntityId::now();

        vault
            .batch()
            .put(&src, 0, test_time_range(1, 2), 3, b"src")
            .put(&tgt, 4, test_time_range(4, 5), 6, b"tgt")
            .commit()?;

        vault.put_edge_with_vad(
            &src,
            EdgeKind::Supports,
            &tgt,
            0.8,
            Vad {
                valence: 0.6,
                arousal: 0.3,
                dominance: 0.9,
            },
        )?;

        let out = vault.edges_out(&src)?;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EdgeKind::Supports);
        assert_eq!(out[0].target, tgt);
        assert!((out[0].weight - 0.8).abs() < f32::EPSILON);
        assert!((out[0].vad.valence - 0.6).abs() < f32::EPSILON);
        assert!((out[0].vad.arousal - 0.3).abs() < f32::EPSILON);
        assert!((out[0].vad.dominance - 0.9).abs() < f32::EPSILON);
        Ok(())
    }

    #[test]
    fn put_edge_with_vad_rejects_non_finite() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let src = EntityId::now();
        let tgt = EntityId::now();

        let err = vault
            .put_edge_with_vad(
                &src,
                EdgeKind::Supports,
                &tgt,
                0.5,
                Vad {
                    valence: f32::NAN,
                    arousal: 0.0,
                    dominance: 0.0,
                },
            )
            .expect_err("expected invalid vad");
        assert!(matches!(err, Error::InvalidVad));

        let err = vault
            .put_edge_with_vad(
                &src,
                EdgeKind::Supports,
                &tgt,
                0.5,
                Vad {
                    valence: 0.0,
                    arousal: f32::INFINITY,
                    dominance: 0.0,
                },
            )
            .expect_err("expected invalid vad");
        assert!(matches!(err, Error::InvalidVad));

        let err = vault
            .put_edge_with_vad(
                &src,
                EdgeKind::Supports,
                &tgt,
                0.5,
                Vad {
                    valence: 1.5,
                    arousal: 0.0,
                    dominance: 0.0,
                },
            )
            .expect_err("expected invalid vad for out-of-range valence");
        assert!(matches!(err, Error::InvalidVad));

        let err = vault
            .put_edge_with_vad(
                &src,
                EdgeKind::Supports,
                &tgt,
                0.5,
                Vad {
                    valence: 0.0,
                    arousal: -0.1,
                    dominance: 0.0,
                },
            )
            .expect_err("expected invalid vad for negative arousal");
        assert!(matches!(err, Error::InvalidVad));
        Ok(())
    }

    #[test]
    fn batch_edge_with_vad_api() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let src = EntityId::now();
        let tgt = EntityId::now();

        vault
            .batch()
            .put(&src, 0, test_time_range(1, 2), 3, b"src")
            .put(&tgt, 4, test_time_range(4, 5), 6, b"tgt")
            .edge_with_vad(
                &src,
                EdgeKind::HasFacet,
                &tgt,
                0.7,
                Vad {
                    valence: 0.5,
                    arousal: 0.4,
                    dominance: 0.3,
                },
            )
            .commit()?;

        let out = vault.edges_out(&src)?;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EdgeKind::HasFacet);
        Ok(())
    }
}
