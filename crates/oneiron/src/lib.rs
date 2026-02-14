use std::path::Path;

use heed::types::Bytes;
use heed::Database;

pub mod batch;
pub mod error;
pub mod store;
pub mod types;

pub use crate::batch::BatchBuilder;
use crate::batch::{deindex_entity, ENTITY_METADATA_HEADER_LEN};
pub use crate::error::{Error, Result};
use crate::store::Store;
pub use crate::types::{
    EdgeKind, EntityId, FieldProfile, HnswConfig, PackFormat, ScoredEntity, Signal, TimeRange,
    VaultConfig,
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

        if bytes.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::InvalidKey);
        }

        Ok(Some(bytes[ENTITY_METADATA_HEADER_LEN..].to_vec()))
    }

    /// Deletes an entity blob by ID.
    pub fn delete_entity(&self, id: &EntityId) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let existed = deindex_entity(&self.store, &mut wtxn, id)?;
        wtxn.commit()?;
        Ok(existed)
    }

    /// Stores a vector for an entity.
    pub fn put_vector(&self, id: &EntityId, vector: &[f32]) -> Result<()> {
        if vector.len() != self.config.dimensions {
            return Err(Error::DimensionMismatch {
                expected: self.config.dimensions,
                got: vector.len(),
            });
        }

        let bytes = f32_slice_to_le_bytes(vector);
        let mut wtxn = self.store.env.write_txn()?;
        self.store.vectors.put(&mut wtxn, id.as_bytes(), &bytes)?;
        wtxn.commit()?;
        Ok(())
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

    /// Deletes a directed edge and its reverse index entry.
    pub fn delete_edge(&self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Result<bool> {
        let key_out = Store::encode_edge_key(src, kind, tgt);
        let key_in = Store::encode_edge_key(tgt, kind, src);

        let mut wtxn = self.store.env.write_txn()?;
        let existed_out = self.store.edges_out.delete(&mut wtxn, &key_out)?;
        let existed_in = self.store.edges_in.delete(&mut wtxn, &key_in)?;
        wtxn.commit()?;
        Ok(existed_out || existed_in)
    }

    /// Returns outbound edges for `src`.
    pub fn edges_out(&self, src: &EntityId) -> Result<Vec<(EdgeKind, EntityId, f32)>> {
        let rtxn = self.store.env.read_txn()?;
        scan_edges(&self.store.edges_out, &rtxn, src.as_bytes())
    }

    /// Returns inbound edges for `tgt`.
    pub fn edges_in(&self, tgt: &EntityId) -> Result<Vec<(EdgeKind, EntityId, f32)>> {
        let rtxn = self.store.env.read_txn()?;
        scan_edges(&self.store.edges_in, &rtxn, tgt.as_bytes())
    }

    /// Creates a new write batch builder bound to this vault.
    pub fn batch(&self) -> BatchBuilder<'_> {
        BatchBuilder::new(self)
    }
}

fn f32_slice_to_le_bytes(values: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for v in values {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes
}

fn le_bytes_to_f32_vec(bytes: &[u8]) -> Result<Vec<f32>> {
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
) -> Result<Vec<(EdgeKind, EntityId, f32)>> {
    database
        .prefix_iter(rtxn, prefix.as_slice())?
        .map(|entry| {
            let (key, value) = entry?;
            parse_edge_record(key, value)
        })
        .collect()
}

fn parse_edge_record(key: &[u8], value: &[u8]) -> Result<(EdgeKind, EntityId, f32)> {
    if key.len() != 33 || value.len() != 12 {
        return Err(Error::InvalidKey);
    }

    let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::InvalidKey)?;
    let neighbor = EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?);
    let weight = f32::from_le_bytes(value[..4].try_into().map_err(|_| Error::InvalidKey)?);

    Ok((kind, neighbor, weight))
}

#[cfg(test)]
mod tests {
    use std::str;

    use heed::types::Bytes;
    use xxhash_rust::xxh32::xxh32;

    use super::*;

    const DB_NAMES: [&str; 18] = [
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
        assert_eq!(out[0].0, kind);
        assert_eq!(out[0].1, tgt);
        assert!((out[0].2 - weight).abs() < f32::EPSILON);

        let inbound = vault.edges_in(&tgt)?;
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].0, kind);
        assert_eq!(inbound[0].1, src);
        assert!((inbound[0].2 - weight).abs() < f32::EPSILON);

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
        assert_eq!(out[0].0, EdgeKind::BelongsTo);
        assert_eq!(out[0].1, tgt);
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
                out.iter().any(|(k, t, w)| {
                    *k == kind && *t == target && (*w - weight).abs() < f32::EPSILON
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
    fn creates_all_18_databases() -> Result<()> {
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
}
