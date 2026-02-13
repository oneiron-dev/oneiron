use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use heed::types::Bytes;
use heed::Database;

pub mod error;
pub mod store;
pub mod types;

use crate::store::Store;
pub use crate::error::{Error, Result};
pub use crate::types::{
    EdgeKind, EntityId, FieldProfile, HnswConfig, PackFormat, ScoredEntity, Signal, TimeRange,
    VaultConfig,
};

/// Main vault API wrapping LMDB storage and configuration.
pub struct Vault {
    store: Store,
    config: VaultConfig,
}

impl Vault {
    /// Opens or creates a vault at `path`.
    pub fn open(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self> {
        let store = Store::open(path, &config)?;
        Ok(Self { store, config })
    }

    /// Stores an entity blob.
    pub fn put_entity(&self, id: &EntityId, data: &[u8]) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.store.entities.put(&mut wtxn, id.as_bytes(), data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Retrieves an entity blob by ID.
    pub fn get(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        let value = self.store.entities.get(&rtxn, id.as_bytes())?;
        Ok(value.map(|bytes| bytes.to_vec()))
    }

    /// Deletes an entity blob by ID.
    pub fn delete_entity(&self, id: &EntityId) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.store.entities.delete(&mut wtxn, id.as_bytes())?;
        wtxn.commit()?;
        Ok(())
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
    pub fn put_edge(&self, src: &EntityId, kind: EdgeKind, tgt: &EntityId, weight: f32) -> Result<()> {
        let key_out = Store::encode_edge_key(src, kind, tgt);
        let key_in = Store::encode_edge_key(tgt, kind, src);
        let value = encode_edge_value(weight, unix_seconds_now());

        let mut wtxn = self.store.env.write_txn()?;
        self.store.edges_out.put(&mut wtxn, &key_out, &value)?;
        self.store.edges_in.put(&mut wtxn, &key_in, &value)?;
        wtxn.commit()?;
        Ok(())
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
}

fn f32_slice_to_le_bytes(values: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[expect(clippy::manual_is_multiple_of, reason = "Use modulo check for portability.")]
fn le_bytes_to_f32_vec(bytes: &[u8]) -> Result<Vec<f32>> {
    if bytes.len() % 4 != 0 {
        return Err(Error::InvalidKey);
    }

    Ok(bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
        .collect())
}

fn encode_edge_value(weight: f32, created_at: u64) -> [u8; 12] {
    let mut value = [0_u8; 12];
    value[..4].copy_from_slice(&weight.to_le_bytes());
    value[4..].copy_from_slice(&created_at.to_le_bytes());
    value
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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
    let neighbor = EntityId::from_bytes(key[17..33].try_into().unwrap());
    let weight = f32::from_le_bytes(value[..4].try_into().unwrap());

    Ok((kind, neighbor, weight))
}

#[cfg(test)]
mod tests {
    use heed::types::Bytes;

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

        vault.put_entity(&id, data)?;
        let got = vault.get(&id)?.ok_or(Error::EntityNotFound)?;
        assert_eq!(got, data);

        vault.delete_entity(&id)?;
        assert!(vault.get(&id)?.is_none());

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
