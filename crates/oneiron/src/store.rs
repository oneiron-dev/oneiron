use std::path::Path;

use heed::types::Bytes;
#[cfg(feature = "sync")]
use heed::types::Str;
use heed::{Database, Env, EnvOpenOptions, RwTxn};

use crate::error::{Error, Result};
use crate::types::{EdgeKind, EntityId, VaultConfig};

const MAX_DBS: u32 = 25;
pub(crate) const MODEL_ID_KEY: &[u8] = b"model_id";
pub(crate) const GRAPH_VERSION_KEY: &[u8] = b"graph_version";
pub(crate) const HNSW_CONFIG_KEY: &[u8] = b"hnsw_config";
pub(crate) const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY: &[u8] =
    b"temporal_long_intervals_schema_version";
const TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION: u8 = 2;
pub(crate) const VECTOR_VERSION_KEY: &[u8] = b"vector_version";
const HNSW_COMPATIBILITY_VERSION: u8 = 1;
const HNSW_COMPATIBILITY_LEN: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PersistedHnswCompatibility {
    dimensions: usize,
    m_max_0: usize,
    ef_construction: usize,
}

impl PersistedHnswCompatibility {
    fn from_config(config: &VaultConfig) -> Self {
        Self {
            dimensions: config.dimensions,
            m_max_0: config.hnsw.m_max_0,
            ef_construction: config.hnsw.ef_construction,
        }
    }
}

enum HnswCompatibilityState {
    Missing,
    Legacy,
    Current(PersistedHnswCompatibility),
}

/// LMDB environment and database handles for a vault.
pub struct Store {
    pub(crate) env: Env,
    pub(crate) entities: Database<Bytes, Bytes>,
    pub(crate) edges_out: Database<Bytes, Bytes>,
    pub(crate) edges_in: Database<Bytes, Bytes>,
    pub(crate) vectors: Database<Bytes, Bytes>,
    pub(crate) hnsw_neighbors: Database<Bytes, Bytes>,
    pub(crate) hnsw_meta: Database<Bytes, Bytes>,
    pub(crate) text_postings: Database<Bytes, Bytes>,
    pub(crate) text_meta: Database<Bytes, Bytes>,
    pub(crate) text_forward: Database<Bytes, Bytes>,
    pub(crate) ppr_cache: Database<Bytes, Bytes>,
    pub(crate) ppr_cache_deps: Database<Bytes, Bytes>,
    pub(crate) type_index: Database<Bytes, Bytes>,
    pub(crate) temporal_occurred_start: Database<Bytes, Bytes>,
    pub(crate) temporal_occurred_end: Database<Bytes, Bytes>,
    pub(crate) temporal_learned: Database<Bytes, Bytes>,
    pub(crate) temporal_long_intervals: Database<Bytes, Bytes>,
    pub(crate) phonetic_index: Database<Bytes, Bytes>,
    pub(crate) phonetic_forward: Database<Bytes, Bytes>,
    pub(crate) short_ids: Database<Bytes, Bytes>,
    pub(crate) short_ids_reverse: Database<Bytes, Bytes>,
    /// CRDT Doc states, state vectors, pending updates, metadata (sync feature only).
    #[cfg(feature = "sync")]
    pub(crate) sync_state: Database<Str, Bytes>,
    /// Offline update queue and embed job queue (sync feature only).
    #[cfg(feature = "sync")]
    pub(crate) sync_queue: Database<Bytes, Bytes>,
}

impl Store {
    /// Opens or creates a store at `path` and initializes all named databases.
    pub fn open(path: impl AsRef<Path>, config: &VaultConfig) -> Result<Self> {
        std::fs::create_dir_all(path.as_ref())?;

        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(config.map_size)
                .max_readers(config.max_readers)
                .max_dbs(MAX_DBS)
                .open(path.as_ref())?
        };

        let mut wtxn = env.write_txn()?;
        let entities = create_db(&env, &mut wtxn, "entities")?;
        let edges_out = create_db(&env, &mut wtxn, "edges_out")?;
        let edges_in = create_db(&env, &mut wtxn, "edges_in")?;
        let vectors = create_db(&env, &mut wtxn, "vectors")?;
        let hnsw_neighbors = create_db(&env, &mut wtxn, "hnsw_neighbors")?;
        let hnsw_meta = create_db(&env, &mut wtxn, "hnsw_meta")?;
        let text_postings = create_db(&env, &mut wtxn, "text_postings")?;
        let text_meta = create_db(&env, &mut wtxn, "text_meta")?;
        let text_forward = create_db(&env, &mut wtxn, "text_forward")?;
        let ppr_cache = create_db(&env, &mut wtxn, "ppr_cache")?;
        let ppr_cache_deps = create_db(&env, &mut wtxn, "ppr_cache_deps")?;
        let type_index = create_db(&env, &mut wtxn, "type_index")?;
        let temporal_occurred_start = create_db(&env, &mut wtxn, "temporal_occurred_start")?;
        let temporal_occurred_end = create_db(&env, &mut wtxn, "temporal_occurred_end")?;
        let temporal_learned = create_db(&env, &mut wtxn, "temporal_learned")?;
        let temporal_long_intervals = create_db(&env, &mut wtxn, "temporal_long_intervals")?;
        let phonetic_index = create_db(&env, &mut wtxn, "phonetic_index")?;
        let phonetic_forward = create_db(&env, &mut wtxn, "phonetic_forward")?;
        let short_ids = create_db(&env, &mut wtxn, "short_ids")?;
        let short_ids_reverse = create_db(&env, &mut wtxn, "short_ids_reverse")?;
        #[cfg(feature = "sync")]
        let sync_state: Database<Str, Bytes> =
            env.create_database(&mut wtxn, Some("sync_state"))?;
        #[cfg(feature = "sync")]
        let sync_queue = create_db(&env, &mut wtxn, "sync_queue")?;
        wtxn.commit()?;

        let should_persist_hnsw_config =
            preflight_hnsw_config(&env, &hnsw_meta, &vectors, &hnsw_neighbors, config)?;
        let should_persist_model_id =
            preflight_embedding_model(&env, &hnsw_meta, config.embedding_model.as_deref())?;
        migrate_temporal_long_intervals_if_needed(&env, &hnsw_meta, &temporal_long_intervals)?;

        if should_persist_hnsw_config {
            persist_hnsw_config_if_missing(&env, &hnsw_meta, &vectors, &hnsw_neighbors, config)?;
        }

        if should_persist_model_id {
            let requested = config
                .embedding_model
                .as_deref()
                .ok_or_else(|| Error::InvalidConfig("missing embedding model".to_owned()))?;
            persist_model_id_if_missing(&env, &hnsw_meta, requested)?;
        }

        Ok(Self {
            env,
            entities,
            edges_out,
            edges_in,
            vectors,
            hnsw_neighbors,
            hnsw_meta,
            text_postings,
            text_meta,
            text_forward,
            ppr_cache,
            ppr_cache_deps,
            type_index,
            temporal_occurred_start,
            temporal_occurred_end,
            temporal_learned,
            temporal_long_intervals,
            phonetic_index,
            phonetic_forward,
            short_ids,
            short_ids_reverse,
            #[cfg(feature = "sync")]
            sync_state,
            #[cfg(feature = "sync")]
            sync_queue,
        })
    }

    /// Encodes an edge key as `[src(16) | kind(1) | tgt(16)]`.
    pub fn encode_edge_key(src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> [u8; 33] {
        let mut key = [0_u8; 33];
        key[..16].copy_from_slice(src.as_bytes());
        key[16] = kind as u8;
        key[17..].copy_from_slice(tgt.as_bytes());
        key
    }

    /// Encodes a temporal key as `[timestamp_be(8) | id(16)]`.
    pub fn encode_temporal_key(ts: u64, id: &EntityId) -> [u8; 24] {
        let mut key = [0_u8; 24];
        key[..8].copy_from_slice(&ts.to_be_bytes());
        key[8..].copy_from_slice(id.as_bytes());
        key
    }

    /// Encodes a type key as `[entity_type(1) | id(16)]`.
    pub fn encode_type_key(entity_type: u8, id: &EntityId) -> [u8; 17] {
        let mut key = [0_u8; 17];
        key[0] = entity_type;
        key[1..].copy_from_slice(id.as_bytes());
        key
    }
}

fn create_db(env: &Env, wtxn: &mut RwTxn<'_>, name: &str) -> Result<Database<Bytes, Bytes>> {
    Ok(env.create_database::<Bytes, Bytes>(wtxn, Some(name))?)
}

fn preflight_embedding_model(
    env: &Env,
    hnsw_meta: &Database<Bytes, Bytes>,
    requested: Option<&str>,
) -> Result<bool> {
    let Some(requested) = requested else {
        return Ok(false);
    };

    let rtxn = env.read_txn()?;
    match hnsw_meta.get(&rtxn, MODEL_ID_KEY)? {
        Some(raw) => {
            let stored = parse_utf8_bytes(raw)?;
            if stored != requested {
                return Err(Error::EmbeddingModelChanged {
                    stored,
                    requested: requested.to_owned(),
                });
            }
            Ok(false)
        }
        None => Ok(true),
    }
}

fn preflight_hnsw_config(
    env: &Env,
    hnsw_meta: &Database<Bytes, Bytes>,
    vectors: &Database<Bytes, Bytes>,
    hnsw_neighbors: &Database<Bytes, Bytes>,
    requested: &VaultConfig,
) -> Result<bool> {
    let rtxn = env.read_txn()?;
    match read_hnsw_compatibility(hnsw_meta, &rtxn)? {
        HnswCompatibilityState::Current(stored) => {
            let requested = PersistedHnswCompatibility::from_config(requested);
            if stored != requested {
                return Err(Error::HnswConfigChanged {
                    stored: format_hnsw_compatibility(&stored),
                    requested: format_hnsw_compatibility(&requested),
                });
            }
            Ok(false)
        }
        HnswCompatibilityState::Missing | HnswCompatibilityState::Legacy => {
            if has_persisted_vector_or_hnsw_data(vectors, hnsw_neighbors, &rtxn)? {
                return Err(Error::InvalidConfig(
                    "populated vault is missing complete vector/hnsw compatibility metadata; rebuild or migrate it before reopening".to_owned(),
                ));
            }
            Ok(true)
        }
    }
}

fn persist_hnsw_config_if_missing(
    env: &Env,
    hnsw_meta: &Database<Bytes, Bytes>,
    vectors: &Database<Bytes, Bytes>,
    hnsw_neighbors: &Database<Bytes, Bytes>,
    requested: &VaultConfig,
) -> Result<()> {
    let requested = PersistedHnswCompatibility::from_config(requested);
    let encoded = encode_hnsw_config(&requested)?;
    let mut wtxn = env.write_txn()?;
    match read_hnsw_compatibility(hnsw_meta, &wtxn)? {
        HnswCompatibilityState::Current(stored) => {
            if stored != requested {
                return Err(Error::HnswConfigChanged {
                    stored: format_hnsw_compatibility(&stored),
                    requested: format_hnsw_compatibility(&requested),
                });
            }
        }
        HnswCompatibilityState::Missing | HnswCompatibilityState::Legacy => {
            if has_persisted_vector_or_hnsw_data(vectors, hnsw_neighbors, &wtxn)? {
                return Err(Error::InvalidConfig(
                    "populated vault is missing complete vector/hnsw compatibility metadata; rebuild or migrate it before reopening".to_owned(),
                ));
            }
            hnsw_meta.put(&mut wtxn, HNSW_CONFIG_KEY, &encoded)?;
            wtxn.commit()?;
        }
    }
    Ok(())
}

fn persist_model_id_if_missing(
    env: &Env,
    hnsw_meta: &Database<Bytes, Bytes>,
    requested: &str,
) -> Result<()> {
    let mut wtxn = env.write_txn()?;
    match hnsw_meta.get(&wtxn, MODEL_ID_KEY)? {
        Some(raw) => {
            let stored = parse_utf8_bytes(raw)?;
            if stored != requested {
                return Err(Error::EmbeddingModelChanged {
                    stored,
                    requested: requested.to_owned(),
                });
            }
        }
        None => {
            hnsw_meta.put(&mut wtxn, MODEL_ID_KEY, requested.as_bytes())?;
            wtxn.commit()?;
        }
    }
    Ok(())
}

fn encode_hnsw_config(config: &PersistedHnswCompatibility) -> Result<[u8; HNSW_COMPATIBILITY_LEN]> {
    let dimensions = u64::try_from(config.dimensions)
        .map_err(|_| Error::InvalidConfig("dimensions too large".to_owned()))?;
    let m_max_0 = u64::try_from(config.m_max_0)
        .map_err(|_| Error::InvalidConfig("hnsw m_max_0 too large".to_owned()))?;
    let ef_construction = u64::try_from(config.ef_construction)
        .map_err(|_| Error::InvalidConfig("hnsw ef_construction too large".to_owned()))?;

    let mut encoded = [0_u8; HNSW_COMPATIBILITY_LEN];
    encoded[0] = HNSW_COMPATIBILITY_VERSION;
    encoded[1..9].copy_from_slice(&dimensions.to_le_bytes());
    encoded[9..17].copy_from_slice(&m_max_0.to_le_bytes());
    encoded[17..25].copy_from_slice(&ef_construction.to_le_bytes());
    Ok(encoded)
}

fn read_hnsw_compatibility(
    hnsw_meta: &Database<Bytes, Bytes>,
    txn: &heed::RoTxn<'_>,
) -> Result<HnswCompatibilityState> {
    let Some(raw) = hnsw_meta.get(txn, HNSW_CONFIG_KEY)? else {
        return Ok(HnswCompatibilityState::Missing);
    };

    match raw.len() {
        HNSW_COMPATIBILITY_LEN => {
            decode_hnsw_compatibility(raw).map(HnswCompatibilityState::Current)
        }
        24 => Ok(HnswCompatibilityState::Legacy),
        _ => Err(Error::InvalidKey),
    }
}

fn decode_hnsw_compatibility(raw: &[u8]) -> Result<PersistedHnswCompatibility> {
    if raw.len() != HNSW_COMPATIBILITY_LEN || raw[0] != HNSW_COMPATIBILITY_VERSION {
        return Err(Error::InvalidKey);
    }

    let dimensions = usize::try_from(u64::from_le_bytes(
        raw[1..9].try_into().map_err(|_| Error::InvalidKey)?,
    ))
    .map_err(|_| Error::InvalidKey)?;
    let m_max_0 = usize::try_from(u64::from_le_bytes(
        raw[9..17].try_into().map_err(|_| Error::InvalidKey)?,
    ))
    .map_err(|_| Error::InvalidKey)?;
    let ef_construction = usize::try_from(u64::from_le_bytes(
        raw[17..25].try_into().map_err(|_| Error::InvalidKey)?,
    ))
    .map_err(|_| Error::InvalidKey)?;

    Ok(PersistedHnswCompatibility {
        dimensions,
        m_max_0,
        ef_construction,
    })
}

fn format_hnsw_compatibility(config: &PersistedHnswCompatibility) -> String {
    format!(
        "dimensions={},m_max_0={},ef_construction={}",
        config.dimensions, config.m_max_0, config.ef_construction
    )
}

fn has_persisted_vector_or_hnsw_data(
    vectors: &Database<Bytes, Bytes>,
    hnsw_neighbors: &Database<Bytes, Bytes>,
    txn: &heed::RoTxn<'_>,
) -> Result<bool> {
    Ok(database_has_entries(vectors, txn)? || database_has_entries(hnsw_neighbors, txn)?)
}

fn database_has_entries(db: &Database<Bytes, Bytes>, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(db.iter(txn)?.next().transpose()?.is_some())
}

fn migrate_temporal_long_intervals_if_needed(
    env: &Env,
    hnsw_meta: &Database<Bytes, Bytes>,
    temporal_long_intervals: &Database<Bytes, Bytes>,
) -> Result<()> {
    let rtxn = env.read_txn()?;
    let stored_version = match hnsw_meta.get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)? {
        Some(raw) if raw.len() == 1 => raw[0],
        Some(_) => return Err(Error::InvalidKey),
        None => 0,
    };
    drop(rtxn);

    if stored_version > TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION {
        return Err(Error::InvalidKey);
    }
    if stored_version == TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION {
        return Ok(());
    }

    let mut wtxn = env.write_txn()?;
    let mut legacy_rows = Vec::<([u8; 16], [u8; 16])>::new();
    for entry in temporal_long_intervals.iter(&wtxn)? {
        let (key, value) = entry?;
        match (key.len(), value.len()) {
            (24, 8) => {}
            (16, 16) => {
                let old_key = key.try_into().map_err(|_| Error::InvalidKey)?;
                let old_value = value.try_into().map_err(|_| Error::InvalidKey)?;
                legacy_rows.push((old_key, old_value));
            }
            _ => return Err(Error::InvalidKey),
        }
    }

    for (legacy_key, legacy_value) in legacy_rows {
        let occurred_start = u64::from_be_bytes(
            legacy_value[..8]
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        );
        let occurred_end = u64::from_be_bytes(
            legacy_value[8..]
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        );
        let new_key = {
            let mut key = [0_u8; 24];
            key[..8].copy_from_slice(&occurred_end.to_be_bytes());
            key[8..].copy_from_slice(&legacy_key);
            key
        };

        temporal_long_intervals.delete(&mut wtxn, &legacy_key)?;
        temporal_long_intervals.put(&mut wtxn, &new_key, &occurred_start.to_be_bytes())?;
    }

    hnsw_meta.put(
        &mut wtxn,
        TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY,
        &[TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION],
    )?;
    wtxn.commit()?;
    Ok(())
}

fn parse_utf8_bytes(bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| Error::InvalidKey)
}
