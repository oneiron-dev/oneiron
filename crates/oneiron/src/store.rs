use std::path::Path;

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, RwTxn};

use crate::error::{Error, Result};
use crate::types::{EdgeKind, EntityId, VaultConfig};

const MAX_DBS: u32 = 24;
const MODEL_ID_KEY: &[u8] = b"model_id";

/// LMDB environment and database handles for a vault.
pub struct Store {
    pub(crate) env: Env,
    pub(crate) entities: Database<Bytes, Bytes>,
    pub(crate) edges_out: Database<Bytes, Bytes>,
    pub(crate) edges_in: Database<Bytes, Bytes>,
    pub(crate) vectors: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) hnsw_neighbors: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) hnsw_meta: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) text_postings: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) text_meta: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) text_forward: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) ppr_cache: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) ppr_cache_deps: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) type_index: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) temporal_occurred_start: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) temporal_occurred_end: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) temporal_learned: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) phonetic_index: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) short_ids: Database<Bytes, Bytes>,
    #[allow(dead_code)]
    pub(crate) short_ids_reverse: Database<Bytes, Bytes>,
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
        let phonetic_index = create_db(&env, &mut wtxn, "phonetic_index")?;
        let short_ids = create_db(&env, &mut wtxn, "short_ids")?;
        let short_ids_reverse = create_db(&env, &mut wtxn, "short_ids_reverse")?;
        wtxn.commit()?;

        if let Some(requested) = config.embedding_model.as_deref() {
            let rtxn = env.read_txn()?;
            let stored = hnsw_meta
                .get(&rtxn, MODEL_ID_KEY)?
                .map(parse_utf8_bytes)
                .transpose()?;
            drop(rtxn);

            match stored {
                Some(stored) if stored != requested => {
                    return Err(Error::EmbeddingModelChanged {
                        stored,
                        requested: requested.to_owned(),
                    });
                }
                Some(_) => {}
                None => {
                    let mut wtxn = env.write_txn()?;
                    hnsw_meta.put(&mut wtxn, MODEL_ID_KEY, requested.as_bytes())?;
                    wtxn.commit()?;
                }
            }
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
            phonetic_index,
            short_ids,
            short_ids_reverse,
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

fn parse_utf8_bytes(bytes: &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidKey)?
        .to_owned())
}
