//! Create-door database phase: open the manifest databases and gate versions.

use std::sync::MutexGuard;

use heed::types::{Bytes, Str};
use heed::{Database, RwTxn};

use crate::error::Result;
use crate::overlay_db::OverlayDb;

use super::manifest_storage_gates::{
    OwnedEnv, create_manifest_db, create_manifest_dupsort_db, create_manifest_str_db,
    gate_storage_versions, lmdb_database_open_guard, validate_db_manifest_set,
};

pub(super) struct CreatedDbs {
    pub(super) entities: Database<Bytes, Bytes>,
    pub(super) edges_out: Database<Bytes, Bytes>,
    pub(super) edges_in: Database<Bytes, Bytes>,
    pub(super) vectors: Database<Bytes, Bytes>,
    pub(super) hnsw_neighbors: Database<Bytes, Bytes>,
    pub(super) hnsw_meta: Database<Bytes, Bytes>,
    pub(super) text_postings: Database<Bytes, Bytes>,
    pub(super) text_meta: Database<Bytes, Bytes>,
    pub(super) text_forward: Database<Bytes, Bytes>,
    pub(super) text_bm25_field_stats: Database<Bytes, Bytes>,
    pub(super) text_doc_field_lengths: Database<Bytes, Bytes>,
    pub(super) vault_meta: Database<Bytes, Bytes>,
    pub(super) ppr_cache: Database<Bytes, Bytes>,
    pub(super) ppr_cache_deps: Database<Bytes, Bytes>,
    pub(super) type_index: Database<Bytes, Bytes>,
    pub(super) temporal_occurred_start: Database<Bytes, Bytes>,
    pub(super) temporal_occurred_end: Database<Bytes, Bytes>,
    pub(super) temporal_learned: Database<Bytes, Bytes>,
    pub(super) temporal_long_intervals: Database<Bytes, Bytes>,
    pub(super) phonetic_index: Database<Bytes, Bytes>,
    pub(super) phonetic_forward: Database<Bytes, Bytes>,
    pub(super) short_ids: Database<Bytes, Bytes>,
    pub(super) short_ids_reverse: Database<Bytes, Bytes>,
    pub(super) sync_state: Database<Str, Bytes>,
    pub(super) sync_queue: Database<Bytes, Bytes>,
    pub(super) attempt_records: Database<Bytes, Bytes>,
    pub(super) attempt_ready: Database<Bytes, Bytes>,
    pub(super) attempt_dedupe: Database<Bytes, Bytes>,
}

pub(super) fn create_dbs(
    env: &OwnedEnv,
    is_new_vault: bool,
    storage_abi_version: u16,
) -> Result<(MutexGuard<'static, ()>, RwTxn<'_>, CreatedDbs, OverlayDb)> {
    let db_open_guard = lmdb_database_open_guard()?;
    let mut wtxn = env.write_txn()?;
    let vault_meta = create_manifest_db(env, &mut wtxn, 4)?;
    let vault_meta_view = OverlayDb::canonical(vault_meta);
    gate_storage_versions(
        &vault_meta_view,
        &mut wtxn,
        is_new_vault,
        storage_abi_version,
    )?;
    if is_new_vault {
        // Pre-manifest bootstrap: the declared typed table owns these bytes,
        // but the Store/ManifestDbs door does not exist yet.
        vault_meta_view.put(
            &mut wtxn,
            crate::side_table::ORIGIN_LFS_CDC_SEED.prefix,
            &crate::origin::lfs::random_lfs_chunk_seed(),
        )?;
    }
    if !is_new_vault {
        validate_db_manifest_set(env, &wtxn)?;
    }

    let entities = create_manifest_db(env, &mut wtxn, 0)?;
    let type_index = create_manifest_db(env, &mut wtxn, 1)?;
    let short_ids = create_manifest_db(env, &mut wtxn, 2)?;
    let short_ids_reverse = create_manifest_db(env, &mut wtxn, 3)?;
    let vectors = create_manifest_db(env, &mut wtxn, 5)?;
    let hnsw_neighbors = create_manifest_db(env, &mut wtxn, 6)?;
    let hnsw_meta = create_manifest_db(env, &mut wtxn, 7)?;
    let text_postings = create_manifest_dupsort_db(env, &mut wtxn, 8)?;
    let text_meta = create_manifest_db(env, &mut wtxn, 9)?;
    let text_forward = create_manifest_db(env, &mut wtxn, 10)?;
    let text_bm25_field_stats = create_manifest_db(env, &mut wtxn, 11)?;
    let text_doc_field_lengths = create_manifest_db(env, &mut wtxn, 12)?;
    let edges_out = create_manifest_db(env, &mut wtxn, 13)?;
    let edges_in = create_manifest_db(env, &mut wtxn, 14)?;
    let ppr_cache = create_manifest_db(env, &mut wtxn, 15)?;
    let ppr_cache_deps = create_manifest_db(env, &mut wtxn, 16)?;
    let temporal_occurred_start = create_manifest_db(env, &mut wtxn, 17)?;
    let temporal_occurred_end = create_manifest_db(env, &mut wtxn, 18)?;
    let temporal_learned = create_manifest_db(env, &mut wtxn, 19)?;
    let temporal_long_intervals = create_manifest_db(env, &mut wtxn, 20)?;
    let phonetic_index = create_manifest_db(env, &mut wtxn, 21)?;
    let phonetic_forward = create_manifest_db(env, &mut wtxn, 22)?;
    let sync_state = create_manifest_str_db(env, &mut wtxn, 23)?;
    let sync_queue = create_manifest_db(env, &mut wtxn, 24)?;
    let attempt_records = create_manifest_db(env, &mut wtxn, 25)?;
    let attempt_ready = create_manifest_db(env, &mut wtxn, 26)?;
    let attempt_dedupe = create_manifest_db(env, &mut wtxn, 27)?;
    if is_new_vault {
        validate_db_manifest_set(env, &wtxn)?;
    }
    let dbs = CreatedDbs {
        entities,
        edges_out,
        edges_in,
        vectors,
        hnsw_neighbors,
        hnsw_meta,
        text_postings,
        text_meta,
        text_forward,
        text_bm25_field_stats,
        text_doc_field_lengths,
        vault_meta,
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
        sync_state,
        sync_queue,
        attempt_records,
        attempt_ready,
        attempt_dedupe,
    };
    Ok((db_open_guard, wtxn, dbs, vault_meta_view))
}
