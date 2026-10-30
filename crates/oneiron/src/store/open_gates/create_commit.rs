//! Create-door commit phase: build handles, re-key, seed and commit.

use std::sync::MutexGuard;

use heed::RwTxn;

#[cfg(test)]
use crate::error::Error;
use crate::error::Result;
use crate::overlay_db::OverlayDb;
#[cfg(test)]
use crate::store::test_hooks;
use crate::store::{RawDatabases, seed_default_policy_manifest_in_txn};

use super::create_dbs::CreatedDbs;
use super::manifest_storage_gates::{
    RegisteredPath, TornCreationCleanup, rekey_short_ids_if_needed_in_txn,
};
use super::open_version_keys::DefaultPolicySeedMode;

pub(super) fn create_commit(
    mut wtxn: RwTxn<'_>,
    db_open_guard: MutexGuard<'static, ()>,
    dbs: &CreatedDbs,
    vault_meta_view: &OverlayDb,
    registered_path: &RegisteredPath,
    is_new_vault: bool,
    seed_mode: DefaultPolicySeedMode,
    torn_creation_cleanup: &mut TornCreationCleanup,
) -> Result<RawDatabases> {
    let raw = RawDatabases {
        entities: dbs.entities,
        edges_out: dbs.edges_out,
        edges_in: dbs.edges_in,
        vectors: dbs.vectors,
        hnsw_neighbors: dbs.hnsw_neighbors,
        hnsw_meta: dbs.hnsw_meta,
        text_postings: dbs.text_postings,
        text_meta: dbs.text_meta,
        text_forward: dbs.text_forward,
        text_bm25_field_stats: dbs.text_bm25_field_stats,
        text_doc_field_lengths: dbs.text_doc_field_lengths,
        vault_meta: dbs.vault_meta,
        ppr_cache: dbs.ppr_cache,
        ppr_cache_deps: dbs.ppr_cache_deps,
        type_index: dbs.type_index,
        temporal_occurred_start: dbs.temporal_occurred_start,
        temporal_occurred_end: dbs.temporal_occurred_end,
        temporal_learned: dbs.temporal_learned,
        temporal_long_intervals: dbs.temporal_long_intervals,
        phonetic_index: dbs.phonetic_index,
        phonetic_forward: dbs.phonetic_forward,
        short_ids: dbs.short_ids,
        short_ids_reverse: dbs.short_ids_reverse,
        sync_state: dbs.sync_state,
        sync_queue: dbs.sync_queue,
        attempt_records: dbs.attempt_records,
        attempt_ready: dbs.attempt_ready,
        attempt_dedupe: dbs.attempt_dedupe,
    };

    // ONE-1930: the presentation-prefix re-key. Runs in THIS transaction;
    // this pass changes prefixes, never type bytes.
    rekey_short_ids_if_needed_in_txn(&raw, vault_meta_view, &mut wtxn)?;

    if is_new_vault && matches!(seed_mode, DefaultPolicySeedMode::Required) {
        let id = crate::gate::default_policy_manifest_id()?;
        let entities = OverlayDb::canonical(raw.entities);
        let type_index = OverlayDb::canonical(raw.type_index);
        let temporal_occurred_start = OverlayDb::canonical(raw.temporal_occurred_start);
        let temporal_learned = OverlayDb::canonical(raw.temporal_learned);
        seed_default_policy_manifest_in_txn(
            &entities,
            &crate::overlay_db::OverlayStrDb::canonical(raw.sync_state),
            &type_index,
            &temporal_occurred_start,
            &temporal_learned,
            &mut wtxn,
            &id,
        )?;
    }
    #[cfg(test)]
    if is_new_vault
        && matches!(seed_mode, DefaultPolicySeedMode::Required)
        && test_hooks::take_fail_initial_seed_commit_for(&registered_path.path)
    {
        return Err(Error::InvalidConfig(
            "test: initial seed transaction interrupted".to_owned(),
        ));
    }
    wtxn.commit()?;
    // The initial creation transaction is durable; later open failures
    // must preserve this committed vault.
    torn_creation_cleanup.disarm();
    drop(db_open_guard);
    Ok(raw)
}
