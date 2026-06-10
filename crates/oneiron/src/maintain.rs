use xxhash_rust::xxh32::xxh32;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, encode_short_id_forward_key, parse_short_id_value};
use crate::error::{Error, Result};
use crate::hnsw::{
    COUNT_KEY, build_hnsw_graph_from_snapshot, read_vector_version, write_rebuilt_hnsw,
};
use crate::types::{EntityId, parse_entity_id};
use crate::vault::write_text_index_manifest;
use crate::{Vault, le_bytes_to_f32_vec, ppr};

const ERR_VECTOR_KEY: &str = "vector key";
const ERR_SHORT_IDS_REVERSE_KEY: &str = "short_ids_reverse key";
const ERR_SHORT_IDS_FORWARD_VALUE: &str = "short_ids value";

struct PreparedHnswRebuild {
    old_count: u64,
    vector_version: u64,
    rebuilt: crate::hnsw::RebuiltHnswGraph,
    invalid_vectors_skipped: u64,
}

/// Builder for running maintenance operations against a vault.
#[must_use = "MaintenanceBuilder performs no work until `.run()` is called"]
pub struct MaintenanceBuilder<'a> {
    vault: &'a Vault,
    do_rebuild_hnsw: bool,
    heal_invalid_vectors_on_rebuild: bool,
    do_cleanup_ppr: bool,
    ppr_max_age_secs: u64,
    do_compact_postings: bool,
    do_recompute_hashes: bool,
    do_clear_text_index: bool,
}

/// Aggregate counters for maintenance operations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceReport {
    /// Nodes omitted from the rebuilt HNSW graph versus the previously committed count.
    ///
    /// In heal mode this can overlap with skipped invalid rows only when those rows
    /// were already present in the previously committed graph; consult
    /// `hnsw_invalid_vectors_skipped` for the explicit invalid-row breakdown, and do
    /// not assume the two counters are mutually inclusive.
    pub hnsw_dead_nodes_removed: u64,
    /// Live HNSW nodes after the rebuild commits.
    pub hnsw_live_nodes: u64,
    /// Invalid stored vector rows skipped only by heal-mode rebuilds.
    pub hnsw_invalid_vectors_skipped: u64,
    pub ppr_caches_evicted: u64,
    pub ppr_deps_cleaned: u64,
    pub postings_compacted: u64,
    /// Orphaned or stale short-id mappings removed from the forward/reverse indexes.
    pub orphan_short_ids_deleted: u64,
    pub short_id_hashes_updated: u64,
    /// Posting-list rows removed by `clear_text_index`.
    pub text_postings_removed: u64,
    /// `text_meta` rows removed by `clear_text_index`. Includes the
    /// `TOTAL_DOCS_KEY` / `TOTAL_LENGTH_KEY` sentinel rows; absence of those
    /// keys is read by `bm25::read_total_docs` as zero, so the deletion is
    /// equivalent to a rewrite-to-zero.
    pub text_meta_removed: u64,
    /// Forward-index rows removed by `clear_text_index`.
    pub text_forward_removed: u64,
    /// Per-field length rows removed by `clear_text_index`.
    pub text_doc_field_lengths_removed: u64,
    /// Per-field stats rows removed by `clear_text_index`.
    pub text_bm25_field_stats_removed: u64,
}

impl<'a> MaintenanceBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            do_rebuild_hnsw: false,
            heal_invalid_vectors_on_rebuild: false,
            do_cleanup_ppr: false,
            ppr_max_age_secs: 0,
            do_compact_postings: false,
            do_recompute_hashes: false,
            do_clear_text_index: false,
        }
    }

    pub fn rebuild_hnsw(mut self) -> Self {
        self.do_rebuild_hnsw = true;
        self.heal_invalid_vectors_on_rebuild = false;
        self
    }

    pub fn rebuild_hnsw_heal_invalid_vectors(mut self) -> Self {
        self.do_rebuild_hnsw = true;
        self.heal_invalid_vectors_on_rebuild = true;
        self
    }

    /// Evicts stale, malformed, dead-seed, and over-age PPR cache rows.
    ///
    /// `max_age_secs` is a HARD age bound, independent of the recency-tiered
    /// serve TTL (ARCH-0019 / ARCH-0014: Active 24 h · Recent 72 h ·
    /// Dormant 168 h, decided per read from the seed set's most recent
    /// `learned_at`). Whether a row may be SERVED is decided exclusively by
    /// the read-time gate; to never evict a row the tiered gate could still
    /// serve, pass at least the longest tier (168 h = 604 800 s).
    pub fn cleanup_ppr_cache(mut self, max_age_secs: u64) -> Self {
        self.do_cleanup_ppr = true;
        self.ppr_max_age_secs = max_age_secs;
        self
    }

    pub fn compact_postings(mut self) -> Self {
        self.do_compact_postings = true;
        self
    }

    pub fn recompute_short_id_hashes(mut self) -> Self {
        self.do_recompute_hashes = true;
        self
    }

    /// Drop every text-index row and rewrite the analyzer manifest from
    /// the currently-discovered dict set. Use after
    /// [`Error::IncompatibleAnalyzer`] or [`Error::Bm25FieldSchemaChanged`]
    /// to rebuild under the current analyzer. Leaves entities, vectors,
    /// edges, and PPR cache untouched — only text-index state is cleared.
    ///
    /// After `clear_text_index` commits, callers must re-run their
    /// indexing pipeline (`batch.text(...)`) to repopulate the index.
    ///
    /// [`Error::IncompatibleAnalyzer`]: crate::Error::IncompatibleAnalyzer
    /// [`Error::Bm25FieldSchemaChanged`]: crate::Error::Bm25FieldSchemaChanged
    pub fn clear_text_index(mut self) -> Self {
        self.do_clear_text_index = true;
        self
    }

    pub fn run(self) -> Result<MaintenanceReport> {
        let mut report = MaintenanceReport::default();

        if self.do_rebuild_hnsw {
            let (dead_removed, live_nodes, invalid_vectors_skipped) =
                rebuild_hnsw(self.vault, self.heal_invalid_vectors_on_rebuild)?;
            report.hnsw_dead_nodes_removed = dead_removed;
            report.hnsw_live_nodes = live_nodes;
            report.hnsw_invalid_vectors_skipped = invalid_vectors_skipped;
        }

        if self.do_cleanup_ppr {
            let (evicted, deps_cleaned) = cleanup_ppr_cache(self.vault, self.ppr_max_age_secs)?;
            report.ppr_caches_evicted = evicted;
            report.ppr_deps_cleaned = deps_cleaned;
        }

        if self.do_compact_postings {
            report.postings_compacted = compact_postings(self.vault)?;
        }

        if self.do_recompute_hashes {
            let (updated, deleted) = recompute_short_id_hashes(self.vault)?;
            report.short_id_hashes_updated = updated;
            report.orphan_short_ids_deleted = deleted;
        }

        if self.do_clear_text_index {
            let counts = clear_text_index(self.vault)?;
            report.text_postings_removed = counts.postings;
            report.text_meta_removed = counts.meta;
            report.text_forward_removed = counts.forward;
            report.text_doc_field_lengths_removed = counts.doc_field_lengths;
            report.text_bm25_field_stats_removed = counts.field_stats;
        }

        Ok(report)
    }
}

struct ClearTextIndexCounts {
    postings: u64,
    meta: u64,
    forward: u64,
    doc_field_lengths: u64,
    field_stats: u64,
}

fn clear_text_index(vault: &Vault) -> Result<ClearTextIndexCounts> {
    let mut wtxn = vault.store.env.write_txn()?;

    let postings = vault.store.text_postings.len(&wtxn)?;
    vault.store.text_postings.clear(&mut wtxn)?;

    let meta = vault.store.text_meta.len(&wtxn)?;
    vault.store.text_meta.clear(&mut wtxn)?;

    let forward = vault.store.text_forward.len(&wtxn)?;
    vault.store.text_forward.clear(&mut wtxn)?;

    let doc_field_lengths = vault.store.text_doc_field_lengths.len(&wtxn)?;
    vault.store.text_doc_field_lengths.clear(&mut wtxn)?;

    let field_stats = vault.store.text_bm25_field_stats.len(&wtxn)?;
    vault.store.text_bm25_field_stats.clear(&mut wtxn)?;

    write_text_index_manifest(&vault.store, &mut wtxn, &vault.analyzer)?;

    wtxn.commit()?;

    // The on-disk manifest now matches the in-memory analyzer; subsequent
    // search_text calls within the same Vault instance can proceed. See
    // `Vault::text_index_trusted`.
    vault
        .text_index_trusted
        .store(true, std::sync::atomic::Ordering::Release);

    Ok(ClearTextIndexCounts {
        postings,
        meta,
        forward,
        doc_field_lengths,
        field_stats,
    })
}

fn rebuild_hnsw(vault: &Vault, heal_invalid_vectors: bool) -> Result<(u64, u64, u64)> {
    let prepared = prepare_rebuild_hnsw(vault, heal_invalid_vectors)?;

    commit_rebuilt_hnsw(vault, &prepared.rebuilt, prepared.vector_version)?;

    let live_nodes = prepared.rebuilt.count;
    let invalid_vectors_skipped = prepared.invalid_vectors_skipped;
    let dead_nodes_removed = prepared.old_count.saturating_sub(live_nodes);
    Ok((dead_nodes_removed, live_nodes, invalid_vectors_skipped))
}

fn cleanup_ppr_cache(vault: &Vault, max_age_secs: u64) -> Result<(u64, u64)> {
    let mut wtxn = vault.store.env.write_txn()?;
    let now = crate::unix_seconds_now();
    let counts = ppr::cleanup_ppr_cache(&vault.store, &mut wtxn, max_age_secs, now)?;
    wtxn.commit()?;
    Ok(counts)
}

fn compact_postings(vault: &Vault) -> Result<u64> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut keys_to_delete = Vec::new();
    for entry in vault.store.text_postings.iter(&wtxn)? {
        let (term, postings) = entry?;
        if postings.is_empty() {
            keys_to_delete.push(term.to_vec());
        }
    }

    for term in &keys_to_delete {
        vault.store.text_postings.delete(&mut wtxn, term)?;
    }

    wtxn.commit()?;
    Ok(keys_to_delete.len() as u64)
}

/// Recomputes short-id content hashes and reaps orphaned/stale mappings under
/// the pinned ARCH-0019 directions: `short_ids_reverse` (entity id ->
/// `short_id ‖ content_hash`) is the entity-keyed source of truth; `short_ids`
/// (`short_id ‖ content_hash` -> entity id) is repaired or pruned from it.
fn recompute_short_id_hashes(vault: &Vault) -> Result<(u64, u64)> {
    let mut wtxn = vault.store.env.write_txn()?;

    struct ShortIdHashUpdate {
        reverse_key: Vec<u8>,
        updated_value: Vec<u8>,
        old_forward_key: Vec<u8>,
        new_forward_key: Vec<u8>,
    }

    // Pass 1: walk the entity-keyed reverse rows. Refresh drifted content
    // hashes (rewriting BOTH rows — the hash is part of the forward KEY),
    // repair missing/stale forward rows, and reap rows whose backing entity
    // record is gone or whose bytes are corrupt.
    let mut hash_updates: Vec<ShortIdHashUpdate> = Vec::new();
    // (forward key, entity id) rows to (re)write.
    let mut forward_repairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    // (reverse key, paired forward key when recoverable) rows to reap.
    let mut reverse_orphans: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();

    for entry in vault.store.short_ids_reverse.iter(&wtxn)? {
        let (key, value) = entry?;

        let id = match parse_entity_id(key, ERR_SHORT_IDS_REVERSE_KEY) {
            Ok(id) => id,
            // `parse_entity_id` returns `CorruptedIndex` on length mismatch
            // and `InvalidKey` for reserved sentinel patterns. Both are
            // corrupt reverse rows that must be pruned, not propagated.
            Err(Error::CorruptedIndex(_)) | Err(Error::InvalidKey) => {
                let forward_key = parse_short_id_value(value)
                    .ok()
                    .map(|(short_id, hash)| encode_short_id_forward_key(short_id, hash));
                reverse_orphans.push((key.to_vec(), forward_key));
                continue;
            }
            Err(other) => return Err(other),
        };

        let (short_id, current_hash) = match parse_short_id_value(value) {
            Ok(parsed) => parsed,
            Err(Error::CorruptedIndex(_)) => {
                reverse_orphans.push((key.to_vec(), None));
                continue;
            }
            Err(other) => return Err(other),
        };
        let current_forward_key = encode_short_id_forward_key(short_id, current_hash);

        let Some(blob) = vault.store.entities.get(&wtxn, id.as_bytes())? else {
            reverse_orphans.push((key.to_vec(), Some(current_forward_key)));
            continue;
        };

        if blob.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::InvalidKey);
        }

        let payload = &blob[ENTITY_METADATA_HEADER_LEN..];
        let new_hash = (xxh32(payload, 0) % 256) as u8;
        if new_hash != current_hash {
            let mut updated_value = Vec::with_capacity(short_id.len() + 1);
            updated_value.extend_from_slice(short_id.as_bytes());
            updated_value.push(new_hash);
            let new_forward_key = encode_short_id_forward_key(short_id, new_hash);
            hash_updates.push(ShortIdHashUpdate {
                reverse_key: key.to_vec(),
                updated_value,
                old_forward_key: current_forward_key,
                new_forward_key,
            });
            continue;
        }

        match vault.store.short_ids.get(&wtxn, &current_forward_key)? {
            Some(forward_id) if forward_id == key => {}
            _ => forward_repairs.push((current_forward_key, key.to_vec())),
        }
    }

    for update in &hash_updates {
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, &update.reverse_key, &update.updated_value)?;
        vault
            .store
            .short_ids
            .delete(&mut wtxn, &update.old_forward_key)?;
        vault
            .store
            .short_ids
            .put(&mut wtxn, &update.new_forward_key, &update.reverse_key)?;
    }
    for (forward_key, id) in &forward_repairs {
        vault.store.short_ids.put(&mut wtxn, forward_key, id)?;
    }
    for (reverse_key, forward_key) in &reverse_orphans {
        if let Some(forward_key) = forward_key {
            vault.store.short_ids.delete(&mut wtxn, forward_key)?;
        }
        vault
            .store
            .short_ids_reverse
            .delete(&mut wtxn, reverse_key)?;
    }

    // Pass 2: forward rows without a healthy reverse counterpart are orphans.
    // Runs after pass-1 writes so repaired/refreshed rows are not re-pruned.
    let mut forward_orphans = Vec::new();
    for entry in vault.store.short_ids.iter(&wtxn)? {
        let (key, value) = entry?;

        // The forward KEY shares the `(short_id ‖ content_hash)` shape with
        // the reverse VALUE; an unparsable key is a corrupt row to prune.
        if parse_short_id_value(key).is_err() {
            forward_orphans.push(key.to_vec());
            continue;
        }

        let id = match parse_entity_id(value, ERR_SHORT_IDS_FORWARD_VALUE) {
            Ok(id) => id,
            Err(Error::CorruptedIndex(_)) | Err(Error::InvalidKey) => {
                forward_orphans.push(key.to_vec());
                continue;
            }
            Err(other) => return Err(other),
        };

        match vault.store.short_ids_reverse.get(&wtxn, id.as_bytes())? {
            Some(reverse_value) if reverse_value == key => {}
            _ => forward_orphans.push(key.to_vec()),
        }
    }
    for forward_key in &forward_orphans {
        vault.store.short_ids.delete(&mut wtxn, forward_key)?;
    }

    wtxn.commit()?;
    Ok((
        hash_updates.len() as u64,
        (reverse_orphans.len() + forward_orphans.len()) as u64,
    ))
}

fn prepare_rebuild_hnsw(vault: &Vault, heal_invalid_vectors: bool) -> Result<PreparedHnswRebuild> {
    let rtxn = vault.store.env.read_txn()?;
    let old_count = decode_u64_opt(vault.store.hnsw_meta.get(&rtxn, COUNT_KEY)?)?.unwrap_or(0);
    let vector_version = read_vector_version(&vault.store, &rtxn)?;
    let mut vector_ids = Vec::<EntityId>::with_capacity(old_count.min(1_000_000) as usize);
    let mut invalid_vectors_skipped = 0_u64;

    for entry in vault.store.vectors.iter(&rtxn)? {
        let (id_bytes, vector_bytes) = entry?;
        let validation = validate_rebuild_vector(vault, id_bytes, vector_bytes);
        match validation {
            Ok(id) => vector_ids.push(id),
            Err(error) if heal_invalid_vectors && is_healable_rebuild_error(&error) => {
                invalid_vectors_skipped += 1;
            }
            Err(error) => return Err(error),
        }
    }

    let rebuilt = build_hnsw_graph_from_snapshot(&vault.store, &vault.config, &rtxn, &vector_ids)?;
    drop(rtxn);

    Ok(PreparedHnswRebuild {
        old_count,
        vector_version,
        rebuilt,
        invalid_vectors_skipped,
    })
}

fn validate_rebuild_vector(
    vault: &Vault,
    id_bytes: &[u8],
    vector_bytes: &[u8],
) -> Result<EntityId> {
    let id = parse_entity_id(id_bytes, ERR_VECTOR_KEY)?;
    let vector = le_bytes_to_f32_vec(vector_bytes)?;
    if vector.len() != vault.config.dimensions {
        return Err(Error::DimensionMismatch {
            expected: vault.config.dimensions,
            got: vector.len(),
        });
    }
    if let Some(error) = Error::invalid_vector_component(&vector) {
        return Err(error);
    }
    Ok(id)
}

fn is_healable_rebuild_error(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidKey
            | Error::InvalidVector { .. }
            | Error::DimensionMismatch { .. }
            | Error::CorruptedIndex(_)
    )
}

fn commit_rebuilt_hnsw(
    vault: &Vault,
    rebuilt: &crate::hnsw::RebuiltHnswGraph,
    expected_vector_version: u64,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let current_vector_version = read_vector_version(&vault.store, &wtxn)?;
    if current_vector_version != expected_vector_version {
        return Err(Error::ConcurrentWrite(
            "vectors changed during hnsw rebuild; retry maintenance",
        ));
    }
    write_rebuilt_hnsw(&vault.store, &mut wtxn, rebuilt)?;
    wtxn.commit()?;
    Ok(())
}

fn decode_u64_opt(raw: Option<&[u8]>) -> Result<Option<u64>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let bytes: [u8; 8] = raw.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(Some(u64::from_le_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use heed::types::Bytes;

    use super::*;
    use crate::store::{
        GRAPH_VERSION_KEY, MODEL_ID_KEY, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY,
        VECTOR_VERSION_KEY,
    };
    use crate::types::{ENTITY_ID_LEN, EdgeKind, HnswConfig, TimeRange, VaultConfig};

    fn test_config() -> VaultConfig {
        VaultConfig {
            map_size: 32 * 1024 * 1024,
            dimensions: 4,
            embedding_model: Some("test-model-v1".to_owned()),
            max_readers: 16,
            hnsw: HnswConfig {
                m_max_0: 64,
                ef_construction: 200,
                ef_search: 128,
            },
            text_analyzer: crate::types::TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            skip_text_index_manifest_check: false,
        }
    }

    fn test_time_range(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes_unchecked([byte; ENTITY_ID_LEN])
    }

    fn read_u64_meta(vault: &Vault, key: &[u8]) -> Result<u64> {
        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .hnsw_meta
            .get(&rtxn, key)?
            .ok_or(Error::EntityNotFound)?;
        let value = u64::from_le_bytes(raw.try_into().map_err(|_| Error::InvalidKey)?);
        Ok(value)
    }

    fn count_entries(db: &heed::Database<Bytes, Bytes>, vault: &Vault) -> Result<usize> {
        let rtxn = vault.store.env.read_txn()?;
        let mut count = 0;
        for entry in db.iter(&rtxn)? {
            entry?;
            count += 1;
        }
        Ok(count)
    }

    fn read_neighbor_bytes(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .hnsw_neighbors
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        Ok(raw.to_vec())
    }

    #[test]
    fn rebuild_hnsw_removes_dead_nodes() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let mut ids = Vec::new();

        for i in 0..50_u8 {
            let id = entity(i.saturating_add(1));
            ids.push(id);
            vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, i as f32])?;
        }

        {
            let mut wtxn = vault.store.env.write_txn()?;
            for id in ids.iter().take(15) {
                vault.store.vectors.delete(&mut wtxn, id.as_bytes())?;
            }
            wtxn.commit()?;
        }

        let report = vault.maintain().rebuild_hnsw().run()?;
        assert_eq!(report.hnsw_dead_nodes_removed, 15);
        assert_eq!(report.hnsw_live_nodes, 35);

        let count = read_u64_meta(&vault, COUNT_KEY)?;
        assert_eq!(count, 35);
        Ok(())
    }

    /// `rebuild_hnsw` must not touch unrelated `hnsw_meta` rows. Each variant
    /// seeds a different key and confirms its value survives the rebuild.
    ///
    /// Variants:
    /// - `graph_version`: `GRAPH_VERSION_KEY` is bumped by edge writes, then
    ///   the rebuild's `u64` value must match the pre-rebuild snapshot.
    /// - `long_interval_schema_version`: raw bytes at
    ///   `TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY` must match.
    /// - `model_id_when_config_matches`: closing the vault and reopening with
    ///   the same `embedding_model` must leave `MODEL_ID_KEY` untouched
    ///   (still `"test-model-v1"`).
    /// - `unrelated_hnsw_meta`: a custom key `b"custom-meta" -> b"keep-me"`
    ///   must not be scrubbed.
    #[test]
    fn rebuild_hnsw_preserves_unrelated_meta() -> Result<()> {
        // graph_version
        {
            let temp_dir = tempfile::tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let a = entity(80);
            let b = entity(81);

            vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
            let before = read_u64_meta(&vault, GRAPH_VERSION_KEY)?;

            let report = vault.maintain().rebuild_hnsw().run()?;
            assert_eq!(
                report.hnsw_dead_nodes_removed, 0,
                "case graph_version: unexpected dead nodes removed"
            );

            let after = read_u64_meta(&vault, GRAPH_VERSION_KEY)?;
            assert_eq!(
                before, after,
                "case graph_version: GRAPH_VERSION_KEY changed by rebuild"
            );
        }

        // long_interval_schema_version
        {
            let temp_dir = tempfile::tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;

            let before = {
                let rtxn = vault.store.env.read_txn()?;
                vault
                    .store
                    .hnsw_meta
                    .get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?
                    .ok_or(Error::EntityNotFound)?
                    .to_vec()
            };

            vault.maintain().rebuild_hnsw().run()?;

            let after = {
                let rtxn = vault.store.env.read_txn()?;
                vault
                    .store
                    .hnsw_meta
                    .get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?
                    .ok_or(Error::EntityNotFound)?
                    .to_vec()
            };
            assert_eq!(
                before, after,
                "case long_interval_schema_version: schema version changed"
            );
        }

        // model_id_when_config_matches
        {
            let temp_dir = tempfile::tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;

            let id = entity(84);
            vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;
            drop(vault);

            let vault = Vault::open(temp_dir.path(), test_config())?;

            vault.maintain().rebuild_hnsw().run()?;

            let rtxn = vault.store.env.read_txn()?;
            let stored = vault.store.hnsw_meta.get(&rtxn, MODEL_ID_KEY)?;
            assert_eq!(
                stored,
                Some(b"test-model-v1".as_slice()),
                "case model_id_when_config_matches: MODEL_ID_KEY changed"
            );
        }

        // unrelated_hnsw_meta
        {
            let temp_dir = tempfile::tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = entity(85);

            vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            {
                let mut wtxn = vault.store.env.write_txn()?;
                vault
                    .store
                    .hnsw_meta
                    .put(&mut wtxn, b"custom-meta", b"keep-me")?;
                wtxn.commit()?;
            }

            vault.maintain().rebuild_hnsw().run()?;

            let rtxn = vault.store.env.read_txn()?;
            let custom_meta = vault.store.hnsw_meta.get(&rtxn, b"custom-meta")?;
            assert_eq!(
                custom_meta,
                Some(b"keep-me".as_slice()),
                "case unrelated_hnsw_meta: custom row scrubbed"
            );
        }

        Ok(())
    }

    #[test]
    fn rebuild_hnsw_strict_preserves_committed_graph_on_invalid_vector() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(86);
        let b = entity(87);

        for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
            vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
            vault.put_vector(&id, &vector)?;
        }

        let count_before = read_u64_meta(&vault, COUNT_KEY)?;
        let neighbors_before = read_neighbor_bytes(&vault, &a)?;

        {
            let mut invalid = Vec::new();
            invalid.extend_from_slice(&1.0_f32.to_le_bytes());
            invalid.extend_from_slice(&2.0_f32.to_le_bytes());
            invalid.extend_from_slice(&3.0_f32.to_le_bytes());

            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.vectors.put(&mut wtxn, b.as_bytes(), &invalid)?;
            wtxn.commit()?;
        }

        let err = vault.maintain().rebuild_hnsw().run().unwrap_err();
        assert!(matches!(
            err,
            Error::DimensionMismatch {
                expected: 4,
                got: 3,
            }
        ));

        let count_after = read_u64_meta(&vault, COUNT_KEY)?;
        let neighbors_after = read_neighbor_bytes(&vault, &a)?;
        assert_eq!(count_before, count_after);
        assert_eq!(neighbors_before, neighbors_after);
        assert_eq!(count_entries(&vault.store.hnsw_neighbors, &vault)?, 2);
        Ok(())
    }

    #[test]
    fn rebuild_hnsw_rejects_stale_vector_snapshot() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(94);
        let b = entity(95);

        for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
            vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
            vault.put_vector(&id, &vector)?;
        }

        let count_before = read_u64_meta(&vault, COUNT_KEY)?;
        let vector_version_before = read_u64_meta(&vault, VECTOR_VERSION_KEY)?;
        let neighbors_before = read_neighbor_bytes(&vault, &a)?;

        let prepared = prepare_rebuild_hnsw(&vault, false)?;
        assert_eq!(prepared.vector_version, vector_version_before);
        assert_eq!(prepared.invalid_vectors_skipped, 0);

        vault.put_vector(&b, &[0.0, 0.5, 0.5, 0.0])?;

        let err =
            commit_rebuilt_hnsw(&vault, &prepared.rebuilt, prepared.vector_version).unwrap_err();
        assert!(matches!(
            err,
            Error::ConcurrentWrite("vectors changed during hnsw rebuild; retry maintenance")
        ));

        let count_after = read_u64_meta(&vault, COUNT_KEY)?;
        let vector_version_after = read_u64_meta(&vault, VECTOR_VERSION_KEY)?;
        let neighbors_after = read_neighbor_bytes(&vault, &a)?;
        assert_eq!(count_before, count_after);
        assert_eq!(neighbors_before, neighbors_after);
        assert!(vector_version_after > vector_version_before);
        assert_eq!(count_entries(&vault.store.hnsw_neighbors, &vault)?, 2);
        Ok(())
    }

    #[test]
    fn rebuild_hnsw_heal_invalid_vectors_skips_bad_rows() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(88);
        let b = entity(89);

        for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
            vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
            vault.put_vector(&id, &vector)?;
        }

        {
            let mut invalid = Vec::new();
            invalid.extend_from_slice(&1.0_f32.to_le_bytes());
            invalid.extend_from_slice(&2.0_f32.to_le_bytes());
            invalid.extend_from_slice(&3.0_f32.to_le_bytes());

            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.vectors.put(&mut wtxn, b.as_bytes(), &invalid)?;
            wtxn.commit()?;
        }

        let report = vault.maintain().rebuild_hnsw_heal_invalid_vectors().run()?;
        assert_eq!(report.hnsw_invalid_vectors_skipped, 1);
        assert_eq!(report.hnsw_live_nodes, 1);
        assert_eq!(report.hnsw_dead_nodes_removed, 1);

        let count = read_u64_meta(&vault, COUNT_KEY)?;
        assert_eq!(count, 1);

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .hnsw_neighbors
                .get(&rtxn, b.as_bytes())?
                .is_none()
        );
        assert!(vault.store.vectors.get(&rtxn, b.as_bytes())?.is_some());
        Ok(())
    }

    #[test]
    fn rebuild_hnsw_builder_modes_are_last_call_wins() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(96);
        let b = entity(97);

        for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
            vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
            vault.put_vector(&id, &vector)?;
        }

        {
            let mut invalid = Vec::new();
            invalid.extend_from_slice(&1.0_f32.to_le_bytes());
            invalid.extend_from_slice(&2.0_f32.to_le_bytes());
            invalid.extend_from_slice(&3.0_f32.to_le_bytes());

            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.vectors.put(&mut wtxn, b.as_bytes(), &invalid)?;
            wtxn.commit()?;
        }

        let err = vault
            .maintain()
            .rebuild_hnsw_heal_invalid_vectors()
            .rebuild_hnsw()
            .run()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::DimensionMismatch {
                expected: 4,
                got: 3,
            }
        ));
        Ok(())
    }

    #[test]
    fn build_hnsw_graph_from_snapshot_rejects_missing_entry_point_vector() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(98);
        let b = entity(99);

        for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
            vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
            vault.put_vector(&id, &vector)?;
        }

        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.vectors.delete(&mut wtxn, a.as_bytes())?;
            wtxn.commit()?;
        }

        let rtxn = vault.store.env.read_txn()?;
        let err = build_hnsw_graph_from_snapshot(&vault.store, &vault.config, &rtxn, &[a, b])
            .unwrap_err();
        assert!(matches!(
            err,
            Error::InvariantViolation(
                "validated rebuild vector disappeared within the same read snapshot"
            )
        ));
        Ok(())
    }

    #[test]
    fn cleanup_ppr_cache_evicts_stale_and_expired() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(82);
        let b = entity(83);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let _ = vault.query().search_ppr(&[a], 3).limit(10).run()?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.2)?;

        let report = vault.maintain().cleanup_ppr_cache(0).run()?;
        assert!(report.ppr_caches_evicted > 0);
        assert!(report.ppr_deps_cleaned > 0);

        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 0);
        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 0);
        Ok(())
    }

    #[test]
    fn compact_postings_removes_empty_lists() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.text_postings.put(&mut wtxn, b"empty-a", &[])?;
            vault.store.text_postings.put(&mut wtxn, b"empty-b", &[])?;
            vault
                .store
                .text_postings
                .put(&mut wtxn, b"keep", &[1, 2, 3])?;
            wtxn.commit()?;
        }

        let report = vault.maintain().compact_postings().run()?;
        assert_eq!(report.postings_compacted, 2);

        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.text_postings.get(&rtxn, b"empty-a")?.is_none());
        assert!(vault.store.text_postings.get(&rtxn, b"empty-b")?.is_none());
        assert!(vault.store.text_postings.get(&rtxn, b"keep")?.is_some());
        Ok(())
    }

    #[test]
    fn recompute_short_id_hashes_updates_stale() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = entity(84);

        vault
            .batch()
            .put(&id, 1, test_time_range(100, 100), 101, b"initial-payload")
            .commit()?;

        let (short_id_before, hash_before) = {
            let rtxn = vault.store.env.read_txn()?;
            let value = vault
                .store
                .short_ids_reverse
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let (short_id, hash) = parse_short_id_value(value)?;
            (short_id.to_owned(), hash)
        };

        let mut new_payload = b"updated-payload".to_vec();
        while ((xxh32(&new_payload, 0) % 256) as u8) == hash_before {
            new_payload.push(0);
        }

        {
            let mut wtxn = vault.store.env.write_txn()?;
            let record = vault
                .store
                .entities
                .get(&wtxn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let mut updated = record[..ENTITY_METADATA_HEADER_LEN].to_vec();
            updated.extend_from_slice(&new_payload);
            vault
                .store
                .entities
                .put(&mut wtxn, id.as_bytes(), &updated)?;
            wtxn.commit()?;
        }

        let report = vault.maintain().recompute_short_id_hashes().run()?;
        assert_eq!(report.short_id_hashes_updated, 1);
        assert_eq!(report.orphan_short_ids_deleted, 0);

        let new_hash = (xxh32(&new_payload, 0) % 256) as u8;
        let rtxn = vault.store.env.read_txn()?;
        let updated_value = vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (short_id_after, hash_after) = parse_short_id_value(updated_value)?;
        assert_eq!(short_id_after, short_id_before);
        assert_eq!(hash_after, new_hash);

        // The hash is part of the forward KEY: the stale forward row must be
        // gone and the refreshed one must point back at the entity.
        let stale_forward_key = encode_short_id_forward_key(&short_id_before, hash_before);
        let fresh_forward_key = encode_short_id_forward_key(&short_id_before, new_hash);
        assert!(
            vault
                .store
                .short_ids
                .get(&rtxn, &stale_forward_key)?
                .is_none(),
            "stale forward row must be reaped on hash refresh"
        );
        assert_eq!(
            vault.store.short_ids.get(&rtxn, &fresh_forward_key)?,
            Some(id.as_bytes().as_slice())
        );
        Ok(())
    }

    /// `recompute_short_id_hashes` must reap orphans from both directions.
    /// Each case mutates the vault, runs the maintenance pass, and verifies the
    /// orphan row(s) are gone.
    ///
    /// Cases (pinned ARCH-0019 directions — `short_ids_reverse` is keyed by
    /// entity id, `short_ids` by `(short_id ‖ content_hash)`):
    /// - `entity_row_deleted`: the entity-keyed `short_ids_reverse[id]` row
    ///   exists but its backing `entities[id]` row is gone — both the reverse
    ///   row and the paired forward row must be reaped.
    /// - `reverse_row_deleted`: only the entity-keyed `short_ids_reverse[id]`
    ///   row is gone, leaving a forward-only orphan — the forward
    ///   `short_ids[(short_id ‖ hash)]` row must be reaped.
    /// - `corrupt_forward_value`: a bogus forward row whose VALUE matches a
    ///   reserved sentinel pattern (`[0xFF; 16]`). `parse_entity_id` returns
    ///   `Error::InvalidKey`, which the forward-scan pass must treat as a
    ///   corrupt row and prune — *not* propagate as an error.
    #[test]
    fn recompute_short_id_hashes_removes_orphans() -> Result<()> {
        /// What the case mutates after the legit entity has been committed.
        /// May return a follow-up forward key whose row should be checked
        /// post-recompute instead of the legit forward key.
        type Mutation = fn(&Vault, &EntityId) -> Result<Option<Vec<u8>>>;

        struct Case {
            name: &'static str,
            mutate: Mutation,
            /// Whether the legit entity-keyed `short_ids_reverse[id]` row
            /// should be reaped.
            expect_reverse_gone: bool,
        }

        fn delete_entity_row(vault: &Vault, id: &EntityId) -> Result<Option<Vec<u8>>> {
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.entities.delete(&mut wtxn, id.as_bytes())?;
            wtxn.commit()?;
            Ok(None)
        }
        fn delete_reverse_row(vault: &Vault, id: &EntityId) -> Result<Option<Vec<u8>>> {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .short_ids_reverse
                .delete(&mut wtxn, id.as_bytes())?;
            wtxn.commit()?;
            Ok(None)
        }
        /// Writes a `short_ids[(bogus short_id ‖ hash)] = [0xFF; 16]` forward
        /// row. `[0xFF; 16]` is a reserved sentinel pattern (see
        /// `is_reserved_entity_id_bytes` in `types.rs`), so `parse_entity_id`
        /// returns `Error::InvalidKey`. The forward-scan in
        /// `recompute_short_id_hashes` must treat that row as corrupt and
        /// prune it, not propagate the error.
        fn inject_corrupt_forward_value(vault: &Vault, _id: &EntityId) -> Result<Option<Vec<u8>>> {
            // `cl-bogus99` is a synthetic short_id that won't collide with
            // the legit row (counter-issued `cl1`).
            let bogus_forward_key = encode_short_id_forward_key("cl-bogus99", 7);
            let sentinel_value = [0xFF_u8; ENTITY_ID_LEN];
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .short_ids
                .put(&mut wtxn, &bogus_forward_key, &sentinel_value)?;
            wtxn.commit()?;
            Ok(Some(bogus_forward_key))
        }

        let cases: Vec<Case> = vec![
            Case {
                name: "entity_row_deleted",
                mutate: delete_entity_row,
                expect_reverse_gone: true,
            },
            Case {
                name: "reverse_row_deleted",
                mutate: delete_reverse_row,
                expect_reverse_gone: true,
            },
            Case {
                name: "corrupt_forward_value",
                mutate: inject_corrupt_forward_value,
                // Legit reverse row stays untouched.
                expect_reverse_gone: false,
            },
        ];

        for case in cases {
            let case_name = case.name;
            let temp_dir = tempfile::tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = entity(93);

            vault
                .batch()
                .put(&id, 1, test_time_range(100, 100), 101, b"payload")
                .commit()?;

            let legit_forward_key = {
                let rtxn = vault.store.env.read_txn()?;
                let value = vault
                    .store
                    .short_ids_reverse
                    .get(&rtxn, id.as_bytes())?
                    .ok_or(Error::EntityNotFound)?;
                value.to_vec()
            };

            let mutator_forward_key = (case.mutate)(&vault, &id)?;

            let report = vault.maintain().recompute_short_id_hashes().run()?;
            assert_eq!(
                report.short_id_hashes_updated, 0,
                "case {case_name}: unexpected hash updates"
            );
            assert_eq!(
                report.orphan_short_ids_deleted, 1,
                "case {case_name}: expected exactly 1 orphan reaped"
            );

            let rtxn = vault.store.env.read_txn()?;
            if case.expect_reverse_gone {
                assert!(
                    vault
                        .store
                        .short_ids_reverse
                        .get(&rtxn, id.as_bytes())?
                        .is_none(),
                    "case {case_name}: entity-keyed short_ids_reverse row should be reaped"
                );
            }
            // Pick the forward key to check: mutator return > legit.
            let forward_key: Vec<u8> = mutator_forward_key
                .clone()
                .unwrap_or_else(|| legit_forward_key.clone());
            assert!(
                vault.store.short_ids.get(&rtxn, &forward_key)?.is_none(),
                "case {case_name}: orphaned forward short_ids row should be reaped"
            );
            if !case.expect_reverse_gone {
                assert_eq!(
                    vault.store.short_ids.get(&rtxn, &legit_forward_key)?,
                    Some(id.as_bytes().as_slice()),
                    "case {case_name}: legit forward row must survive"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn recompute_short_id_hashes_repairs_missing_forward_mapping() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = entity(99);

        vault
            .batch()
            .put(&id, 1, test_time_range(100, 100), 101, b"payload")
            .commit()?;

        let forward_key = {
            let rtxn = vault.store.env.read_txn()?;
            vault
                .store
                .short_ids_reverse
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?
                .to_vec()
        };

        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.short_ids.delete(&mut wtxn, &forward_key)?;
            wtxn.commit()?;
        }

        let report = vault.maintain().recompute_short_id_hashes().run()?;
        assert_eq!(report.short_id_hashes_updated, 0);
        assert_eq!(report.orphan_short_ids_deleted, 0);

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault.store.short_ids.get(&rtxn, &forward_key)?,
            Some(id.as_bytes().as_slice())
        );
        Ok(())
    }

    #[test]
    fn recompute_short_id_hashes_repairs_stale_forward_mapping() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = entity(100);
        let wrong_id = entity(101);

        vault
            .batch()
            .put(&id, 1, test_time_range(100, 100), 101, b"payload")
            .commit()?;

        let forward_key = {
            let rtxn = vault.store.env.read_txn()?;
            vault
                .store
                .short_ids_reverse
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?
                .to_vec()
        };

        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .short_ids
                .put(&mut wtxn, &forward_key, wrong_id.as_bytes())?;
            wtxn.commit()?;
        }

        vault.maintain().recompute_short_id_hashes().run()?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault.store.short_ids.get(&rtxn, &forward_key)?,
            Some(id.as_bytes().as_slice())
        );
        Ok(())
    }

    #[test]
    fn recompute_short_id_hashes_processes_custom_ids_near_sentinel_pattern() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let mut raw = [0xFF; ENTITY_ID_LEN];
        raw[0] = 0xFE;
        let id = EntityId::from_bytes(raw)?;

        vault
            .batch()
            .put(&id, 1, test_time_range(100, 100), 101, b"initial-payload")
            .commit()?;

        let hash_before = {
            let rtxn = vault.store.env.read_txn()?;
            let value = vault
                .store
                .short_ids_reverse
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let (_, hash) = parse_short_id_value(value)?;
            hash
        };

        let mut new_payload = b"updated-payload".to_vec();
        while ((xxh32(&new_payload, 0) % 256) as u8) == hash_before {
            new_payload.push(0);
        }

        {
            let mut wtxn = vault.store.env.write_txn()?;
            let record = vault
                .store
                .entities
                .get(&wtxn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let mut updated = record[..ENTITY_METADATA_HEADER_LEN].to_vec();
            updated.extend_from_slice(&new_payload);
            vault
                .store
                .entities
                .put(&mut wtxn, id.as_bytes(), &updated)?;
            wtxn.commit()?;
        }

        let report = vault.maintain().recompute_short_id_hashes().run()?;
        assert_eq!(report.short_id_hashes_updated, 1);
        assert_eq!(report.orphan_short_ids_deleted, 0);
        Ok(())
    }

    #[test]
    fn recompute_short_id_hashes_prunes_corrupt_reverse_rows() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = entity(102);

        vault
            .batch()
            .put(&id, 1, test_time_range(100, 100), 101, b"payload")
            .commit()?;

        // `short_ids_reverse` is keyed by 16-byte entity ids; an 8-byte
        // `b"deadbeef"` key is a corrupt row the reverse scan must prune
        // (not propagate as an error).
        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .short_ids_reverse
                .put(&mut wtxn, b"deadbeef", &[0xFF; ENTITY_ID_LEN])?;
            wtxn.commit()?;
        }

        let report = vault.maintain().recompute_short_id_hashes().run()?;
        assert_eq!(report.orphan_short_ids_deleted, 1);

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .short_ids_reverse
                .get(&rtxn, b"deadbeef")?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn rebuild_hnsw_heal_invalid_vectors_skips_reserved_id_rows() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let live = entity(103);

        vault.put_entity(&live, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&live, &[1.0, 0.0, 0.0, 0.0])?;

        {
            let mut wtxn = vault.store.env.write_txn()?;
            let valid_vector = [
                1.0_f32.to_le_bytes(),
                0.0_f32.to_le_bytes(),
                0.0_f32.to_le_bytes(),
                0.0_f32.to_le_bytes(),
            ]
            .concat();
            vault
                .store
                .vectors
                .put(&mut wtxn, &[0xFF; ENTITY_ID_LEN], &valid_vector)?;
            wtxn.commit()?;
        }

        let report = vault.maintain().rebuild_hnsw_heal_invalid_vectors().run()?;
        assert_eq!(report.hnsw_invalid_vectors_skipped, 1);
        assert_eq!(report.hnsw_live_nodes, 1);
        Ok(())
    }

    #[test]
    fn run_all_operations() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(90);
        let b = entity(91);
        let c = entity(92);

        for id in [a, b, c] {
            vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        }

        vault.put_vector(&a, &[1.0, 0.0, 0.0, 0.0])?;
        vault.put_vector(&b, &[0.0, 1.0, 0.0, 0.0])?;
        vault.put_vector(&c, &[0.0, 0.0, 1.0, 0.0])?;

        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.vectors.delete(&mut wtxn, c.as_bytes())?;
            vault.store.entities.delete(&mut wtxn, c.as_bytes())?;
            vault
                .store
                .text_postings
                .put(&mut wtxn, b"empty-maintain", &[])?;
            wtxn.commit()?;
        }

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let _ = vault.query().search_ppr(&[a], 3).limit(10).run()?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.25)?;

        let current_hash = {
            let rtxn = vault.store.env.read_txn()?;
            let value = vault
                .store
                .short_ids_reverse
                .get(&rtxn, a.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let (_, hash) = parse_short_id_value(value)?;
            hash
        };
        let mut drifted_payload = b"hash-drifted".to_vec();
        while ((xxh32(&drifted_payload, 0) % 256) as u8) == current_hash {
            drifted_payload.push(0);
        }

        {
            let mut wtxn = vault.store.env.write_txn()?;
            let record = vault
                .store
                .entities
                .get(&wtxn, a.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let mut updated = record[..ENTITY_METADATA_HEADER_LEN].to_vec();
            updated.extend_from_slice(&drifted_payload);
            vault
                .store
                .entities
                .put(&mut wtxn, a.as_bytes(), &updated)?;
            wtxn.commit()?;
        }

        let report = vault
            .maintain()
            .rebuild_hnsw()
            .cleanup_ppr_cache(0)
            .compact_postings()
            .recompute_short_id_hashes()
            .run()?;

        assert!(report.hnsw_dead_nodes_removed > 0);
        assert!(report.hnsw_live_nodes > 0);
        assert!(report.ppr_caches_evicted > 0);
        assert!(report.ppr_deps_cleaned > 0);
        assert!(report.postings_compacted > 0);
        assert!(report.orphan_short_ids_deleted > 0);
        assert!(report.short_id_hashes_updated > 0);
        Ok(())
    }

    #[test]
    fn run_no_operations() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let report = vault.maintain().run()?;
        assert_eq!(report, MaintenanceReport::default());
        Ok(())
    }

    #[test]
    fn clear_text_index_removes_all_text_rows_and_rewrites_manifest() -> Result<()> {
        use crate::store::{
            TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
            TEXT_INDEX_SCHEMA_VERSION_KEY,
        };

        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(120);
        let b = entity(121);

        vault
            .batch()
            .put(&a, 1, test_time_range(1, 1), 1, b"a")
            .put(&b, 1, test_time_range(1, 1), 1, b"b")
            .text(&a, &[("body", "hello world")])
            .text(&b, &[("body", "world of rust")])
            .commit()?;

        let hits = vault.search_text("world", 10)?;
        assert_eq!(hits.len(), 2);

        let manifest_hash_before = {
            let rtxn = vault.store.env.read_txn()?;
            vault
                .store
                .vault_meta
                .get(&rtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?
                .map(|b| b.to_vec())
        };
        assert!(manifest_hash_before.is_some());

        let report = vault.maintain().clear_text_index().run()?;
        assert!(report.text_postings_removed > 0);
        assert!(report.text_meta_removed > 0);
        assert!(report.text_forward_removed > 0);
        assert!(report.text_doc_field_lengths_removed > 0);
        assert!(report.text_bm25_field_stats_removed > 0);

        assert_eq!(count_entries(&vault.store.text_postings, &vault)?, 0);
        assert_eq!(count_entries(&vault.store.text_meta, &vault)?, 0);
        assert_eq!(count_entries(&vault.store.text_forward, &vault)?, 0);
        assert_eq!(
            count_entries(&vault.store.text_doc_field_lengths, &vault)?,
            0
        );
        assert_eq!(
            count_entries(&vault.store.text_bm25_field_stats, &vault)?,
            0
        );

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, TEXT_INDEX_SCHEMA_VERSION_KEY)?
                .is_some()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?
                .is_some()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?
                .is_some()
        );
        drop(rtxn);

        // Entities still present — clear_text_index only touches text DBs.
        assert!(vault.get_entity_type(&a)?.is_some());
        assert!(vault.get_entity_type(&b)?.is_some());

        // Index reusable after clear.
        vault
            .batch()
            .text(&a, &[("body", "hello again")])
            .commit()?;
        let hits = vault.search_text("hello", 10)?;
        assert!(!hits.is_empty());
        Ok(())
    }

    #[test]
    fn rebuild_hnsw_empty_vault() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let report = vault.maintain().rebuild_hnsw().run()?;
        assert_eq!(report.hnsw_dead_nodes_removed, 0);
        assert_eq!(report.hnsw_live_nodes, 0);
        assert_eq!(report.hnsw_invalid_vectors_skipped, 0);
        Ok(())
    }
}
