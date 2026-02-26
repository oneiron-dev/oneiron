use xxhash_rust::xxh32::xxh32;

use crate::batch::{parse_short_id_value, ENTITY_METADATA_HEADER_LEN};
use crate::error::{Error, Result};
use crate::hnsw::{hnsw_insert, COUNT_KEY};
use crate::store::MODEL_ID_KEY;
use crate::types::{EntityId, ENTITY_ID_LEN};
use crate::{le_bytes_to_f32_vec, ppr, Vault};

const GRAPH_VERSION_KEY: &[u8] = b"graph_version";

/// Builder for running maintenance operations against a vault.
pub struct MaintenanceBuilder<'a> {
    vault: &'a Vault,
    do_rebuild_hnsw: bool,
    do_cleanup_ppr: bool,
    ppr_max_age_secs: u64,
    do_compact_postings: bool,
    do_recompute_hashes: bool,
}

/// Aggregate counters for maintenance operations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceReport {
    pub hnsw_dead_nodes_removed: u64,
    pub hnsw_live_nodes: u64,
    pub ppr_caches_evicted: u64,
    pub ppr_deps_cleaned: u64,
    pub postings_compacted: u64,
    pub short_id_hashes_updated: u64,
}

impl<'a> MaintenanceBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            do_rebuild_hnsw: false,
            do_cleanup_ppr: false,
            ppr_max_age_secs: 0,
            do_compact_postings: false,
            do_recompute_hashes: false,
        }
    }

    pub fn rebuild_hnsw(&mut self) -> &mut Self {
        self.do_rebuild_hnsw = true;
        self
    }

    pub fn cleanup_ppr_cache(&mut self, max_age_secs: u64) -> &mut Self {
        self.do_cleanup_ppr = true;
        self.ppr_max_age_secs = max_age_secs;
        self
    }

    pub fn compact_postings(&mut self) -> &mut Self {
        self.do_compact_postings = true;
        self
    }

    pub fn recompute_short_id_hashes(&mut self) -> &mut Self {
        self.do_recompute_hashes = true;
        self
    }

    pub fn run(&self) -> Result<MaintenanceReport> {
        let mut report = MaintenanceReport::default();

        if self.do_rebuild_hnsw {
            let (dead_removed, live_nodes) = rebuild_hnsw(self.vault)?;
            report.hnsw_dead_nodes_removed = dead_removed;
            report.hnsw_live_nodes = live_nodes;
        }

        if self.do_cleanup_ppr {
            let (evicted, deps_cleaned) =
                cleanup_ppr_cache(self.vault, self.ppr_max_age_secs)?;
            report.ppr_caches_evicted = evicted;
            report.ppr_deps_cleaned = deps_cleaned;
        }

        if self.do_compact_postings {
            report.postings_compacted = compact_postings(self.vault)?;
        }

        if self.do_recompute_hashes {
            report.short_id_hashes_updated = recompute_short_id_hashes(self.vault)?;
        }

        Ok(report)
    }
}

fn rebuild_hnsw(vault: &Vault) -> Result<(u64, u64)> {
    let mut wtxn = vault.store.env.write_txn()?;

    let graph_version = decode_u64_opt(vault.store.hnsw_meta.get(&wtxn, GRAPH_VERSION_KEY)?)?;
    let old_count = decode_u64_opt(vault.store.hnsw_meta.get(&wtxn, COUNT_KEY)?)?.unwrap_or(0);

    let mut vectors = Vec::<(EntityId, Vec<f32>)>::with_capacity(old_count as usize);
    for entry in vault.store.vectors.iter(&wtxn)? {
        let (id_bytes, vector_bytes) = entry?;
        let id = parse_entity_id(id_bytes)?;
        let vector = le_bytes_to_f32_vec(vector_bytes)?;
        vectors.push((id, vector));
    }

    vault.store.hnsw_neighbors.clear(&mut wtxn)?;
    vault.store.hnsw_meta.clear(&mut wtxn)?;

    if let Some(version) = graph_version {
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, GRAPH_VERSION_KEY, &version.to_le_bytes())?;
    }

    if let Some(model) = vault.config.embedding_model.as_deref().filter(|m| !m.is_empty()) {
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, MODEL_ID_KEY, model.as_bytes())?;
    }

    for (id, vector) in &vectors {
        hnsw_insert(&vault.store, &vault.config, &mut wtxn, id, vector)?;
    }

    wtxn.commit()?;

    let live_nodes = vectors.len() as u64;
    let dead_nodes_removed = old_count.saturating_sub(live_nodes);
    Ok((dead_nodes_removed, live_nodes))
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

fn recompute_short_id_hashes(vault: &Vault) -> Result<u64> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut updates = Vec::new();
    for entry in vault.store.short_ids.iter(&wtxn)? {
        let (key, value) = entry?;

        if is_sentinel_short_id_key(key) {
            continue;
        }

        let (short_id, current_hash) = parse_short_id_value(value)?;
        let Some(blob) = vault.store.entities.get(&wtxn, key)? else {
            continue;
        };

        if blob.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::InvalidKey);
        }

        let payload = &blob[ENTITY_METADATA_HEADER_LEN..];
        let new_hash = (xxh32(payload, 0) % 256) as u8;
        if new_hash == current_hash {
            continue;
        }

        let mut updated_value = Vec::with_capacity(short_id.len() + 1);
        updated_value.extend_from_slice(short_id.as_bytes());
        updated_value.push(new_hash);
        updates.push((key.to_vec(), updated_value));
    }

    for (key, value) in &updates {
        vault.store.short_ids.put(&mut wtxn, key, value)?;
    }

    wtxn.commit()?;
    Ok(updates.len() as u64)
}

fn parse_entity_id(bytes: &[u8]) -> Result<EntityId> {
    let raw: [u8; ENTITY_ID_LEN] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(EntityId::from_bytes(raw))
}

fn decode_u64_opt(raw: Option<&[u8]>) -> Result<Option<u64>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let bytes: [u8; 8] = raw.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(Some(u64::from_le_bytes(bytes)))
}

fn is_sentinel_short_id_key(key: &[u8]) -> bool {
    key.len() == ENTITY_ID_LEN && key[1..].iter().all(|&b| b == 0xFF)
}

#[cfg(test)]
mod tests {
    use heed::types::Bytes;

    use super::*;
    use crate::types::{EdgeKind, HnswConfig, TimeRange, VaultConfig};

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
        }
    }

    fn test_time_range(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; ENTITY_ID_LEN])
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

    #[test]
    fn rebuild_hnsw_removes_dead_nodes() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let mut ids = Vec::new();

        for i in 0..50_u8 {
            let id = entity(i.saturating_add(1));
            ids.push(id);
            vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
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

    #[test]
    fn rebuild_hnsw_preserves_graph_version() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(80);
        let b = entity(81);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let before = read_u64_meta(&vault, GRAPH_VERSION_KEY)?;

        let report = vault.maintain().rebuild_hnsw().run()?;
        assert_eq!(report.hnsw_dead_nodes_removed, 0);

        let after = read_u64_meta(&vault, GRAPH_VERSION_KEY)?;
        assert_eq!(before, after);
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
            vault.store.text_postings.put(&mut wtxn, b"keep", &[1, 2, 3])?;
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
            .put(&id, 0, test_time_range(100, 100), 101, b"initial-payload")
            .commit()?;

        let (short_id_before, hash_before) = {
            let rtxn = vault.store.env.read_txn()?;
            let value = vault
                .store
                .short_ids
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
            vault.store.entities.put(&mut wtxn, id.as_bytes(), &updated)?;
            wtxn.commit()?;
        }

        let report = vault.maintain().recompute_short_id_hashes().run()?;
        assert_eq!(report.short_id_hashes_updated, 1);

        let rtxn = vault.store.env.read_txn()?;
        let updated_value = vault
            .store
            .short_ids
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (short_id_after, hash_after) = parse_short_id_value(updated_value)?;
        assert_eq!(short_id_after, short_id_before);
        assert_eq!(hash_after, (xxh32(&new_payload, 0) % 256) as u8);
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
            vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
        }

        vault.put_vector(&a, &[1.0, 0.0, 0.0, 0.0])?;
        vault.put_vector(&b, &[0.0, 1.0, 0.0, 0.0])?;
        vault.put_vector(&c, &[0.0, 0.0, 1.0, 0.0])?;

        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.vectors.delete(&mut wtxn, c.as_bytes())?;
            vault.store.text_postings.put(&mut wtxn, b"empty-maintain", &[])?;
            wtxn.commit()?;
        }

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let _ = vault.query().search_ppr(&[a], 3).limit(10).run()?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.25)?;

        let current_hash = {
            let rtxn = vault.store.env.read_txn()?;
            let value = vault
                .store
                .short_ids
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
            vault.store.entities.put(&mut wtxn, a.as_bytes(), &updated)?;
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
    fn rebuild_hnsw_empty_vault() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let report = vault.maintain().rebuild_hnsw().run()?;
        assert_eq!(report.hnsw_dead_nodes_removed, 0);
        assert_eq!(report.hnsw_live_nodes, 0);
        Ok(())
    }
}
