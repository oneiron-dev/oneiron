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
#[cfg(feature = "sync")]
pub mod sync;
pub mod types;

use crate::batch::{deindex_entity, EntityMetadataHeader, ENTITY_METADATA_HEADER_LEN};
pub use crate::batch::{BatchBuilder, TxnBatchBuilder};
pub use crate::context_pack::ContextPackBuilder;
pub use crate::error::{Error, Result};
pub use crate::maintain::{MaintenanceBuilder, MaintenanceReport};
pub use crate::pipeline::PipelineBuilder;
use crate::store::Store;
use crate::types::{parse_vad, EDGE_KEY_LEN, EDGE_VALUE_LEN};
pub use crate::types::{
    ContextEntity, ContextPack, EdgeInfo, EdgeKind, EntityId, FieldProfile, HnswConfig, PackFormat,
    PackStats, ScoredEntity, Signal, TemporalAnchorMode, TemporalGranularity, TimeRange,
    TokenAllocation, Vad, VaultConfig,
};

const MIN_MAP_SIZE_BYTES: usize = 1 << 20;

/// Build a 17-byte edge prefix `[entity_id(16) | kind(1)]` for targeted
/// LMDB prefix scans. Avoids scanning all edge kinds for a given entity.
fn edge_kind_prefix(id: &EntityId, kind: EdgeKind) -> [u8; 17] {
    let mut prefix = [0u8; 17];
    prefix[..16].copy_from_slice(id.as_bytes());
    prefix[16] = kind as u8;
    prefix
}

/// Returns the first outbound ChildOf parent for `node`, or `None` if it has
/// no ChildOf edge (i.e. it is a root).
///
/// Each node has at most one ChildOf parent. If multiple exist due to data
/// corruption, only the first by LMDB key order is returned.
fn first_child_of_parent(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    node: &EntityId,
) -> Result<Option<EntityId>> {
    let prefix = edge_kind_prefix(node, EdgeKind::ChildOf);
    for entry in store.edges_out.prefix_iter(rtxn, &prefix)? {
        let (key, _) = entry?;
        if key.len() != EDGE_KEY_LEN {
            continue;
        }
        let parent =
            EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?)?;
        return Ok(Some(parent));
    }
    Ok(None)
}

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
        if config.hnsw.m_max_0 == 0 {
            return Err(Error::InvalidConfig(
                "hnsw m_max_0 must be greater than zero".to_owned(),
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
        let (existed, had_vector, had_graph_mutation, neighbors) =
            deindex_entity(&self.store, &mut wtxn, id)?;
        ppr::invalidate_ppr_for_delete(&self.store, &mut wtxn, id, &neighbors)?;
        if had_graph_mutation {
            ppr::increment_graph_version(&self.store, &mut wtxn)?;
        }
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
        }
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

    /// Creates a batch builder that writes into an externally-owned transaction.
    ///
    /// Call `.apply(wtxn)` to execute writes without committing.
    /// Use with `with_write_txn()` for atomic multi-operation writes (e.g. entity + pm marker).
    pub fn batch_in(&self) -> TxnBatchBuilder<'_> {
        TxnBatchBuilder::new(self)
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

    /// Checks if an entity exists in the LMDB vault.
    pub fn entity_exists(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self.store.entities.get(&rtxn, id.as_bytes())?.is_some())
    }

    /// Checks if a directed edge exists in the LMDB vault.
    pub fn edge_exists(&self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Result<bool> {
        let key = Store::encode_edge_key(src, kind, tgt);
        let rtxn = self.store.env.read_txn()?;
        Ok(self.store.edges_out.get(&rtxn, &key)?.is_some())
    }

    /// Returns the `learned_at` timestamp from an entity's header (bytes 17-24).
    pub fn get_learned_at(&self, id: &EntityId) -> Result<u64> {
        let rtxn = self.store.env.read_txn()?;
        let raw = self
            .store
            .entities
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(raw).ok_or(Error::InvalidKey)?;
        Ok(header.learned_at)
    }

    /// Returns entity IDs whose `learned_at` falls within `[start, end)`.
    ///
    /// Iterates the `temporal_learned` index and filters by timestamp range.
    pub fn entities_in_learned_range(&self, start: u64, end: u64) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        for entry in self.store.temporal_learned.iter(&rtxn)? {
            let (key, _) = entry?;
            if key.len() != 24 {
                continue;
            }
            let ts = u64::from_be_bytes(key[..8].try_into().map_err(|_| Error::InvalidKey)?);
            if ts < start {
                continue;
            }
            if ts >= end {
                break; // temporal keys are sorted by timestamp (BE), so we can stop
            }
            let id =
                EntityId::from_bytes(key[8..24].try_into().map_err(|_| Error::InvalidKey)?)?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// Executes a closure within a single LMDB write transaction.
    ///
    /// The transaction commits on `Ok(())` return and rolls back on `Err`.
    /// Used by the sync layer to atomically write entity data + pending-mirror markers.
    pub fn with_write_txn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    {
        let mut wtxn = self.store.env.write_txn()?;
        let result = f(&mut wtxn)?;
        wtxn.commit()?;
        Ok(result)
    }

    /// Reads a value from the sync_state database.
    #[cfg(feature = "sync")]
    pub fn sync_state_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self
            .store
            .sync_state
            .get(&rtxn, key)?
            .map(|bytes| bytes.to_vec()))
    }

    /// Writes a value to the sync_state database.
    #[cfg(feature = "sync")]
    pub fn sync_state_put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.with_write_txn(|wtxn| {
            self.store.sync_state.put(wtxn, key, value)?;
            Ok(())
        })
    }

    /// Deletes a key from the sync_state database.
    #[cfg(feature = "sync")]
    pub fn sync_state_delete(&self, key: &str) -> Result<bool> {
        self.with_write_txn(|wtxn| Ok(self.store.sync_state.delete(wtxn, key)?))
    }

    /// Lists all keys with the given prefix in sync_state.
    #[cfg(feature = "sync")]
    pub fn sync_state_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let rtxn = self.store.env.read_txn()?;
        let mut keys = Vec::new();
        let iter = self.store.sync_state.prefix_iter(&rtxn, prefix)?;
        for entry in iter {
            let (k, _) = entry?;
            keys.push(k.to_string());
        }
        Ok(keys)
    }

    /// Returns the raw entity blob (header + data) for an entity.
    ///
    /// Unlike `get()` which strips the header, this returns the full LMDB value.
    pub fn get_raw(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self
            .store
            .entities
            .get(&rtxn, id.as_bytes())?
            .map(|bytes| bytes.to_vec()))
    }

    // ─── Tree Query API ───────────────────────────────────────

    /// Returns all entity IDs of a given type via prefix scan on type_index.
    ///
    /// Returns up to `MAX_TYPE_QUERY_RESULTS` entities to prevent unbounded allocation.
    pub fn entities_by_type(&self, entity_type: u8) -> Result<Vec<EntityId>> {
        const MAX_TYPE_QUERY_RESULTS: usize = 100_000;
        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        for entry in self.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
            let (key, _) = entry?;
            if key.len() != 17 {
                continue;
            }
            let id =
                EntityId::from_bytes(key[1..17].try_into().map_err(|_| Error::InvalidKey)?)?;
            ids.push(id);
            if ids.len() >= MAX_TYPE_QUERY_RESULTS {
                break;
            }
        }
        Ok(ids)
    }

    /// Returns the entity type byte for a stored entity, or None if not found.
    pub fn get_entity_type(&self, id: &EntityId) -> Result<Option<u8>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header = EntityMetadataHeader::parse(raw).ok_or(Error::InvalidKey)?;
        Ok(Some(header.entity_type))
    }

    /// Outbound edge targets filtered by kind and optional target entity type.
    ///
    /// For a ChildOf edge (child → parent), calling `targets(child, ChildOf, None)`
    /// returns the parent(s).
    pub fn targets(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        target_type: Option<u8>,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.filtered_edge_peers(&rtxn, &self.store.edges_out, src, kind, target_type)
    }

    /// Inbound edge sources filtered by kind and optional source entity type.
    ///
    /// For a ChildOf edge (child → parent), calling `sources(parent, ChildOf, None)`
    /// returns the children.
    pub fn sources(
        &self,
        tgt: &EntityId,
        kind: EdgeKind,
        source_type: Option<u8>,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.filtered_edge_peers(&rtxn, &self.store.edges_in, tgt, kind, source_type)
    }

    /// Scans an edge database (edges_out or edges_in) for entries matching `kind`,
    /// returning the peer entity IDs. Optionally filters by the peer's entity type.
    ///
    /// Capped at `MAX_EDGE_QUERY_RESULTS` to prevent unbounded allocation.
    fn filtered_edge_peers(
        &self,
        rtxn: &heed::RoTxn<'_>,
        db: &Database<Bytes, Bytes>,
        prefix_id: &EntityId,
        kind: EdgeKind,
        peer_type: Option<u8>,
    ) -> Result<Vec<EntityId>> {
        const MAX_EDGE_QUERY_RESULTS: usize = 100_000;
        let prefix = edge_kind_prefix(prefix_id, kind);
        let mut ids = Vec::new();
        for entry in db.prefix_iter(rtxn, &prefix)? {
            let (key, _) = entry?;
            if key.len() != EDGE_KEY_LEN {
                continue;
            }
            let peer =
                EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?)?;

            if let Some(req_type) = peer_type {
                if !self.entity_has_type(rtxn, &peer, req_type)? {
                    continue;
                }
            }

            ids.push(peer);
            if ids.len() >= MAX_EDGE_QUERY_RESULTS {
                break;
            }
        }
        Ok(ids)
    }

    /// Returns true if the entity exists and has the given type byte.
    ///
    /// Returns `Ok(false)` for missing entities or unparseable headers (corruption).
    /// This is intentional for edge filtering: a corrupted peer should be skipped,
    /// not fail the entire query. Compare with `get_entity_type()` which returns
    /// `Err(InvalidKey)` on corruption — appropriate for direct lookups where the
    /// caller should know about data issues.
    fn entity_has_type(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        expected_type: u8,
    ) -> Result<bool> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let Some(header) = EntityMetadataHeader::parse(raw) else {
            return Ok(false);
        };
        Ok(header.entity_type == expected_type)
    }

    /// Subtree descendants via ChildOf traversal, limited to `max_depth`.
    /// Returns `(id, depth)` pairs sorted by depth.
    ///
    /// Uses BFS internally (queue-based) so that when the result cap is hit,
    /// shallower nodes are always included before deeper ones. This ensures
    /// fair capping across wide trees.
    /// Children are found via inbound ChildOf edges (since ChildOf direction is
    /// child → parent, children appear in the parent's edges_in).
    ///
    /// Returns up to `MAX_SUBTREE_RESULTS` nodes to prevent unbounded allocation.
    pub fn subtree(&self, root: &EntityId, max_depth: u32) -> Result<Vec<(EntityId, u32)>> {
        const MAX_SUBTREE_RESULTS: usize = 50_000;
        let rtxn = self.store.env.read_txn()?;
        let mut result = Vec::new();
        let mut frontier = std::collections::VecDeque::from([(*root, 0_u32)]);
        let mut visited = std::collections::HashSet::new();
        visited.insert(*root);

        while let Some((node, depth)) = frontier.pop_front() {
            if depth > 0 {
                result.push((node, depth));
                if result.len() >= MAX_SUBTREE_RESULTS {
                    break;
                }
            }
            if depth >= max_depth {
                continue;
            }

            // Find children: inbound ChildOf edges (child --ChildOf--> node)
            let child_prefix = edge_kind_prefix(&node, EdgeKind::ChildOf);
            for entry in self.store.edges_in.prefix_iter(&rtxn, &child_prefix)? {
                let (key, _) = entry?;
                if key.len() != EDGE_KEY_LEN {
                    continue;
                }
                let child =
                    EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?)?;
                if visited.insert(child) {
                    frontier.push_back((child, depth + 1));
                }
            }
        }

        // BFS already produces depth-ordered results, but sort to ensure
        // deterministic ordering within each depth level (by entity ID).
        result.sort_unstable_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
        });
        Ok(result)
    }

    /// Walk ancestors via outbound ChildOf edges.
    ///
    /// Returns ancestor IDs from immediate parent to root (nearest first).
    /// The `visited` set prevents infinite loops on corrupted cyclic data.
    pub fn ancestors(&self, node: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut result = Vec::new();
        let mut current = *node;
        let mut visited = std::collections::HashSet::new();
        visited.insert(current);

        while let Some(parent) = first_child_of_parent(&self.store, &rtxn, &current)? {
            if !visited.insert(parent) {
                break; // Cycle detected — stop walking but don't error
            }
            result.push(parent);
            current = parent;
        }

        Ok(result)
    }

    /// Checks whether making `target` a parent of `node` would create a cycle.
    ///
    /// Convenience wrapper that opens its own read transaction.
    /// For atomic check+insert, use [`would_create_cycle_in_txn`] within a
    /// write transaction (see `BatchBuilder::edge_checked`).
    pub fn would_create_cycle(&self, node: &EntityId, target: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        self.would_create_cycle_in_txn(&rtxn, node, target)
    }

    /// Checks whether making `target` a parent of `node` would create a cycle,
    /// using the provided read transaction for atomicity with subsequent writes.
    ///
    /// Walks ancestors of `target` — if `node` is found among them, it's a cycle.
    /// Short-circuits as soon as `node` is found instead of collecting all ancestors.
    /// The `visited` set prevents infinite loops on corrupted cyclic data.
    pub(crate) fn would_create_cycle_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        node: &EntityId,
        target: &EntityId,
    ) -> Result<bool> {
        if node == target {
            return Ok(true);
        }
        let mut current = *target;
        let mut visited = std::collections::HashSet::new();
        visited.insert(current);

        while let Some(parent) = first_child_of_parent(&self.store, rtxn, &current)? {
            if parent == *node {
                return Ok(true);
            }
            if !visited.insert(parent) {
                break; // Existing cycle in data — stop walking
            }
            current = parent;
        }
        Ok(false)
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
    let target = EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?)?;
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
    use crate::store::{
        GRAPH_VERSION_KEY, HNSW_CONFIG_KEY, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY,
        VECTOR_VERSION_KEY,
    };

    #[cfg(not(feature = "sync"))]
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

    #[cfg(feature = "sync")]
    const DB_NAMES: [&str; 21] = [
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
        "sync_state",
        "sync_queue",
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

    fn read_hnsw_meta_u64(vault: &Vault, key: &[u8]) -> Result<u64> {
        let rtxn = vault.store.env.read_txn()?;
        let Some(raw) = vault.store.hnsw_meta.get(&rtxn, key)? else {
            return Ok(0);
        };
        Ok(u64::from_le_bytes(
            raw.try_into().map_err(|_| Error::InvalidKey)?,
        ))
    }

    #[test]
    fn encode_edge_key_has_exact_layout() {
        let src = EntityId::from_bytes_unchecked([0x11; 16]);
        let tgt = EntityId::from_bytes_unchecked([0x22; 16]);
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
    fn vector_version_bumps_once_per_batch_commit() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = EntityId::now();
        let b = EntityId::now();

        assert_eq!(read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?, 0);

        vault
            .batch()
            .vector(&a, &[0.1_f32, 0.2, 0.3, 0.4])
            .vector(&b, &[0.4_f32, 0.3, 0.2, 0.1])
            .commit()?;
        assert_eq!(read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?, 1);

        vault.batch().delete(&a).delete(&b).commit()?;
        assert_eq!(read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?, 2);
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
    fn batch_put_writes_long_interval_index_by_end_time() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 1;

        vault
            .batch()
            .put(&id, 6, test_time_range(1_000, end), 3_000, b"long-range")
            .commit()?;

        let key = Store::encode_temporal_key(end, &id);
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &key)?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(
            u64::from_be_bytes(value.try_into().map_err(|_| Error::InvalidKey)?),
            1_000
        );
        Ok(())
    }

    #[test]
    fn open_migrates_legacy_long_interval_rows() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path();
        let id = EntityId::now();
        let end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;

        let vault = Vault::open(path, test_config())?;
        vault
            .batch()
            .put(
                &id,
                6,
                test_time_range(1_000, end),
                3_000,
                b"legacy-long-range",
            )
            .commit()?;

        let new_key = Store::encode_temporal_key(end, &id);
        let mut legacy_value = [0_u8; 16];
        legacy_value[..8].copy_from_slice(&1_000_u64.to_be_bytes());
        legacy_value[8..].copy_from_slice(&end.to_be_bytes());

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .temporal_long_intervals
            .delete(&mut wtxn, &new_key)?;
        vault
            .store
            .temporal_long_intervals
            .put(&mut wtxn, id.as_bytes(), &legacy_value)?;
        vault
            .store
            .hnsw_meta
            .delete(&mut wtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?;
        wtxn.commit()?;
        drop(vault);

        let reopened = Vault::open(path, test_config())?;
        let rtxn = reopened.store.env.read_txn()?;
        assert!(reopened
            .store
            .temporal_long_intervals
            .get(&rtxn, id.as_bytes())?
            .is_none());
        let value = reopened
            .store
            .temporal_long_intervals
            .get(&rtxn, &new_key)?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(
            u64::from_be_bytes(value.try_into().map_err(|_| Error::InvalidKey)?),
            1_000
        );
        Ok(())
    }

    #[test]
    fn open_rejects_newer_long_interval_schema_version() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path();

        let vault = Vault::open(path, test_config())?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.hnsw_meta.put(
            &mut wtxn,
            TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY,
            &[3_u8],
        )?;
        wtxn.commit()?;
        drop(vault);

        let reopened = Vault::open(path, test_config());
        assert!(matches!(reopened, Err(Error::InvalidKey)));
        Ok(())
    }

    #[test]
    fn open_checks_model_id_before_migrating_long_interval_schema() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path();
        let id = EntityId::now();
        let end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;

        let mut cfg = test_config();
        cfg.embedding_model = Some("model-a".to_owned());
        let vault = Vault::open(path, cfg)?;
        vault
            .batch()
            .put(
                &id,
                6,
                test_time_range(1_000, end),
                3_000,
                b"legacy-long-range",
            )
            .commit()?;

        let new_key = Store::encode_temporal_key(end, &id);
        let mut legacy_value = [0_u8; 16];
        legacy_value[..8].copy_from_slice(&1_000_u64.to_be_bytes());
        legacy_value[8..].copy_from_slice(&end.to_be_bytes());

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .temporal_long_intervals
            .delete(&mut wtxn, &new_key)?;
        vault
            .store
            .temporal_long_intervals
            .put(&mut wtxn, id.as_bytes(), &legacy_value)?;
        vault
            .store
            .hnsw_meta
            .delete(&mut wtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?;
        wtxn.commit()?;
        drop(vault);

        let mut mismatch_cfg = test_config();
        mismatch_cfg.embedding_model = Some("model-b".to_owned());
        assert!(matches!(
            Vault::open(path, mismatch_cfg),
            Err(Error::EmbeddingModelChanged { .. })
        ));

        let cfg = test_config();
        let env = unsafe {
            heed::EnvOpenOptions::new()
                .map_size(cfg.map_size)
                .max_readers(cfg.max_readers)
                .max_dbs(24)
                .open(path)?
        };
        let rtxn = env.read_txn()?;
        let hnsw_meta = env
            .open_database::<Bytes, Bytes>(&rtxn, Some("hnsw_meta"))?
            .ok_or(Error::EntityNotFound)?;
        let temporal_long_intervals = env
            .open_database::<Bytes, Bytes>(&rtxn, Some("temporal_long_intervals"))?
            .ok_or(Error::EntityNotFound)?;

        assert!(temporal_long_intervals.get(&rtxn, id.as_bytes())?.is_some());
        assert!(temporal_long_intervals.get(&rtxn, &new_key)?.is_none());
        assert!(hnsw_meta
            .get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?
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
    fn reput_rekeys_long_interval_index_and_drops_shortened_range() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let old_end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;
        let new_end = 5_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 20;

        vault
            .batch()
            .put(&id, 0, test_time_range(1_000, old_end), 300, b"long-old")
            .commit()?;

        let old_key = Store::encode_temporal_key(old_end, &id);
        let new_key = Store::encode_temporal_key(new_end, &id);

        vault
            .batch()
            .put(&id, 0, test_time_range(5_000, new_end), 300, b"long-new")
            .commit()?;

        {
            let rtxn = vault.store.env.read_txn()?;
            assert!(vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &old_key)?
                .is_none());
            let value = vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &new_key)?
                .ok_or(Error::EntityNotFound)?;
            assert_eq!(
                u64::from_be_bytes(value.try_into().map_err(|_| Error::InvalidKey)?),
                5_000
            );
        }

        vault
            .batch()
            .put(&id, 0, test_time_range(10_000, 10_001), 300, b"short")
            .commit()?;

        let rtxn = vault.store.env.read_txn()?;
        assert!(vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &new_key)?
            .is_none());
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
    fn delete_entity_cleans_edge_only_nodes_and_bumps_graph_version() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let src = EntityId::now();
        let tgt = EntityId::now();

        vault.put_edge(&src, EdgeKind::Supports, &tgt, 0.9)?;
        let before = read_hnsw_meta_u64(&vault, GRAPH_VERSION_KEY)?;

        assert!(!vault.delete_entity(&src)?);
        assert!(vault.edges_out(&src)?.is_empty());
        assert!(vault.edges_in(&tgt)?.is_empty());

        let after = read_hnsw_meta_u64(&vault, GRAPH_VERSION_KEY)?;
        assert_eq!(after, before + 1);
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
    fn validates_dimensions_hnsw_and_map_size() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;

        let mut invalid_dims = test_config();
        invalid_dims.dimensions = 0;
        let err = match Vault::open(temp_dir.path(), invalid_dims) {
            Ok(_) => panic!("expected invalid config"),
            Err(err) => err,
        };
        assert!(matches!(err, Error::InvalidConfig(_)));

        let mut invalid_hnsw = test_config();
        invalid_hnsw.hnsw.m_max_0 = 0;
        let err = match Vault::open(temp_dir.path(), invalid_hnsw) {
            Ok(_) => panic!("expected invalid config"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            Error::InvalidConfig(ref message) if message == "hnsw m_max_0 must be greater than zero"
        ));

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
    fn detects_hnsw_config_mismatch_on_open() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        drop(vault);

        let mut cfg = test_config();
        cfg.hnsw.ef_construction += 1;
        let Err(err) = Vault::open(temp_dir.path(), cfg) else {
            panic!("expected hnsw config mismatch");
        };
        assert!(matches!(
            err,
            Error::HnswConfigChanged {
                ref stored,
                ref requested
            } if stored == "dimensions=4,m_max_0=64,ef_construction=200"
                && requested == "dimensions=4,m_max_0=64,ef_construction=201"
        ));

        Ok(())
    }

    #[test]
    fn detects_dimension_mismatch_on_open() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        drop(vault);

        let mut cfg = test_config();
        cfg.dimensions = 8;
        let Err(err) = Vault::open(temp_dir.path(), cfg) else {
            panic!("expected hnsw config mismatch");
        };
        assert!(matches!(
            err,
            Error::HnswConfigChanged {
                ref stored,
                ref requested
            } if stored == "dimensions=4,m_max_0=64,ef_construction=200"
                && requested == "dimensions=8,m_max_0=64,ef_construction=200"
        ));

        Ok(())
    }

    #[test]
    fn allows_ef_search_retuning_on_open() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
        drop(vault);

        let mut cfg = test_config();
        cfg.hnsw.ef_search = 512;
        let reopened = Vault::open(temp_dir.path(), cfg)?;
        drop(reopened);
        Ok(())
    }

    #[test]
    fn rejects_populated_vault_missing_hnsw_compatibility_metadata() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path();
        let vault = Vault::open(path, test_config())?;
        let id = EntityId::now();
        vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;

        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.hnsw_meta.delete(&mut wtxn, HNSW_CONFIG_KEY)?;
            wtxn.commit()?;
        }
        drop(vault);

        let Err(err) = Vault::open(path, test_config()) else {
            panic!("expected missing compatibility metadata rejection");
        };
        assert!(matches!(
            err,
            Error::InvalidConfig(ref message)
                if message.contains("missing complete vector/hnsw compatibility metadata")
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
            (18, EdgeKind::ChildOf),
            (19, EdgeKind::AssignedTo),
        ];
        for (disc, expected) in new_kinds {
            let kind = EdgeKind::try_from_u8(disc).expect("valid discriminant");
            assert_eq!(kind, expected);
            assert_eq!(kind as u8, disc);
        }
        assert!(EdgeKind::try_from_u8(20).is_none());
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
        assert_eq!(short_id_prefix(12).unwrap(), "og");
        assert_eq!(short_id_prefix(13).unwrap(), "fc");
        assert_eq!(short_id_prefix(14).unwrap(), "wd");
        assert!(short_id_prefix(15).is_err());
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

    // ─── Phase 2A: Productivity Entity Types ──────────────────

    #[test]
    fn productivity_entity_types_round_trip() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let task_list = EntityId::now();
        let task = EntityId::now();

        vault
            .batch()
            .put(&task_list, 60, test_time_range(100, 100), 101, b"project")
            .put(&task, 61, test_time_range(200, 200), 201, b"task-data")
            .commit()?;

        assert_eq!(vault.get(&task_list)?.unwrap(), b"project");
        assert_eq!(vault.get(&task)?.unwrap(), b"task-data");
        Ok(())
    }

    #[test]
    fn productivity_short_id_prefixes() {
        use crate::types::short_id_prefix;
        assert_eq!(short_id_prefix(60).unwrap(), "tl");
        assert_eq!(short_id_prefix(61).unwrap(), "tk");
        assert_eq!(short_id_prefix(62).unwrap(), "mc");
    }

    #[test]
    fn invalid_entity_type_rejected() {
        use crate::types::short_id_prefix;
        assert!(short_id_prefix(99).is_err());
        assert!(short_id_prefix(255).is_err());
        assert!(short_id_prefix(30).is_err()); // companion range, not yet defined
    }

    #[test]
    fn entity_id_rejects_reserved_sentinel_bytes() {
        assert!(EntityId::from_bytes([0x00; 16]).is_err());
        assert!(EntityId::from_bytes([0xFF; 16]).is_err());
    }

    #[test]
    fn entity_id_from_hex_rejects_reserved_sentinel_bytes() {
        assert!(EntityId::from_hex("00000000000000000000000000000000").is_err());
        assert!(EntityId::from_hex("ffffffffffffffffffffffffffffffff").is_err());
    }

    #[test]
    fn batch_put_invalid_entity_type_returns_early_error() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        let err = vault
            .batch()
            .put(&id, 255, test_time_range(1, 1), 2, b"bad-type")
            .commit()
            .expect_err("expected InvalidEntityType for type 255");
        assert!(
            matches!(err, Error::InvalidEntityType(255)),
            "expected InvalidEntityType(255), got {err:?}"
        );

        // Verify nothing was written
        assert!(vault.get(&id)?.is_none());
        Ok(())
    }

    #[test]
    fn edge_kinds_child_of_and_assigned_to() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let child = EntityId::now();
        let parent = EntityId::now();
        let machine = EntityId::now();

        vault.put_edge(&child, EdgeKind::ChildOf, &parent, 1.0)?;
        vault.put_edge(&child, EdgeKind::AssignedTo, &machine, 0.8)?;

        let out = vault.edges_out(&child)?;
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .any(|e| e.kind == EdgeKind::ChildOf && e.target == parent));
        assert!(out
            .iter()
            .any(|e| e.kind == EdgeKind::AssignedTo && e.target == machine));

        assert_eq!(EdgeKind::ChildOf.default_weight(), 1.0);
        assert_eq!(EdgeKind::AssignedTo.default_weight(), 0.8);
        Ok(())
    }

    // ─── Phase 2A: Tree Query API ─────────────────────────────

    #[test]
    fn entities_by_type_returns_correct_ids() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let tl1 = EntityId::now();
        let tl2 = EntityId::now();
        let tk1 = EntityId::now();

        vault
            .batch()
            .put(&tl1, 60, test_time_range(1, 1), 2, b"project-1")
            .put(&tl2, 60, test_time_range(3, 3), 4, b"project-2")
            .put(&tk1, 61, test_time_range(5, 5), 6, b"task-1")
            .commit()?;

        let task_lists = vault.entities_by_type(60)?;
        assert_eq!(task_lists.len(), 2);
        assert!(task_lists.contains(&tl1));
        assert!(task_lists.contains(&tl2));

        let tasks = vault.entities_by_type(61)?;
        assert_eq!(tasks.len(), 1);
        assert!(tasks.contains(&tk1));

        let empty = vault.entities_by_type(62)?;
        assert!(empty.is_empty());
        Ok(())
    }

    #[test]
    fn targets_and_sources_with_kind_filter() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let child = EntityId::now();
        let parent = EntityId::now();
        let sibling = EntityId::now();
        let task_list = EntityId::now();

        vault
            .batch()
            .put(&child, 61, test_time_range(1, 1), 2, b"child")
            .put(&parent, 61, test_time_range(3, 3), 4, b"parent")
            .put(&sibling, 61, test_time_range(5, 5), 6, b"sibling")
            .put(&task_list, 60, test_time_range(7, 7), 8, b"project")
            .edge(&child, EdgeKind::ChildOf, &parent, 1.0)
            .edge(&sibling, EdgeKind::ChildOf, &parent, 1.0)
            .edge(&child, EdgeKind::BelongsTo, &task_list, 1.0)
            .commit()?;

        // targets(child, ChildOf) should return the parent
        let parents = vault.targets(&child, EdgeKind::ChildOf, None)?;
        assert_eq!(parents, vec![parent]);

        // sources(parent, ChildOf) should return both children
        let children = vault.sources(&parent, EdgeKind::ChildOf, None)?;
        assert_eq!(children.len(), 2);
        assert!(children.contains(&child));
        assert!(children.contains(&sibling));

        // targets with type filter: child's BelongsTo targets of type 60
        let lists = vault.targets(&child, EdgeKind::BelongsTo, Some(60))?;
        assert_eq!(lists, vec![task_list]);

        // targets with wrong type filter: should be empty
        let wrong = vault.targets(&child, EdgeKind::BelongsTo, Some(61))?;
        assert!(wrong.is_empty());
        Ok(())
    }

    #[test]
    fn subtree_four_level_tree() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        // Build: root → child1 → grandchild → great_grandchild
        //             → child2
        let root = EntityId::now();
        let child1 = EntityId::now();
        let child2 = EntityId::now();
        let grandchild = EntityId::now();
        let great_grandchild = EntityId::now();

        vault
            .batch()
            .put(&root, 61, test_time_range(1, 1), 2, b"root")
            .put(&child1, 61, test_time_range(3, 3), 4, b"child1")
            .put(&child2, 61, test_time_range(5, 5), 6, b"child2")
            .put(&grandchild, 61, test_time_range(7, 7), 8, b"gc")
            .put(&great_grandchild, 61, test_time_range(9, 9), 10, b"ggc")
            .edge(&child1, EdgeKind::ChildOf, &root, 1.0)
            .edge(&child2, EdgeKind::ChildOf, &root, 1.0)
            .edge(&grandchild, EdgeKind::ChildOf, &child1, 1.0)
            .edge(&great_grandchild, EdgeKind::ChildOf, &grandchild, 1.0)
            .commit()?;

        let tree = vault.subtree(&root, 10)?;
        assert_eq!(tree.len(), 4); // child1, child2, grandchild, great_grandchild

        // Verify depths
        let depth_of = |id: EntityId| tree.iter().find(|(i, _)| *i == id).map(|(_, d)| *d);
        assert_eq!(depth_of(child1), Some(1));
        assert_eq!(depth_of(child2), Some(1));
        assert_eq!(depth_of(grandchild), Some(2));
        assert_eq!(depth_of(great_grandchild), Some(3));

        // max_depth=1 should only return direct children
        let shallow = vault.subtree(&root, 1)?;
        assert_eq!(shallow.len(), 2);
        assert!(shallow.iter().all(|(_, d)| *d == 1));

        Ok(())
    }

    #[test]
    fn ancestors_walks_to_root() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let root = EntityId::now();
        let mid = EntityId::now();
        let leaf = EntityId::now();

        vault
            .batch()
            .put(&root, 61, test_time_range(1, 1), 2, b"root")
            .put(&mid, 61, test_time_range(3, 3), 4, b"mid")
            .put(&leaf, 61, test_time_range(5, 5), 6, b"leaf")
            .edge(&mid, EdgeKind::ChildOf, &root, 1.0)
            .edge(&leaf, EdgeKind::ChildOf, &mid, 1.0)
            .commit()?;

        let anc = vault.ancestors(&leaf)?;
        assert_eq!(anc, vec![mid, root]);

        // Root has no ancestors
        let root_anc = vault.ancestors(&root)?;
        assert!(root_anc.is_empty());

        Ok(())
    }

    #[test]
    fn cycle_prevention_rejects_self_parent() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let node = EntityId::now();
        vault.put_entity(&node, 61, test_time_range(1, 1), 2, b"self")?;

        assert!(vault.would_create_cycle(&node, &node)?);
        Ok(())
    }

    #[test]
    fn cycle_prevention_detects_ancestor_cycle() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        // A → B → C (ChildOf chain)
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        vault
            .batch()
            .put(&a, 61, test_time_range(1, 1), 2, b"a")
            .put(&b, 61, test_time_range(3, 3), 4, b"b")
            .put(&c, 61, test_time_range(5, 5), 6, b"c")
            .edge(&b, EdgeKind::ChildOf, &a, 1.0)
            .edge(&c, EdgeKind::ChildOf, &b, 1.0)
            .commit()?;

        // Making A a child of C would create A → B → C → A
        assert!(vault.would_create_cycle(&a, &c)?);

        // Making D a child of C is fine (D doesn't appear in C's ancestors)
        let d = EntityId::now();
        vault.put_entity(&d, 61, test_time_range(7, 7), 8, b"d")?;
        assert!(!vault.would_create_cycle(&d, &c)?);

        Ok(())
    }

    #[test]
    fn test_deep_ancestor_chain() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        // Build a 200-deep ChildOf chain: node[0] ← node[1] ← ... ← node[200]
        // (each node[i+1] --ChildOf--> node[i])
        const DEPTH: usize = 200;
        let mut nodes = Vec::with_capacity(DEPTH + 1);
        for _ in 0..=DEPTH {
            nodes.push(EntityId::now());
        }

        // Put all entities
        {
            let mut batch = vault.batch();
            for (i, node) in nodes.iter().enumerate() {
                batch = batch.put(
                    node,
                    61,
                    test_time_range(i as u64, i as u64),
                    i as u64 + 1,
                    format!("node-{i}").as_bytes(),
                );
            }
            // Build ChildOf edges: node[i+1] --ChildOf--> node[i]
            for i in 0..DEPTH {
                batch = batch.edge(&nodes[i + 1], EdgeKind::ChildOf, &nodes[i], 1.0);
            }
            batch.commit()?;
        }

        // ancestors(node[200]) should return all 200 ancestors: node[199], ..., node[0]
        let anc = vault.ancestors(&nodes[DEPTH])?;
        assert_eq!(
            anc.len(),
            DEPTH,
            "expected {DEPTH} ancestors, got {}",
            anc.len()
        );
        // Verify order: nearest first (node[199]) to root (node[0])
        for (i, ancestor) in anc.iter().enumerate() {
            assert_eq!(
                *ancestor,
                nodes[DEPTH - 1 - i],
                "ancestor at position {i} should be node[{}]",
                DEPTH - 1 - i
            );
        }

        // would_create_cycle: making node[0] a child of node[200] would create a cycle
        assert!(vault.would_create_cycle(&nodes[0], &nodes[DEPTH])?);

        // would_create_cycle: an unrelated node should not create a cycle
        let unrelated = EntityId::now();
        vault.put_entity(
            &unrelated,
            61,
            test_time_range(999, 999),
            1000,
            b"unrelated",
        )?;
        assert!(!vault.would_create_cycle(&unrelated, &nodes[DEPTH])?);

        Ok(())
    }

    #[test]
    fn belongs_to_edge_for_task_list_membership() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let project = EntityId::now();
        let task1 = EntityId::now();
        let task2 = EntityId::now();

        vault
            .batch()
            .put(&project, 60, test_time_range(1, 1), 2, b"proj")
            .put(&task1, 61, test_time_range(3, 3), 4, b"t1")
            .put(&task2, 61, test_time_range(5, 5), 6, b"t2")
            .edge(&task1, EdgeKind::BelongsTo, &project, 1.0)
            .edge(&task2, EdgeKind::BelongsTo, &project, 1.0)
            .commit()?;

        // Query: all tasks belonging to project (sources of BelongsTo)
        let members = vault.sources(&project, EdgeKind::BelongsTo, Some(61))?;
        assert_eq!(members.len(), 2);
        assert!(members.contains(&task1));
        assert!(members.contains(&task2));

        Ok(())
    }

    #[test]
    fn get_entity_type_returns_correct_type() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let tl = EntityId::now();
        let tk = EntityId::now();

        vault
            .batch()
            .put(&tl, 60, test_time_range(1, 1), 2, b"tl")
            .put(&tk, 61, test_time_range(3, 3), 4, b"tk")
            .commit()?;

        assert_eq!(vault.get_entity_type(&tl)?, Some(60));
        assert_eq!(vault.get_entity_type(&tk)?, Some(61));
        assert_eq!(vault.get_entity_type(&EntityId::now())?, None);
        Ok(())
    }

    #[test]
    fn child_of_has_no_ppr_hop_limit() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        // Build a 5-level deep ChildOf chain: a → b → c → d → e
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();
        let d = EntityId::now();
        let e = EntityId::now();

        vault
            .batch()
            .put(&a, 61, test_time_range(1, 1), 2, b"a")
            .put(&b, 61, test_time_range(3, 3), 4, b"b")
            .put(&c, 61, test_time_range(5, 5), 6, b"c")
            .put(&d, 61, test_time_range(7, 7), 8, b"d")
            .put(&e, 61, test_time_range(9, 9), 10, b"e")
            .edge(&b, EdgeKind::ChildOf, &a, 1.0)
            .edge(&c, EdgeKind::ChildOf, &b, 1.0)
            .edge(&d, EdgeKind::ChildOf, &c, 1.0)
            .edge(&e, EdgeKind::ChildOf, &d, 1.0)
            .commit()?;

        // PPR from e should reach a (5 hops via ChildOf, no limit)
        {
            let rtxn = vault.store.env.read_txn()?;
            let scores = ppr::ppr_compute(&vault.store, &rtxn, &[e], 6, 0.15)?;
            let a_score = scores
                .iter()
                .find(|s| s.id == a)
                .map(|s| s.score)
                .unwrap_or(0.0);
            assert!(
                a_score > 0.0,
                "ChildOf should propagate beyond 2 hops, got score={a_score}"
            );
        }

        // Compare with PartOf chain of same depth — d should be blocked at 3rd hop
        let p1 = EntityId::now();
        let p2 = EntityId::now();
        let p3 = EntityId::now();
        let p4 = EntityId::now();
        let p5 = EntityId::now();

        vault
            .batch()
            .put(&p1, 9, test_time_range(1, 1), 2, b"p1")
            .put(&p2, 9, test_time_range(3, 3), 4, b"p2")
            .put(&p3, 9, test_time_range(5, 5), 6, b"p3")
            .put(&p4, 9, test_time_range(7, 7), 8, b"p4")
            .put(&p5, 9, test_time_range(9, 9), 10, b"p5")
            .edge(&p2, EdgeKind::PartOf, &p1, 1.0)
            .edge(&p3, EdgeKind::PartOf, &p2, 1.0)
            .edge(&p4, EdgeKind::PartOf, &p3, 1.0)
            .edge(&p5, EdgeKind::PartOf, &p4, 1.0)
            .commit()?;

        {
            let rtxn = vault.store.env.read_txn()?;
            let part_of_scores = ppr::ppr_compute(&vault.store, &rtxn, &[p5], 6, 0.15)?;
            let p1_score = part_of_scores
                .iter()
                .find(|s| s.id == p1)
                .map(|s| s.score)
                .unwrap_or(0.0);
            // p1 is 4 PartOf hops from p5 — should be blocked (only 2 PartOf hops allowed)
            assert!(
                p1_score < 1e-6,
                "PartOf should block at 3rd hop, but p1 got score={p1_score}"
            );
        }

        Ok(())
    }

    #[test]
    fn child_of_survives_mixed_part_of_path() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        // Build a mixed path: place1 --PartOf--> place2 --PartOf--> place3 --ChildOf--> task
        // After 2 PartOf hops (place1→place3), the next edge is ChildOf.
        // Without the ChildOf exemption in PPR, this would be blocked at hop 3.
        let place1 = EntityId::now();
        let place2 = EntityId::now();
        let place3 = EntityId::now();
        let task = EntityId::now();

        vault
            .batch()
            .put(&place1, 9, test_time_range(1, 1), 2, b"p1") // Place
            .put(&place2, 9, test_time_range(3, 3), 4, b"p2")
            .put(&place3, 9, test_time_range(5, 5), 6, b"p3")
            .put(&task, 61, test_time_range(7, 7), 8, b"task")
            .edge(&place2, EdgeKind::PartOf, &place1, 1.0)
            .edge(&place3, EdgeKind::PartOf, &place2, 1.0)
            .edge(&task, EdgeKind::ChildOf, &place3, 1.0)
            .commit()?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr::ppr_compute(&vault.store, &rtxn, &[task], 6, 0.15)?;

        // place1 is reachable via: task --ChildOf--> place3 --PartOf--> place2 --PartOf--> place1
        // The ChildOf hop doesn't count, so only 2 PartOf hops (within limit).
        // Without the ChildOf exemption, hops would be 3 and place1 would be blocked.
        let place1_score = scores
            .iter()
            .find(|s| s.id == place1)
            .map(|s| s.score)
            .unwrap_or(0.0);
        assert!(
            place1_score > 0.0,
            "ChildOf should not count toward PartOf hop limit in mixed paths, got score={place1_score}"
        );

        Ok(())
    }

    #[test]
    fn edge_checked_detects_cycle_atomically() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        // Build: a → b → c (ChildOf chain)
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        vault
            .batch()
            .put(&a, 61, test_time_range(1, 1), 2, b"a")
            .put(&b, 61, test_time_range(3, 3), 4, b"b")
            .put(&c, 61, test_time_range(5, 5), 6, b"c")
            .edge(&b, EdgeKind::ChildOf, &a, 1.0)
            .edge(&c, EdgeKind::ChildOf, &b, 1.0)
            .commit()?;

        // Try to make a a child of c — would create cycle a→b→c→a
        let result = vault.batch().edge_checked(&a, &c, 1.0).commit();
        assert!(
            matches!(result, Err(Error::CycleDetected)),
            "expected CycleDetected, got {result:?}"
        );

        // Verify the rejected edge was not written
        assert!(
            !vault.edge_exists(&a, EdgeKind::ChildOf, &c)?,
            "cyclic edge should not have been persisted"
        );

        // Non-cyclic edge should succeed
        let d = EntityId::now();
        vault
            .batch()
            .put(&d, 61, test_time_range(7, 7), 8, b"d")
            .edge_checked(&d, &c, 1.0)
            .commit()?;

        // Verify d is a child of c
        let children = vault.sources(&c, EdgeKind::ChildOf, None)?;
        assert!(children.contains(&d));

        Ok(())
    }

    #[test]
    fn edge_checked_rejects_self_cycle() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let node = EntityId::now();

        vault
            .batch()
            .put(&node, 61, test_time_range(1, 1), 2, b"self")
            .commit()?;

        let result = vault.batch().edge_checked(&node, &node, 1.0).commit();
        assert!(
            matches!(result, Err(Error::CycleDetected)),
            "self-cycle should be rejected, got {result:?}"
        );
        assert!(
            !vault.edge_exists(&node, EdgeKind::ChildOf, &node)?,
            "self-cycle edge should not have been persisted"
        );

        Ok(())
    }

    #[test]
    fn subtree_excludes_root() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let root = EntityId::now();
        let child = EntityId::now();

        vault
            .batch()
            .put(&root, 61, test_time_range(1, 1), 2, b"root")
            .put(&child, 61, test_time_range(3, 3), 4, b"child")
            .edge(&child, EdgeKind::ChildOf, &root, 1.0)
            .commit()?;

        let tree = vault.subtree(&root, 10)?;
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].0, child);
        assert!(
            !tree.iter().any(|(id, _)| *id == root),
            "root should not appear in its own subtree"
        );

        Ok(())
    }
}
#[cfg(test)]
mod tests_bug;
