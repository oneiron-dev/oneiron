//! Top-level `Vault` API: the crate's main entry point for all LMDB-backed
//! entity / vector / edge / text / temporal operations. Also hosts the private
//! edge-record helpers used exclusively by Vault methods.

use std::path::Path;

use heed::Database;
use heed::types::Bytes;

use crate::analyzer::{AnalyzerChannel, AnalyzerManifest, AnalyzerMode, MultilingualAnalyzer};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, deindex_entity};
use crate::error::{Error, Result};
use crate::limits::{
    ERR_CHILD_OF_CYCLE_CHECK, MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS,
};
use crate::store::{
    Store, TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_ANALYZER_MANIFEST_KEY,
    TEXT_BM25_FIELD_SCHEMA_HASH_KEY, TEXT_INDEX_SCHEMA_VERSION, TEXT_INDEX_SCHEMA_VERSION_KEY,
};
use crate::types::{
    EDGE_KEY_LEN, EDGE_VALUE_LEN, ENTITY_ID_LEN, EdgeInfo, EdgeKind, EntityId, ScoredEntity,
    TimeRange, Vad, VaultConfig, parse_vad,
};
use crate::{
    BatchBuilder, ContextPackBuilder, MaintenanceBuilder, PipelineBuilder, TxnBatchBuilder, bm25,
    hnsw, le_bytes_to_f32_vec, ppr,
};

const MIN_MAP_SIZE_BYTES: usize = 1 << 20;

/// Length of the edge-kind prefix: `entity_id (16) | kind (1)`.
const EDGE_KIND_PREFIX_LEN: usize = ENTITY_ID_LEN + 1;

/// Cap for `entities_by_type` to prevent unbounded allocation on large indexes.
const MAX_TYPE_QUERY_RESULTS: usize = 100_000;

/// Cap for `entities_in_learned_range` to prevent unbounded allocation on
/// wide time-range queries. Distinct from `MAX_TYPE_QUERY_RESULTS` so the two
/// APIs can be tuned independently.
const MAX_LEARNED_RANGE_RESULTS: usize = 100_000;

/// Cap for `targets`/`sources` to prevent unbounded allocation.
const MAX_EDGE_QUERY_RESULTS: usize = 100_000;

/// Cap for `subtree` to prevent unbounded allocation on deep trees.
const MAX_SUBTREE_RESULTS: usize = 50_000;

/// Cap for `sync_state_keys_with_prefix` to prevent unbounded allocation when
/// a pathological prefix scans a very large sync_state database.
#[cfg(feature = "sync")]
const MAX_SYNC_STATE_KEYS: usize = 10_000;

/// Build an edge prefix `[entity_id | kind]` for targeted LMDB prefix scans.
/// Avoids scanning all edge kinds for a given entity.
fn edge_kind_prefix(id: &EntityId, kind: EdgeKind) -> [u8; EDGE_KIND_PREFIX_LEN] {
    let mut prefix = [0u8; EDGE_KIND_PREFIX_LEN];
    prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
    prefix[ENTITY_ID_LEN] = kind as u8;
    prefix
}

fn require_key_len(key: &[u8], expected: usize, context: &'static str) -> Result<()> {
    if key.len() != expected {
        return Err(Error::CorruptedIndex(context));
    }
    Ok(())
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
    if let Some(entry) = store.edges_out.prefix_iter(rtxn, &prefix)?.next() {
        let (key, value) = entry?;
        return Ok(Some(parse_edge_record(key, value)?.target));
    }
    Ok(None)
}

/// Main vault API wrapping LMDB storage and configuration.
pub struct Vault {
    pub(crate) store: Store,
    pub(crate) config: VaultConfig,
    pub(crate) analyzer: MultilingualAnalyzer,
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
        let analyzer = MultilingualAnalyzer::discover(&config.dict_search_paths)
            .map_err(|e| Error::AnalyzerError(e.to_string()))?;
        if !config.skip_text_index_manifest_check {
            handshake_text_index_manifest(&store, &analyzer)?;
        }

        Ok(Self {
            store,
            config,
            analyzer,
        })
    }

    /// Current text-index status. `analyzer_manifest` reflects the analyzer
    /// this vault was opened with; `schema_version` and `total_docs` reflect
    /// what was persisted by prior writes.
    pub fn text_index_status(&self) -> Result<TextIndexStatus> {
        let rtxn = self.store.env.read_txn()?;
        let total_docs = bm25::read_total_docs(&self.store, &rtxn)?;
        let schema_version = read_text_schema_version(&self.store, &rtxn)?;
        Ok(TextIndexStatus {
            total_docs,
            schema_version,
            analyzer_manifest: self.analyzer.manifest(),
        })
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
            return Err(Error::CorruptedIndex("entity header"));
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
            // Persisted-data corruption — the LMDB row decoded to a vector
            // whose length does not match the configured dimensionality.
            // Distinct from `DimensionMismatch`, which is reserved for
            // caller input validation in `search_vector` / `index_vector`.
            return Err(Error::CorruptedIndex("vector value"));
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
        let key_in = Store::encode_edge_key(tgt, kind, src);

        self.with_write_txn(|wtxn| {
            let existed_out = self.store.edges_out.delete(wtxn, &key_out)?;
            let deleted_in = self.store.edges_in.delete(wtxn, &key_in)?;

            if !existed_out {
                // Inbound-only rows are opportunistic cleanup for an inconsistent
                // reverse index and do not affect the outbound graph PPR uses.
                let _ = deleted_in;
                return Ok(false);
            }

            ppr::invalidate_ppr_for_edge(&self.store, wtxn, src, tgt)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
            Ok(true)
        })
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
        bm25::search_text(
            &self.store,
            &rtxn,
            &self.analyzer,
            &bm25::Bm25Config::default(),
            query,
            limit,
        )
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
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
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
            require_key_len(key, 24, "temporal learned key")?;
            let ts = u64::from_be_bytes(
                key[..8]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            );
            if ts < start {
                continue;
            }
            if ts >= end {
                break; // temporal keys are sorted by timestamp (BE), so we can stop
            }
            // Cap check BEFORE push so an exact-MAX result set returns Ok,
            // matching scan_edges semantics. Only an MAX+1-th in-range row
            // triggers IndexOverflow. See ONE-336 for the range-seek perf
            // fix that lifts the cap.
            if ids.len() >= MAX_LEARNED_RANGE_RESULTS {
                return Err(Error::IndexOverflow("entities_in_learned_range"));
            }
            let id = EntityId::from_bytes(
                key[8..24]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?;
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
            // Cap check BEFORE push — matches scan_edges semantics.
            if keys.len() >= MAX_SYNC_STATE_KEYS {
                return Err(Error::IndexOverflow("sync_state_keys_with_prefix"));
            }
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
    /// Returns all matching entity IDs, or `Err(IndexOverflow("entities_by_type"))`
    /// if the scan would exceed `MAX_TYPE_QUERY_RESULTS`.
    pub fn entities_by_type(&self, entity_type: u8) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        for entry in self.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
            if ids.len() >= MAX_TYPE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("entities_by_type"));
            }
            let (key, _) = entry?;
            require_key_len(key, 17, "type index key")?;
            let id = EntityId::from_bytes(
                key[1..17]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("type index key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("type index key"))?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// Returns the entity type byte for a stored entity, or None if not found.
    pub fn get_entity_type(&self, id: &EntityId) -> Result<Option<u8>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(Some(header.entity_type))
    }

    /// Outbound edge targets filtered by kind and optional target entity type.
    ///
    /// For a ChildOf edge (child → parent), calling `targets(child, ChildOf, None)`
    /// returns the parent.
    pub fn targets(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        target_type: Option<u8>,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.filtered_edge_peers(
            &rtxn,
            &self.store.edges_out,
            src,
            kind,
            target_type,
            "targets",
        )
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
        self.filtered_edge_peers(
            &rtxn,
            &self.store.edges_in,
            tgt,
            kind,
            source_type,
            "sources",
        )
    }

    /// Scans an edge database (edges_out or edges_in) for entries matching `kind`,
    /// returning the peer entity IDs. Optionally filters by the peer's entity type.
    ///
    /// Capped at `MAX_EDGE_QUERY_RESULTS` scanned peer rows to prevent
    /// unbounded allocation and worst-case filtered scans.
    fn filtered_edge_peers(
        &self,
        rtxn: &heed::RoTxn<'_>,
        db: &Database<Bytes, Bytes>,
        prefix_id: &EntityId,
        kind: EdgeKind,
        peer_type: Option<u8>,
        overflow_context: &'static str,
    ) -> Result<Vec<EntityId>> {
        let prefix = edge_kind_prefix(prefix_id, kind);
        let mut ids = Vec::new();
        for (scanned, entry) in db.prefix_iter(rtxn, &prefix)?.enumerate() {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow(overflow_context));
            }
            let (key, value) = entry?;
            let peer = parse_edge_record(key, value)?.target;

            if let Some(req_type) = peer_type
                && !self.entity_has_type(rtxn, &peer, req_type)?
            {
                continue;
            }

            ids.push(peer);
        }
        Ok(ids)
    }

    /// Returns true if the entity exists and has the given type byte.
    ///
    /// Returns `Ok(false)` for missing entities or unparsable headers (corruption).
    /// This is intentional for edge filtering: a corrupted peer should be skipped,
    /// not fail the entire query. Compare with `get_entity_type()` which returns
    /// `Err(CorruptedIndex("entity header"))` on corruption — appropriate for
    /// direct lookups where the caller should know about data issues.
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
    /// Returns all descendants, or `Err(IndexOverflow("subtree"))` if the
    /// result set or pending frontier would exceed `MAX_SUBTREE_RESULTS`.
    pub fn subtree(&self, root: &EntityId, max_depth: u32) -> Result<Vec<(EntityId, u32)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut result = Vec::new();
        let mut frontier = std::collections::VecDeque::from([(*root, 0_u32)]);
        let mut visited = std::collections::HashSet::new();
        visited.insert(*root);

        while let Some((node, depth)) = frontier.pop_front() {
            if depth > 0 {
                if result.len() >= MAX_SUBTREE_RESULTS {
                    return Err(Error::IndexOverflow("subtree"));
                }
                result.push((node, depth));
            }
            if depth >= max_depth {
                continue;
            }

            // Find children: inbound ChildOf edges (child --ChildOf--> node)
            let child_prefix = edge_kind_prefix(&node, EdgeKind::ChildOf);
            for entry in self.store.edges_in.prefix_iter(&rtxn, &child_prefix)? {
                let (key, value) = entry?;
                let child = parse_edge_record(key, value)?.target;
                if visited.insert(child) {
                    if result.len() + frontier.len() >= MAX_SUBTREE_RESULTS {
                        return Err(Error::IndexOverflow("subtree"));
                    }
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
    /// The `visited` set prevents infinite loops on corrupted cyclic data, and
    /// `MAX_ANCESTOR_DEPTH` bounds pathological acyclic chains.
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
            if result.len() >= MAX_ANCESTOR_DEPTH {
                return Err(Error::IndexOverflow("ancestors"));
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
    /// The `visited` set prevents infinite loops on corrupted cyclic data, and
    /// `MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS` bounds pathological acyclic chains.
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
        let mut traversed_steps = 0usize;

        while let Some(parent) = first_child_of_parent(&self.store, rtxn, &current)? {
            if traversed_steps >= MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS {
                return Err(Error::IndexOverflow(ERR_CHILD_OF_CYCLE_CHECK));
            }
            traversed_steps += 1;
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

fn scan_edges(
    database: &Database<Bytes, Bytes>,
    rtxn: &heed::RoTxn<'_>,
    prefix: &[u8; 16],
) -> Result<Vec<EdgeInfo>> {
    let mut edges = Vec::new();
    for entry in database.prefix_iter(rtxn, prefix.as_slice())? {
        if edges.len() >= MAX_EDGE_QUERY_RESULTS {
            // Fail loud — sync mirror paths (replay_pending_mirrors,
            // reverse_rematerialize) must not silently truncate edges
            // for high-degree nodes.
            return Err(Error::IndexOverflow("scan_edges"));
        }
        let (key, value) = entry?;
        edges.push(parse_edge_record(key, value)?);
    }
    Ok(edges)
}

/// Snapshot of a vault's text-index state. Returned from
/// [`Vault::text_index_status`].
#[derive(Debug, Clone)]
pub struct TextIndexStatus {
    /// Number of logical documents currently indexed.
    pub total_docs: u32,
    /// Schema version recorded on disk. `None` for vaults with no text
    /// index writes yet.
    pub schema_version: Option<u16>,
    /// Analyzer manifest resolved at open time (reflects dict discovery
    /// against `VaultConfig.dict_search_paths`).
    pub analyzer_manifest: AnalyzerManifest,
}

/// Canonical hash over the ordered list of BM25F channels currently
/// compiled into the analyzer. Changes when the channel set is added to,
/// removed from, or renumbered — in other words, when the posting binary
/// layout is no longer compatible with older indexes.
fn bm25_field_schema_hash() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for channel in AnalyzerChannel::ALL_V1 {
        h.update(channel.as_str().as_bytes());
        h.update(b"|");
    }
    h.finalize().into()
}

fn read_text_schema_version(store: &Store, rtxn: &heed::RoTxn<'_>) -> Result<Option<u16>> {
    let Some(raw) = store.vault_meta.get(rtxn, TEXT_INDEX_SCHEMA_VERSION_KEY)? else {
        return Ok(None);
    };
    let bytes: [u8; 2] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("text schema version"))?;
    Ok(Some(u16::from_le_bytes(bytes)))
}

/// Validate the on-disk analyzer manifest against the in-memory one. Runs
/// once at `Vault::open`. States are handled per plan ONE-317 §4.2:
///
/// * empty index, any stored state → rewrite manifest, proceed
/// * non-empty, matching hashes → proceed
/// * non-empty, field schema mismatch → `Bm25FieldSchemaChanged`
/// * non-empty, manifest hash mismatch → `IncompatibleAnalyzer` naming the
///   first language whose mode flipped (or `*` when the stored manifest is
///   absent / unparseable, i.e. pre-ONE-317 vault)
fn handshake_text_index_manifest(store: &Store, analyzer: &MultilingualAnalyzer) -> Result<()> {
    let current_manifest = analyzer.manifest();
    let current_manifest_hash = current_manifest
        .canonical_hash()
        .map_err(|e| Error::AnalyzerError(format!("manifest hash: {e}")))?;
    let current_field_schema_hash = bm25_field_schema_hash();

    let mut wtxn = store.env.write_txn()?;
    let total_docs = bm25::read_total_docs(store, &wtxn)?;

    if total_docs == 0 {
        // Empty text index — safe to (re)write the manifest. Clears any
        // stale pre-ONE-317 metadata by overwriting the known keys.
        write_text_index_manifest(store, &mut wtxn, analyzer)?;
        wtxn.commit()?;
        return Ok(());
    }

    let stored_manifest_hash = store
        .vault_meta
        .get(&wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?
        .map(|b| b.to_vec());
    let stored_field_schema_hash = store
        .vault_meta
        .get(&wtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?
        .map(|b| b.to_vec());
    let stored_manifest_bytes = store
        .vault_meta
        .get(&wtxn, TEXT_ANALYZER_MANIFEST_KEY)?
        .map(|b| b.to_vec());

    let Some(stored_hash) = stored_manifest_hash else {
        // Pre-ONE-317 vault with docs in it: fail closed.
        return Err(Error::IncompatibleAnalyzer {
            lang: "*".to_owned(),
            stored_mode: "unknown",
            current_mode: AnalyzerMode::Portable.as_str(),
        });
    };

    // A present manifest with a missing field-schema hash signals partial
    // corruption, not schema evolution — route it to IncompatibleAnalyzer.
    match stored_field_schema_hash {
        Some(hash) if hash == current_field_schema_hash => {}
        Some(_) => return Err(Error::Bm25FieldSchemaChanged),
        None => {
            return Err(Error::IncompatibleAnalyzer {
                lang: "*".to_owned(),
                stored_mode: "corrupt",
                current_mode: "any",
            });
        }
    }

    if stored_hash == current_manifest_hash {
        return Ok(());
    }

    // Manifest hash changed. Try to name the specific language whose mode
    // flipped; fall back to `*` if the stored manifest doesn't parse.
    if let Some(bytes) = stored_manifest_bytes
        && let Ok(stored) = serde_json::from_slice::<AnalyzerManifest>(&bytes)
    {
        for (lang, current_policy) in &current_manifest.langs {
            if let Some(stored_policy) = stored.langs.get(lang)
                && stored_policy.mode != current_policy.mode
            {
                return Err(Error::IncompatibleAnalyzer {
                    lang: lang.clone(),
                    stored_mode: stored_policy.mode.as_str(),
                    current_mode: current_policy.mode.as_str(),
                });
            }
        }
    }

    Err(Error::IncompatibleAnalyzer {
        lang: "*".to_owned(),
        stored_mode: "mismatched",
        current_mode: "mismatched",
    })
}

/// Write the current analyzer manifest + field-schema hash + schema
/// version into `vault_meta`. Used by open-on-empty-index and by
/// `MaintenanceBuilder::clear_text_index`.
pub(crate) fn write_text_index_manifest(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
) -> Result<()> {
    let manifest = analyzer.manifest();
    let manifest_json = manifest
        .canonical_json()
        .map_err(|e| Error::AnalyzerError(format!("manifest json: {e}")))?;
    let manifest_hash = manifest
        .canonical_hash()
        .map_err(|e| Error::AnalyzerError(format!("manifest hash: {e}")))?;
    let field_schema_hash = bm25_field_schema_hash();

    store.vault_meta.put(
        wtxn,
        TEXT_INDEX_SCHEMA_VERSION_KEY,
        &TEXT_INDEX_SCHEMA_VERSION.to_le_bytes(),
    )?;
    store
        .vault_meta
        .put(wtxn, TEXT_ANALYZER_MANIFEST_KEY, manifest_json.as_bytes())?;
    store
        .vault_meta
        .put(wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY, &manifest_hash)?;
    store
        .vault_meta
        .put(wtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY, &field_schema_hash)?;
    Ok(())
}

fn parse_edge_record(key: &[u8], value: &[u8]) -> Result<EdgeInfo> {
    if key.len() != EDGE_KEY_LEN || value.len() != EDGE_VALUE_LEN {
        return Err(Error::CorruptedIndex("edge record"));
    }

    let kind =
        EdgeKind::try_from_u8(key[ENTITY_ID_LEN]).ok_or(Error::CorruptedIndex("edge record"))?;
    let target = EntityId::from_bytes(
        key[EDGE_KIND_PREFIX_LEN..EDGE_KEY_LEN]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("edge record"))?,
    )
    .map_err(|_| Error::CorruptedIndex("edge record"))?;
    let weight = f32::from_le_bytes(
        value[..4]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("edge record"))?,
    );
    let created_at = u64::from_le_bytes(
        value[4..12]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("edge record"))?,
    );
    let vad = parse_vad(value);
    if !weight.is_finite() {
        return Err(Error::CorruptedIndex("edge record"));
    }
    if !vad.is_finite() || !vad.is_in_range() {
        return Err(Error::CorruptedIndex("edge record"));
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
    use std::path::PathBuf;

    use super::*;
    use crate::store::{
        TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_ANALYZER_MANIFEST_KEY,
        TEXT_BM25_FIELD_SCHEMA_HASH_KEY, TEXT_INDEX_SCHEMA_VERSION_KEY,
    };
    use crate::types::{HnswConfig, TextAnalyzerConfig, TimeRange, VaultConfig};

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
            text_analyzer: TextAnalyzerConfig::default(),
            dict_search_paths: Vec::<PathBuf>::new(),
            skip_text_index_manifest_check: false,
        }
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes_unchecked([byte; ENTITY_ID_LEN])
    }

    fn range(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    #[test]
    fn new_empty_vault_writes_manifest_keys() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let vault = Vault::open(tmp.path(), test_config())?;

        let status = vault.text_index_status()?;
        assert_eq!(status.total_docs, 0);
        assert_eq!(status.schema_version, Some(2));
        assert!(!status.analyzer_manifest.channels.is_empty());

        let rtxn = vault.store.env.read_txn()?;
        for key in [
            TEXT_INDEX_SCHEMA_VERSION_KEY,
            TEXT_ANALYZER_MANIFEST_KEY,
            TEXT_ANALYZER_MANIFEST_HASH_KEY,
            TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
        ] {
            assert!(
                vault.store.vault_meta.get(&rtxn, key)?.is_some(),
                "missing handshake key {:?}",
                std::str::from_utf8(key).unwrap(),
            );
        }
        Ok(())
    }

    #[test]
    fn reopen_same_manifest_preserves_text_index() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(11);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
            assert_eq!(vault.search_text("hello", 10)?.len(), 1);
        }

        let vault = Vault::open(tmp.path(), test_config())?;
        assert_eq!(vault.search_text("hello", 10)?.len(), 1);
        Ok(())
    }

    #[test]
    fn reopen_missing_manifest_on_populated_vault_fails_closed() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(21);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
        }

        // Simulate a pre-ONE-317 populated vault by deleting the handshake
        // hash key while leaving text_postings populated.
        {
            let vault = Vault::open(tmp.path(), test_config())?;
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .vault_meta
                .delete(&mut wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?;
            wtxn.commit()?;
        }

        let err = match Vault::open(tmp.path(), test_config()) {
            Ok(_) => panic!("expected Vault::open to fail"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::IncompatibleAnalyzer { .. }),
            "expected IncompatibleAnalyzer, got {err:?}",
        );
        Ok(())
    }

    #[test]
    fn field_schema_hash_mismatch_fails_closed() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(31);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
        }

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .vault_meta
                .put(&mut wtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY, &[0xEE; 32])?;
            wtxn.commit()?;
        }

        let err = match Vault::open(tmp.path(), test_config()) {
            Ok(_) => panic!("expected Vault::open to fail"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::Bm25FieldSchemaChanged),
            "expected Bm25FieldSchemaChanged, got {err:?}",
        );
        Ok(())
    }

    #[test]
    fn analyzer_manifest_hash_mismatch_fails_closed() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(41);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
        }

        // Overwrite the stored manifest hash to simulate a dict mode flip.
        {
            let vault = Vault::open(tmp.path(), test_config())?;
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .vault_meta
                .put(&mut wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY, &[0xCC; 32])?;
            wtxn.commit()?;
        }

        let err = match Vault::open(tmp.path(), test_config()) {
            Ok(_) => panic!("expected Vault::open to fail"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::IncompatibleAnalyzer { .. }),
            "expected IncompatibleAnalyzer, got {err:?}",
        );
        Ok(())
    }

    #[test]
    fn skip_manifest_check_unblocks_clear_text_index_recovery() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(61);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
        }

        // Corrupt the analyzer manifest hash so a normal open fails closed.
        {
            let vault = Vault::open(tmp.path(), test_config())?;
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .vault_meta
                .put(&mut wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY, &[0xAB; 32])?;
            wtxn.commit()?;
        }

        assert!(matches!(
            Vault::open(tmp.path(), test_config()),
            Err(Error::IncompatibleAnalyzer { .. })
        ));

        // Bypass the handshake just long enough to rebuild.
        {
            let mut cfg = test_config();
            cfg.skip_text_index_manifest_check = true;
            let vault = Vault::open(tmp.path(), cfg)?;
            vault.maintain().clear_text_index().run()?;
        }

        // Normal open now succeeds — clear_text_index rewrote the manifest.
        let vault = Vault::open(tmp.path(), test_config())?;
        assert_eq!(vault.text_index_status()?.total_docs, 0);
        Ok(())
    }

    #[test]
    fn text_index_status_reflects_indexed_docs() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let vault = Vault::open(tmp.path(), test_config())?;
        let a = entity(51);
        let b = entity(52);

        vault
            .batch()
            .put(&a, 0, range(1, 1), 1, b"a")
            .put(&b, 0, range(1, 1), 1, b"b")
            .text(&a, &[("body", "first")])
            .text(&b, &[("body", "second")])
            .commit()?;

        assert_eq!(vault.text_index_status()?.total_docs, 2);
        Ok(())
    }
}
