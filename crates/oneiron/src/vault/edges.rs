//! Vault edge writes, adjacency queries and graph traversal.

use super::Vault;
use crate::affect::Vad;

use crate::edge::{EdgeInfo, EdgeKind, parse_strict_edge_record};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::limits::{
    ERR_CHILD_OF_CYCLE_CHECK, MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS,
};
use crate::ports::EdgeDirection;
use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;
use crate::store::Store;

/// Length of the edge-kind prefix: `entity_id (16) | kind (1)`.
const EDGE_KIND_PREFIX_LEN: usize = ENTITY_ID_LEN + 1;

/// Contract stored-weight prior for `claim_of` edges (contracts.ts
/// `edgeKinds.pprWeight` = 1.0), unwrapped at COMPILE time: the writers below
/// hardwire kinds whose prior is pinned non-null, so a contract change to
/// `null` fails the build instead of the write.
pub(crate) const CLAIM_OF_DEFAULT_WEIGHT: f32 = match EdgeKind::ClaimOf.default_weight() {
    Some(weight) => weight,
    None => panic!("contract pins a non-null pprWeight for claim_of"),
};

/// Contract stored-weight prior for `supersedes` edges (contracts.ts
/// `edgeKinds.pprWeight` = 0.3); compile-time unwrapped like
/// [`CLAIM_OF_DEFAULT_WEIGHT`].
pub(crate) const SUPERSEDES_DEFAULT_WEIGHT: f32 = match EdgeKind::Supersedes.default_weight() {
    Some(weight) => weight,
    None => panic!("contract pins a non-null pprWeight for supersedes"),
};

/// Cap for `targets`/`sources` to prevent unbounded allocation.
pub(crate) const MAX_EDGE_QUERY_RESULTS: usize = 100_000;

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
    if let Some(entry) = store
        .port_edges(
            rtxn,
            node,
            crate::ports::EdgeDirection::Out,
            Some(EdgeKind::ChildOf),
            None,
        )?
        .next()
    {
        let edge_row = entry?;
        return Ok(Some(edge_row.target));
    }
    Ok(None)
}

/// Cap for `subtree` to prevent unbounded allocation on deep trees.
const MAX_SUBTREE_RESULTS: usize = 50_000;

/// Build an edge prefix `[entity_id | kind]` for targeted LMDB prefix scans.
/// Avoids scanning all edge kinds for a given entity.
pub(crate) fn edge_kind_prefix(id: &EntityId, kind: EdgeKind) -> [u8; EDGE_KIND_PREFIX_LEN] {
    let mut prefix = [0u8; EDGE_KIND_PREFIX_LEN];
    prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
    prefix[ENTITY_ID_LEN] = kind as u8;
    prefix
}

/// Parses one `edges_out` / `edges_in` row into an [`EdgeInfo`].
///
/// Compatibility wrapper over [`crate::edge::parse_strict_edge_record`] so
/// Vault and context-pack readers classify malformed edge rows identically.
pub(crate) fn parse_edge_record(key: &[u8], value: &[u8]) -> Result<EdgeInfo> {
    Ok(parse_strict_edge_record(key, value)?.into_edge_info())
}

impl Vault {
    // NOTE (ONE-1133): the bare non-txn `purge_entity_active_store` wrapper
    // was removed — both sync replay surfaces now route through the
    // reason-aware `apply_replayed_tombstone`, and a bare purge entry point
    // would be an invitation to bypass the ARCH-0038 reason semantics.

    // -----------------------------------------------------------------
    // ARCH-0050 R6 L2 code-memory doors (ONE-1608).
    //
    // Every wrapper here opens ONE transaction, delegates to the internal
    // `crate::code_memory` implementation, and commits exactly once on
    // success. None exposes `Store`, `RoTxn`, or `RwTxn`; the public
    // contract suite reaches only these methods.
    // -----------------------------------------------------------------

    // Read/write/list helpers intentionally remain behind `feature = "sync"`
    // instead of `cfg(test)` because the sync bridge regression suite is an
    // integration test crate. Production bridge code still uses direct
    // transactional `sync_state` access when multiple keys must update
    // atomically.

    // ─── Tree Query API ───────────────────────────────────────

    /// Stores a directed edge and its reverse index entry.
    ///
    /// `FacetOf` edges pass the commit-time type table (ONE-1645): the source
    /// must be an existing CLAIM, TURN, or EVENT and the target an existing
    /// FACET, or the commit fails closed with [`RegistryError::InvalidFacetOfEdge`](crate::error::RegistryError::InvalidFacetOfEdge)
    /// and writes nothing. Every other edge kind is unaffected.
    ///
    /// A stamp from ANY admitted source type can move a disclosure decision.
    /// The federation selector mirrors this SAME table on the read side: it
    /// honors a `FacetOf` row only when BOTH endpoints resolve onto it —
    /// source in `{CLAIM, TURN, EVENT}`, target proving FACET — resolving each
    /// endpoint's type STORED-FIRST, with the stored row winning outright over
    /// a conflicting document blob. So an EVENT- or TURN-sourced stamp to an
    /// unselected facet withholds that entity from a facet-limited peer even
    /// though the local query filter reads CLAIM-sourced stamps only, while an
    /// off-table stamp is scope-inert on both sides.
    pub fn put_edge(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            crate::ports::EdgeStore::port_edge_upsert(self, txn, src, kind, tgt, weight)
        })
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

    /// Operational weight setter (ONE-1113, ARCH-0034 #write-protection
    /// carve-out): rewrites ONLY the weight bytes (f32 LE at offset 0..4) of
    /// an EXISTING edge, writing IDENTICAL bytes to both `edges_out` and
    /// `edges_in`. Weight is a LOCAL operational field (M3 weight pin) — the
    /// provenance Claim asserts the relation, never the weight — so this
    /// setter works on bare AND provenanced edges alike, preserves the
    /// 26-byte hot-flag bytes verbatim, and never touches provenance Claims.
    /// Exempt from the [`ClaimError::EdgeIsProvenanced`](crate::error::ClaimError::EdgeIsProvenanced) reject gate by
    /// construction.
    ///
    /// For decay / retrieval-feedback loops use the batch form
    /// [`BatchBuilder::set_edge_weight`](crate::BatchBuilder::set_edge_weight).
    ///
    /// Fail-closed: [`Error::EdgeNotFound`] when the edge does not exist
    /// (the setter never upserts); [`Error::InvalidEdgeWeight`] outside the
    /// contract \[0, 1\]; [`RegistryError::ReservedEdgeKind`](crate::error::RegistryError::ReservedEdgeKind) on the redirect-shell
    /// kinds (`merged_into` / `split_into`) — a weight rewrite is a
    /// topology-effect mutation (PPR drops a zero-weight shell edge), so
    /// shell edges move only through the identity-topology door
    /// (ARCH-0055). PPR caches for the edge endpoints are invalidated
    /// exactly like a plain edge write.
    pub fn set_edge_weight(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
    ) -> Result<()> {
        self.batch()
            .set_edge_weight(src, kind, tgt, weight)
            .commit()
    }

    /// Operational VAD setter (ONE-1113, ARCH-0034 #write-protection
    /// carve-out): rewrites ONLY the VAD bytes (three f32 LE at offset
    /// 12..24) of an EXISTING semantic edge, writing IDENTICAL bytes to both
    /// directions. Weight, `created_at`, the value LENGTH (a 24-byte bare
    /// value stays 24 B; a 26-byte provenanced value keeps its hot-flag
    /// bytes verbatim), and provenance Claims are untouched. Exempt from the
    /// [`ClaimError::EdgeIsProvenanced`](crate::error::ClaimError::EdgeIsProvenanced) reject gate by construction.
    ///
    /// For batched feedback loops use [`BatchBuilder::set_edge_vad`](crate::BatchBuilder::set_edge_vad).
    ///
    /// Fail-closed: [`Error::EdgeNotFound`] when the edge does not exist;
    /// [`Error::InvalidVad`] on non-finite/out-of-range components; a typed
    /// rejection on structural 12-byte kinds (the contract layout table —
    /// structural edges carry no VAD); [`RegistryError::ReservedEdgeKind`](crate::error::RegistryError::ReservedEdgeKind) on the
    /// redirect-shell kinds (`merged_into` / `split_into`), same as every
    /// other public edge write (ARCH-0055).
    pub fn set_edge_vad(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        vad: Vad,
    ) -> Result<()> {
        self.batch().set_edge_vad(src, kind, tgt, vad).commit()
    }

    /// Deletes a directed edge and its reverse index entry.
    pub fn delete_edge(&self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Result<bool> {
        self.with_write_txn(|txn| {
            crate::ports::EdgeStore::port_edge_delete(self, txn, src, kind, tgt)
        })
    }

    /// Returns outbound edges for `src`.
    pub fn edges_out(&self, src: &EntityId) -> Result<Vec<EdgeInfo>> {
        let txn = self.store.env.read_txn()?;
        crate::ports::EdgeStore::port_edge_neighbors(
            self,
            &txn,
            src,
            crate::ports::EdgeDirection::Out,
            None,
            MAX_EDGE_QUERY_RESULTS,
        )
    }

    /// Returns inbound edges for `tgt`.
    pub fn edges_in(&self, tgt: &EntityId) -> Result<Vec<EdgeInfo>> {
        let txn = self.store.env.read_txn()?;
        crate::ports::EdgeStore::port_edge_neighbors(
            self,
            &txn,
            tgt,
            crate::ports::EdgeDirection::In,
            None,
            MAX_EDGE_QUERY_RESULTS,
        )
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
            crate::ports::EdgeDirection::Out,
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
            crate::ports::EdgeDirection::In,
            tgt,
            kind,
            source_type,
            "sources",
        )
    }

    /// Returns at most `limit` inbound edge sources after `after_source`.
    ///
    /// This is the bounded counterpart to [`Self::sources`]. Results follow
    /// the LMDB inbound edge key order `[target | kind | source]`, so
    /// `after_source` is an exclusive lower bound on the source entity id.
    pub fn sources_page(
        &self,
        tgt: &EntityId,
        kind: EdgeKind,
        source_type: Option<u8>,
        after_source: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        self.filtered_edge_peers_page(
            crate::ports::EdgeDirection::In,
            tgt,
            kind,
            source_type,
            after_source,
            limit,
        )
    }

    /// Scans an edge database (edges_out or edges_in) for entries matching `kind`,
    /// returning the peer entity IDs. Optionally filters by the peer's entity type.
    ///
    /// Capped at `MAX_EDGE_QUERY_RESULTS` scanned peer rows to prevent
    /// unbounded allocation and worst-case filtered scans.
    pub(crate) fn filtered_edge_peers(
        &self,
        rtxn: &heed::RoTxn<'_>,
        direction: EdgeDirection,
        prefix_id: &EntityId,
        kind: EdgeKind,
        peer_type: Option<u8>,
        overflow_context: &'static str,
    ) -> Result<Vec<EntityId>> {
        let mut ids = Vec::new();
        for (scanned, entry) in self
            .store
            .port_edges(rtxn, prefix_id, direction, Some(kind), None)?
            .enumerate()
        {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow(overflow_context));
            }
            let peer = entry?.target;

            if let Some(req_type) = peer_type
                && !self.entity_has_type(rtxn, &peer, req_type)?
            {
                continue;
            }

            ids.push(peer);
        }
        Ok(ids)
    }

    fn filtered_edge_peers_page(
        &self,
        direction: EdgeDirection,
        prefix_id: &EntityId,
        kind: EdgeKind,
        peer_type: Option<u8>,
        after_peer: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let limit = limit.min(MAX_EDGE_QUERY_RESULTS);
        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::with_capacity(limit.min(1024));
        for entry in
            self.store
                .port_edges(&rtxn, prefix_id, direction, Some(kind), after_peer.copied())?
        {
            let peer = entry?.target;

            if let Some(req_type) = peer_type
                && !self.entity_has_type(&rtxn, &peer, req_type)?
            {
                continue;
            }

            ids.push(peer);
            if ids.len() >= limit {
                break;
            }
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
        let Some(raw) = self.store.port_entity_record(rtxn, &id)? else {
            return Ok(false);
        };

        Ok(raw.entity_type == expected_type)
    }

    /// Bounded neighbor-edge scan for one direction with the kind and
    /// minimum-weight filters pushed into the LMDB prefix iterator, stopping
    /// after `limit` matches.
    ///
    /// Unlike [`Self::edges_out`]/[`Self::edges_in`] (which materialize every
    /// edge and error with [`Error::IndexOverflow`] past
    /// `MAX_EDGE_QUERY_RESULTS`), this walks only until `limit` matches accrue,
    /// so a high-degree node never allocates its full edge set. When `kind` is
    /// set the walk is further narrowed to the `[id | kind]` key span.
    pub(crate) fn neighbor_edges_bounded(
        &self,
        center: &EntityId,
        outbound: bool,
        kind: Option<EdgeKind>,
        min_weight: Option<f32>,
        limit: usize,
    ) -> Result<Vec<EdgeInfo>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let direction = if outbound {
            EdgeDirection::Out
        } else {
            EdgeDirection::In
        };
        let rtxn = self.store.env.read_txn()?;
        let mut edges = Vec::new();
        for entry in self
            .store
            .port_edges(&rtxn, center, direction, kind, None)?
        {
            let edge = entry?;
            if min_weight.is_some_and(|min| edge.weight < min) {
                continue;
            }
            edges.push(edge);
            if edges.len() >= limit {
                break;
            }
        }
        Ok(edges)
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

            for entry in self.store.port_edges(
                &rtxn,
                &node,
                crate::ports::EdgeDirection::In,
                Some(EdgeKind::ChildOf),
                None,
            )? {
                let edge_row = entry?;
                let child = edge_row.target;
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
    /// For atomic check+insert, use `would_create_cycle_in_txn` within a
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
    fn would_create_cycle_in_txn(
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
