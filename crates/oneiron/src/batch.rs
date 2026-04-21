use std::collections::{HashMap, HashSet, VecDeque};
use std::str;

use heed::RwTxn;
use xxhash_rust::xxh32::xxh32;

use crate::Vault;
use crate::error::{Error, Result};
use crate::ppr;
use crate::store::Store;
use crate::types::{
    EDGE_KEY_LEN, EDGE_VALUE_LEN, ENTITY_ID_LEN, EdgeKind, EntityId, TimeRange, Vad, parse_vad,
    short_id_prefix,
};

pub(crate) const ENTITY_METADATA_HEADER_LEN: usize = 25;
pub(crate) const SHORT_ID_COUNTER_LEN: usize = 8;
pub(crate) const LONG_INTERVAL_THRESHOLD_SECS: u64 = 14 * 86_400;

#[derive(Debug, Clone, Copy)]
pub(crate) struct EntityMetadataHeader {
    pub(crate) entity_type: u8,
    pub(crate) occurred_start: u64,
    pub(crate) occurred_end: u64,
    pub(crate) learned_at: u64,
}

impl EntityMetadataHeader {
    pub(crate) fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return None;
        }

        let entity_type = raw[0];
        let occurred_start = u64::from_be_bytes(raw[1..9].try_into().ok()?);
        let occurred_end = u64::from_be_bytes(raw[9..17].try_into().ok()?);
        let learned_at = u64::from_be_bytes(raw[17..25].try_into().ok()?);

        Some(Self {
            entity_type,
            occurred_start,
            occurred_end,
            learned_at,
        })
    }
}

/// Builder for atomic multi-database write batches.
#[must_use = "BatchBuilder performs no writes until `.commit()` is called"]
pub struct BatchBuilder<'a> {
    vault: &'a Vault,
    ops: Vec<BatchOp>,
    validation_error: Option<Error>,
}

#[derive(Clone)]
pub(crate) enum BatchOp {
    Put {
        id: EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: Vec<u8>,
    },
    Vector {
        id: EntityId,
        vector: Vec<f32>,
    },
    Edge {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
        weight: f32,
        vad: Vad,
    },
    EdgeWithCreatedAt {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
        weight: f32,
        created_at: u64,
        vad: Vad,
    },
    Text {
        id: EntityId,
        fields: Vec<(String, String)>,
    },
    Phonetic {
        id: EntityId,
        codes: Vec<String>,
    },
    Delete {
        id: EntityId,
    },
    DeleteEdge {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
    },
}

impl<'a> BatchBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            ops: Vec::new(),
            validation_error: None,
        }
    }

    /// Adds an entity put operation to the batch.
    ///
    /// Validates `entity_type` eagerly via [`short_id_prefix`]. If validation
    /// fails, the error is stored and surfaced on [`commit()`](Self::commit).
    pub fn put(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = short_id_prefix(entity_type)
        {
            self.validation_error = Some(e);
        }
        self.ops.push(BatchOp::Put {
            id: *id,
            entity_type,
            occurred,
            learned_at,
            data: data.to_vec(),
        });
        self
    }

    /// Adds a vector write operation to the batch.
    pub fn vector(mut self, id: &EntityId, vector: &[f32]) -> Self {
        self.ops.push(BatchOp::Vector {
            id: *id,
            vector: vector.to_vec(),
        });
        self
    }

    /// Adds a graph edge write operation to the batch.
    pub fn edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId, weight: f32) -> Self {
        self.ops.push(BatchOp::Edge {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            vad: Vad::NEUTRAL,
        });
        self
    }

    /// Adds a ChildOf edge write operation.
    ///
    /// All `ChildOf` writes are validated atomically during commit/apply to
    /// enforce single-parent tree semantics and reject cycles.
    pub fn edge_checked(self, src: &EntityId, tgt: &EntityId, weight: f32) -> Self {
        self.edge(src, EdgeKind::ChildOf, tgt, weight)
    }

    /// Adds a graph edge with explicit VAD scores to the batch.
    pub fn edge_with_vad(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        vad: Vad,
    ) -> Self {
        self.ops.push(BatchOp::Edge {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            vad,
        });
        self
    }

    /// Adds a graph edge with an explicit `created_at` timestamp.
    ///
    /// Used by the sync bridge to preserve CRDT edge timestamps exactly,
    /// bypassing the default `unix_seconds_now()`.
    pub fn edge_with_created_at(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        created_at: u64,
    ) -> Self {
        self.ops.push(BatchOp::EdgeWithCreatedAt {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            created_at,
            vad: Vad::NEUTRAL,
        });
        self
    }

    /// Adds a graph edge with explicit `created_at` and VAD scores.
    pub fn edge_with_created_at_and_vad(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        created_at: u64,
        vad: Vad,
    ) -> Self {
        self.ops.push(BatchOp::EdgeWithCreatedAt {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            created_at,
            vad,
        });
        self
    }

    /// Adds a text indexing operation to the batch.
    pub fn text(mut self, id: &EntityId, fields: &[(&str, &str)]) -> Self {
        self.ops.push(BatchOp::Text {
            id: *id,
            fields: fields
                .iter()
                .map(|(f, v)| ((*f).to_owned(), (*v).to_owned()))
                .collect(),
        });
        self
    }

    /// Adds a phonetic indexing operation to the batch.
    pub fn phonetic(mut self, id: &EntityId, codes: &[&str]) -> Self {
        self.ops.push(BatchOp::Phonetic {
            id: *id,
            codes: codes.iter().map(|c| (*c).to_owned()).collect(),
        });
        self
    }

    /// Adds a full entity delete/deindex operation to the batch.
    pub fn delete(mut self, id: &EntityId) -> Self {
        self.ops.push(BatchOp::Delete { id: *id });
        self
    }

    /// Adds an edge delete operation to the batch.
    pub fn delete_edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Self {
        self.ops.push(BatchOp::DeleteEdge {
            src: *src,
            kind,
            tgt: *tgt,
        });
        self
    }

    /// Commits all queued operations atomically in a single LMDB write transaction.
    ///
    /// Returns any validation error captured during `put()` before opening
    /// the LMDB write transaction, avoiding unnecessary I/O on bad input.
    pub fn commit(self) -> Result<()> {
        if let Some(err) = self.validation_error {
            return Err(err);
        }
        let mut wtxn = self.vault.store.env.write_txn()?;

        apply_ops(&self.vault.store, &self.vault.config, &mut wtxn, self.ops)?;
        wtxn.commit()?;
        Ok(())
    }
}

/// Builder for batch writes into an externally-owned LMDB write transaction.
///
/// Created by [`Vault::batch_in`]. Writes are applied via [`apply()`](TxnBatchBuilder::apply)
/// without committing — the caller controls transaction commit via `with_write_txn`.
#[must_use = "TxnBatchBuilder performs no writes until `.apply()` is called"]
pub struct TxnBatchBuilder<'a> {
    vault: &'a Vault,
    ops: Vec<BatchOp>,
}

impl<'a> TxnBatchBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            ops: Vec::new(),
        }
    }

    /// Adds an entity put operation.
    pub fn put(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        self.ops.push(BatchOp::Put {
            id: *id,
            entity_type,
            occurred,
            learned_at,
            data: data.to_vec(),
        });
        self
    }

    /// Adds a graph edge write operation.
    pub fn edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId, weight: f32) -> Self {
        self.ops.push(BatchOp::Edge {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            vad: Vad::NEUTRAL,
        });
        self
    }

    /// Adds a graph edge with explicit `created_at` timestamp.
    pub fn edge_with_created_at(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        created_at: u64,
    ) -> Self {
        self.ops.push(BatchOp::EdgeWithCreatedAt {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            created_at,
            vad: Vad::NEUTRAL,
        });
        self
    }

    /// Adds a graph edge with explicit `created_at` and VAD scores.
    pub fn edge_with_created_at_and_vad(
        mut self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        created_at: u64,
        vad: Vad,
    ) -> Self {
        self.ops.push(BatchOp::EdgeWithCreatedAt {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
            created_at,
            vad,
        });
        self
    }

    /// Adds an edge delete operation to the batch.
    pub fn delete_edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Self {
        self.ops.push(BatchOp::DeleteEdge {
            src: *src,
            kind,
            tgt: *tgt,
        });
        self
    }

    /// Applies all queued operations to the given write transaction without committing.
    pub fn apply(self, wtxn: &mut RwTxn<'_>) -> Result<()> {
        apply_ops(&self.vault.store, &self.vault.config, wtxn, self.ops)
    }
}

/// Applies a list of batch operations to an LMDB write transaction.
pub(crate) fn apply_ops(
    store: &Store,
    config: &crate::types::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    ops: Vec<BatchOp>,
) -> Result<()> {
    let child_of_overlay = ChildOfBatchOverlay::from_ops(&ops);
    validate_child_of_batch(store, &*wtxn, &child_of_overlay)?;
    let mut had_graph_mutation = false;
    let mut had_vector_mutation = false;

    for op in ops {
        match op {
            BatchOp::Put {
                id,
                entity_type,
                occurred,
                learned_at,
                data,
            } => {
                apply_put(store, wtxn, id, entity_type, occurred, learned_at, &data)?;
            }
            BatchOp::Vector { id, vector } => {
                apply_vector(store, config, wtxn, id, &vector)?;
                crate::hnsw::hnsw_insert(store, config, wtxn, &id, &vector)?;
                had_vector_mutation = true;
            }
            BatchOp::Edge {
                src,
                kind,
                tgt,
                weight,
                vad,
            } => {
                apply_edge(store, wtxn, src, kind, tgt, weight, vad)?;
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            BatchOp::EdgeWithCreatedAt {
                src,
                kind,
                tgt,
                weight,
                created_at,
                vad,
            } => {
                apply_edge_with_created_at(store, wtxn, src, kind, tgt, weight, created_at, vad)?;
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                had_graph_mutation = true;
            }
            BatchOp::Text { id, fields } => {
                crate::bm25::index_text(store, wtxn, &id, &fields)?;
            }
            BatchOp::Phonetic { id, codes } => {
                apply_phonetic(store, wtxn, id, &codes)?;
            }
            BatchOp::Delete { id } => {
                let (_existed, had_vector, deleted_graph_state, neighbors) =
                    deindex_entity(store, wtxn, &id)?;
                ppr::invalidate_ppr_for_delete(store, wtxn, &id, &neighbors)?;
                had_graph_mutation |= deleted_graph_state;
                had_vector_mutation |= had_vector;
            }
            BatchOp::DeleteEdge { src, kind, tgt } => {
                if apply_delete_edge(store, wtxn, src, kind, tgt)? {
                    ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                    had_graph_mutation = true;
                }
            }
        }
    }

    if had_graph_mutation {
        ppr::increment_graph_version(store, wtxn)?;
    }
    if had_vector_mutation {
        crate::hnsw::increment_vector_version(store, wtxn)?;
    }

    Ok(())
}

#[derive(Debug, Default)]
struct ChildOfBatchOverlay {
    entity_clears: HashMap<EntityId, usize>,
    edge_ops: HashMap<(EntityId, EntityId), (usize, bool)>,
    edge_candidates: HashMap<EntityId, HashSet<EntityId>>,
}

impl ChildOfBatchOverlay {
    fn from_ops(ops: &[BatchOp]) -> Self {
        let mut overlay = Self::default();

        for (index, op) in ops.iter().enumerate() {
            match op {
                BatchOp::Edge { src, kind, tgt, .. }
                | BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. }
                    if *kind == EdgeKind::ChildOf =>
                {
                    overlay.edge_ops.insert((*src, *tgt), (index, true));
                    overlay
                        .edge_candidates
                        .entry(*src)
                        .or_default()
                        .insert(*tgt);
                }
                BatchOp::DeleteEdge { src, kind, tgt } if *kind == EdgeKind::ChildOf => {
                    overlay.edge_ops.insert((*src, *tgt), (index, false));
                    overlay
                        .edge_candidates
                        .entry(*src)
                        .or_default()
                        .insert(*tgt);
                }
                BatchOp::Delete { id } => {
                    overlay.entity_clears.insert(*id, index);
                }
                _ => {}
            }
        }

        overlay
    }

    fn final_edge_override(&self, child: &EntityId, parent: &EntityId) -> Option<bool> {
        let clear_seq = self
            .entity_clears
            .get(child)
            .copied()
            .into_iter()
            .chain(self.entity_clears.get(parent).copied())
            .max();
        let edge_seq = self.edge_ops.get(&(*child, *parent)).copied();

        match (clear_seq, edge_seq) {
            (Some(clear_seq), Some((op_seq, present))) if op_seq > clear_seq => Some(present),
            (Some(_), _) => Some(false),
            (None, Some((_, present))) => Some(present),
            (None, None) => None,
        }
    }

    fn effective_parents(
        &self,
        store: &Store,
        rtxn: &heed::RoTxn<'_>,
        child: &EntityId,
    ) -> Result<HashSet<EntityId>> {
        let mut parents = HashSet::new();
        let prefix = child_of_prefix(child);

        for entry in store.edges_out.prefix_iter(rtxn, &prefix)? {
            let (key, value) = entry?;
            validate_edge_record(key, value)?;
            let parent = EntityId::from_bytes(
                key[17..33]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("edge record"))?,
            )
            .map_err(|_| Error::CorruptedIndex("edge record"))?;

            if self.final_edge_override(child, &parent).unwrap_or(true) {
                parents.insert(parent);
            }
        }

        if let Some(candidates) = self.edge_candidates.get(child) {
            for parent in candidates {
                if self.final_edge_override(child, parent) == Some(true) {
                    parents.insert(*parent);
                }
            }
        }

        Ok(parents)
    }

    fn affected_children(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.edge_candidates.keys().copied()
    }
}

pub(crate) fn deindex_entity(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, bool, bool, Vec<EntityId>)> {
    // Clean secondary indexes unconditionally — they may exist even without an
    // entity record (e.g. text indexed via batch().text() without a preceding put()).
    crate::bm25::deindex_text(store, wtxn, id)?;
    delete_from_phonetic_postings(store, wtxn, id)?;
    let had_vector = store.vectors.delete(wtxn, id.as_bytes())?;
    crate::hnsw::hnsw_deindex(store, wtxn, id)?;
    let neighbors = delete_related_edges(store, wtxn, id)?;
    let mut had_graph_mutation = !neighbors.is_empty();

    if let Some(raw) = store.short_ids.get(wtxn, id.as_bytes())? {
        let (short_id, _) = parse_short_id_value(raw)?;
        let short_id = short_id.to_owned();
        store.short_ids_reverse.delete(wtxn, short_id.as_bytes())?;
        store.short_ids.delete(wtxn, id.as_bytes())?;
    }

    let Some(entity_record) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok((false, had_vector, had_graph_mutation, neighbors));
    };
    had_graph_mutation = true;

    let (entity_type, occurred, learned_at) = parse_entity_metadata(entity_record)?;
    let type_key = Store::encode_type_key(entity_type, id);
    store.type_index.delete(wtxn, &type_key)?;

    let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
    store
        .temporal_occurred_start
        .delete(wtxn, &occurred_start_key)?;
    if occurred.start != occurred.end {
        let occurred_end_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_occurred_end
            .delete(wtxn, &occurred_end_key)?;
    }
    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let long_interval_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_long_intervals
            .delete(wtxn, &long_interval_key)?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, id);
    store.temporal_learned.delete(wtxn, &learned_key)?;

    store.entities.delete(wtxn, id.as_bytes())?;
    Ok((true, had_vector, had_graph_mutation, neighbors))
}

fn apply_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
) -> Result<()> {
    short_id_prefix(entity_type)?;
    let short_id_plan = plan_short_id_update(store, &*wtxn, &id, entity_type, data)?;

    let mut occurred = occurred;
    if occurred.start > occurred.end {
        std::mem::swap(&mut occurred.start, &mut occurred.end);
    }

    if let Some(old_record) = store.entities.get(wtxn, id.as_bytes())? {
        let (old_type, old_occurred, old_learned) = parse_entity_metadata(old_record)?;
        if old_occurred.end.saturating_sub(old_occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
            let old_long_interval_key = Store::encode_temporal_key(old_occurred.end, &id);
            store
                .temporal_long_intervals
                .delete(wtxn, &old_long_interval_key)?;
        }

        if old_type != entity_type {
            let old_type_key = Store::encode_type_key(old_type, &id);
            store.type_index.delete(wtxn, &old_type_key)?;
        }

        if old_occurred.start != occurred.start {
            let old_start_key = Store::encode_temporal_key(old_occurred.start, &id);
            store.temporal_occurred_start.delete(wtxn, &old_start_key)?;
        }

        let old_is_range = old_occurred.start != old_occurred.end;
        let new_is_range = occurred.start != occurred.end;
        if old_is_range && (!new_is_range || old_occurred.end != occurred.end) {
            let old_end_key = Store::encode_temporal_key(old_occurred.end, &id);
            store.temporal_occurred_end.delete(wtxn, &old_end_key)?;
        }

        if old_learned != learned_at {
            let old_learned_key = Store::encode_temporal_key(old_learned, &id);
            store.temporal_learned.delete(wtxn, &old_learned_key)?;
        }
    }

    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(entity_type);
    payload.extend_from_slice(&occurred.start.to_be_bytes());
    payload.extend_from_slice(&occurred.end.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(data);

    store.entities.put(wtxn, id.as_bytes(), &payload)?;

    let type_key = Store::encode_type_key(entity_type, &id);
    store.type_index.put(wtxn, &type_key, &[])?;

    let occurred_start_key = Store::encode_temporal_key(occurred.start, &id);
    store
        .temporal_occurred_start
        .put(wtxn, &occurred_start_key, &[])?;

    if occurred.start != occurred.end {
        let occurred_end_key = Store::encode_temporal_key(occurred.end, &id);
        store
            .temporal_occurred_end
            .put(wtxn, &occurred_end_key, &[])?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, &id);
    store.temporal_learned.put(wtxn, &learned_key, &[])?;

    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let long_interval_key = Store::encode_temporal_key(occurred.end, &id);
        let occurred_start_value = occurred.start.to_be_bytes();
        store
            .temporal_long_intervals
            .put(wtxn, &long_interval_key, &occurred_start_value)?;
    }

    apply_short_id_plan(store, wtxn, &id, short_id_plan)?;
    Ok(())
}

fn apply_vector(
    store: &Store,
    config: &crate::types::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    vector: &[f32],
) -> Result<()> {
    if vector.len() != config.dimensions {
        return Err(Error::DimensionMismatch {
            expected: config.dimensions,
            got: vector.len(),
        });
    }
    if vector.iter().any(|value| !value.is_finite()) {
        return Err(Error::InvalidVector);
    }

    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for v in vector {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    store.vectors.put(wtxn, id.as_bytes(), &bytes)?;
    Ok(())
}

fn apply_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
    vad: Vad,
) -> Result<()> {
    apply_edge_with_created_at(
        store,
        wtxn,
        src,
        kind,
        tgt,
        weight,
        crate::unix_seconds_now(),
        vad,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "decomposing would obscure direct LMDB write logic"
)]
fn apply_edge_with_created_at(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
    created_at: u64,
    vad: Vad,
) -> Result<()> {
    if !weight.is_finite() {
        return Err(Error::InvalidEdgeWeight);
    }
    if !vad.is_finite() || !vad.is_in_range() {
        return Err(Error::InvalidVad);
    }

    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let value = encode_edge_value(weight, created_at, vad);
    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    Ok(())
}

fn validate_child_of_batch(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    child_of_overlay: &ChildOfBatchOverlay,
) -> Result<()> {
    for child in child_of_overlay.affected_children() {
        let parents = child_of_overlay.effective_parents(store, rtxn, &child)?;
        if parents.len() > 1 {
            return Err(Error::InvariantViolation(
                "childof requires a single parent",
            ));
        }
        if let Some(parent) = parents.iter().next() {
            if child == *parent {
                return Err(Error::CycleDetected);
            }
            if would_create_child_of_cycle(store, rtxn, child_of_overlay, &child, parent)? {
                return Err(Error::CycleDetected);
            }
        }
    }

    Ok(())
}

fn would_create_child_of_cycle(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    child_of_overlay: &ChildOfBatchOverlay,
    child: &EntityId,
    proposed_parent: &EntityId,
) -> Result<bool> {
    let mut frontier = VecDeque::new();
    frontier.push_back(*proposed_parent);
    let mut visited = HashSet::new();
    visited.insert(*proposed_parent);

    while let Some(node) = frontier.pop_front() {
        for parent in child_of_overlay.effective_parents(store, rtxn, &node)? {
            if parent == *child {
                return Ok(true);
            }
            if visited.insert(parent) {
                frontier.push_back(parent);
            }
        }
    }

    Ok(false)
}

fn child_of_prefix(id: &EntityId) -> [u8; 17] {
    let mut prefix = [0u8; 17];
    prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
    prefix[ENTITY_ID_LEN] = EdgeKind::ChildOf as u8;
    prefix
}

fn apply_delete_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<bool> {
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let deleted_out = store.edges_out.delete(wtxn, &key_out)?;
    let _deleted_in = store.edges_in.delete(wtxn, &key_in)?;
    Ok(deleted_out)
}

fn apply_phonetic(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    codes: &[String],
) -> Result<()> {
    let mut forward_codes = match store.phonetic_forward.get(wtxn, id.as_bytes())? {
        Some(raw) => match decode_phonetic_forward_codes(raw) {
            Ok(codes) => codes,
            Err(Error::CorruptedIndex(_)) => Vec::new(),
            Err(err) => return Err(err),
        },
        None => Vec::new(),
    };
    let mut forward_changed = false;

    for code in codes {
        validate_phonetic_code(code)?;
        let existing = store.phonetic_index.get(wtxn, code.as_bytes())?;
        let mut posting =
            existing.map_or_else(|| Vec::with_capacity(ENTITY_ID_LEN), |bytes| bytes.to_vec());
        if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
            return Err(Error::CorruptedIndex("phonetic posting"));
        }

        if posting
            .chunks_exact(ENTITY_ID_LEN)
            .any(|chunk| chunk == id.as_bytes())
        {
            if !forward_codes.iter().any(|known| known == code) {
                forward_codes.push(code.clone());
                forward_changed = true;
            }
            continue;
        }

        posting.extend_from_slice(id.as_bytes());
        store.phonetic_index.put(wtxn, code.as_bytes(), &posting)?;

        if !forward_codes.iter().any(|known| known == code) {
            forward_codes.push(code.clone());
            forward_changed = true;
        }
    }

    if forward_changed {
        forward_codes.sort();
        forward_codes.dedup();
        let encoded = encode_phonetic_forward_codes(&forward_codes);
        store.phonetic_forward.put(wtxn, id.as_bytes(), &encoded)?;
    }

    Ok(())
}

enum ShortIdPlan {
    UpdateExisting {
        short_id: String,
        content_hash: u8,
    },
    InsertNew {
        sentinel_key: [u8; ENTITY_ID_LEN],
        next_counter: u64,
        short_id: String,
        content_hash: u8,
    },
}

fn plan_short_id_update(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    data: &[u8],
) -> Result<ShortIdPlan> {
    let content_hash = (xxh32(data, 0) % 256) as u8;

    if let Some(existing) = store.short_ids.get(txn, id.as_bytes())? {
        let (short_id, _) = parse_short_id_value(existing)?;
        return Ok(ShortIdPlan::UpdateExisting {
            short_id: short_id.to_owned(),
            content_hash,
        });
    }

    let sentinel_key = short_id_counter_sentinel(entity_type);
    let current = match store.short_ids.get(txn, &sentinel_key)? {
        Some(raw) => {
            let buf: [u8; SHORT_ID_COUNTER_LEN] = raw
                .try_into()
                .map_err(|_| Error::CorruptedIndex("short id counter"))?;
            u64::from_le_bytes(buf)
        }
        None => 0,
    };

    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("short id counter"))?;
    let short_id = format!("{}{}", short_id_prefix(entity_type)?, next);
    Ok(ShortIdPlan::InsertNew {
        sentinel_key,
        next_counter: next,
        short_id,
        content_hash,
    })
}

fn apply_short_id_plan(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    plan: ShortIdPlan,
) -> Result<()> {
    match plan {
        ShortIdPlan::UpdateExisting {
            short_id,
            content_hash,
        } => {
            let mut value = Vec::with_capacity(short_id.len() + 1);
            value.extend_from_slice(short_id.as_bytes());
            value.push(content_hash);
            store.short_ids.put(wtxn, id.as_bytes(), &value)?;
        }
        ShortIdPlan::InsertNew {
            sentinel_key,
            next_counter,
            short_id,
            content_hash,
        } => {
            store
                .short_ids
                .put(wtxn, &sentinel_key, &next_counter.to_le_bytes())?;

            let mut short_id_value = Vec::with_capacity(short_id.len() + 1);
            short_id_value.extend_from_slice(short_id.as_bytes());
            short_id_value.push(content_hash);

            store.short_ids.put(wtxn, id.as_bytes(), &short_id_value)?;
            store
                .short_ids_reverse
                .put(wtxn, short_id.as_bytes(), id.as_bytes())?;
        }
    }

    Ok(())
}

fn short_id_counter_sentinel(entity_type: u8) -> [u8; ENTITY_ID_LEN] {
    debug_assert_ne!(
        entity_type, 0xFF,
        "0xFF is reserved for short-id sentinel keys"
    );
    let mut key = [0xFF_u8; ENTITY_ID_LEN];
    key[0] = entity_type;
    key
}

pub(crate) fn parse_short_id_value(value: &[u8]) -> Result<(&str, u8)> {
    if value.len() < 2 {
        return Err(Error::CorruptedIndex("short id value"));
    }

    let (short_id_bytes, hash_bytes) = value.split_at(value.len() - 1);
    let short_id =
        str::from_utf8(short_id_bytes).map_err(|_| Error::CorruptedIndex("short id value"))?;
    Ok((short_id, hash_bytes[0]))
}

fn parse_entity_metadata(record: &[u8]) -> Result<(u8, TimeRange, u64)> {
    let header =
        EntityMetadataHeader::parse(record).ok_or(Error::CorruptedIndex("entity metadata"))?;

    Ok((
        header.entity_type,
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
    ))
}

fn delete_related_edges(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut outbound = Vec::new();
    for entry in store.edges_out.prefix_iter(wtxn, id.as_bytes())? {
        let (key, value) = entry?;
        validate_edge_record(key, value)?;
        let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::CorruptedIndex("edge record"))?;
        let target = EntityId::from_bytes(
            key[17..33]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("edge record"))?,
        )
        .map_err(|_| Error::CorruptedIndex("edge record"))?;
        outbound.push((kind, target));
    }

    for (kind, target) in &outbound {
        let out_key = Store::encode_edge_key(id, *kind, target);
        let in_key = Store::encode_edge_key(target, *kind, id);
        store.edges_out.delete(wtxn, &out_key)?;
        store.edges_in.delete(wtxn, &in_key)?;
    }

    let mut inbound = Vec::new();
    for entry in store.edges_in.prefix_iter(wtxn, id.as_bytes())? {
        let (key, value) = entry?;
        validate_edge_record(key, value)?;
        let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::CorruptedIndex("edge record"))?;
        let source = EntityId::from_bytes(
            key[17..33]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("edge record"))?,
        )
        .map_err(|_| Error::CorruptedIndex("edge record"))?;
        inbound.push((kind, source));
    }

    for (kind, source) in &inbound {
        let in_key = Store::encode_edge_key(id, *kind, source);
        let out_key = Store::encode_edge_key(source, *kind, id);
        store.edges_in.delete(wtxn, &in_key)?;
        store.edges_out.delete(wtxn, &out_key)?;
    }

    let mut neighbors: Vec<EntityId> = outbound
        .into_iter()
        .map(|(_, id)| id)
        .chain(inbound.into_iter().map(|(_, id)| id))
        .collect();
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok(neighbors)
}

fn delete_from_phonetic_postings(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    if let Some(raw) = store.phonetic_forward.get(wtxn, id.as_bytes())? {
        match decode_phonetic_forward_codes(raw) {
            Ok(codes) => match delete_from_known_phonetic_codes(store, wtxn, id, &codes) {
                Ok(()) => {
                    if reconcile_phonetic_postings(store, wtxn, id)? {
                        log_phonetic_forward_fallback(id, "stale_forward_row");
                    }
                    store.phonetic_forward.delete(wtxn, id.as_bytes())?;
                    return Ok(());
                }
                Err(Error::MissingPostingEntry) => {
                    log_phonetic_forward_fallback(id, "missing_posting_entry");
                }
                Err(err) => return Err(err),
            },
            Err(Error::CorruptedIndex(_)) => {
                log_phonetic_forward_fallback(id, "corrupted_forward_row");
            }
            Err(err) => return Err(err),
        }
    }

    let mut updates = Vec::new();
    let mut deletes = Vec::new();

    for entry in store.phonetic_index.iter(wtxn)? {
        let (code, posting) = entry?;
        let Some(updated) = posting_without_entity(posting, id)? else {
            continue;
        };

        if updated.is_empty() {
            deletes.push(code.to_vec());
        } else {
            updates.push((code.to_vec(), updated));
        }
    }

    for code in deletes {
        store.phonetic_index.delete(wtxn, &code)?;
    }

    for (code, posting) in updates {
        store.phonetic_index.put(wtxn, &code, &posting)?;
    }

    store.phonetic_forward.delete(wtxn, id.as_bytes())?;
    Ok(())
}

fn log_phonetic_forward_fallback(id: &EntityId, reason: &'static str) {
    tracing::warn!(
        entity = %id.to_hex(),
        reason,
        "phonetic_forward unavailable during delete; falling back to full scan"
    );
}

fn delete_from_known_phonetic_codes(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    codes: &[String],
) -> Result<()> {
    for code in codes {
        let posting = store
            .phonetic_index
            .get(wtxn, code.as_bytes())?
            .ok_or(Error::MissingPostingEntry)?;
        let updated = posting_without_entity(posting, id)?.ok_or(Error::MissingPostingEntry)?;

        if updated.is_empty() {
            store.phonetic_index.delete(wtxn, code.as_bytes())?;
        } else {
            store.phonetic_index.put(wtxn, code.as_bytes(), &updated)?;
        }
    }

    Ok(())
}

fn validate_phonetic_code(code: &str) -> Result<()> {
    if code.is_empty() || code.as_bytes().contains(&0) {
        return Err(Error::InvalidKey);
    }

    Ok(())
}

fn posting_without_entity(posting: &[u8], id: &EntityId) -> Result<Option<Vec<u8>>> {
    if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
        return Err(Error::CorruptedIndex("phonetic posting"));
    }

    let retained: Vec<u8> = posting
        .chunks_exact(ENTITY_ID_LEN)
        .filter(|chunk| *chunk != id.as_bytes())
        .flat_map(|chunk| chunk.iter().copied())
        .collect();

    Ok((retained.len() != posting.len()).then_some(retained))
}

fn reconcile_phonetic_postings(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<bool> {
    let mut repaired = false;
    let mut updates = Vec::new();
    let mut deletes = Vec::new();

    for entry in store.phonetic_index.iter(wtxn)? {
        let (code, posting) = entry?;
        let Some(updated) = posting_without_entity(posting, id)? else {
            continue;
        };

        repaired = true;
        if updated.is_empty() {
            deletes.push(code.to_vec());
        } else {
            updates.push((code.to_vec(), updated));
        }
    }

    for code in deletes {
        store.phonetic_index.delete(wtxn, &code)?;
    }

    for (code, posting) in updates {
        store.phonetic_index.put(wtxn, &code, &posting)?;
    }

    Ok(repaired)
}

fn decode_phonetic_forward_codes(raw: &[u8]) -> Result<Vec<String>> {
    if raw.is_empty() {
        return Err(Error::CorruptedIndex("phonetic forward row"));
    }

    let mut codes: Vec<String> = raw
        .split(|b| *b == 0)
        .map(|chunk| {
            if chunk.is_empty() {
                return Err(Error::CorruptedIndex("phonetic forward row"));
            }
            str::from_utf8(chunk)
                .map(str::to_owned)
                .map_err(|_| Error::CorruptedIndex("phonetic forward row"))
        })
        .collect::<Result<_>>()?;
    codes.sort();
    codes.dedup();
    Ok(codes)
}

fn encode_phonetic_forward_codes(codes: &[String]) -> Vec<u8> {
    codes.join("\0").into_bytes()
}

fn validate_edge_record(key: &[u8], value: &[u8]) -> Result<()> {
    if key.len() != EDGE_KEY_LEN || value.len() != EDGE_VALUE_LEN {
        return Err(Error::CorruptedIndex("edge record"));
    }

    if EdgeKind::try_from_u8(key[16]).is_none() {
        return Err(Error::CorruptedIndex("edge record"));
    }

    let weight = f32::from_le_bytes(value[..4].try_into().unwrap());
    if !weight.is_finite() {
        return Err(Error::CorruptedIndex("edge record"));
    }
    let vad = parse_vad(value);
    if !vad.is_finite() || !vad.is_in_range() {
        return Err(Error::CorruptedIndex("edge record"));
    }

    Ok(())
}

fn encode_edge_value(weight: f32, created_at: u64, vad: Vad) -> [u8; EDGE_VALUE_LEN] {
    let mut value = [0_u8; EDGE_VALUE_LEN];
    value[..4].copy_from_slice(&weight.to_le_bytes());
    value[4..12].copy_from_slice(&created_at.to_le_bytes());
    value[12..16].copy_from_slice(&vad.valence.to_le_bytes());
    value[16..20].copy_from_slice(&vad.arousal.to_le_bytes());
    value[20..24].copy_from_slice(&vad.dominance.to_le_bytes());
    value
}
