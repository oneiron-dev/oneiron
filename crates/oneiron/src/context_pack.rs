#[cfg(test)]
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::time::Instant;

use heed::RoTxn;

use crate::batch::{EntityMetadataHeader, ENTITY_METADATA_HEADER_LEN};
use crate::error::{Error, Result};
use crate::pipeline::PipelineBuilder;
use crate::serialize::{serialize_pack, SerializeConfig};
use crate::store::Store;
use crate::types::{
    parse_vad, ContextEntity, ContextPack, EdgeInfo, EntityId, FieldProfile, PackFormat, PackStats,
    Signal, TemporalAnchorMode, TemporalGranularity, TimeRange, TokenAllocation, EDGE_KEY_LEN,
    EDGE_VALUE_LEN,
};
use crate::{le_bytes_to_f32_vec, Vault};

const DEFAULT_MAX_NEIGHBORS: usize = 50;
const DEFAULT_TOKEN_BUDGET: usize = 4000;
const DEFAULT_MAX_FIELD_CHARS: usize = 500;
const MAX_EDGE_HOP: u32 = 5;
const MAX_CONTEXT_NEIGHBORS: usize = 1000;
#[cfg(test)]
thread_local! {
    static EDGE_SCAN_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Default)]
struct EdgeWalkResult {
    neighbor_ids: Vec<EntityId>,
    scanned_edges: HashMap<EntityId, Vec<EdgeInfo>>,
}

#[derive(Clone, Copy)]
struct HydrateOptions<'a> {
    hydrate_fields: bool,
    include_edges: bool,
    include_vectors: bool,
    edge_cache: Option<&'a HashMap<EntityId, Vec<EdgeInfo>>>,
}

pub struct ContextPackBuilder<'a> {
    pipeline: PipelineBuilder<'a>,
    vault: &'a Vault,
    hydrate: bool,
    include_edges: bool,
    edge_hop: u32,
    max_neighbors: usize,
    include_vectors: bool,
    include_stats: bool,
    merge_neighbors: bool,
    format: PackFormat,
    field_profile: FieldProfile,
    token_budget: usize,
    token_allocation: TokenAllocation,
    max_field_chars: usize,
    signals_used: Vec<Signal>,
}

impl<'a> ContextPackBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            pipeline: vault.query(),
            vault,
            hydrate: true,
            include_edges: false,
            edge_hop: 0,
            max_neighbors: DEFAULT_MAX_NEIGHBORS,
            include_vectors: false,
            include_stats: false,
            merge_neighbors: true,
            format: PackFormat::default(),
            field_profile: FieldProfile::default(),
            token_budget: DEFAULT_TOKEN_BUDGET,
            token_allocation: TokenAllocation::default(),
            max_field_chars: DEFAULT_MAX_FIELD_CHARS,
            signals_used: Vec::new(),
        }
    }

    pub fn search_vector(mut self, vector: &[f32], limit: usize) -> Self {
        self.pipeline = self.pipeline.search_vector(vector, limit);
        self.signals_used.push(Signal::Vector);
        self
    }

    pub fn search_text(mut self, query: &str, limit: usize) -> Self {
        self.pipeline = self.pipeline.search_text(query, limit);
        self.signals_used.push(Signal::Text);
        self
    }

    pub fn search_phonetic(mut self, codes: &[&str]) -> Self {
        self.pipeline = self.pipeline.search_phonetic(codes);
        self.signals_used.push(Signal::Phonetic);
        self
    }

    pub fn search_temporal(mut self, anchor_start: u64, anchor_end: u64, limit: usize) -> Self {
        self.pipeline = self
            .pipeline
            .search_temporal(anchor_start, anchor_end, limit);
        self.signals_used.push(Signal::Temporal);
        self
    }

    pub fn search_temporal_with_sigma(
        mut self,
        anchor_start: u64,
        anchor_end: u64,
        sigma_secs: u64,
        anchor_mode: TemporalAnchorMode,
        limit: usize,
    ) -> Self {
        self.pipeline = self.pipeline.search_temporal_with_sigma(
            anchor_start,
            anchor_end,
            sigma_secs,
            anchor_mode,
            limit,
        );
        self.signals_used.push(Signal::Temporal);
        self
    }

    pub fn search_temporal_with_granularity(
        mut self,
        anchor_start: u64,
        anchor_end: u64,
        granularity: TemporalGranularity,
        anchor_mode: TemporalAnchorMode,
        limit: usize,
    ) -> Self {
        self.pipeline = self.pipeline.search_temporal_with_granularity(
            anchor_start,
            anchor_end,
            granularity,
            anchor_mode,
            limit,
        );
        self.signals_used.push(Signal::Temporal);
        self
    }

    pub fn search_temporal_bitemporal(
        mut self,
        occurred_start: u64,
        occurred_end: u64,
        learned_start: u64,
        learned_end: u64,
        sigma_secs: u64,
        limit: usize,
    ) -> Self {
        self.pipeline = self.pipeline.search_temporal_bitemporal(
            occurred_start,
            occurred_end,
            learned_start,
            learned_end,
            sigma_secs,
            limit,
        );
        self.signals_used.push(Signal::Temporal);
        self
    }

    pub fn temporal_adaptive(mut self, enabled: bool) -> Self {
        self.pipeline = self.pipeline.temporal_adaptive(enabled);
        self
    }

    pub fn search(
        mut self,
        query: &str,
        vector: &[f32],
        time: Option<TimeRange>,
        limit: usize,
    ) -> Self {
        self.pipeline = self.pipeline.search(query, vector, time, limit);
        self.signals_used.push(Signal::Text);
        self.signals_used.push(Signal::Vector);
        if time.is_some() {
            self.signals_used.push(Signal::Temporal);
        }
        self
    }

    pub fn search_ppr(mut self, seeds: &[EntityId], depth: u32) -> Self {
        self.pipeline = self.pipeline.search_ppr(seeds, depth);
        self.signals_used.push(Signal::Ppr);
        self
    }

    pub fn expand_ppr(mut self, seeds: &[EntityId], depth: u32) -> Self {
        self.pipeline = self.pipeline.expand_ppr(seeds, depth);
        self.signals_used.push(Signal::Ppr);
        self
    }

    pub fn boost_recency(mut self, half_life_days: f32) -> Self {
        self.pipeline = self.pipeline.boost_recency(half_life_days);
        self
    }

    pub fn boost_salience(mut self) -> Self {
        self.pipeline = self.pipeline.boost_salience();
        self
    }

    pub fn boost_confidence(mut self) -> Self {
        self.pipeline = self.pipeline.boost_confidence();
        self
    }

    pub fn boost_contiguity(mut self) -> Self {
        self.pipeline = self.pipeline.boost_contiguity();
        self
    }

    pub fn filter_types(mut self, types: &[u8]) -> Self {
        self.pipeline = self.pipeline.filter_types(types);
        self
    }

    pub fn filter_since(mut self, timestamp: u64) -> Self {
        self.pipeline = self.pipeline.filter_since(timestamp);
        self
    }

    pub fn filter_occurred_range(mut self, start: u64, end: u64) -> Self {
        self.pipeline = self.pipeline.filter_occurred_range(start, end);
        self
    }

    pub fn filter_learned_range(mut self, start: u64, end: u64) -> Self {
        self.pipeline = self.pipeline.filter_learned_range(start, end);
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.pipeline = self.pipeline.limit(n);
        self
    }

    pub fn hydrate(mut self, yes: bool) -> Self {
        self.hydrate = yes;
        self
    }

    pub fn include_edges(mut self, yes: bool) -> Self {
        self.include_edges = yes;
        self
    }

    pub fn edge_hop(mut self, depth: u32) -> Self {
        self.edge_hop = depth.min(MAX_EDGE_HOP);
        self
    }

    pub fn max_neighbors(mut self, n: usize) -> Self {
        self.max_neighbors = n.min(MAX_CONTEXT_NEIGHBORS);
        self
    }

    pub fn include_vectors(mut self, yes: bool) -> Self {
        self.include_vectors = yes;
        self
    }

    pub fn include_stats(mut self, yes: bool) -> Self {
        self.include_stats = yes;
        self
    }

    pub fn merge_neighbors(mut self, yes: bool) -> Self {
        self.merge_neighbors = yes;
        self
    }

    pub fn format(mut self, fmt: PackFormat) -> Self {
        self.format = fmt;
        self
    }

    pub fn field_profile(mut self, profile: FieldProfile) -> Self {
        self.field_profile = profile;
        self
    }

    pub fn token_budget(mut self, budget: usize) -> Self {
        self.token_budget = budget;
        self
    }

    pub fn token_allocation(mut self, allocation: TokenAllocation) -> Self {
        self.token_allocation = allocation;
        self
    }

    pub fn max_field_chars(mut self, max: usize) -> Self {
        self.max_field_chars = max;
        self
    }

    pub fn run(self) -> Result<ContextPack> {
        let started = Instant::now();
        let scored = self.pipeline.run()?;

        let rtxn = self.vault.store.env.read_txn()?;
        let hydrate_result_edges = self.include_edges && self.edge_hop == 0;
        let result_options = HydrateOptions {
            hydrate_fields: self.hydrate,
            include_edges: hydrate_result_edges,
            include_vectors: self.include_vectors,
            edge_cache: None,
        };

        let mut results = Vec::with_capacity(scored.len());
        for entry in scored.iter().copied() {
            let Some(entity) =
                hydrate_entity(self.vault, &rtxn, entry.id, entry.score, result_options)?
            else {
                continue;
            };
            results.push(entity);
        }

        let seed_ids: Vec<EntityId> = results.iter().map(|entity| entity.id).collect();
        let result_ids: HashSet<EntityId> = seed_ids.iter().copied().collect();
        let edge_walk = if self.edge_hop > 0 && self.max_neighbors > 0 {
            walk_edges(
                &self.vault.store,
                &rtxn,
                &seed_ids,
                self.edge_hop,
                self.max_neighbors,
                &result_ids,
            )?
        } else {
            EdgeWalkResult::default()
        };
        let edge_cache = self.include_edges.then_some(&edge_walk.scanned_edges);
        let neighbor_options = HydrateOptions {
            hydrate_fields: self.hydrate,
            include_edges: self.include_edges,
            include_vectors: self.include_vectors,
            edge_cache,
        };

        if self.include_edges && self.edge_hop > 0 {
            for entity in &mut results {
                entity.edges = Some(load_entity_edges(
                    &self.vault.store,
                    &rtxn,
                    &entity.id,
                    edge_cache,
                )?);
            }
        }

        let mut neighbors = Vec::with_capacity(edge_walk.neighbor_ids.len());
        for id in edge_walk.neighbor_ids {
            let Some(entity) = hydrate_entity(self.vault, &rtxn, id, 0.0, neighbor_options)? else {
                continue;
            };
            neighbors.push(entity);
        }

        resolve_edge_short_ids(&mut results, &mut neighbors);

        let stats = PackStats {
            candidates_considered: scored.len(),
            signals_used: dedupe_signals(self.signals_used),
            query_time_us: started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            entities_hydrated: results.len(),
            neighbors_hydrated: neighbors.len(),
        };

        Ok(ContextPack {
            results,
            neighbors,
            stats,
        })
    }

    pub fn run_serialized(self) -> Result<Vec<u8>> {
        let config = SerializeConfig {
            format: self.format,
            profile: self.field_profile,
            budget: self.token_budget,
            allocation: self.token_allocation,
            include_stats: self.include_stats,
            merge_neighbors: self.merge_neighbors,
            max_field_chars: self.max_field_chars,
        };
        let pack = self.run()?;
        Ok(serialize_pack(&pack, &config))
    }
}

fn dedupe_signals(signals: Vec<Signal>) -> Vec<Signal> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::with_capacity(signals.len());
    for signal in signals {
        if seen.insert(signal) {
            deduped.push(signal);
        }
    }
    deduped
}

fn resolve_edge_short_ids(results: &mut [ContextEntity], neighbors: &mut [ContextEntity]) {
    let mut index = HashMap::<EntityId, String>::new();
    for entity in results.iter().chain(neighbors.iter()) {
        index.insert(entity.id, entity.short_id.clone());
    }

    for entity in results.iter_mut().chain(neighbors.iter_mut()) {
        let Some(edges) = entity.edges.as_mut() else {
            continue;
        };

        for edge in edges.iter_mut() {
            if let Some(short_id) = index.get(&edge.target) {
                edge.target_short_id = Some(short_id.clone());
            }
        }
    }
}

fn hydrate_entity(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    id: EntityId,
    score: f32,
    options: HydrateOptions<'_>,
) -> Result<Option<ContextEntity>> {
    let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };

    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(None);
    };

    let fields = if options.hydrate_fields {
        Some(decode_entity_fields(raw).unwrap_or_default())
    } else {
        None
    };

    let (short_id, content_hash) =
        read_short_id(&vault.store, rtxn, &id)?.unwrap_or_else(|| (id.to_hex(), 0));

    let edges = if options.include_edges {
        Some(load_entity_edges(
            &vault.store,
            rtxn,
            &id,
            options.edge_cache,
        )?)
    } else {
        None
    };

    let vector = if options.include_vectors {
        read_vector(vault, rtxn, &id)?
    } else {
        None
    };

    Ok(Some(ContextEntity {
        id,
        short_id,
        content_hash,
        entity_type: header.entity_type,
        score,
        fields,
        edges,
        vector,
    }))
}

fn decode_entity_fields(raw: &[u8]) -> Option<HashMap<String, serde_json::Value>> {
    if raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Some(HashMap::new());
    }

    let payload = &raw[ENTITY_METADATA_HEADER_LEN..];
    let mut cursor = Cursor::new(payload);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    let rmpv::Value::Map(entries) = value else {
        return None;
    };

    let mut out = HashMap::with_capacity(entries.len());
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            continue;
        };
        out.insert(key.to_owned(), rmpv_to_json(&value));
    }

    Some(out)
}

fn rmpv_to_json(value: &rmpv::Value) -> serde_json::Value {
    match value {
        rmpv::Value::Nil => serde_json::Value::Null,
        rmpv::Value::Boolean(v) => serde_json::Value::Bool(*v),
        rmpv::Value::Integer(v) => {
            if let Some(i) = v.as_i64() {
                serde_json::json!(i)
            } else if let Some(u) = v.as_u64() {
                serde_json::json!(u)
            } else {
                serde_json::Value::Null
            }
        }
        rmpv::Value::F32(v) => serde_json::json!(v),
        rmpv::Value::F64(v) => serde_json::json!(v),
        rmpv::Value::String(v) => {
            serde_json::Value::String(v.as_str().unwrap_or_default().to_owned())
        }
        rmpv::Value::Binary(_) => serde_json::Value::Null,
        rmpv::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(rmpv_to_json).collect())
        }
        rmpv::Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (key, value) in entries {
                let Some(key) = key.as_str() else {
                    continue;
                };
                map.insert(key.to_owned(), rmpv_to_json(value));
            }
            serde_json::Value::Object(map)
        }
        rmpv::Value::Ext(_, _) => serde_json::Value::Null,
    }
}

fn read_short_id(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<(String, u8)>> {
    let Some(value) = store.short_ids.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };

    if value.len() < 2 {
        return Ok(None);
    }

    let (short_id_bytes, hash) = value.split_at(value.len() - 1);
    let short_id = std::str::from_utf8(short_id_bytes)
        .map_err(|_| Error::InvalidKey)?
        .to_owned();

    Ok(Some((short_id, hash[0])))
}

fn read_vector(vault: &Vault, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<Vec<f32>>> {
    let Some(raw) = vault.store.vectors.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };

    let Ok(vector) = le_bytes_to_f32_vec(raw) else {
        return Ok(None);
    };

    if vector.len() != vault.config.dimensions {
        return Ok(None);
    }

    Ok(Some(vector))
}

fn load_entity_edges(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    edge_cache: Option<&HashMap<EntityId, Vec<EdgeInfo>>>,
) -> Result<Vec<EdgeInfo>> {
    if let Some(edges) = edge_cache.and_then(|cache| cache.get(id)) {
        Ok(edges.clone())
    } else {
        scan_edges_for_entity(store, rtxn, id)
    }
}

fn scan_edges_for_entity(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EdgeInfo>> {
    #[cfg(test)]
    EDGE_SCAN_COUNT.with(|count| count.set(count.get().saturating_add(1)));

    let mut edges = Vec::new();

    for entry in store.edges_out.prefix_iter(rtxn, id.as_bytes())? {
        let (key, value) = entry?;
        if key.len() != EDGE_KEY_LEN || value.len() != EDGE_VALUE_LEN {
            continue;
        }

        let Some(kind) = crate::types::EdgeKind::try_from_u8(key[16]) else {
            continue;
        };

        let Ok(target_bytes) = key[17..33].try_into() else {
            continue;
        };
        let Ok(target) = EntityId::from_bytes(target_bytes) else {
            continue;
        };

        let Ok(weight_bytes) = value[..4].try_into() else {
            continue;
        };
        let weight = f32::from_le_bytes(weight_bytes);

        let Ok(created_at_bytes) = value[4..12].try_into() else {
            continue;
        };
        let created_at = u64::from_le_bytes(created_at_bytes);

        let vad = parse_vad(value);
        if !weight.is_finite() || !vad.is_finite() || !vad.is_in_range() {
            continue;
        }

        edges.push(EdgeInfo {
            kind,
            target,
            target_short_id: None,
            weight,
            created_at,
            vad,
        });
    }

    Ok(edges)
}

fn walk_edges(
    store: &Store,
    rtxn: &RoTxn<'_>,
    seed_ids: &[EntityId],
    hops: u32,
    max_neighbors: usize,
    exclude: &HashSet<EntityId>,
) -> Result<EdgeWalkResult> {
    if hops == 0 || max_neighbors == 0 || seed_ids.is_empty() {
        return Ok(EdgeWalkResult::default());
    }

    let mut visited = HashSet::with_capacity(max_neighbors);
    let mut ordered_neighbors = Vec::with_capacity(max_neighbors);
    let mut frontier = seed_ids.to_vec();
    frontier.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let mut scanned_edges = HashMap::<EntityId, Vec<EdgeInfo>>::new();

    for _ in 0..hops {
        if frontier.is_empty() || visited.len() >= max_neighbors {
            break;
        }

        let mut candidates = HashMap::<EntityId, f32>::new();

        for id in &frontier {
            if !scanned_edges.contains_key(id) {
                scanned_edges.insert(*id, scan_edges_for_entity(store, rtxn, id)?);
            }

            let Some(edges) = scanned_edges.get(id) else {
                continue;
            };
            for edge in edges {
                if exclude.contains(&edge.target) || visited.contains(&edge.target) {
                    continue;
                }
                candidates
                    .entry(edge.target)
                    .and_modify(|best_weight| {
                        if edge.weight.total_cmp(best_weight).is_gt() {
                            *best_weight = edge.weight;
                        }
                    })
                    .or_insert(edge.weight);
            }
        }

        if candidates.is_empty() {
            break;
        }

        let remaining = max_neighbors.saturating_sub(visited.len());
        let mut next_frontier: Vec<(EntityId, f32)> = candidates.into_iter().collect();
        next_frontier.sort_unstable_by(|a, b| {
            b.1.total_cmp(&a.1)
                .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
        });
        next_frontier.truncate(remaining);

        frontier = next_frontier
            .into_iter()
            .map(|(id, _)| {
                visited.insert(id);
                ordered_neighbors.push(id);
                id
            })
            .collect();
    }

    Ok(EdgeWalkResult {
        neighbor_ids: ordered_neighbors,
        scanned_edges,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::types::{HnswConfig, TimeRange, VaultConfig};

    use super::*;

    fn reset_edge_scan_count() {
        EDGE_SCAN_COUNT.with(|count| count.set(0));
    }

    fn edge_scan_count() -> usize {
        EDGE_SCAN_COUNT.with(Cell::get)
    }

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

    fn msgpack_entity(fields: serde_json::Value) -> Vec<u8> {
        rmp_serde::to_vec_named(&fields).expect("msgpack encode")
    }

    fn put_text_entity(
        vault: &Vault,
        id: &EntityId,
        entity_type: u8,
        text: &str,
        fields: serde_json::Value,
    ) -> Result<()> {
        let payload = msgpack_entity(fields);
        vault
            .batch()
            .put(id, entity_type, TimeRange { start: 1, end: 1 }, 1, &payload)
            .text(id, &[("body", text)])
            .commit()
    }

    #[test]
    fn basic_hydration_populates_fields() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_entity(
            &vault,
            &id,
            0,
            "learn japanese",
            serde_json::json!({
                "pred": "goal.learning",
                "val": "Learn Japanese by June",
                "conf": 0.9
            }),
        )?;

        let pack = vault.context_pack().search_text("japanese", 10).run()?;
        assert_eq!(pack.results.len(), 1);
        let entity = &pack.results[0];
        assert_eq!(entity.id, id);
        assert_eq!(entity.entity_type, 0);
        assert!(!entity.short_id.is_empty());

        let fields = entity.fields.as_ref().expect("fields missing");
        assert_eq!(
            fields.get("pred").and_then(|v| v.as_str()),
            Some("goal.learning")
        );
        assert_eq!(fields.get("conf").and_then(|v| v.as_f64()), Some(0.9));
        Ok(())
    }

    #[test]
    fn builder_clamps_edge_expansion_settings() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let builder = vault.context_pack().edge_hop(99).max_neighbors(10_000);
        assert_eq!(builder.edge_hop, MAX_EDGE_HOP);
        assert_eq!(builder.max_neighbors, MAX_CONTEXT_NEIGHBORS);
        Ok(())
    }

    #[test]
    fn include_edges_returns_edge_info() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let src = EntityId::now();
        let tgt = EntityId::now();
        put_text_entity(
            &vault,
            &src,
            0,
            "alpha",
            serde_json::json!({"pred": "x", "val": "y"}),
        )?;
        put_text_entity(
            &vault,
            &tgt,
            4,
            "beta",
            serde_json::json!({"name": "Alice"}),
        )?;

        vault.put_edge(&src, crate::types::EdgeKind::Supports, &tgt, 0.7)?;

        let pack = vault
            .context_pack()
            .search_text("alpha", 10)
            .include_edges(true)
            .run()?;

        let edges = pack.results[0].edges.as_ref().expect("expected edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].target, tgt);
        assert_eq!(edges[0].kind, crate::types::EdgeKind::Supports);
        Ok(())
    }

    #[test]
    fn vad_round_trip_through_hydration() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let src = EntityId::now();
        let tgt = EntityId::now();
        put_text_entity(
            &vault,
            &src,
            0,
            "gamma",
            serde_json::json!({"pred": "x", "val": "y"}),
        )?;
        put_text_entity(&vault, &tgt, 4, "delta", serde_json::json!({"name": "Bob"}))?;

        vault.put_edge_with_vad(
            &src,
            crate::types::EdgeKind::HasFacet,
            &tgt,
            0.8,
            crate::types::Vad {
                valence: 0.6,
                arousal: 0.3,
                dominance: 0.9,
            },
        )?;

        let pack = vault
            .context_pack()
            .search_text("gamma", 10)
            .include_edges(true)
            .run()?;

        let edges = pack.results[0].edges.as_ref().expect("expected edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, crate::types::EdgeKind::HasFacet);
        assert!((edges[0].weight - 0.8).abs() < f32::EPSILON);
        assert!((edges[0].vad.valence - 0.6).abs() < f32::EPSILON);
        assert!((edges[0].vad.arousal - 0.3).abs() < f32::EPSILON);
        assert!((edges[0].vad.dominance - 0.9).abs() < f32::EPSILON);
        Ok(())
    }

    #[test]
    fn edge_hops_collect_neighbors() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        put_text_entity(
            &vault,
            &a,
            0,
            "root",
            serde_json::json!({"pred": "root", "val": "root"}),
        )?;
        put_text_entity(&vault, &b, 4, "child", serde_json::json!({"name": "B"}))?;
        put_text_entity(&vault, &c, 4, "leaf", serde_json::json!({"name": "C"}))?;

        vault.put_edge(&a, crate::types::EdgeKind::Supports, &b, 1.0)?;
        vault.put_edge(&b, crate::types::EdgeKind::Supports, &c, 1.0)?;

        let hop1 = vault
            .context_pack()
            .search_text("root", 10)
            .edge_hop(1)
            .run()?;
        let hop1_ids: HashSet<EntityId> = hop1.neighbors.iter().map(|e| e.id).collect();
        assert!(hop1_ids.contains(&b));
        assert!(!hop1_ids.contains(&c));

        let hop2 = vault
            .context_pack()
            .search_text("root", 10)
            .edge_hop(2)
            .run()?;
        let hop2_ids: HashSet<EntityId> = hop2.neighbors.iter().map(|e| e.id).collect();
        assert!(hop2_ids.contains(&b));
        assert!(hop2_ids.contains(&c));
        Ok(())
    }

    #[test]
    fn max_neighbors_caps_neighbor_count() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let root = EntityId::now();
        put_text_entity(
            &vault,
            &root,
            0,
            "root",
            serde_json::json!({"pred": "root", "val": "root"}),
        )?;

        for i in 0..20_u8 {
            let id = EntityId::from_bytes_unchecked([i + 1; 16]);
            put_text_entity(
                &vault,
                &id,
                4,
                "neighbor",
                serde_json::json!({"name": format!("P{i}")}),
            )?;
            vault.put_edge(&root, crate::types::EdgeKind::Mentions, &id, 1.0)?;
        }

        let pack = vault
            .context_pack()
            .search_text("root", 10)
            .edge_hop(1)
            .max_neighbors(5)
            .run()?;

        assert!(pack.neighbors.len() <= 5);
        Ok(())
    }

    #[test]
    fn neighbor_selection_prefers_highest_weight_edges() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let root = EntityId::from_bytes_unchecked([1; 16]);
        put_text_entity(
            &vault,
            &root,
            0,
            "root",
            serde_json::json!({"pred": "root", "val": "root"}),
        )?;

        let weighted = [
            (EntityId::from_bytes_unchecked([2; 16]), 0.4_f32),
            (EntityId::from_bytes_unchecked([3; 16]), 0.9_f32),
            (EntityId::from_bytes_unchecked([4; 16]), 0.7_f32),
            (EntityId::from_bytes_unchecked([5; 16]), 0.2_f32),
        ];

        for (id, weight) in weighted {
            put_text_entity(
                &vault,
                &id,
                4,
                "neighbor",
                serde_json::json!({"name": format!("P{:?}", id.as_bytes()[0])}),
            )?;
            vault.put_edge(&root, crate::types::EdgeKind::Mentions, &id, weight)?;
        }

        let pack = vault
            .context_pack()
            .search_text("root", 10)
            .edge_hop(1)
            .max_neighbors(2)
            .run()?;

        let neighbor_ids: Vec<EntityId> = pack.neighbors.iter().map(|entity| entity.id).collect();
        assert_eq!(
            neighbor_ids,
            vec![
                EntityId::from_bytes_unchecked([3; 16]),
                EntityId::from_bytes_unchecked([4; 16])
            ]
        );
        Ok(())
    }

    #[test]
    fn include_edges_reuses_walk_scans_for_results() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let root = EntityId::from_bytes_unchecked([7; 16]);
        let child = EntityId::from_bytes_unchecked([8; 16]);
        put_text_entity(
            &vault,
            &root,
            0,
            "root",
            serde_json::json!({"pred": "root", "val": "root"}),
        )?;
        put_text_entity(
            &vault,
            &child,
            4,
            "child",
            serde_json::json!({"name": "Child"}),
        )?;
        vault.put_edge(&root, crate::types::EdgeKind::Supports, &child, 1.0)?;

        reset_edge_scan_count();
        let rtxn = vault.store.env.read_txn()?;
        let walked = walk_edges(&vault.store, &rtxn, &[root], 1, 10, &HashSet::from([root]))?;
        assert_eq!(edge_scan_count(), 1, "walk should scan the root once");

        let cached_edges =
            load_entity_edges(&vault.store, &rtxn, &root, Some(&walked.scanned_edges))?;
        assert_eq!(cached_edges.len(), 1);
        assert_eq!(
            edge_scan_count(),
            1,
            "loading root edges from the walk cache should not rescan"
        );

        let uncached_edges =
            load_entity_edges(&vault.store, &rtxn, &child, Some(&walked.scanned_edges))?;
        assert!(uncached_edges.is_empty());
        assert_eq!(
            edge_scan_count(),
            2,
            "loading uncached neighbor edges should perform one scan"
        );
        Ok(())
    }

    #[test]
    fn include_vectors_controls_vector_hydration() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_entity(
            &vault,
            &id,
            0,
            "vec",
            serde_json::json!({"pred": "a", "val": "b"}),
        )?;

        vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;

        let with_vectors = vault
            .context_pack()
            .search_text("vec", 10)
            .include_vectors(true)
            .run()?;
        assert_eq!(
            with_vectors.results[0].vector.as_ref().map(Vec::len),
            Some(4)
        );

        let without_vectors = vault.context_pack().search_text("vec", 10).run()?;
        assert!(without_vectors.results[0].vector.is_none());
        Ok(())
    }

    #[test]
    fn empty_results_return_empty_pack() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let pack = vault.context_pack().search_text("nothing", 10).run()?;
        assert!(pack.results.is_empty());
        assert!(pack.neighbors.is_empty());
        assert_eq!(pack.stats.candidates_considered, 0);
        Ok(())
    }

    #[test]
    fn scores_match_pipeline_scores() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let a = EntityId::now();
        let b = EntityId::now();
        put_text_entity(
            &vault,
            &a,
            0,
            "alpha alpha",
            serde_json::json!({"pred": "a", "val": "a"}),
        )?;
        put_text_entity(
            &vault,
            &b,
            0,
            "alpha",
            serde_json::json!({"pred": "b", "val": "b"}),
        )?;

        let expected = vault.query().search_text("alpha", 10).run()?;
        let pack = vault.context_pack().search_text("alpha", 10).run()?;

        assert_eq!(expected.len(), pack.results.len());
        for (left, right) in expected.iter().zip(pack.results.iter()) {
            assert_eq!(left.id, right.id);
            assert!((left.score - right.score).abs() < 1e-6);
        }
        Ok(())
    }

    #[test]
    fn missing_short_id_falls_back_without_crashing() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let id = EntityId::now();
        put_text_entity(
            &vault,
            &id,
            0,
            "fallback",
            serde_json::json!({"pred": "a", "val": "b"}),
        )?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.short_ids.delete(&mut wtxn, id.as_bytes())?;
        wtxn.commit()?;

        let pack = vault.context_pack().search_text("fallback", 10).run()?;
        assert_eq!(pack.results.len(), 1);
        assert_eq!(pack.results[0].id, id);
        assert_eq!(pack.results[0].short_id.len(), 32);
        Ok(())
    }
}
