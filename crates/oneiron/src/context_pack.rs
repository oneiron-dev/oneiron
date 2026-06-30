#[cfg(test)]
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::time::Instant;

use heed::RoTxn;
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSubject, claim_surfaceable};
use crate::codebase::RepoRef;
use crate::error::{Error, Result};
use crate::pipeline::{PipelineBuilder, RetrievalWithTelemetry, WorldScope};
use crate::serialize::{SerializeConfig, SerializedPackTelemetry, serialize_pack_with_telemetry};
use crate::store::{RetrievalAction, RetrievalRunId, Store};
use crate::types::{
    ContextEntity, ContextPack, ContextPackRetrievalBudget, ENTITY_TYPE_CLAIM,
    EdgeConfirmationStatus, EdgeInfo, EdgeKind, EmptyContext, EmptyReason, EntityId, FieldProfile,
    PackFormat, PackStats, ScoredEntity, Signal, TemporalAnchorMode, TemporalGranularity,
    TimeRange, TokenAllocation,
};
use crate::{Vault, le_bytes_to_f32_vec};

const DEFAULT_MAX_NEIGHBORS: usize = 50;
const DEFAULT_TOKEN_BUDGET: usize = 4000;
const DEFAULT_MAX_FIELD_CHARS: usize = 500;
const MAX_EDGE_HOP: u32 = 5;
#[cfg(not(test))]
const MAX_EDGE_SCAN_RESULTS: usize = 100_000;
#[cfg(test)]
const MAX_EDGE_SCAN_RESULTS: usize = 64;
const MAX_CONTEXT_NEIGHBORS: usize = 1000;
const PACK_VALIDATION_DUPLICATE_ID: &str = "conflicting duplicate id";
const PACK_VALIDATION_MISSING_PAYLOAD: &str = "missing referenced payload";
const PACK_VALIDATION_IMPOSSIBLE_TIME: &str = "impossible time ordering";
const PACK_VALIDATION_MISSING_EVIDENCE: &str = "missing required evidence";
const PACK_VALIDATION_DELETED_PAYLOAD: &str = "deleted payload reference";
const PACK_VALIDATION_QUARANTINED_PAYLOAD: &str = "quarantined payload reference";
const PACK_QUARANTINE_ROW: &str = "sync quarantine row";
const PACK_REMAT_MARKER_PREFIX: &str = "rm:w:";
/// Default share of the claim budget that non-base (fictional / dream) worlds
/// may occupy in an `All`-scope pack — fiction takes at most half, so it can
/// never crowd base reality out (ARCH-0004 / ARCH-0022).
const DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION: f32 = 0.5;
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
    /// Claim bodies already decoded and accepted before hydration: pipeline
    /// result claims from the D19 gate, plus any neighbor claims decoded by
    /// pre-assembly validation. The hydrator projects fields from these
    /// instead of re-decoding, so each surfaced claim body is decoded once.
    claim_bodies: Option<&'a HashMap<EntityId, ClaimBody>>,
}

#[must_use = "ContextPackBuilder executes no query until a terminal `.run*()` method is called"]
pub struct ContextPackBuilder<'a> {
    pipeline: PipelineBuilder<'a>,
    vault: &'a Vault,
    hydrate: bool,
    include_edges: bool,
    edge_hop: u32,
    selected_edge_budget: usize,
    retrieval_budget: Option<ContextPackRetrievalBudget>,
    include_vectors: bool,
    include_stats: bool,
    merge_neighbors: bool,
    format: PackFormat,
    field_profile: FieldProfile,
    token_budget: usize,
    token_allocation: TokenAllocation,
    max_field_chars: usize,
    max_item_tokens: usize,
    signals_used: Vec<Signal>,
    world_scope: WorldScope,
    non_base_world_fraction: f32,
}

struct ContextPackRun<'a> {
    pack: ContextPack,
    telemetry_run_id: Option<RetrievalRunId>,
    store: &'a Store,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum PackQuarantineContainer {
    Entities,
    Edges,
    Tombstones,
    Leases,
}

#[derive(Debug, Deserialize, Serialize)]
struct PackQuarantineRecord {
    window_key: String,
    container: PackQuarantineContainer,
    crdt_key_hash: u64,
    crdt_key_len: u32,
}

#[derive(Debug, Default)]
struct PackQuarantineIndex {
    active_entity_keys: HashSet<(u64, u32)>,
}

impl PackQuarantineIndex {
    fn contains_entity(&self, id: &EntityId) -> bool {
        self.active_entity_keys
            .contains(&pack_entity_crdt_key_metadata(id))
    }
}

impl<'a> ContextPackBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            pipeline: vault.query().telemetry_action(RetrievalAction::ContextPack),
            vault,
            hydrate: true,
            include_edges: false,
            edge_hop: 0,
            selected_edge_budget: DEFAULT_MAX_NEIGHBORS,
            retrieval_budget: None,
            include_vectors: false,
            include_stats: false,
            merge_neighbors: true,
            format: PackFormat::default(),
            field_profile: FieldProfile::default(),
            token_budget: DEFAULT_TOKEN_BUDGET,
            token_allocation: TokenAllocation::default(),
            max_field_chars: DEFAULT_MAX_FIELD_CHARS,
            max_item_tokens: 0,
            signals_used: Vec::new(),
            world_scope: WorldScope::All,
            non_base_world_fraction: DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION,
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

    pub fn filter_repo_ref(mut self, repo_ref: RepoRef) -> Self {
        self.pipeline = self.pipeline.filter_repo_ref(repo_ref);
        self
    }

    pub fn filter_project_id(mut self, project_id: impl Into<String>) -> Self {
        self.pipeline = self.pipeline.filter_project_id(project_id);
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.pipeline = self.pipeline.limit(n);
        self
    }

    /// Sets the ARCH-0004 / ARCH-0022 world scope. Delegates the post-fusion
    /// filter to the pipeline; under the default [`WorldScope::All`] the pack
    /// additionally groups surviving claims by world (base section first). For
    /// [`WorldScope::Base`] / [`WorldScope::World`] the pack stays flat.
    pub fn world(mut self, scope: WorldScope) -> Self {
        self.pipeline = self.pipeline.world(scope);
        self.world_scope = scope;
        self
    }

    /// Sets the share of the claim budget non-base worlds may occupy when the
    /// pack is partitioned under [`WorldScope::All`] (default `0.5`). Base
    /// claims are always kept; non-base claims beyond `floor(fraction × claim
    /// budget)` are dropped so fiction cannot crowd base reality out. Only
    /// consulted for `All` scope with surviving non-base claims.
    pub fn non_base_world_claim_fraction(mut self, fraction: f32) -> Self {
        self.non_base_world_fraction = fraction;
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
        self = self.selected_edge_budget(n);
        self
    }

    pub fn selected_edge_budget(mut self, n: usize) -> Self {
        self.selected_edge_budget = n.min(MAX_CONTEXT_NEIGHBORS);
        if let Some(budget) = self.retrieval_budget.as_mut() {
            budget.selected_edges = self.selected_edge_budget;
        }
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

    pub fn retrieval_budget(mut self, budget: ContextPackRetrievalBudget) -> Self {
        let selected_edges = budget.selected_edges.min(MAX_CONTEXT_NEIGHBORS);
        self.selected_edge_budget = selected_edges;
        self.retrieval_budget = Some(ContextPackRetrievalBudget {
            selected_edges,
            ..budget
        });
        self
    }

    pub fn max_field_chars(mut self, max: usize) -> Self {
        self.max_field_chars = max;
        self
    }

    pub fn max_item_tokens(mut self, max: usize) -> Self {
        self.max_item_tokens = max;
        self
    }

    pub fn run(self) -> Result<ContextPack> {
        Ok(self.run_with_telemetry()?.value)
    }

    pub fn run_with_telemetry(self) -> Result<RetrievalWithTelemetry<ContextPack>> {
        let run = self.run_unfinalized()?;
        let surfaced_result_ids: Vec<[u8; 16]> = run
            .pack
            .results
            .iter()
            .map(|entity| *entity.id.as_bytes())
            .collect();
        let telemetry_run_id = finalize_context_pack_telemetry(
            run.store,
            run.telemetry_run_id,
            run.pack.stats.query_time_us,
            run.pack.stats.claims_suppressed,
            &surfaced_result_ids,
            context_pack_empty_reason(&run.pack, &surfaced_result_ids),
        );
        Ok(RetrievalWithTelemetry {
            value: run.pack,
            run_id: telemetry_run_id,
        })
    }

    fn run_unfinalized(self) -> Result<ContextPackRun<'a>> {
        let started = Instant::now();
        let retrieval_budget = self.retrieval_budget.unwrap_or_else(|| {
            ContextPackRetrievalBudget::from_limit(
                self.pipeline.result_limit(),
                self.token_allocation,
                self.selected_edge_budget,
            )
        });
        let selected_edge_budget = retrieval_budget.selected_edges;
        let pipeline_output = self
            .pipeline
            .context_pack_budget(retrieval_budget)
            .run_for_pack()?;
        let telemetry_run_id = pipeline_output.telemetry_run_id;
        let store = &self.vault.store;
        let result = (|| {
            let total_in_scope = pipeline_output.total_in_scope;
            let pipeline_empty_reason = pipeline_output.empty_reason;
            let scored = pipeline_output.scores;
            validate_scored_candidates(&scored)?;
            let surfaced_candidate_count = scored.len();
            let claim_bodies = pipeline_output.claim_bodies;
            let mut claims_suppressed = pipeline_output.claims_suppressed;
            let cosine_ghosts_dampened = pipeline_output.cosine_ghosts_dampened;

            let rtxn = self.vault.store.env.read_txn()?;
            let hydrate_result_edges = self.include_edges && self.edge_hop == 0;
            let mut claim_bodies = claim_bodies;
            let quarantine_index = load_pack_quarantine_index(&self.vault.store, &rtxn)?;

            let result_options = HydrateOptions {
                hydrate_fields: self.hydrate,
                include_edges: hydrate_result_edges,
                include_vectors: self.include_vectors,
                edge_cache: None,
                claim_bodies: Some(&claim_bodies),
            };
            let mut results = Vec::with_capacity(scored.len());
            for entry in scored.iter().copied() {
                let Some(entity) = hydrate_entity(
                    self.vault,
                    &rtxn,
                    entry.id,
                    entry.score,
                    result_options,
                    &mut claims_suppressed,
                )?
                else {
                    continue;
                };
                results.push(entity);
            }

            // ARCH-0004 / ARCH-0022 world partitioning (ONE-1117): under the
            // default `All` scope, group surviving claims by world — base section
            // first, then one section per non-base world — and cap how much of the
            // claim budget fiction may take. Flat (unchanged) for Base / World(id).
            if matches!(self.world_scope, WorldScope::All) {
                partition_results_by_world(
                    &self.vault.store,
                    &rtxn,
                    &mut results,
                    self.non_base_world_fraction,
                    &claim_bodies,
                )?;
            }

            for entity in &results {
                validate_pack_entity_reference(
                    &self.vault.store,
                    &rtxn,
                    &entity.id,
                    &mut claim_bodies,
                    &quarantine_index,
                )?;
            }

            let seed_ids: Vec<EntityId> = results.iter().map(|entity| entity.id).collect();
            let result_ids: HashSet<EntityId> = seed_ids.iter().copied().collect();
            let edge_walk = if self.edge_hop > 0 && selected_edge_budget > 0 {
                walk_edges(
                    &self.vault.store,
                    &rtxn,
                    &seed_ids,
                    self.edge_hop,
                    selected_edge_budget,
                    &result_ids,
                )?
            } else {
                EdgeWalkResult::default()
            };
            let edge_cache = self.include_edges.then_some(&edge_walk.scanned_edges);
            for id in &edge_walk.neighbor_ids {
                validate_pack_entity_reference(
                    &self.vault.store,
                    &rtxn,
                    id,
                    &mut claim_bodies,
                    &quarantine_index,
                )?;
            }
            let neighbor_options = HydrateOptions {
                hydrate_fields: self.hydrate,
                include_edges: self.include_edges,
                include_vectors: self.include_vectors,
                edge_cache,
                claim_bodies: Some(&claim_bodies),
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
                let Some(entity) = hydrate_entity(
                    self.vault,
                    &rtxn,
                    id,
                    0.0,
                    neighbor_options,
                    &mut claims_suppressed,
                )?
                else {
                    continue;
                };
                neighbors.push(entity);
            }

            validate_hydrated_pack_entities(&results, &neighbors)?;
            validate_pack_edge_references(
                &self.vault.store,
                &rtxn,
                &results,
                &mut claim_bodies,
                &quarantine_index,
            )?;
            validate_pack_edge_references(
                &self.vault.store,
                &rtxn,
                &neighbors,
                &mut claim_bodies,
                &quarantine_index,
            )?;
            resolve_edge_short_ids(&mut results, &mut neighbors);

            let pack_is_empty = results.is_empty() && neighbors.is_empty();
            let candidates_considered = if pack_is_empty {
                total_in_scope
            } else {
                surfaced_candidate_count
            };
            let stats = PackStats {
                candidates_considered,
                signals_used: dedupe_signals(self.signals_used),
                query_time_us: started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                entities_hydrated: results.len(),
                neighbors_hydrated: neighbors.len(),
                cosine_ghosts_dampened,
                claims_suppressed,
                items_truncated: crate::types::PackItemAccounting::item_budget(),
                items_dropped: crate::types::PackItemAccounting::token_budget(),
            };
            let empty = empty_context(pack_is_empty, &stats, pipeline_empty_reason);

            Ok(ContextPackRun {
                pack: ContextPack {
                    results,
                    neighbors,
                    stats,
                    empty,
                },
                telemetry_run_id,
                store,
            })
        })();

        if result.is_err() {
            discard_failed_context_pack_telemetry(store, telemetry_run_id);
        }
        result
    }

    pub fn run_serialized(self) -> Result<Vec<u8>> {
        Ok(self.run_serialized_with_telemetry()?.value)
    }

    pub fn run_serialized_with_telemetry(self) -> Result<RetrievalWithTelemetry<Vec<u8>>> {
        let config = SerializeConfig {
            format: self.format,
            profile: self.field_profile,
            budget: self.token_budget,
            allocation: self.token_allocation,
            include_stats: self.include_stats,
            merge_neighbors: self.merge_neighbors,
            max_field_chars: self.max_field_chars,
            max_item_tokens: self.max_item_tokens,
        };
        let run = self.run_unfinalized()?;
        let (bytes, telemetry) = serialize_pack_with_telemetry(&run.pack, &config);
        let telemetry_run_id = finalize_context_pack_telemetry(
            run.store,
            run.telemetry_run_id,
            telemetry.stats.query_time_us,
            telemetry.stats.claims_suppressed,
            &telemetry.result_ids,
            serialized_context_pack_empty_reason(&run.pack, &telemetry),
        );
        Ok(RetrievalWithTelemetry {
            value: bytes,
            run_id: telemetry_run_id,
        })
    }
}

fn context_pack_validation_error(id: EntityId, reason: &'static str) -> Error {
    Error::ContextPackValidation { id, reason }
}

fn validate_scored_candidates(scored: &[ScoredEntity]) -> Result<()> {
    let mut seen = HashSet::with_capacity(scored.len());
    for entry in scored {
        if !seen.insert(entry.id) {
            return Err(context_pack_validation_error(
                entry.id,
                PACK_VALIDATION_DUPLICATE_ID,
            ));
        }
    }
    Ok(())
}

fn validate_hydrated_pack_entities(
    results: &[ContextEntity],
    neighbors: &[ContextEntity],
) -> Result<()> {
    let mut seen = HashSet::with_capacity(results.len() + neighbors.len());
    for entity in results.iter().chain(neighbors.iter()) {
        if !seen.insert(entity.id) {
            return Err(context_pack_validation_error(
                entity.id,
                PACK_VALIDATION_DUPLICATE_ID,
            ));
        }
    }
    Ok(())
}

fn validate_pack_edge_references(
    store: &Store,
    rtxn: &RoTxn<'_>,
    entities: &[ContextEntity],
    claim_bodies: &mut HashMap<EntityId, ClaimBody>,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    for entity in entities {
        let Some(edges) = &entity.edges else {
            continue;
        };
        for edge in edges {
            validate_pack_entity_reference(
                store,
                rtxn,
                &edge.target,
                claim_bodies,
                quarantine_index,
            )?;
        }
    }
    Ok(())
}

fn validate_pack_entity_reference(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    claim_bodies: &mut HashMap<EntityId, ClaimBody>,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    validate_pack_payload_reference(store, rtxn, id, quarantine_index)?;
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Err(context_pack_validation_error(
            *id,
            PACK_VALIDATION_MISSING_PAYLOAD,
        ));
    };
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Err(Error::CorruptedIndex("entity metadata header"));
    };
    validate_entity_time_ordering(*id, header)?;

    if header.entity_type == ENTITY_TYPE_CLAIM {
        if let Some(body) = claim_bodies.get(id) {
            validate_claim_pack_consistency(store, rtxn, *id, body, quarantine_index)?;
        } else {
            let Ok(body) = raw
                .get(ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("entity metadata header"))
                .and_then(|payload| crate::claim::decode_claim_body(payload, true))
            else {
                return Ok(());
            };
            validate_claim_pack_consistency(store, rtxn, *id, &body, quarantine_index)?;
            if claim_surfaceable(&body) {
                claim_bodies.insert(*id, body);
            }
        }
    }
    Ok(())
}

fn validate_pack_payload_reference(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    if store
        .sync_state
        .get(rtxn, &crate::deletion::local_hard_delete_key(id))?
        .is_some()
    {
        return Err(context_pack_validation_error(
            *id,
            PACK_VALIDATION_DELETED_PAYLOAD,
        ));
    }
    if quarantine_index.contains_entity(id) {
        return Err(context_pack_validation_error(
            *id,
            PACK_VALIDATION_QUARANTINED_PAYLOAD,
        ));
    }

    if store.entities.get(rtxn, id.as_bytes())?.is_none() {
        return Err(context_pack_validation_error(
            *id,
            PACK_VALIDATION_MISSING_PAYLOAD,
        ));
    }
    Ok(())
}

fn validate_entity_time_ordering(id: EntityId, header: EntityMetadataHeader) -> Result<()> {
    if header.occurred_start > header.occurred_end {
        return Err(context_pack_validation_error(
            id,
            PACK_VALIDATION_IMPOSSIBLE_TIME,
        ));
    }
    Ok(())
}

fn validate_claim_pack_consistency(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: EntityId,
    body: &ClaimBody,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    if let (Some(valid_from), Some(valid_to)) = (body.valid_from, body.valid_to)
        && valid_from > valid_to
    {
        return Err(context_pack_validation_error(
            id,
            PACK_VALIDATION_IMPOSSIBLE_TIME,
        ));
    }

    validate_claim_subject_references(store, rtxn, body, quarantine_index)?;

    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        let record = crate::provenance::decode_edge_provenance_body(&body.value)
            .map_err(|_| context_pack_validation_error(id, PACK_VALIDATION_MISSING_EVIDENCE))?;
        crate::provenance::resolve_persisted_actor_class(&record, body.evidence.as_ref())
            .map_err(|_| context_pack_validation_error(id, PACK_VALIDATION_MISSING_EVIDENCE))?;
    }
    Ok(())
}

fn validate_claim_subject_references(
    store: &Store,
    rtxn: &RoTxn<'_>,
    body: &ClaimBody,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    match body.subject {
        ClaimSubject::Entity(id) => {
            validate_pack_payload_reference(store, rtxn, &id, quarantine_index)?;
        }
        ClaimSubject::Edge { source, target, .. } => {
            validate_pack_payload_reference(store, rtxn, &source, quarantine_index)?;
            validate_pack_payload_reference(store, rtxn, &target, quarantine_index)?;
        }
    }
    Ok(())
}

fn load_pack_quarantine_index(store: &Store, rtxn: &RoTxn<'_>) -> Result<PackQuarantineIndex> {
    let active_remat_markers = load_active_pack_entity_remat_markers(store, rtxn)?;
    let mut active_entity_keys: HashSet<(u64, u32)> = active_remat_markers
        .iter()
        .map(|(_window, entity_key)| *entity_key)
        .collect();
    let iter = store.sync_queue.prefix_iter(rtxn, b"x:")?;
    for entry in iter {
        let (key, value) = entry?;
        if !is_quarantine_key(key) {
            continue;
        }
        let record = rmp_serde::from_slice::<PackQuarantineRecord>(value)
            .map_err(|_| Error::CorruptedIndex(PACK_QUARANTINE_ROW))?;
        if record.container != PackQuarantineContainer::Entities {
            continue;
        }
        // `x:` rows are retained diagnostics; the pending `rm:w:` marker is
        // the live retry signal that keeps the referenced entity blocked.
        let entity_key = (record.crdt_key_hash, record.crdt_key_len);
        if active_remat_markers.contains(&(record.window_key, entity_key)) {
            active_entity_keys.insert(entity_key);
        }
    }
    Ok(PackQuarantineIndex { active_entity_keys })
}

fn load_active_pack_entity_remat_markers(
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<HashSet<(String, (u64, u32))>> {
    let mut markers = HashSet::new();
    let iter = store
        .sync_state
        .prefix_iter(rtxn, PACK_REMAT_MARKER_PREFIX)?;
    for entry in iter {
        let (key, _) = entry?;
        let rest = &key[PACK_REMAT_MARKER_PREFIX.len()..];
        let Some((window_key, entity_hex)) = rest.split_once(':') else {
            continue;
        };
        if EntityId::from_hex(entity_hex).is_err() {
            continue;
        }
        markers.insert((window_key.to_string(), pack_crdt_key_metadata(entity_hex)));
    }
    Ok(markers)
}

fn pack_entity_crdt_key_metadata(id: &EntityId) -> (u64, u32) {
    pack_crdt_key_metadata(&id.to_hex())
}

fn pack_crdt_key_metadata(key: &str) -> (u64, u32) {
    (
        xxh3_64(key.as_bytes()),
        u32::try_from(key.len()).unwrap_or(u32::MAX),
    )
}

fn is_quarantine_key(key: &[u8]) -> bool {
    key.len() == 10 && key.starts_with(b"x:")
}

fn finalize_context_pack_telemetry(
    store: &Store,
    telemetry_run_id: Option<RetrievalRunId>,
    elapsed_us: u64,
    claims_suppressed: usize,
    surfaced_result_ids: &[[u8; 16]],
    empty_reason: Option<String>,
) -> Option<RetrievalRunId> {
    let run_id = telemetry_run_id?;
    match store.finalize_context_pack_retrieval_run(
        run_id,
        elapsed_us,
        claims_suppressed,
        surfaced_result_ids,
        empty_reason,
    ) {
        Ok(()) => Some(run_id),
        Err(error) => {
            tracing::warn!(
                ?error,
                "context-pack retrieval telemetry finalization failed; discarding provisional run id"
            );
            discard_failed_context_pack_telemetry(store, Some(run_id));
            None
        }
    }
}

fn discard_failed_context_pack_telemetry(store: &Store, telemetry_run_id: Option<RetrievalRunId>) {
    let Some(run_id) = telemetry_run_id else {
        return;
    };
    if let Err(error) = store.delete_retrieval_run(run_id) {
        tracing::warn!(
            ?error,
            "failed context-pack retrieval telemetry discard failed; continuing error return"
        );
    }
}

fn context_pack_empty_reason(
    pack: &ContextPack,
    surfaced_result_ids: &[[u8; 16]],
) -> Option<String> {
    if !surfaced_result_ids.is_empty() {
        return None;
    }
    let reason = pack
        .empty
        .as_ref()
        .map(|empty| empty.reason)
        .unwrap_or(EmptyReason::FilterMatchedNone);
    Some(format!("{reason:?}"))
}

fn serialized_context_pack_empty_reason(
    pack: &ContextPack,
    telemetry: &SerializedPackTelemetry,
) -> Option<String> {
    if !telemetry.result_ids.is_empty() {
        return None;
    }
    if !pack.results.is_empty()
        && telemetry.stats.items_dropped.count > pack.stats.items_dropped.count
    {
        return Some(format!("{:?}", telemetry.stats.items_dropped.reason));
    }
    context_pack_empty_reason(pack, &telemetry.result_ids)
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

fn empty_context(
    pack_is_empty: bool,
    stats: &PackStats,
    pipeline_reason: Option<EmptyReason>,
) -> Option<EmptyContext> {
    if !pack_is_empty {
        return None;
    }

    let reason = match pipeline_reason {
        Some(reason) => reason,
        None if stats.candidates_considered == 0 => EmptyReason::NoData,
        None => EmptyReason::FilterMatchedNone,
    };

    Some(EmptyContext {
        reason,
        total_in_scope: stats.candidates_considered,
        hint: empty_hint(reason).to_owned(),
    })
}

fn empty_hint(reason: EmptyReason) -> &'static str {
    match reason {
        EmptyReason::FilterMatchedNone => {
            "Try removing filters or widening the world, type, or time scope"
        }
        EmptyReason::NoData => "Add data to the vault or broaden the query scope",
        EmptyReason::AllActivated => {
            "All matching items are already activated; allow activated results to revisit them"
        }
        EmptyReason::BelowThreshold => "Try broadening the query or lowering the result threshold",
    }
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

/// ARCH-0004 / ARCH-0022 world partitioning for an `All`-scope pack: reorders
/// `results` so claims are grouped by world — the base section (claims with no
/// `world` key plus every non-claim entity) first, then one section per
/// non-base world (sections ordered by their highest-scoring claim; score
/// order preserved within a section). A per-non-base-world cap drops the
/// lowest-scoring fiction so non-base worlds occupy at most `non_base_fraction`
/// of the claim budget (every CLAIM in the pack), keeping all base claims.
///
/// When no non-base claim survives, `results` are left flat in score order.
fn partition_results_by_world(
    store: &Store,
    rtxn: &RoTxn<'_>,
    results: &mut Vec<ContextEntity>,
    non_base_fraction: f32,
    claim_bodies: &HashMap<EntityId, ClaimBody>,
) -> Result<()> {
    let mut base: Vec<ContextEntity> = Vec::with_capacity(results.len());
    let mut non_base: Vec<(EntityId, ContextEntity)> = Vec::new();

    for entity in results.drain(..) {
        match entity_world(store, rtxn, &entity, claim_bodies)? {
            None => base.push(entity),
            Some(world) => non_base.push((world, entity)),
        }
    }

    // No fictional / dream claim survived — leave the pack flat (score order).
    if non_base.is_empty() {
        *results = base;
        return Ok(());
    }

    // Claim budget = every CLAIM in the pack (base claims + non-base claims);
    // non-claim base entities do not count. Non-base worlds share at most
    // `non_base_fraction` of it.
    let base_claim_count = base
        .iter()
        .filter(|entity| entity.entity_type == ENTITY_TYPE_CLAIM)
        .count();
    let claim_budget = base_claim_count + non_base.len();
    let non_base_cap = ((claim_budget as f32) * non_base_fraction).floor().max(0.0) as usize;

    // `non_base` is in score order (results arrive score-sorted). Keep the top
    // `non_base_cap` by score and drop the rest so fiction cannot crowd base
    // reality out.
    non_base.truncate(non_base_cap);

    // Group survivors by world; sections ordered by first (highest-score)
    // appearance, score order preserved within each section.
    let mut world_order: Vec<EntityId> = Vec::new();
    let mut groups: HashMap<EntityId, Vec<ContextEntity>> = HashMap::new();
    for (world, entity) in non_base {
        if !groups.contains_key(&world) {
            world_order.push(world);
        }
        groups.entry(world).or_default().push(entity);
    }

    let mut out = base;
    for world in world_order {
        if let Some(section) = groups.remove(&world) {
            out.extend(section);
        }
    }
    *results = out;
    Ok(())
}

/// Reads a hydrated result's world for partitioning: `None` for base reality
/// (a non-claim entity, or a claim with no `world` key) and `Some(world_id)`
/// for a world-scoped claim. The `world` key was structurally validated to a
/// 16-byte id at write time.
///
/// Every result CLAIM passed the pipeline D19 gate, so its body is already in
/// `claim_bodies`: reuse that decode instead of a second MessagePack pass,
/// keeping the claim body decoded ONCE per result for gate + projection +
/// world grouping (D19 AC 9). The raw-read fallback only covers a defensive
/// cache miss.
fn entity_world(
    store: &Store,
    rtxn: &RoTxn<'_>,
    entity: &ContextEntity,
    claim_bodies: &HashMap<EntityId, ClaimBody>,
) -> Result<Option<EntityId>> {
    if entity.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    if let Some(body) = claim_bodies.get(&entity.id) {
        return Ok(body.world);
    }
    let Some(raw) = store.entities.get(rtxn, entity.id.as_bytes())? else {
        return Ok(None);
    };
    if raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Ok(None);
    }
    crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(|body| body.world)
}

/// Hydrates one entity for the context pack.
///
/// Type-0 (CLAIM) records pass through the D19 status gate here too — pack
/// NEIGHBORS never run through the pipeline, so this is their only gate
/// (results were gated in the pipeline already; their decoded bodies arrive
/// via `options.claim_bodies` and are NOT re-decoded). Fail-closed: a type-0
/// record whose body is missing or fails the pinned CLAIM ABI decode is
/// excluded — it never surfaces with empty fields — and counted in
/// `claims_suppressed`, exactly like a status-gated claim. Bodies of every
/// other type byte stay opaque and are projected through the generic
/// best-effort field decode, unchanged.
fn hydrate_entity(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    id: EntityId,
    score: f32,
    options: HydrateOptions<'_>,
    claims_suppressed: &mut usize,
) -> Result<Option<ContextEntity>> {
    let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };

    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Err(Error::CorruptedIndex("entity metadata header"));
    };

    let mut gated_claim_body: Option<&ClaimBody> = None;
    let decoded_here: Option<ClaimBody>;
    if header.entity_type == ENTITY_TYPE_CLAIM {
        match options.claim_bodies.and_then(|cache| cache.get(&id)) {
            // Pipeline-gated result: already decoded once and surfaceable.
            Some(body) => gated_claim_body = Some(body),
            None => {
                // Neighbor (or cache miss): decode once for gate +
                // projection; reads allow reserved `edge.*` predicates.
                decoded_here = raw
                    .get(ENTITY_METADATA_HEADER_LEN..)
                    .and_then(|body| crate::claim::decode_claim_body(body, true).ok());
                match &decoded_here {
                    Some(body) if claim_surfaceable(body) => gated_claim_body = Some(body),
                    _ => {
                        *claims_suppressed += 1;
                        return Ok(None);
                    }
                }
            }
        }
    }

    let fields = if options.hydrate_fields {
        Some(match gated_claim_body {
            Some(body) => claim_fields_to_json(body),
            None => decode_entity_fields(raw).unwrap_or_default(),
        })
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

/// Projects an already-decoded CLAIM body into the hydrated-fields map —
/// the same shape `decode_entity_fields` produces from the raw MessagePack
/// map (pinned D11 short keys; `subj` is binary on disk so it projects as
/// JSON null; `stale` appears only when `true`, mirroring the encoder which
/// omits `false`). Reusing the gate's decode means the body is MessagePack-
/// decoded once per result for gate + projection (AC 9).
fn claim_fields_to_json(body: &ClaimBody) -> HashMap<String, serde_json::Value> {
    let mut out = HashMap::new();
    out.insert(
        "pred".to_owned(),
        serde_json::Value::String(body.predicate.clone()),
    );
    out.insert("val".to_owned(), rmpv_to_json(&body.value));
    out.insert("conf".to_owned(), serde_json::json!(body.confidence));
    if let Some(salience) = body.salience {
        out.insert("sal".to_owned(), serde_json::json!(salience));
    }
    if let Some(evidence) = &body.evidence {
        out.insert("evid".to_owned(), rmpv_to_json(evidence));
    }
    if let Some(valid_from) = body.valid_from {
        out.insert("from".to_owned(), serde_json::json!(valid_from));
    }
    if let Some(valid_to) = body.valid_to {
        out.insert("to".to_owned(), serde_json::json!(valid_to));
    }
    if let Some(source) = body.source {
        out.insert(
            "src".to_owned(),
            serde_json::Value::String(source.as_str().to_owned()),
        );
    }
    if body.world.is_some() {
        // On-disk `world` is a 16-byte binary id (ONE-1117); the generic
        // projection renders binary as null, and so does this one — same as
        // `subj` below. Only present when the claim carries a world scope.
        out.insert("world".to_owned(), serde_json::Value::Null);
    }
    // On-disk `subj` is MessagePack binary; the generic projection renders
    // binary as null, and so does this one.
    out.insert("subj".to_owned(), serde_json::Value::Null);
    if let Some(scope) = &body.scope {
        out.insert("scope".to_owned(), rmpv_to_json(scope));
    }
    out.insert(
        "appr".to_owned(),
        serde_json::Value::String(body.approval.as_str().to_owned()),
    );
    out.insert(
        "life".to_owned(),
        serde_json::Value::String(body.lifecycle.as_str().to_owned()),
    );
    if body.stale {
        out.insert("stale".to_owned(), serde_json::Value::Bool(true));
    }
    out
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
    // ARCH-0019 row n4: `short_ids_reverse` is the entity-id-keyed direction
    // (entity_id -> short_id ‖ content_hash).
    let Some(value) = store.short_ids_reverse.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };

    if value.len() < 2 {
        return Ok(None);
    }

    let Some((&hash, short_id_bytes)) = value.split_last() else {
        return Ok(None);
    };
    let Ok(short_id) = std::str::from_utf8(short_id_bytes) else {
        return Ok(None);
    };

    Ok(Some((short_id.to_owned(), hash)))
}

fn read_vector(vault: &Vault, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<Vec<f32>>> {
    let Some(raw) = vault.store.vectors.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };

    let vector = le_bytes_to_f32_vec(raw).map_err(|_| Error::CorruptedIndex("entity vector"))?;

    if vector.len() != vault.config.dimensions {
        return Err(Error::CorruptedIndex("entity vector"));
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

/// Scans the outbound edge rows for one entity, failing closed on any
/// malformed row.
///
/// Every row is parsed through [`crate::vault::parse_edge_record`] so the
/// context-pack read path (result-edge hydration and the `walk_edges`
/// neighbor expansion) classifies corruption exactly like the canonical
/// vault readers (`edges_out` / `edges_in` / `targets` / `sources`): a key
/// that is not 33 bytes, an unknown edge-kind byte, a reserved target id,
/// or a value whose length is not a valid layout for the kind (12/24/26 B
/// per ARCH-0034) returns `Error::CorruptedIndex("edge record")` — never a
/// silent skip (ONE-1101 / pinned decision D9).
fn scan_edges_for_entity(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EdgeInfo>> {
    #[cfg(test)]
    EDGE_SCAN_COUNT.with(|count| count.set(count.get().saturating_add(1)));

    let mut edges = Vec::new();

    for entry in store.edges_out.prefix_iter(rtxn, id.as_bytes())? {
        let (key, value) = entry?;
        if edges.len() >= MAX_EDGE_SCAN_RESULTS {
            return Err(Error::CorruptedIndex("edge scan exceeded bound"));
        }
        edges.push(crate::vault::parse_edge_record(key, value)?);
    }

    Ok(edges)
}

fn walk_edges(
    store: &Store,
    rtxn: &RoTxn<'_>,
    seed_ids: &[EntityId],
    hops: u32,
    selected_edge_budget: usize,
    exclude: &HashSet<EntityId>,
) -> Result<EdgeWalkResult> {
    if hops == 0 || selected_edge_budget == 0 || seed_ids.is_empty() {
        return Ok(EdgeWalkResult::default());
    }

    let mut visited = HashSet::with_capacity(selected_edge_budget);
    let mut ordered_neighbors = Vec::with_capacity(selected_edge_budget);
    let mut frontier = seed_ids.to_vec();
    frontier.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let mut scanned_edges = HashMap::<EntityId, Vec<EdgeInfo>>::new();

    for _ in 0..hops {
        if frontier.is_empty() || visited.len() >= selected_edge_budget {
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
                // `child_of` / `assigned_to` are STRUCTURAL plumbing with no
                // retrieval scoring (ARCH-0004 edgeKinds: lambda null, "Not
                // traversed.") — never neighbor-expanded regardless of the
                // stored weight bytes. They still hydrate on the seed's own
                // edge list; only the walk skips them.
                if matches!(edge.kind, EdgeKind::ChildOf | EdgeKind::AssignedTo) {
                    continue;
                }
                // D8-consistent: a provenanced edge whose hot flag says
                // retracted contributes nothing to expansion. Unlike PPR
                // (λ_opposes = 0), `opposes` IS followed here — a surfaced
                // contradiction is useful context-pack signal.
                if edge.provenance.is_some_and(|flags| {
                    flags.confirmation_status == EdgeConfirmationStatus::Retracted
                }) {
                    continue;
                }
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

        let remaining = selected_edge_budget.saturating_sub(visited.len());
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
    use std::collections::{BTreeMap, HashSet};

    use crate::error::Error;
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

    fn open_test_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(test_config())
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

    /// Writes a structurally valid CLAIM (type 0, D11 pinned body keys) plus
    /// a text row so it is retrievable through `search_text`.
    fn put_claim_text_entity(
        vault: &Vault,
        id: &EntityId,
        text: &str,
        pred: &str,
        val: &str,
    ) -> Result<()> {
        put_claim_text_entity_with_lifecycle(
            vault,
            id,
            text,
            pred,
            val,
            crate::claim::ClaimLifecycleStatus::Active,
        )
    }

    fn put_claim_text_entity_with_lifecycle(
        vault: &Vault,
        id: &EntityId,
        text: &str,
        pred: &str,
        val: &str,
        life: crate::claim::ClaimLifecycleStatus,
    ) -> Result<()> {
        put_claim_text_entity_with_status(
            vault,
            id,
            text,
            pred,
            val,
            crate::claim::ClaimApprovalStatus::Auto,
            life,
        )
    }

    fn put_claim_text_entity_with_status(
        vault: &Vault,
        id: &EntityId,
        text: &str,
        pred: &str,
        val: &str,
        appr: crate::claim::ClaimApprovalStatus,
        life: crate::claim::ClaimLifecycleStatus,
    ) -> Result<()> {
        let subject = default_claim_subject_id()?;
        ensure_claim_subject_payload(vault, &subject)?;
        let body = crate::claim::ClaimBody::new(
            pred,
            crate::claim::ClaimSubject::Entity(subject),
            rmpv::Value::from(val),
            0.9,
            appr,
            life,
        );
        let payload = crate::claim::encode_claim_body(&body)?;
        vault
            .batch()
            .put(id, 0, TimeRange { start: 1, end: 1 }, 1, &payload)
            .text(id, &[("body", text)])
            .commit()
    }

    /// A vector-ranked CLAIM whose body carries an optional `world` scope
    /// (`None` = base reality). Built through the pinned claim encoder so the
    /// `world` key is the real 16-byte binary the partitioner groups by.
    fn put_world_claim(
        vault: &Vault,
        id: EntityId,
        vector: [f32; 4],
        world: Option<EntityId>,
    ) -> Result<()> {
        let subject = default_claim_subject_id()?;
        ensure_claim_subject_payload(vault, &subject)?;
        let mut body = crate::claim::ClaimBody::new(
            "facet.scope_test",
            crate::claim::ClaimSubject::Entity(subject),
            rmpv::Value::from("v"),
            0.9,
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Active,
        );
        body.world = world;
        let payload = crate::claim::encode_claim_body(&body)?;
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &payload,
            )
            .vector(&id, &vector)
            .commit()
    }

    fn raw_entity_record(
        entity_type: u8,
        occurred_start: u64,
        occurred_end: u64,
        learned_at: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + payload.len());
        raw.push(entity_type);
        raw.extend_from_slice(&occurred_start.to_be_bytes());
        raw.extend_from_slice(&occurred_end.to_be_bytes());
        raw.extend_from_slice(&learned_at.to_be_bytes());
        raw.extend_from_slice(payload);
        raw
    }

    fn overwrite_raw_entity(vault: &Vault, id: &EntityId, raw: &[u8]) -> Result<()> {
        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), raw)?;
            Ok(())
        })
    }

    fn default_claim_subject_id() -> Result<EntityId> {
        EntityId::from_bytes([0x7C; 16])
    }

    fn ensure_claim_subject_payload(vault: &Vault, id: &EntityId) -> Result<()> {
        if vault.get_raw(id)?.is_some() {
            return Ok(());
        }
        let raw = raw_entity_record(4, 1, 1, 1, &[]);
        overwrite_raw_entity(vault, id, &raw)
    }

    fn put_claim_text_entity_with_subject(
        vault: &Vault,
        id: &EntityId,
        subject: crate::claim::ClaimSubject,
        text: &str,
        pred: &str,
        val: &str,
    ) -> Result<()> {
        let body = crate::claim::ClaimBody::new(
            pred,
            subject,
            rmpv::Value::from(val),
            0.9,
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Active,
        );
        let payload = crate::claim::encode_claim_body(&body)?;
        vault
            .batch()
            .put(
                id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &payload,
            )
            .text(id, &[("body", text)])
            .commit()
    }

    fn assert_context_pack_validation(
        err: Error,
        expected_id: EntityId,
        expected_reason: &'static str,
    ) {
        match err {
            Error::ContextPackValidation { id, reason } => {
                assert_eq!(id, expected_id);
                assert_eq!(reason, expected_reason);
            }
            other => panic!(
                "expected ContextPackValidation({expected_reason:?}) for {}, got {other:?}",
                expected_id.to_hex()
            ),
        }
    }

    fn pack_quarantine_record_for_entity(window_key: &str, id: &EntityId) -> PackQuarantineRecord {
        let (crdt_key_hash, crdt_key_len) = pack_entity_crdt_key_metadata(id);
        PackQuarantineRecord {
            window_key: window_key.to_string(),
            container: PackQuarantineContainer::Entities,
            crdt_key_hash,
            crdt_key_len,
        }
    }

    fn pack_remat_marker_key(window_key: &str, id: &EntityId) -> String {
        format!("rm:w:{window_key}:{}", id.to_hex())
    }

    #[test]
    fn dedupe_signals_preserves_first_occurrence_order() {
        let signals = vec![
            Signal::Text,
            Signal::Vector,
            Signal::Text,
            Signal::Temporal,
            Signal::Vector,
        ];

        assert_eq!(
            dedupe_signals(signals),
            vec![Signal::Text, Signal::Vector, Signal::Temporal]
        );
    }

    #[test]
    fn basic_hydration_populates_fields() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        put_claim_text_entity(
            &vault,
            &id,
            "learn japanese",
            "goal.learning",
            "Learn Japanese by June",
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
        let conf = fields
            .get("conf")
            .and_then(serde_json::Value::as_f64)
            .expect("conf field missing");
        assert!((conf - 0.9).abs() < 1e-6, "conf drifted: {conf}");
        Ok(())
    }

    #[test]
    fn builder_clamps_edge_expansion_settings() {
        let (_dir, vault) = open_test_vault();

        let builder = vault.context_pack().edge_hop(99).max_neighbors(10_000);
        assert_eq!(builder.edge_hop, MAX_EDGE_HOP);
        assert_eq!(builder.selected_edge_budget, MAX_CONTEXT_NEIGHBORS);
    }

    #[test]
    fn hydrate_entity_rejects_present_corrupt_header() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), b"short")?;
            Ok(())
        })?;

        let rtxn = vault.store.env.read_txn()?;
        let mut claims_suppressed = 0;
        let err = match hydrate_entity(
            &vault,
            &rtxn,
            id,
            0.0,
            HydrateOptions {
                hydrate_fields: true,
                include_edges: false,
                include_vectors: false,
                edge_cache: None,
                claim_bodies: None,
            },
            &mut claims_suppressed,
        ) {
            Ok(_) => panic!("present corrupt entity header must fail closed"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::CorruptedIndex("entity metadata header")),
            "expected CorruptedIndex(\"entity metadata header\"), got {err:?}"
        );
        assert_eq!(claims_suppressed, 0);
        Ok(())
    }

    #[test]
    fn read_vector_splits_absent_from_corrupt_rows() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        {
            let rtxn = vault.store.env.read_txn()?;
            assert!(
                read_vector(&vault, &rtxn, &id)?.is_none(),
                "absent vector rows must remain Ok(None)"
            );
        }

        vault.with_write_txn(|wtxn| {
            vault.store.vectors.put(wtxn, id.as_bytes(), &[1, 2, 3])?;
            Ok(())
        })?;
        {
            let rtxn = vault.store.env.read_txn()?;
            let err = read_vector(&vault, &rtxn, &id)
                .expect_err("present undecodable vector row must fail closed");
            assert!(
                matches!(err, Error::CorruptedIndex("entity vector")),
                "expected CorruptedIndex(\"entity vector\"), got {err:?}"
            );
        }

        let wrong_dimension = [1.0_f32, 2.0, 3.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect::<Vec<_>>();
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vectors
                .put(wtxn, id.as_bytes(), &wrong_dimension)?;
            Ok(())
        })?;
        let rtxn = vault.store.env.read_txn()?;
        let err = read_vector(&vault, &rtxn, &id)
            .expect_err("present wrong-dimension vector row must fail closed");
        assert!(
            matches!(err, Error::CorruptedIndex("entity vector")),
            "expected CorruptedIndex(\"entity vector\"), got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn include_edges_returns_edge_info() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let src = EntityId::now();
        let tgt = EntityId::now();
        put_claim_text_entity(&vault, &src, "alpha", "test.x", "y")?;
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
    fn include_edges_rejects_malformed_edge_rows() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let src = EntityId::now();
        let healthy = EntityId::now();
        let tgt = EntityId::now();
        // Non-claim type byte (TURN = 1): this test is about EDGE rows, so the
        // seeded source must stay clear of the type-0 CLAIM body validation
        // (D17/D18) — its body is opaque at the storage layer.
        put_text_entity(
            &vault,
            &src,
            1,
            "alpha",
            serde_json::json!({"text": "alpha"}),
        )?;
        put_text_entity(
            &vault,
            &healthy,
            4,
            "beta",
            serde_json::json!({"name": "Alice"}),
        )?;
        vault.put_edge(&src, crate::types::EdgeKind::Supports, &healthy, 0.7)?;

        // Plant a 13-byte edge value via a raw write: the contract pins the
        // edge value as a fixed-width LE buffer of exactly 12/24/26 bytes
        // (dbManifest n14), so 13 bytes is on-disk corruption.
        let key = Store::encode_edge_key(&src, crate::types::EdgeKind::Mentions, &tgt);
        let value = [0_u8; 13];
        vault.with_write_txn(|wtxn| {
            vault.store.edges_out.put(wtxn, &key, &value)?;
            Ok(())
        })?;

        // The healthy edge must not rescue the pack: hydration fails closed
        // on the corrupt row instead of returning partial edges (D9).
        let err = vault
            .context_pack()
            .search_text("alpha", 10)
            .include_edges(true)
            .run()
            .expect_err("malformed edge row must fail context-pack hydration closed");
        assert!(
            matches!(err, Error::CorruptedIndex("edge record")),
            "expected CorruptedIndex(\"edge record\"), got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn scan_edges_for_entity_enforces_result_bound() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let small_src = EntityId::from_bytes_unchecked([0x01; 16]);
        let bounded_src = EntityId::from_bytes_unchecked([0x02; 16]);
        let value = crate::types::encode_edge_value(
            crate::types::EdgeKind::Mentions,
            0.5,
            0,
            crate::types::Vad::NEUTRAL,
            None,
        )?;

        vault.with_write_txn(|wtxn| {
            let target = EntityId::from_bytes_unchecked([0x03; 16]);
            let key = Store::encode_edge_key(&small_src, crate::types::EdgeKind::Mentions, &target);
            vault.store.edges_out.put(wtxn, &key, &value)?;
            Ok(())
        })?;
        {
            let rtxn = vault.store.env.read_txn()?;
            assert_eq!(
                scan_edges_for_entity(&vault.store, &rtxn, &small_src)?.len(),
                1
            );
        }

        vault.with_write_txn(|wtxn| {
            for i in 0..MAX_EDGE_SCAN_RESULTS {
                let target_byte = u8::try_from(i + 4).expect("test cap fits in u8");
                let target = EntityId::from_bytes_unchecked([target_byte; 16]);
                let key =
                    Store::encode_edge_key(&bounded_src, crate::types::EdgeKind::Mentions, &target);
                vault.store.edges_out.put(wtxn, &key, &value)?;
            }
            Ok(())
        })?;
        {
            let rtxn = vault.store.env.read_txn()?;
            assert_eq!(
                scan_edges_for_entity(&vault.store, &rtxn, &bounded_src)?.len(),
                MAX_EDGE_SCAN_RESULTS
            );
        }

        vault.with_write_txn(|wtxn| {
            let overflow_target = EntityId::from_bytes_unchecked([0xFE; 16]);
            let key = Store::encode_edge_key(
                &bounded_src,
                crate::types::EdgeKind::Mentions,
                &overflow_target,
            );
            vault.store.edges_out.put(wtxn, &key, &value)?;
            Ok(())
        })?;

        let rtxn = vault.store.env.read_txn()?;
        let err = scan_edges_for_entity(&vault.store, &rtxn, &bounded_src)
            .expect_err("edge scan must fail closed once the result bound is exceeded");
        assert!(
            matches!(err, Error::CorruptedIndex("edge scan exceeded bound")),
            "expected CorruptedIndex(\"edge scan exceeded bound\"), got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_walk_rejects_malformed_edge_rows() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let root = EntityId::now();
        let neighbor = EntityId::now();
        let tgt = EntityId::now();
        // Non-claim type byte (TURN = 1): keeps this edge-row fixture clear of
        // the type-0 CLAIM body validation (D17/D18).
        put_text_entity(
            &vault,
            &root,
            1,
            "root",
            serde_json::json!({"text": "root"}),
        )?;
        put_text_entity(
            &vault,
            &neighbor,
            4,
            "friend",
            serde_json::json!({"name": "B"}),
        )?;
        vault.put_edge(&root, crate::types::EdgeKind::Supports, &neighbor, 1.0)?;

        let key = Store::encode_edge_key(&root, crate::types::EdgeKind::Mentions, &tgt);
        let value = [0_u8; 13];
        vault.with_write_txn(|wtxn| {
            vault.store.edges_out.put(wtxn, &key, &value)?;
            Ok(())
        })?;

        // include_edges stays off, so result hydration never scans edges —
        // the only edge reader on this path is the walk_edges neighbor
        // expansion, which must fail closed too (ONE-1101 AC 1).
        let err = vault
            .context_pack()
            .search_text("root", 10)
            .edge_hop(1)
            .run()
            .expect_err("malformed edge row must fail the neighbor walk closed");
        assert!(
            matches!(err, Error::CorruptedIndex("edge record")),
            "expected CorruptedIndex(\"edge record\"), got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn scan_rejects_each_malformed_edge_row_shape_like_vault_readers() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let src = EntityId::now();
        let tgt = EntityId::now();
        // Non-claim type byte (TURN = 1): keeps this edge-row fixture clear of
        // the type-0 CLAIM body validation (D17/D18).
        put_text_entity(
            &vault,
            &src,
            1,
            "alpha",
            serde_json::json!({"text": "alpha"}),
        )?;

        let supports_key =
            Store::encode_edge_key(&src, crate::types::EdgeKind::Supports, &tgt).to_vec();
        let child_of_key =
            Store::encode_edge_key(&src, crate::types::EdgeKind::ChildOf, &tgt).to_vec();

        // 33-byte key whose kind byte (20) is outside the pinned 0-19 range.
        let mut unknown_kind_key = src.as_bytes().to_vec();
        unknown_kind_key.push(20);
        unknown_kind_key.extend_from_slice(tgt.as_bytes());

        // 17-byte key: source id + kind byte, target id missing entirely.
        let mut truncated_key = src.as_bytes().to_vec();
        truncated_key.push(crate::types::EdgeKind::Supports as u8);

        // 33-byte key whose target is the reserved all-0xFF sentinel id.
        let mut reserved_target_key = src.as_bytes().to_vec();
        reserved_target_key.push(crate::types::EdgeKind::Supports as u8);
        reserved_target_key.extend_from_slice(&[0xFF; 16]);

        // 26-byte value with confirmation_status byte 4 (valid enums are 0-3).
        let mut bad_flag_value = vec![0_u8; 26];
        bad_flag_value[24] = 4;

        // Value lengths outside {12, 24, 26} and kind/layout-class mismatches
        // must all classify as CorruptedIndex("edge record") — exactly like
        // vault::parse_edge_record (ONE-1101 AC 3).
        let cases: Vec<(&str, &[u8], Vec<u8>)> = vec![
            ("empty value", &supports_key, vec![0_u8; 0]),
            ("13-byte value", &supports_key, vec![0_u8; 13]),
            ("25-byte value", &supports_key, vec![0_u8; 25]),
            ("27-byte value", &supports_key, vec![0_u8; 27]),
            (
                "12B structural value under a semantic kind",
                &supports_key,
                vec![0_u8; 12],
            ),
            (
                "24B semantic value under a structural kind",
                &child_of_key,
                vec![0_u8; 24],
            ),
            (
                "26B value with confirmation_status byte 4",
                &supports_key,
                bad_flag_value,
            ),
            ("unknown kind byte 20", &unknown_kind_key, vec![0_u8; 24]),
            ("truncated 17-byte key", &truncated_key, vec![0_u8; 24]),
            (
                "reserved sentinel target id",
                &reserved_target_key,
                vec![0_u8; 24],
            ),
        ];

        for (name, key, value) in &cases {
            vault.with_write_txn(|wtxn| {
                vault.store.edges_out.put(wtxn, key, value)?;
                Ok(())
            })?;

            {
                let rtxn = vault.store.env.read_txn()?;
                let err = scan_edges_for_entity(&vault.store, &rtxn, &src)
                    .expect_err("context-pack scan must fail closed");
                assert!(
                    matches!(err, Error::CorruptedIndex("edge record")),
                    "case `{name}`: context-pack scan returned {err:?}"
                );
            }

            // Classification parity with the canonical vault reader on the
            // same planted bytes.
            let vault_err = vault
                .edges_out(&src)
                .expect_err("vault reader must fail closed");
            assert!(
                matches!(vault_err, Error::CorruptedIndex("edge record")),
                "case `{name}`: vault.edges_out returned {vault_err:?}"
            );

            vault.with_write_txn(|wtxn| {
                vault.store.edges_out.delete(wtxn, key)?;
                Ok(())
            })?;
            let rtxn = vault.store.env.read_txn()?;
            assert!(
                scan_edges_for_entity(&vault.store, &rtxn, &src)?.is_empty(),
                "case `{name}`: scan should be clean after removing the planted row"
            );
        }

        Ok(())
    }

    #[test]
    fn vad_round_trip_through_hydration() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let src = EntityId::now();
        let tgt = EntityId::now();
        put_claim_text_entity(&vault, &src, "gamma", "test.x", "y")?;
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
        let vad = edges[0].vad.expect("semantic edge should hydrate VAD");
        assert!((vad.valence - 0.6).abs() < f32::EPSILON);
        assert!((vad.arousal - 0.3).abs() < f32::EPSILON);
        assert!((vad.dominance - 0.9).abs() < f32::EPSILON);
        Ok(())
    }

    #[test]
    fn edge_hops_collect_neighbors() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        put_claim_text_entity(&vault, &a, "root", "test.root", "root")?;
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
        let (_dir, vault) = open_test_vault();

        let root = EntityId::now();
        put_claim_text_entity(&vault, &root, "root", "test.root", "root")?;

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
    fn retrieval_budget_balances_claim_turn_and_facet_before_global_truncation() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let claim_top = EntityId::from_bytes_unchecked([0xA1; 16]);
        let claim_crowder_a = EntityId::from_bytes_unchecked([0xA2; 16]);
        let claim_crowder_b = EntityId::from_bytes_unchecked([0xA3; 16]);
        let turn = EntityId::from_bytes_unchecked([0xB1; 16]);
        let facet = EntityId::from_bytes_unchecked([0xC1; 16]);

        put_claim_text_entity(
            &vault,
            &claim_top,
            "budgetbalance",
            "test.budget.top",
            "top",
        )?;
        put_claim_text_entity(
            &vault,
            &claim_crowder_a,
            "budgetbalance",
            "test.budget.crowder_a",
            "crowder a",
        )?;
        put_claim_text_entity(
            &vault,
            &claim_crowder_b,
            "budgetbalance",
            "test.budget.crowder_b",
            "crowder b",
        )?;
        put_text_entity(
            &vault,
            &turn,
            crate::types::ENTITY_TYPE_TURN,
            "budgetbalance",
            serde_json::json!({"text": "turn"}),
        )?;
        put_text_entity(
            &vault,
            &facet,
            crate::types::ENTITY_TYPE_FACET,
            "budgetbalance",
            serde_json::json!({"name": "active facet"}),
        )?;

        vault.put_vector(&claim_top, &[1.0, 0.0, 0.0, 0.0])?;
        vault.put_vector(&claim_crowder_a, &[0.9, 0.1, 0.0, 0.0])?;
        vault.put_vector(&claim_crowder_b, &[0.8, 0.2, 0.0, 0.0])?;
        vault.put_vector(&turn, &[0.7, 0.3, 0.0, 0.0])?;
        vault.put_vector(&facet, &[0.6, 0.4, 0.0, 0.0])?;

        let pack = vault
            .context_pack()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(3)
            .retrieval_budget(ContextPackRetrievalBudget::new(1, 1, 0, 1, 0, 0))
            .run()?;

        let ids: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
        assert_eq!(
            ids,
            vec![claim_top, turn, facet],
            "CLAIM/TURN/FACET budgets must apply before global truncation"
        );
        assert!(
            !ids.contains(&claim_crowder_a) && !ids.contains(&claim_crowder_b),
            "lower-ranked claims must not consume the TURN/FACET budget"
        );
        Ok(())
    }

    #[test]
    fn retrieval_budget_zero_caps_remain_excluded_after_surplus_redistribution() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let claim = EntityId::from_bytes_unchecked([0xE1; 16]);
        let summary_a = EntityId::from_bytes_unchecked([0xE2; 16]);
        let summary_b = EntityId::from_bytes_unchecked([0xE3; 16]);

        put_claim_text_entity(&vault, &claim, "zerocapbudget", "test.zero.cap", "claim")?;
        put_text_entity(
            &vault,
            &summary_a,
            crate::types::ENTITY_TYPE_SUMMARY,
            "zerocapbudget",
            serde_json::json!({"text": "summary a"}),
        )?;
        put_text_entity(
            &vault,
            &summary_b,
            crate::types::ENTITY_TYPE_SUMMARY,
            "zerocapbudget",
            serde_json::json!({"text": "summary b"}),
        )?;

        let pack = vault
            .context_pack()
            .search_text("zerocapbudget", 10)
            .limit(3)
            .retrieval_budget(ContextPackRetrievalBudget::new(2, 0, 0, 0, 0, 0))
            .run()?;

        let ids: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
        assert_eq!(
            ids,
            vec![claim],
            "explicit zero caps must not become eligible during surplus redistribution"
        );
        Ok(())
    }

    #[test]
    fn default_retrieval_budget_keeps_small_limit_turn_results_eligible() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let turn = EntityId::from_bytes_unchecked([0xE4; 16]);
        put_text_entity(
            &vault,
            &turn,
            crate::types::ENTITY_TYPE_TURN,
            "smalllimitturn",
            serde_json::json!({"text": "turn"}),
        )?;

        let pack = vault
            .context_pack()
            .search_text("smalllimitturn", 10)
            .limit(3)
            .run()?;

        let ids: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
        assert_eq!(ids, vec![turn]);
        Ok(())
    }

    #[test]
    fn selected_edge_budget_caps_edge_walk() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let root = EntityId::from_bytes_unchecked([0xD1; 16]);
        let strongest = EntityId::from_bytes_unchecked([0xD2; 16]);
        let weaker = EntityId::from_bytes_unchecked([0xD3; 16]);
        put_claim_text_entity(&vault, &root, "edgebudget", "test.edge.root", "root")?;
        put_text_entity(
            &vault,
            &strongest,
            4,
            "edge neighbor strongest",
            serde_json::json!({"name": "strongest"}),
        )?;
        put_text_entity(
            &vault,
            &weaker,
            4,
            "edge neighbor weaker",
            serde_json::json!({"name": "weaker"}),
        )?;
        vault.put_edge(&root, crate::types::EdgeKind::Mentions, &strongest, 0.9)?;
        vault.put_edge(&root, crate::types::EdgeKind::Mentions, &weaker, 0.8)?;

        let pack = vault
            .context_pack()
            .search_text("edgebudget", 10)
            .edge_hop(1)
            .selected_edge_budget(1)
            .run()?;

        let neighbor_ids: Vec<EntityId> = pack.neighbors.iter().map(|entity| entity.id).collect();
        assert_eq!(neighbor_ids, vec![strongest]);
        Ok(())
    }

    #[test]
    fn neighbor_selection_prefers_highest_weight_edges() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let root = EntityId::from_bytes_unchecked([1; 16]);
        put_claim_text_entity(&vault, &root, "root", "test.root", "root")?;

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
        let (_dir, vault) = open_test_vault();

        let root = EntityId::from_bytes_unchecked([7; 16]);
        let child = EntityId::from_bytes_unchecked([8; 16]);
        put_claim_text_entity(&vault, &root, "root", "test.root", "root")?;
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
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        put_claim_text_entity(&vault, &id, "vec", "test.a", "b")?;

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
        let (_dir, vault) = open_test_vault();

        let pack = vault.context_pack().search_text("nothing", 10).run()?;
        assert!(pack.results.is_empty());
        assert!(pack.neighbors.is_empty());
        assert_eq!(pack.stats.candidates_considered, 0);
        let empty = pack.empty.as_ref().expect("empty context");
        assert_eq!(empty.reason, EmptyReason::NoData);
        assert_eq!(empty.total_in_scope, 0);
        Ok(())
    }

    #[test]
    fn non_empty_results_omit_empty_context() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();
        put_claim_text_entity(&vault, &id, "alpha", "test.alpha", "a")?;

        let pack = vault.context_pack().search_text("alpha", 10).run()?;
        assert_eq!(pack.results.len(), 1);
        assert!(pack.neighbors.is_empty());
        assert!(pack.empty.is_none());
        Ok(())
    }

    #[test]
    fn filtered_empty_reports_pre_filter_scope_count() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        for i in 0..3_u8 {
            let id = EntityId::from_bytes([0x30 + i; 16])?;
            put_claim_text_entity(&vault, &id, "sharedneedle", "test.filter", "v")?;
        }

        let pack = vault
            .context_pack()
            .search_text("sharedneedle", 10)
            .filter_types(&[1])
            .run()?;

        assert!(pack.results.is_empty());
        assert!(pack.neighbors.is_empty());
        assert_eq!(pack.stats.candidates_considered, 3);
        let empty = pack.empty.as_ref().expect("empty context");
        assert_eq!(empty.reason, EmptyReason::FilterMatchedNone);
        assert_eq!(empty.total_in_scope, 3);
        Ok(())
    }

    #[test]
    fn status_suppressed_empty_reports_all_activated() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let superseded = EntityId::from_bytes([0x41; 16])?;
        let retracted = EntityId::from_bytes([0x42; 16])?;
        put_claim_text_entity_with_status(
            &vault,
            &superseded,
            "deadneedle",
            "test.status",
            "superseded",
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Superseded,
        )?;
        put_claim_text_entity_with_status(
            &vault,
            &retracted,
            "deadneedle",
            "test.status",
            "retracted",
            crate::claim::ClaimApprovalStatus::Approved,
            crate::claim::ClaimLifecycleStatus::Retracted,
        )?;

        let pack = vault.context_pack().search_text("deadneedle", 10).run()?;

        assert!(pack.results.is_empty());
        assert!(pack.neighbors.is_empty());
        assert_eq!(pack.stats.candidates_considered, 2);
        assert_eq!(pack.stats.claims_suppressed, 2);
        let empty = pack.empty.as_ref().expect("empty context");
        assert_eq!(empty.reason, EmptyReason::AllActivated);
        assert_eq!(empty.total_in_scope, 2);
        Ok(())
    }

    #[test]
    fn retract_claim_end_to_end_removes_stale_text_from_context_pack() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x43; 16])?;
        put_claim_text_entity(
            &vault,
            &id,
            "retractpackneedle",
            "test.retract_pack",
            "active",
        )?;

        let before = vault
            .context_pack()
            .search_text("retractpackneedle", 10)
            .run()?;
        assert_eq!(before.results.len(), 1);
        assert_eq!(before.results[0].id, id);

        vault.retract_claim(&id, 2_000)?;

        let after = vault
            .context_pack()
            .search_text("retractpackneedle", 10)
            .run()?;
        assert!(after.results.is_empty());
        assert!(after.neighbors.is_empty());
        assert_eq!(
            after.stats.candidates_considered, 0,
            "retraction must deindex stale BM25F rows, not only filter them later"
        );
        assert_eq!(after.stats.claims_suppressed, 0);
        let empty = after.empty.as_ref().expect("empty context");
        assert_eq!(empty.reason, EmptyReason::NoData);
        assert_eq!(empty.total_in_scope, 0);
        Ok(())
    }

    #[test]
    fn empty_after_result_cap_reports_below_threshold() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();
        put_claim_text_entity(&vault, &id, "capneedle", "test.cap", "v")?;

        let pack = vault
            .context_pack()
            .search_text("capneedle", 10)
            .limit(0)
            .run()?;

        assert!(pack.results.is_empty());
        assert!(pack.neighbors.is_empty());
        assert_eq!(pack.stats.candidates_considered, 1);
        let empty = pack.empty.as_ref().expect("empty context");
        assert_eq!(empty.reason, EmptyReason::BelowThreshold);
        assert_eq!(empty.total_in_scope, pack.stats.candidates_considered);
        Ok(())
    }

    #[test]
    fn scores_match_pipeline_scores() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let a = EntityId::now();
        let b = EntityId::now();
        put_claim_text_entity(&vault, &a, "alpha alpha", "test.a", "a")?;
        put_claim_text_entity(&vault, &b, "alpha", "test.b", "b")?;

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
    fn short_id_falls_back_to_hex_on_corruption() -> Result<()> {
        // (case_name, ingest_text, search_query, corrupt_fn)
        // After each corruption, `context_pack().search_text(query).run()` must
        // still return the entity with a 32-char (hex) short_id fallback.
        type CorruptFn = fn(&Vault, &EntityId) -> Result<()>;
        let cases: &[(&str, &str, &str, CorruptFn)] = &[
            ("missing", "fallback", "fallback", |vault, id| {
                let mut wtxn = vault.store.env.write_txn()?;
                vault
                    .store
                    .short_ids_reverse
                    .delete(&mut wtxn, id.as_bytes())?;
                wtxn.commit()?;
                Ok(())
            }),
            ("corrupt", "corrupt fallback", "corrupt", |vault, id| {
                let mut wtxn = vault.store.env.write_txn()?;
                vault
                    .store
                    .short_ids_reverse
                    .put(&mut wtxn, id.as_bytes(), &[0xff, 0xfe, 7])?;
                wtxn.commit()?;
                Ok(())
            }),
        ];

        for (name, ingest_text, search_query, corrupt) in cases {
            let (_dir, vault) = open_test_vault();
            let id = EntityId::now();

            put_claim_text_entity(&vault, &id, ingest_text, "test.a", "b")?;

            corrupt(&vault, &id)?;

            let pack = vault.context_pack().search_text(search_query, 10).run()?;
            assert_eq!(pack.results.len(), 1, "case {name}");
            assert_eq!(pack.results[0].id, id, "case {name}");
            assert_eq!(
                pack.results[0].short_id.len(),
                32,
                "case {name}: short_id should fall back to 32-char hex"
            );
        }

        Ok(())
    }

    /// Blocker 2 partitioning: under the default `All` scope the pack is
    /// ordered base section first, then one section per non-base world —
    /// EVEN when fictional claims outrank the base claim. Pins base-first
    /// ordering + adjacency grouping; `fraction(1.0)` disables the cap so
    /// every claim survives.
    #[test]
    fn world_all_scope_partitions_base_first() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let world_w = EntityId::from_bytes([0xE1; 16])?;
        let world_v = EntityId::from_bytes([0xE2; 16])?;

        let w1 = EntityId::from_bytes([0x71; 16])?; // rank 0 — world W
        let w2 = EntityId::from_bytes([0x72; 16])?; // rank 1 — world W
        let claim_base = EntityId::from_bytes([0x61; 16])?; // rank 2 — base
        let v1 = EntityId::from_bytes([0x81; 16])?; // rank 3 — world V
        put_world_claim(&vault, w1, [1.0, 0.0, 0.0, 0.0], Some(world_w))?;
        put_world_claim(&vault, w2, [0.9, 0.1, 0.0, 0.0], Some(world_w))?;
        put_world_claim(&vault, claim_base, [0.8, 0.2, 0.0, 0.0], None)?;
        put_world_claim(&vault, v1, [0.7, 0.3, 0.0, 0.0], Some(world_v))?;

        let pack = vault
            .context_pack()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .non_base_world_claim_fraction(1.0) // disable the cap
            .run()?;

        let order: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
        assert_eq!(
            order,
            vec![claim_base, w1, w2, v1],
            "All-scope pack must be base section first, then world W (adjacent), then world V"
        );
        Ok(())
    }

    // ── D19 read-path claim status gate (ONE-1111) ─────────────────

    /// Writes a CLAIM with an explicit status triple and no text row —
    /// reachable only through the edge walk.
    fn put_claim_with_status(
        vault: &Vault,
        id: &EntityId,
        appr: crate::claim::ClaimApprovalStatus,
        life: crate::claim::ClaimLifecycleStatus,
        stale: bool,
    ) -> Result<()> {
        let subject = default_claim_subject_id()?;
        ensure_claim_subject_payload(vault, &subject)?;
        let mut body = crate::claim::ClaimBody::new(
            "test.status",
            crate::claim::ClaimSubject::Entity(subject),
            rmpv::Value::from("v"),
            0.9,
            appr,
            life,
        );
        body.stale = stale;
        let payload = crate::claim::encode_claim_body(&body)?;
        vault
            .batch()
            .put(id, 0, TimeRange { start: 1, end: 1 }, 1, &payload)
            .commit()
    }

    /// AC 6 — results AND neighbors apply the same gate: dead claims
    /// reached through `supports` / `claim_of` edges never enter
    /// `pack.neighbors`, while a non-claim neighbor on the same seed does.
    #[test]
    fn pack_neighbors_apply_the_status_gate() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let a = EntityId::from_bytes_unchecked([0x31; 16]);
        let retracted = EntityId::from_bytes_unchecked([0x32; 16]);
        let proposed = EntityId::from_bytes_unchecked([0x33; 16]);
        let person = EntityId::from_bytes_unchecked([0x34; 16]);

        put_claim_text_entity(&vault, &a, "rootclaim", "test.root", "root")?;
        put_claim_with_status(
            &vault,
            &retracted,
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Retracted,
            false,
        )?;
        put_claim_with_status(
            &vault,
            &proposed,
            crate::claim::ClaimApprovalStatus::Proposed,
            crate::claim::ClaimLifecycleStatus::Active,
            false,
        )?;
        put_text_entity(
            &vault,
            &person,
            4,
            "friendly",
            serde_json::json!({"name": "N"}),
        )?;

        vault.put_edge(&a, crate::types::EdgeKind::Supports, &retracted, 0.9)?;
        vault.put_edge(&a, crate::types::EdgeKind::ClaimOf, &proposed, 1.0)?;
        vault.put_edge(&a, crate::types::EdgeKind::Supports, &person, 0.8)?;

        let pack = vault
            .context_pack()
            .search_text("rootclaim", 10)
            .edge_hop(1)
            .max_neighbors(10)
            .run()?;

        assert_eq!(pack.results.len(), 1);
        assert_eq!(pack.results[0].id, a);

        let neighbor_ids: HashSet<EntityId> = pack.neighbors.iter().map(|e| e.id).collect();
        assert!(
            !neighbor_ids.contains(&retracted),
            "retracted claim via supports edge must not enter pack.neighbors"
        );
        assert!(
            !neighbor_ids.contains(&proposed),
            "proposed claim via claim_of edge must not enter pack.neighbors"
        );
        assert!(
            neighbor_ids.contains(&person),
            "non-claim neighbor must still hydrate"
        );
        assert_eq!(
            pack.stats.claims_suppressed, 2,
            "both dead claim neighbors counted"
        );
        Ok(())
    }

    /// Blocker 2 cap: with the default 0.5 fraction, 2 base + 4 fictional
    /// claims give a claim budget of 6 and a non-base cap of 3 — the three
    /// highest-scoring fiction claims survive, the lowest is dropped, and both
    /// base claims are always kept (fiction can never crowd base out).
    #[test]
    fn world_all_scope_cap_drops_excess_fiction() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let world_w = EntityId::from_bytes([0xE1; 16])?;

        let base1 = EntityId::from_bytes([0x61; 16])?; // rank 0 — base
        let f1 = EntityId::from_bytes([0x71; 16])?; // rank 1 — world W
        let f2 = EntityId::from_bytes([0x72; 16])?; // rank 2 — world W
        let base2 = EntityId::from_bytes([0x62; 16])?; // rank 3 — base
        let f3 = EntityId::from_bytes([0x73; 16])?; // rank 4 — world W
        let f4 = EntityId::from_bytes([0x74; 16])?; // rank 5 — world W (dropped)
        put_world_claim(&vault, base1, [1.0, 0.0, 0.0, 0.0], None)?;
        put_world_claim(&vault, f1, [0.9, 0.1, 0.0, 0.0], Some(world_w))?;
        put_world_claim(&vault, f2, [0.8, 0.2, 0.0, 0.0], Some(world_w))?;
        put_world_claim(&vault, base2, [0.7, 0.3, 0.0, 0.0], None)?;
        put_world_claim(&vault, f3, [0.6, 0.4, 0.0, 0.0], Some(world_w))?;
        put_world_claim(&vault, f4, [0.0, 1.0, 0.0, 0.0], Some(world_w))?;

        let pack = vault
            .context_pack()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .run()?; // default fraction = 0.5

        let ids: HashSet<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
        assert!(
            ids.contains(&base1) && ids.contains(&base2),
            "both base claims must always be kept, got {ids:?}"
        );
        assert!(
            ids.contains(&f1) && ids.contains(&f2) && ids.contains(&f3),
            "the top-3 fiction claims must survive the cap, got {ids:?}"
        );
        assert!(
            !ids.contains(&f4),
            "the lowest-scoring fiction claim must be dropped by the cap"
        );
        assert_eq!(
            pack.results.len(),
            5,
            "2 base + capped 3 fiction = 5 surviving claims"
        );
        Ok(())
    }

    #[test]
    fn pack_validation_skips_world_partition_dropped_results() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let world_w = EntityId::from_bytes([0xE1; 16])?;

        let base = EntityId::from_bytes([0x63; 16])?;
        let kept_fiction = EntityId::from_bytes([0x75; 16])?;
        let dropped_fiction = EntityId::from_bytes([0x76; 16])?;
        put_world_claim(&vault, base, [1.0, 0.0, 0.0, 0.0], None)?;
        put_world_claim(&vault, kept_fiction, [0.9, 0.1, 0.0, 0.0], Some(world_w))?;
        put_world_claim(&vault, dropped_fiction, [0.0, 1.0, 0.0, 0.0], Some(world_w))?;

        let raw = vault
            .get_raw(&dropped_fiction)?
            .expect("dropped fiction claim exists");
        let payload = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        let reversed = raw_entity_record(ENTITY_TYPE_CLAIM, 20, 10, 1, &payload);
        overwrite_raw_entity(&vault, &dropped_fiction, &reversed)?;

        let pack = vault
            .context_pack()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .run()?;

        let ids: HashSet<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
        assert!(ids.contains(&base), "base claim must survive");
        assert!(
            ids.contains(&kept_fiction),
            "top fiction claim must survive the cap"
        );
        assert!(
            !ids.contains(&dropped_fiction),
            "invalid fiction claim dropped by the cap must not abort the pack"
        );
        Ok(())
    }

    // ── RET-005 pre-assembly pack validation ───────────────────────

    #[test]
    fn pack_validation_rejects_conflicting_duplicate_ids() -> Result<()> {
        let id = EntityId::from_bytes([0x91; 16])?;
        let err = validate_scored_candidates(&[
            ScoredEntity { id, score: 1.0 },
            ScoredEntity { id, score: 0.5 },
        ])
        .expect_err("duplicate retrieval candidate id must fail before pack assembly");

        assert_context_pack_validation(err, id, PACK_VALIDATION_DUPLICATE_ID);
        Ok(())
    }

    #[test]
    fn pack_validation_rejects_missing_required_evidence() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x92; 16])?;

        put_text_entity(
            &vault,
            &id,
            1,
            "missingevidenceneedle",
            serde_json::json!({"body": "placeholder"}),
        )?;

        let source = EntityId::from_bytes([0x21; 16])?;
        let target = EntityId::from_bytes([0x22; 16])?;
        let actor = EntityId::from_bytes([0x23; 16])?;
        ensure_claim_subject_payload(&vault, &source)?;
        ensure_claim_subject_payload(&vault, &target)?;
        let value = crate::provenance::encode_edge_provenance_value(
            &crate::provenance::EdgeProvenanceClaimBody::new(
                actor,
                0.75,
                crate::provenance::SupersessionStatus::Confirmed,
            ),
        );
        let body = crate::claim::ClaimBody::new(
            crate::provenance::PREDICATE_EDGE_PROVENANCE,
            crate::claim::ClaimSubject::Edge {
                source,
                kind: crate::types::EdgeKind::Supports,
                target,
            },
            value,
            0.75,
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Active,
        );
        let payload = crate::claim::encode_claim_body(&body)?;
        let raw = raw_entity_record(ENTITY_TYPE_CLAIM, 1, 1, 1, &payload);
        overwrite_raw_entity(&vault, &id, &raw)?;

        let err = vault
            .context_pack()
            .search_text("missingevidenceneedle", 10)
            .run()
            .expect_err("provenance claim without actor-class evidence must fail pack validation");

        assert_context_pack_validation(err, id, PACK_VALIDATION_MISSING_EVIDENCE);
        Ok(())
    }

    #[test]
    fn pack_validation_rejects_missing_claim_entity_subject() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x98; 16])?;
        let subject = EntityId::from_bytes([0x5A; 16])?;
        put_claim_text_entity_with_subject(
            &vault,
            &id,
            crate::claim::ClaimSubject::Entity(subject),
            "missingclaimsubjectneedle",
            "test.missing_subject",
            "payload",
        )?;

        let err = vault
            .context_pack()
            .search_text("missingclaimsubjectneedle", 10)
            .run()
            .expect_err("missing claim subject payload must fail pack validation");

        assert_context_pack_validation(err, subject, PACK_VALIDATION_MISSING_PAYLOAD);
        Ok(())
    }

    #[test]
    fn pack_validation_rejects_deleted_claim_entity_subject() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x99; 16])?;
        let subject = EntityId::from_bytes([0x5B; 16])?;
        ensure_claim_subject_payload(&vault, &subject)?;
        put_claim_text_entity_with_subject(
            &vault,
            &id,
            crate::claim::ClaimSubject::Entity(subject),
            "deletedclaimsubjectneedle",
            "test.deleted_subject",
            "payload",
        )?;
        vault.with_write_txn(|wtxn| {
            vault.store.sync_state.put(
                wtxn,
                &crate::deletion::local_hard_delete_key(&subject),
                b"present",
            )?;
            Ok(())
        })?;

        let err = vault
            .context_pack()
            .search_text("deletedclaimsubjectneedle", 10)
            .run()
            .expect_err("deleted claim subject payload must fail pack validation");

        assert_context_pack_validation(err, subject, PACK_VALIDATION_DELETED_PAYLOAD);
        Ok(())
    }

    #[test]
    fn pack_validation_rejects_quarantined_claim_edge_subject_endpoint() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x9A; 16])?;
        let source = EntityId::from_bytes([0x5C; 16])?;
        let target = EntityId::from_bytes([0x5D; 16])?;
        let window_key = "2026-03";
        ensure_claim_subject_payload(&vault, &source)?;
        ensure_claim_subject_payload(&vault, &target)?;
        put_claim_text_entity_with_subject(
            &vault,
            &id,
            crate::claim::ClaimSubject::Edge {
                source,
                kind: crate::types::EdgeKind::Supports,
                target,
            },
            "quarantinededgeclaimsubjectneedle",
            "test.quarantined_edge_subject",
            "payload",
        )?;

        let record = pack_quarantine_record_for_entity(window_key, &target);
        let encoded = rmp_serde::to_vec_named(&record).expect("quarantine record encode");
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .sync_queue
                .put(wtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x04", &encoded)?;
            vault.store.sync_state.put(
                wtxn,
                &pack_remat_marker_key(window_key, &target),
                &[1u8],
            )?;
            Ok(())
        })?;

        let err = vault
            .context_pack()
            .search_text("quarantinededgeclaimsubjectneedle", 10)
            .run()
            .expect_err("quarantined claim edge subject endpoint must fail pack validation");

        assert_context_pack_validation(err, target, PACK_VALIDATION_QUARANTINED_PAYLOAD);
        Ok(())
    }

    #[test]
    fn pack_validation_rejects_impossible_time_ordering() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x93; 16])?;
        put_claim_text_entity(&vault, &id, "reversedtimeneedle", "test.time", "payload")?;

        let raw = vault.get_raw(&id)?.expect("claim exists");
        let payload = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        let reversed = raw_entity_record(ENTITY_TYPE_CLAIM, 20, 10, 1, &payload);
        overwrite_raw_entity(&vault, &id, &reversed)?;

        let err = vault
            .context_pack()
            .search_text("reversedtimeneedle", 10)
            .run()
            .expect_err("reversed entity envelope must fail pack validation");

        assert_context_pack_validation(err, id, PACK_VALIDATION_IMPOSSIBLE_TIME);
        Ok(())
    }

    #[test]
    fn pack_validation_rejects_deleted_payload_reference() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x94; 16])?;
        put_claim_text_entity(
            &vault,
            &id,
            "deletedreferenceneedle",
            "test.deleted",
            "payload",
        )?;

        vault.with_write_txn(|wtxn| {
            vault.store.sync_state.put(
                wtxn,
                &crate::deletion::local_hard_delete_key(&id),
                b"present",
            )?;
            Ok(())
        })?;

        let err = vault
            .context_pack()
            .search_text("deletedreferenceneedle", 10)
            .run()
            .expect_err("deleted payload reference must fail pack validation");

        assert_context_pack_validation(err, id, PACK_VALIDATION_DELETED_PAYLOAD);
        Ok(())
    }

    #[test]
    fn pack_validation_rejects_deleted_edge_target_reference() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let source = EntityId::from_bytes([0x54; 16])?;
        let target = EntityId::from_bytes([0x55; 16])?;
        put_claim_text_entity(
            &vault,
            &source,
            "deletededgetargetneedle",
            "test.edge_source",
            "payload",
        )?;
        put_text_entity(
            &vault,
            &target,
            4,
            "edge target",
            serde_json::json!({"body": "target"}),
        )?;
        vault.put_edge(&source, crate::types::EdgeKind::Supports, &target, 0.7)?;
        vault.with_write_txn(|wtxn| {
            vault.store.sync_state.put(
                wtxn,
                &crate::deletion::local_hard_delete_key(&target),
                b"present",
            )?;
            Ok(())
        })?;

        let err = vault
            .context_pack()
            .search_text("deletededgetargetneedle", 10)
            .include_edges(true)
            .run()
            .expect_err("deleted edge target reference must fail pack validation");

        assert_context_pack_validation(err, target, PACK_VALIDATION_DELETED_PAYLOAD);
        Ok(())
    }

    #[test]
    fn pack_validation_rejects_quarantined_payload_reference() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x95; 16])?;
        let window_key = "2026-03";
        put_claim_text_entity(
            &vault,
            &id,
            "quarantinedreferenceneedle",
            "test.quarantined",
            "payload",
        )?;

        let record = pack_quarantine_record_for_entity(window_key, &id);
        let encoded = rmp_serde::to_vec_named(&record).expect("quarantine record encode");
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .sync_queue
                .put(wtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x01", &encoded)?;
            vault
                .store
                .sync_state
                .put(wtxn, &pack_remat_marker_key(window_key, &id), &[1u8])?;
            Ok(())
        })?;

        let err = vault
            .context_pack()
            .search_text("quarantinedreferenceneedle", 10)
            .run()
            .expect_err("quarantined payload reference must fail pack validation");

        assert_context_pack_validation(err, id, PACK_VALIDATION_QUARANTINED_PAYLOAD);
        Ok(())
    }

    #[test]
    fn pack_validation_rejects_active_remat_marker_without_quarantine_row() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x5E; 16])?;
        let window_key = "2026-03";
        put_claim_text_entity(
            &vault,
            &id,
            "rematmarkerwithoutquarantineneedle",
            "test.marker_only",
            "payload",
        )?;

        vault.with_write_txn(|wtxn| {
            vault
                .store
                .sync_state
                .put(wtxn, &pack_remat_marker_key(window_key, &id), &[1u8])?;
            Ok(())
        })?;

        let err = vault
            .context_pack()
            .search_text("rematmarkerwithoutquarantineneedle", 10)
            .run()
            .expect_err("active remat marker alone must fail pack validation");

        assert_context_pack_validation(err, id, PACK_VALIDATION_QUARANTINED_PAYLOAD);
        Ok(())
    }

    #[test]
    fn pack_validation_rejects_active_edge_source_remat_marker() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let source = EntityId::from_bytes([0x5F; 16])?;
        let target = EntityId::from_bytes([0x60; 16])?;
        let window_key = "2026-03";
        put_claim_text_entity(
            &vault,
            &source,
            "edgesourcerematmarkerneedle",
            "test.edge_marker",
            "payload",
        )?;
        put_text_entity(
            &vault,
            &target,
            4,
            "edge target",
            serde_json::json!({"body": "target"}),
        )?;
        vault.put_edge(&source, crate::types::EdgeKind::Supports, &target, 0.7)?;
        vault.with_write_txn(|wtxn| {
            vault.store.sync_state.put(
                wtxn,
                &pack_remat_marker_key(window_key, &source),
                &[1u8],
            )?;
            Ok(())
        })?;

        let err = vault
            .context_pack()
            .search_text("edgesourcerematmarkerneedle", 10)
            .include_edges(true)
            .run()
            .expect_err("active edge-source remat marker must fail pack validation");

        assert_context_pack_validation(err, source, PACK_VALIDATION_QUARANTINED_PAYLOAD);
        Ok(())
    }

    #[test]
    fn pack_validation_ignores_stale_quarantine_row_after_reference_heals() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x96; 16])?;
        let window_key = "2026-03";
        put_claim_text_entity(
            &vault,
            &id,
            "stalequarantinereferenceneedle",
            "test.stale_quarantine",
            "payload",
        )?;

        let record = pack_quarantine_record_for_entity(window_key, &id);
        let encoded = rmp_serde::to_vec_named(&record).expect("quarantine record encode");
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .sync_queue
                .put(wtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x02", &encoded)?;
            Ok(())
        })?;

        let pack = vault
            .context_pack()
            .search_text("stalequarantinereferenceneedle", 10)
            .run()?;

        assert!(pack.results.iter().any(|entity| entity.id == id));
        Ok(())
    }

    #[test]
    fn pack_validation_fails_closed_on_corrupt_quarantine_row() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::from_bytes([0x97; 16])?;
        put_claim_text_entity(
            &vault,
            &id,
            "corruptquarantinerowneedle",
            "test.corrupt_quarantine",
            "payload",
        )?;

        vault.with_write_txn(|wtxn| {
            vault
                .store
                .sync_queue
                .put(wtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x03", &[0xc1])?;
            Ok(())
        })?;

        let err = vault
            .context_pack()
            .search_text("corruptquarantinerowneedle", 10)
            .run()
            .expect_err("corrupt quarantine row must fail closed");

        match err {
            Error::CorruptedIndex(row) => assert_eq!(row, PACK_QUARANTINE_ROW),
            other => panic!("expected CorruptedIndex({PACK_QUARANTINE_ROW:?}), got {other:?}"),
        }
        Ok(())
    }

    /// AC 7 — fail-closed hydration: a raw-written type-0 neighbor whose
    /// body is not the pinned CLAIM ABI is EXCLUDED (and counted), never
    /// surfaced with empty fields. Exclusion, not error.
    #[test]
    fn pack_hydration_fails_closed_on_undecodable_claim_neighbor() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let a = EntityId::from_bytes_unchecked([0x41; 16]);
        let bad = EntityId::from_bytes_unchecked([0x42; 16]);
        put_claim_text_entity(&vault, &a, "badneighbor", "test.root", "root")?;

        // Raw 25-byte envelope (type 0) + a non-map MessagePack body.
        let mut junk_body = Vec::new();
        rmpv::encode::write_value(&mut junk_body, &rmpv::Value::from("junk"))
            .expect("msgpack encode");
        let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + junk_body.len());
        raw.push(0);
        raw.extend_from_slice(&1_u64.to_be_bytes());
        raw.extend_from_slice(&1_u64.to_be_bytes());
        raw.extend_from_slice(&1_u64.to_be_bytes());
        raw.extend_from_slice(&junk_body);
        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, bad.as_bytes(), &raw)?;
            Ok(())
        })?;
        vault.put_edge(&a, crate::types::EdgeKind::Supports, &bad, 0.9)?;

        let pack = vault
            .context_pack()
            .search_text("badneighbor", 10)
            .edge_hop(1)
            .run()?;

        assert_eq!(pack.results.len(), 1);
        assert!(
            pack.neighbors.iter().all(|e| e.id != bad),
            "undecodable type-0 neighbor must be excluded, not surfaced with empty fields"
        );
        assert_eq!(pack.stats.claims_suppressed, 1);
        Ok(())
    }

    /// AC 9 — a claim body is MessagePack-decoded exactly ONCE per entity
    /// for gate + projection: results reuse the pipeline gate's decode,
    /// neighbors reuse the pre-assembly validation decode. Counted via the
    /// claim-module decode counter, not by round-tripping output.
    #[test]
    fn claim_body_is_decoded_once_per_result_for_gate_and_projection() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let a = EntityId::from_bytes_unchecked([0x51; 16]);
        let b = EntityId::from_bytes_unchecked([0x52; 16]);
        put_claim_text_entity(&vault, &a, "decodeonce", "test.root", "root")?;
        put_claim_with_status(
            &vault,
            &b,
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Active,
            false,
        )?;
        vault.put_edge(&a, crate::types::EdgeKind::Supports, &b, 0.9)?;

        crate::claim::reset_claim_body_decode_count();
        let pack = vault
            .context_pack()
            .search_text("decodeonce", 10)
            .edge_hop(1)
            .run()?;
        assert_eq!(
            crate::claim::claim_body_decode_count(),
            2,
            "one decode for the result claim (pipeline gate, reused by projection) \
             + one for the neighbor claim (validation, reused by projection)"
        );

        // The single decode still projects full fields on both.
        assert_eq!(pack.results.len(), 1);
        let result_fields = pack.results[0].fields.as_ref().expect("result fields");
        assert_eq!(
            result_fields.get("pred").and_then(|v| v.as_str()),
            Some("test.root")
        );
        assert_eq!(
            result_fields.get("appr").and_then(|v| v.as_str()),
            Some("auto")
        );
        assert_eq!(
            result_fields.get("life").and_then(|v| v.as_str()),
            Some("active")
        );
        assert!(
            result_fields.contains_key("subj"),
            "subj key projects (as null) like the generic decoder"
        );

        let neighbor = pack
            .neighbors
            .iter()
            .find(|e| e.id == b)
            .expect("active claim neighbor hydrates");
        let neighbor_fields = neighbor.fields.as_ref().expect("neighbor fields");
        assert_eq!(
            neighbor_fields.get("pred").and_then(|v| v.as_str()),
            Some("test.status")
        );
        Ok(())
    }

    /// AC 10 — walk_edges kind/provenance gating: `child_of` and
    /// `assigned_to` (structural, not retrieval-scored) contribute no
    /// neighbor even at weight 1.0; retracted-provenanced edges are skipped
    /// (D8-consistent); `opposes` and non-retracted provenanced edges ARE
    /// followed.
    #[test]
    fn walk_edges_gates_structural_kinds_and_retracted_provenance() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let root = EntityId::from_bytes_unchecked([0x61; 16]);
        put_claim_text_entity(&vault, &root, "walkroot", "test.root", "root")?;

        let child_of_tgt = EntityId::from_bytes_unchecked([0x62; 16]);
        let assigned_tgt = EntityId::from_bytes_unchecked([0x63; 16]);
        let opposes_tgt = EntityId::from_bytes_unchecked([0x64; 16]);
        let retracted_tgt = EntityId::from_bytes_unchecked([0x65; 16]);
        let confirmed_tgt = EntityId::from_bytes_unchecked([0x66; 16]);
        for (i, id) in [
            child_of_tgt,
            assigned_tgt,
            opposes_tgt,
            retracted_tgt,
            confirmed_tgt,
        ]
        .iter()
        .enumerate()
        {
            put_text_entity(
                &vault,
                id,
                4,
                "target",
                serde_json::json!({"name": format!("T{i}")}),
            )?;
        }

        // Structural plumbing at FULL weight — must contribute no neighbor.
        vault.put_edge(&root, crate::types::EdgeKind::ChildOf, &child_of_tgt, 1.0)?;
        vault.put_edge(
            &root,
            crate::types::EdgeKind::AssignedTo,
            &assigned_tgt,
            1.0,
        )?;
        // Contradiction IS context — opposes is followed (unlike PPR λ=0).
        vault.put_edge(&root, crate::types::EdgeKind::Opposes, &opposes_tgt, 0.5)?;

        // Two provenanced (26 B) edges planted raw: confirmation_status
        // byte 24 = retracted (3) must be skipped, confirmed (1) followed.
        let plant = |tgt: &EntityId, status: crate::types::EdgeConfirmationStatus| -> Result<()> {
            let key = Store::encode_edge_key(&root, crate::types::EdgeKind::Supports, tgt);
            let value = crate::types::encode_edge_value(
                crate::types::EdgeKind::Supports,
                0.9,
                1,
                crate::types::Vad::NEUTRAL,
                Some(crate::types::EdgeProvenanceFlags {
                    confirmation_status: status,
                    actor_class: crate::types::EdgeActorClass::Human,
                }),
            )?;
            vault.with_write_txn(|wtxn| {
                vault.store.edges_out.put(wtxn, &key, &value)?;
                Ok(())
            })
        };
        plant(
            &retracted_tgt,
            crate::types::EdgeConfirmationStatus::Retracted,
        )?;
        plant(
            &confirmed_tgt,
            crate::types::EdgeConfirmationStatus::Confirmed,
        )?;

        let pack = vault
            .context_pack()
            .search_text("walkroot", 10)
            .edge_hop(1)
            .max_neighbors(10)
            .run()?;

        let neighbor_ids: HashSet<EntityId> = pack.neighbors.iter().map(|e| e.id).collect();
        assert!(
            !neighbor_ids.contains(&child_of_tgt),
            "child_of (weight 1.0) must contribute no neighbor"
        );
        assert!(
            !neighbor_ids.contains(&assigned_tgt),
            "assigned_to must contribute no neighbor"
        );
        assert!(
            !neighbor_ids.contains(&retracted_tgt),
            "retracted-provenanced edge must be skipped"
        );
        assert!(
            neighbor_ids.contains(&opposes_tgt),
            "opposes must still be followed"
        );
        assert!(
            neighbor_ids.contains(&confirmed_tgt),
            "confirmed-provenanced edge must still be followed"
        );
        Ok(())
    }

    /// Pipeline-suppressed claims are reported through
    /// `PackStats::claims_suppressed` (exclusion is silent — the count is
    /// the only signal).
    #[test]
    fn pack_stats_count_pipeline_suppressed_claims() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let live = EntityId::from_bytes_unchecked([0x71; 16]);
        let dead = EntityId::from_bytes_unchecked([0x72; 16]);
        put_claim_text_entity(&vault, &live, "statneedle", "test.live", "v")?;
        put_claim_text_entity_with_lifecycle(
            &vault,
            &dead,
            "statneedle",
            "test.dead",
            "v",
            crate::claim::ClaimLifecycleStatus::Retracted,
        )?;

        let pack = vault.context_pack().search_text("statneedle", 10).run()?;
        assert_eq!(pack.results.len(), 1);
        assert_eq!(pack.results[0].id, live);
        assert_eq!(pack.stats.claims_suppressed, 1);
        Ok(())
    }

    #[test]
    fn context_pack_telemetry_records_final_hydration_suppressions() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let live = EntityId::from_bytes_unchecked([0x73; 16]);
        let dead_neighbor = EntityId::from_bytes_unchecked([0x74; 16]);
        put_claim_text_entity(&vault, &live, "telemetryhydrate", "test.live", "v")?;
        put_claim_with_status(
            &vault,
            &dead_neighbor,
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Retracted,
            false,
        )?;
        vault.put_edge(&live, crate::types::EdgeKind::Supports, &dead_neighbor, 0.9)?;

        let pack_with_telemetry = vault
            .context_pack()
            .search_text("telemetryhydrate", 10)
            .edge_hop(1)
            .run_with_telemetry()?;
        let run_id = pack_with_telemetry
            .run_id
            .expect("context-pack telemetry run id");
        let pack = pack_with_telemetry.value;
        assert_eq!(pack.results.len(), 1);
        assert_eq!(pack.results[0].id, live);
        assert!(pack.neighbors.is_empty());
        assert_eq!(pack.stats.claims_suppressed, 1);

        let runs = vault.retrieval_runs(1)?;
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].action, crate::store::RetrievalAction::ContextPack);
        assert_eq!(runs[0].run_id, run_id);
        assert_eq!(runs[0].claims_suppressed, pack.stats.claims_suppressed);
        assert_eq!(runs[0].result_ids, vec![*live.as_bytes()]);
        assert_eq!(runs[0].score_breakdown.len(), 1);
        assert_eq!(runs[0].score_breakdown[0].result_id, *live.as_bytes());
        Ok(())
    }

    #[test]
    fn context_pack_provisional_telemetry_hidden_until_finalization() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let id = EntityId::from_bytes_unchecked([0x7E; 16]);
        put_text_entity(
            &vault,
            &id,
            crate::types::ENTITY_TYPE_PERSON,
            "telemetry unpublished finalization",
            serde_json::json!({"name": "Unpublished"}),
        )?;

        let run = vault
            .context_pack()
            .search_text("telemetry unpublished finalization", 10)
            .run_unfinalized()?;
        let run_id = run
            .telemetry_run_id
            .expect("unfinalized context-pack telemetry run id");
        assert!(
            vault.retrieval_runs(10)?.is_empty(),
            "unfinalized context-pack telemetry must not be publicly listed"
        );
        let outcome_error = run
            .store
            .record_retrieval_outcome(crate::store::RetrievalOutcome {
                run_id,
                key: "click".to_owned(),
                reward: Some(1.0),
                accepted: Some(true),
                metadata: BTreeMap::new(),
            })
            .expect_err("unfinalized context-pack telemetry must reject outcomes");
        assert!(matches!(outcome_error, Error::InvalidConfig(_)));

        let surfaced_result_ids: Vec<[u8; 16]> = run
            .pack
            .results
            .iter()
            .map(|entity| *entity.id.as_bytes())
            .collect();
        let finalized_run_id = finalize_context_pack_telemetry(
            run.store,
            run.telemetry_run_id,
            run.pack.stats.query_time_us,
            run.pack.stats.claims_suppressed,
            &surfaced_result_ids,
            context_pack_empty_reason(&run.pack, &surfaced_result_ids),
        );
        assert_eq!(finalized_run_id, Some(run_id));

        let runs = vault.retrieval_runs(1)?;
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert_eq!(runs[0].result_ids, vec![*id.as_bytes()]);
        run.store
            .record_retrieval_outcome(crate::store::RetrievalOutcome {
                run_id,
                key: "click".to_owned(),
                reward: Some(1.0),
                accepted: Some(true),
                metadata: BTreeMap::new(),
            })?;
        assert_eq!(run.store.retrieval_outcomes(run_id)?.len(), 1);
        Ok(())
    }

    #[test]
    fn context_pack_telemetry_discards_run_on_assembly_error() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let id = EntityId::from_bytes_unchecked([0x7B; 16]);
        vault
            .batch()
            .put(
                &id,
                crate::types::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &msgpack_entity(serde_json::json!({"name": "Corrupt"})),
            )
            .text(&id, &[("body", "telemetry corrupt vector")])
            .vector(&id, &[1.0, 0.0, 0.0, 0.0])
            .commit()?;
        vault.with_write_txn(|wtxn| {
            vault.store.vectors.put(wtxn, id.as_bytes(), &[1, 2, 3])?;
            Ok(())
        })?;

        let error = vault
            .context_pack()
            .search_text("telemetry corrupt vector", 10)
            .include_vectors(true)
            .run_with_telemetry()
            .expect_err("corrupt post-pipeline vector hydration should fail the context pack");
        assert!(
            matches!(error, Error::CorruptedIndex("entity vector")),
            "expected CorruptedIndex(\"entity vector\"), got {error:?}"
        );
        assert!(
            vault.retrieval_runs(10)?.is_empty(),
            "failed context-pack assembly must not leave a completed telemetry row"
        );
        Ok(())
    }

    #[test]
    fn context_pack_telemetry_discard_removes_provisional_outcomes() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let id = EntityId::from_bytes_unchecked([0x7C; 16]);
        put_text_entity(
            &vault,
            &id,
            crate::types::ENTITY_TYPE_PERSON,
            "telemetry provisional outcome",
            serde_json::json!({"name": "Provisional"}),
        )?;

        let run = vault
            .context_pack()
            .search_text("telemetry provisional outcome", 10)
            .run_unfinalized()?;
        let run_id = run
            .telemetry_run_id
            .expect("unfinalized context-pack telemetry run id");
        let outcome_error = run
            .store
            .record_retrieval_outcome(crate::store::RetrievalOutcome {
                run_id,
                key: "click".to_owned(),
                reward: Some(1.0),
                accepted: Some(true),
                metadata: BTreeMap::new(),
            })
            .expect_err("unfinalized context-pack telemetry must reject outcomes");
        assert!(matches!(outcome_error, Error::InvalidConfig(_)));
        assert!(run.store.retrieval_outcomes(run_id)?.is_empty());

        discard_failed_context_pack_telemetry(run.store, run.telemetry_run_id);

        assert!(
            !run.store
                .retrieval_runs(10)?
                .iter()
                .any(|record| record.run_id == run_id),
            "discarded context-pack telemetry run should not remain readable"
        );
        assert!(
            run.store.retrieval_outcomes(run_id)?.is_empty(),
            "discarded context-pack telemetry run should not leave readable outcomes"
        );
        Ok(())
    }

    #[test]
    fn context_pack_telemetry_finalization_failure_returns_no_run_id() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let id = EntityId::from_bytes_unchecked([0x7D; 16]);
        put_text_entity(
            &vault,
            &id,
            crate::types::ENTITY_TYPE_PERSON,
            "telemetry corrupt finalization",
            serde_json::json!({"name": "Corrupt Finalization"}),
        )?;

        let run = vault
            .context_pack()
            .search_text("telemetry corrupt finalization", 10)
            .run_unfinalized()?;
        let run_id = run
            .telemetry_run_id
            .expect("unfinalized context-pack telemetry run id");
        let outcome_error = run
            .store
            .record_retrieval_outcome(crate::store::RetrievalOutcome {
                run_id,
                key: "click".to_owned(),
                reward: Some(1.0),
                accepted: Some(true),
                metadata: BTreeMap::new(),
            })
            .expect_err("unfinalized context-pack telemetry must reject outcomes");
        assert!(matches!(outcome_error, Error::InvalidConfig(_)));

        let mut run_key = Vec::from(&b"retr_run:v0:"[..]);
        run_key.extend_from_slice(&run_id.as_bytes());
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .put(wtxn, &run_key, b"not a retrieval run")?;
            Ok(())
        })?;

        let surfaced_result_ids: Vec<[u8; 16]> = run
            .pack
            .results
            .iter()
            .map(|entity| *entity.id.as_bytes())
            .collect();
        let returned_run_id = finalize_context_pack_telemetry(
            run.store,
            run.telemetry_run_id,
            run.pack.stats.query_time_us,
            run.pack.stats.claims_suppressed,
            &surfaced_result_ids,
            context_pack_empty_reason(&run.pack, &surfaced_result_ids),
        );

        assert_eq!(returned_run_id, None);
        assert!(
            !run.store
                .retrieval_runs(10)?
                .iter()
                .any(|record| record.run_id == run_id),
            "failed finalization should discard the provisional telemetry row"
        );
        assert!(
            run.store.retrieval_outcomes(run_id)?.is_empty(),
            "failed finalization should discard provisional outcomes"
        );
        Ok(())
    }

    #[test]
    fn context_pack_serialized_telemetry_reflects_budget_surviving_results() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let survivor = EntityId::from_bytes_unchecked([0x75; 16]);
        let dropped = EntityId::from_bytes_unchecked([0x76; 16]);
        let put_turn = |id: EntityId, vector: [f32; 4], text: &str| -> Result<()> {
            let payload = msgpack_entity(serde_json::json!({
                "txt": text,
                "spkr": "user",
                "at": 1_u64,
            }));
            vault
                .batch()
                .put(
                    &id,
                    crate::types::ENTITY_TYPE_TURN,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &payload,
                )
                .vector(&id, &vector)
                .commit()
        };
        put_turn(survivor, [1.0, 0.0, 0.0, 0.0], "budget survivor")?;
        put_turn(dropped, [0.0, 1.0, 0.0, 0.0], "budget dropped")?;

        let serialized = vault
            .context_pack()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .format(PackFormat::Plaintext)
            .token_budget(1)
            .run_serialized_with_telemetry()?;
        assert!(!serialized.value.is_empty());
        let run_id = serialized.run_id.expect("serialized telemetry run id");

        let runs = vault.retrieval_runs(1)?;
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert_eq!(runs[0].action, crate::store::RetrievalAction::ContextPack);
        assert!(
            runs[0].total_in_scope >= 2,
            "test setup should hydrate at least two pre-budget primary results"
        );
        assert_eq!(runs[0].result_ids, vec![*survivor.as_bytes()]);
        assert!(!runs[0].result_ids.contains(dropped.as_bytes()));
        assert_eq!(runs[0].score_breakdown.len(), 1);
        assert_eq!(runs[0].score_breakdown[0].result_id, *survivor.as_bytes());
        assert_eq!(runs[0].score_breakdown[0].final_rank, 1);
        assert_eq!(runs[0].empty_reason, None);
        Ok(())
    }

    #[test]
    fn context_pack_serialized_telemetry_reports_item_budget_empty() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let first = EntityId::from_bytes_unchecked([0x77; 16]);
        let second = EntityId::from_bytes_unchecked([0x78; 16]);
        let put_turn = |id: EntityId, vector: [f32; 4], text: &str| -> Result<()> {
            let payload = msgpack_entity(serde_json::json!({
                "txt": text,
                "spkr": "user",
                "at": 1_u64,
            }));
            vault
                .batch()
                .put(
                    &id,
                    crate::types::ENTITY_TYPE_TURN,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &payload,
                )
                .vector(&id, &vector)
                .commit()
        };
        put_turn(first, [1.0, 0.0, 0.0, 0.0], "budget empty first")?;
        put_turn(second, [0.0, 1.0, 0.0, 0.0], "budget empty second")?;

        let serialized = vault
            .context_pack()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .format(PackFormat::Plaintext)
            .max_item_tokens(1)
            .run_serialized_with_telemetry()?;
        let run_id = serialized.run_id.expect("serialized telemetry run id");

        let runs = vault.retrieval_runs(1)?;
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert!(
            runs[0].total_in_scope >= 2,
            "test setup should hydrate at least two pre-budget primary results"
        );
        assert!(runs[0].result_ids.is_empty());
        assert!(runs[0].score_breakdown.is_empty());
        assert_eq!(runs[0].empty_reason.as_deref(), Some("ItemBudget"));
        Ok(())
    }

    #[test]
    fn context_pack_serialized_telemetry_excludes_merged_neighbors() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let result = EntityId::from_bytes_unchecked([0x7A; 16]);
        let neighbor = EntityId::from_bytes_unchecked([0x7B; 16]);
        put_claim_text_entity(
            &vault,
            &result,
            "serializedneighborroot",
            "test.result",
            "root",
        )?;
        put_text_entity(
            &vault,
            &neighbor,
            crate::types::ENTITY_TYPE_PERSON,
            "serialized neighbor",
            serde_json::json!({"name": "Neighbor"}),
        )?;
        vault.put_edge(&result, crate::types::EdgeKind::Supports, &neighbor, 1.0)?;

        let serialized = vault
            .context_pack()
            .search_text("serializedneighborroot", 10)
            .edge_hop(1)
            .format(PackFormat::Plaintext)
            .run_serialized_with_telemetry()?;
        assert!(!serialized.value.is_empty());
        let text = std::str::from_utf8(&serialized.value).expect("plaintext context pack");
        assert!(
            text.contains("Neighbor"),
            "test setup should serialize the merged neighbor"
        );
        let run_id = serialized.run_id.expect("serialized telemetry run id");

        let runs = vault.retrieval_runs(1)?;
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert_eq!(runs[0].action, crate::store::RetrievalAction::ContextPack);
        assert_eq!(runs[0].result_ids, vec![*result.as_bytes()]);
        assert!(!runs[0].result_ids.contains(neighbor.as_bytes()));
        assert_eq!(runs[0].score_breakdown.len(), 1);
        assert_eq!(runs[0].score_breakdown[0].result_id, *result.as_bytes());
        Ok(())
    }
}
