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
use crate::companion::{
    CompanionLifecycleEvent, CompanionScope, CompanionSubject, ENTITY_TYPE_COMPANION_REGISTER,
    decode_companion_record_body,
};
use crate::disclosure::{DisclosureAssembly, DisclosureContext, DisclosureMode};
use crate::edge::{EdgeConfirmationStatus, EdgeInfo, EdgeKind};
use crate::eiri::EIRI_CONTEXT_VERSION_V4;
use crate::eiri::EiriCompanionAssembly;
use crate::eiri::EiriMemoryBoard;
use crate::eiri::EiriMemoryBoardBudget;
use crate::eiri::EiriMemoryBoardRow;
use crate::eiri::EiriMemoryBoardSlot;
use crate::eiri::EiriMemoryBoardSource;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::pipeline::Signal;
use crate::pipeline::{PipelineBuilder, RetrievalWithTelemetry, WorldScope};
use crate::psych_profile::{PsychMirrorSourceCandidate, psych_mirror_text_entropy};
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::serialize::{SerializeConfig, SerializedPackTelemetry, serialize_pack_with_telemetry};
use crate::store::{RetrievalAction, RetrievalRunId, RetrievalSignal, Store};
use crate::temporal::TemporalAnchorMode;
use crate::temporal::TemporalGranularity;
use crate::temporal::TimeRange;
use crate::{Vault, le_bytes_to_f32_vec};

pub const DEFAULT_MAX_NEIGHBORS: usize = 50;
const DEFAULT_TOKEN_BUDGET: usize = 4000;
pub const DEFAULT_MAX_FIELD_CHARS: usize = 500;
pub const MAX_EDGE_HOP: u32 = 5;
#[cfg(not(test))]
const MAX_EDGE_SCAN_RESULTS: usize = 100_000;
#[cfg(test)]
const MAX_EDGE_SCAN_RESULTS: usize = 64;
pub const MAX_CONTEXT_NEIGHBORS: usize = 1000;
const PACK_VALIDATION_DUPLICATE_ID: &str = "conflicting duplicate id";
const PACK_VALIDATION_MISSING_PAYLOAD: &str = "missing referenced payload";
const PACK_VALIDATION_IMPOSSIBLE_TIME: &str = "impossible time ordering";
const PACK_VALIDATION_MISSING_EVIDENCE: &str = "missing required evidence";
const PACK_VALIDATION_DELETED_PAYLOAD: &str = "deleted payload reference";
const PACK_VALIDATION_QUARANTINED_PAYLOAD: &str = "quarantined payload reference";
const PACK_QUARANTINE_ROW: &str = "sync quarantine row";
const PACK_REMAT_MARKER_PREFIX: &str = "rm:w:";
const PSYCH_MIRROR_CONTEXT_TEXT_FIELD_ALIASES: [&str; 4] = ["val", "txt", "text", "body"];
const PSYCH_MIRROR_STRUCTURED_TEXT_SEPARATOR: &str = "\n";
/// Default share of the claim budget that non-base (fictional / dream) worlds
/// may occupy in an `All`-scope pack — fiction takes at most half, so it can
/// never crowd base reality out (ARCH-0004 / ARCH-0022).
const DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION: f32 = 0.5;
pub const MCP_CONTEXT_PACK_REF_SCHEMA_VERSION: &str = "context_pack_ref.v1";
#[cfg(test)]
thread_local! {
    static EDGE_SCAN_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpContextPackRef {
    pub schema_version: String,
    #[serde(default)]
    pub context_version: Option<String>,
    #[serde(default)]
    pub pack_ref: Option<String>,
    #[serde(default)]
    pub retrieval_run_id: Option<String>,
    #[serde(default)]
    pub result_ids: Vec<String>,
    #[serde(default)]
    pub budget_ref: Option<String>,
}

impl McpContextPackRef {
    pub fn validate(&self) -> std::result::Result<(), McpContextPackRefError> {
        if self.schema_version != MCP_CONTEXT_PACK_REF_SCHEMA_VERSION {
            return Err(McpContextPackRefError::UnsupportedSchemaVersion);
        }
        validate_optional_context_pack_ref_field(
            "context_version",
            self.context_version.as_deref(),
        )?;
        validate_optional_context_pack_ref_field("pack_ref", self.pack_ref.as_deref())?;
        validate_optional_context_pack_ref_field(
            "retrieval_run_id",
            self.retrieval_run_id.as_deref(),
        )?;
        validate_optional_context_pack_ref_field("budget_ref", self.budget_ref.as_deref())?;
        if self.pack_ref.is_none() && self.retrieval_run_id.is_none() && self.result_ids.is_empty()
        {
            return Err(McpContextPackRefError::MissingHandle);
        }
        for result_id in &self.result_ids {
            validate_context_pack_result_id(result_id)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum McpContextPackRefError {
    #[error("unsupported context-pack reference schema version")]
    UnsupportedSchemaVersion,
    #[error("context-pack reference requires pack_ref, retrieval_run_id, or result_ids")]
    MissingHandle,
    #[error("{0} must not be blank")]
    BlankField(&'static str),
    #[error("result_ids entries must be canonical entity ids")]
    InvalidResultId,
}

fn validate_optional_context_pack_ref_field(
    field: &'static str,
    value: Option<&str>,
) -> std::result::Result<(), McpContextPackRefError> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        return Err(McpContextPackRefError::BlankField(field));
    }
    Ok(())
}

fn validate_context_pack_result_id(
    result_id: &str,
) -> std::result::Result<(), McpContextPackRefError> {
    let parsed =
        EntityId::from_hex(result_id).map_err(|_| McpContextPackRefError::InvalidResultId)?;
    if parsed.to_hex() != result_id {
        return Err(McpContextPackRefError::InvalidResultId);
    }
    Ok(())
}

#[derive(Debug, Default)]
struct EdgeWalkResult {
    neighbor_ids: Vec<EntityId>,
    scanned_edges: HashMap<EntityId, Vec<EdgeInfo>>,
}

#[derive(Debug, Clone)]
pub struct SerializedContextPack {
    pub bytes: Vec<u8>,
    pub stats: PackStats,
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
    /// OF-365 disclosure clamp: hydrated edge lists filter non-admitted
    /// targets next to the off-record fence check.
    clamp: Option<&'a DisclosureContext>,
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
    disclosure: Option<DisclosureContext>,
    /// Additive session routing (ONE-1570 Arm B). `None` on every canonical
    /// entry, which is therefore behaviorally unchanged. The sibling field on
    /// `PipelineBuilder` routes the PROVISIONAL registration; this one is what
    /// lets the FINALIZE reach the same row, so the two halves of a
    /// context-pack run cannot land on different targets.
    session: Option<&'a crate::off_record::SessionRetrievalTelemetry<'a>>,
}

/// Where this assembly's retrieval-run telemetry lives, CAPTURED ONCE at run
/// entry (ONE-1570 Arm B).
///
/// A context pack registers a PROVISIONAL run row and finalizes it in a SECOND
/// write. Both writes must reach the same row. Re-deriving the target between
/// them would let an assembly whose room flipped mid-run stage its provisional
/// into the session overlay and then finalize into BASE — publishing the
/// room's `result_ids` durably under a route it no longer held. Carrying the
/// target as a value makes that unrepresentable, which is why this replaced
/// the bare `&Store` these structs used to hold.
#[derive(Clone, Copy)]
enum ContextPackTelemetry<'a> {
    /// The canonical base ledger. Every non-session entry takes this arm and
    /// is behaviorally unchanged.
    Base(&'a Store),
    /// A live off-record room (ARCH-0052 K8/K10): the row rides the session's
    /// overlay `VaultMeta` and evaporates with the transcript at close, where
    /// the pre-close census counts it as a deleted context receipt.
    ///
    /// Carries the OVERLAY rather than the view the provisional registered
    /// through, because both writes below READ the row first and a
    /// `SessionStoreView` cannot see rows staged after its own construction.
    Session {
        vault: &'a Vault,
        overlay: &'a std::sync::Arc<crate::session_overlay::SessionOverlay>,
    },
}

impl ContextPackTelemetry<'_> {
    /// Clears the provisional marker and publishes the final row, against
    /// whichever target registered the provisional.
    fn finalize(
        self,
        run_id: RetrievalRunId,
        elapsed_us: u64,
        claims_suppressed: usize,
        surfaced_result_ids: &[[u8; 16]],
        empty_reason: Option<String>,
    ) -> Result<()> {
        match self {
            Self::Base(store) => store.finalize_context_pack_retrieval_run(
                run_id,
                elapsed_us,
                claims_suppressed,
                surfaced_result_ids,
                empty_reason,
            ),
            // Same base-writer-then-segment-permit order every other overlay
            // staging site takes; the guard applies staged rows only once the
            // base commit returns. The view is built AFTER the install so it
            // is segment-aware and can read back the provisional row this
            // call rewrites.
            Self::Session { vault, overlay } => vault
                .with_write_txn(|wtxn| {
                    let segment = overlay.install_txn_segment()?;
                    let view = vault.store.session_view(overlay.clone())?;
                    view.finalize_context_pack_retrieval_run_in_txn(
                        wtxn,
                        run_id,
                        elapsed_us,
                        claims_suppressed,
                        surfaced_result_ids,
                        empty_reason,
                    )?;
                    Ok(segment)
                })
                .and_then(crate::session_overlay::TxnSegmentGuard::commit),
        }
    }

    /// Removes a provisional row whose assembly failed, leaving no residue on
    /// the target that holds it.
    fn discard(self, run_id: RetrievalRunId) -> Result<()> {
        match self {
            Self::Base(store) => store.delete_retrieval_run(run_id),
            Self::Session { vault, overlay } => vault
                .with_write_txn(|wtxn| {
                    let segment = overlay.install_txn_segment()?;
                    let view = vault.store.session_view(overlay.clone())?;
                    view.delete_retrieval_run_in_txn(wtxn, run_id)?;
                    Ok(segment)
                })
                .and_then(crate::session_overlay::TxnSegmentGuard::commit),
        }
    }
}

struct ContextPackRun<'a> {
    pack: ContextPack,
    telemetry_run_id: Option<RetrievalRunId>,
    telemetry: ContextPackTelemetry<'a>,
    clamped_out: u64,
}

pub struct UnfinalizedContextPack<'a> {
    pub value: ContextPack,
    telemetry_run_id: Option<RetrievalRunId>,
    telemetry: ContextPackTelemetry<'a>,
    clamped_out: u64,
}

impl UnfinalizedContextPack<'_> {
    pub fn discard_telemetry(&mut self) {
        discard_failed_context_pack_telemetry(self.telemetry, self.telemetry_run_id.take());
    }

    /// Scored candidates dropped by the disclosure clamp's candidate sweep
    /// this assembly (OF-365 ILD-2). Non-clamped runs report 0.
    #[must_use]
    pub fn clamped_out(&self) -> u64 {
        self.clamped_out
    }

    pub fn finish_projected_json(
        mut self,
        config: &SerializeConfig,
    ) -> RetrievalWithTelemetry<ContextPack> {
        let pre_projection_stats = self.value.stats.clone();
        let pre_projection_had_results = !self.value.results.is_empty();
        let mut pack = crate::serialize::project_pack_for_json_response(self.value, config);
        refresh_projected_empty_context(&mut pack);
        let surfaced_result_ids: Vec<[u8; 16]> = pack
            .results
            .iter()
            .map(|entity| *entity.id.as_bytes())
            .collect();
        let telemetry_run_id = finalize_context_pack_telemetry(
            self.telemetry,
            self.telemetry_run_id.take(),
            pack.stats.query_time_us,
            pack.stats.claims_suppressed,
            &surfaced_result_ids,
            projected_context_pack_empty_reason(
                &pack,
                &pre_projection_stats,
                pre_projection_had_results,
                &surfaced_result_ids,
            ),
        );
        RetrievalWithTelemetry {
            value: pack,
            run_id: telemetry_run_id,
        }
    }
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
            disclosure: None,
            session: None,
        }
    }

    /// Routes this assembly's retrieval-run telemetry into a live off-record
    /// room (ONE-1570 Arm B) — BOTH the provisional registration and its
    /// finalize, which is the whole point of threading the view here as well
    /// as into the pipeline.
    ///
    /// Additive and scoping-neutral: retrieval scoring, filters, hydration and
    /// every base reader stay exactly as they were, so a canonical assembly is
    /// byte-identical. Callers get the handles from
    /// `OffRecordSession::retrieval_telemetry`, which answers `None` once
    /// the room is on record — an ordinary retrieval never enters the room's
    /// receipt set merely because a session is live.
    pub(crate) fn in_session(
        mut self,
        session: &'a crate::off_record::SessionRetrievalTelemetry<'a>,
    ) -> Self {
        self.pipeline = self.pipeline.in_session(session.view());
        self.session = Some(session);
        self
    }

    /// Attaches the OF-365 disclosure clamp for this assembly. Absent means
    /// `OwnerAlone` — byte-identical legacy behavior for every existing
    /// caller (the server decides when a context is mandatory).
    pub fn disclosure_context(mut self, ctx: DisclosureContext) -> Self {
        self.disclosure = Some(ctx);
        self
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

    pub fn capture_retrieval_trace(mut self, enabled: bool) -> Self {
        self.pipeline = self.pipeline.capture_retrieval_trace(enabled);
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
            run.telemetry,
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

    pub fn run_projected_json_with_telemetry(
        self,
        config: &SerializeConfig,
    ) -> Result<RetrievalWithTelemetry<ContextPack>> {
        Ok(self
            .run_unfinalized_with_telemetry()?
            .finish_projected_json(config))
    }

    pub fn run_unfinalized_with_telemetry(self) -> Result<UnfinalizedContextPack<'a>> {
        let run = self.run_unfinalized()?;
        Ok(UnfinalizedContextPack {
            value: run.pack,
            telemetry_run_id: run.telemetry_run_id,
            telemetry: run.telemetry,
            clamped_out: run.clamped_out,
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
        // OF-365: a clamped assembly persists NO retrieval stage trace. The
        // pipeline records per_channel/fused/blended/reranked stages BEFORE
        // the clamp's candidate sweep runs, so a captured trace would retain
        // exactly the ids the clamp removes — absence is the boundary, and
        // suppressing capture is the fail-closed form of scrubbing every
        // stage. OwnerAlone (and no-context) assemblies keep the caller's
        // trace setting unchanged.
        let mut pipeline = self.pipeline;
        if self
            .disclosure
            .as_ref()
            .is_some_and(|ctx| ctx.mode() != DisclosureMode::OwnerAlone)
        {
            pipeline = pipeline.capture_retrieval_trace(false);
        }
        // Captured BEFORE the run, from the same view the pipeline registers
        // the provisional row through, and carried on every outcome — so the
        // finalize, the failure discard, and a deferred `finish_projected_json`
        // all reach the row that was actually written (ONE-1570 Arm B).
        let telemetry = match self.session {
            Some(session) => ContextPackTelemetry::Session {
                vault: self.vault,
                overlay: session.overlay(),
            },
            None => ContextPackTelemetry::Base(&self.vault.store),
        };
        let pipeline_output = pipeline
            .context_pack_budget(retrieval_budget)
            .run_for_pack()?;
        let telemetry_run_id = pipeline_output.telemetry_run_id;
        let result = (|| {
            let total_in_scope = pipeline_output.total_in_scope;
            let pipeline_empty_reason = pipeline_output.empty_reason;
            let pipeline_signals = pipeline_output.signals;
            let scored = pipeline_output.scores;
            validate_scored_candidates(&scored)?;
            let claim_bodies = pipeline_output.claim_bodies;
            let mut claims_suppressed = pipeline_output.claims_suppressed;
            let cosine_ghosts_dampened = pipeline_output.cosine_ghosts_dampened;

            let rtxn = self.vault.store.env.read_txn()?;
            let hydrate_result_edges = self.include_edges && self.edge_hop == 0;
            let mut claim_bodies = claim_bodies;
            let quarantine_index = load_pack_quarantine_index(&self.vault.store, &rtxn)?;

            // OF-365 disclosure clamp, enforcement point 1 (candidate sweep,
            // the only point that counts): drop non-admitted scored ids
            // before hydration. Absence is the boundary — a clamped id never
            // reaches hydration, results, or stats.
            let clamp = self.disclosure.as_ref();
            let mut scored = scored;
            let mut clamped_out: u64 = 0;
            if let Some(ctx) = clamp
                && ctx.mode() != DisclosureMode::OwnerAlone
            {
                let mut kept = Vec::with_capacity(scored.len());
                for entry in scored {
                    if disclosure_admits_candidate(
                        &self.vault.store,
                        &rtxn,
                        ctx,
                        &entry.id,
                        &claim_bodies,
                    )? {
                        kept.push(entry);
                    } else {
                        clamped_out = clamped_out.saturating_add(1);
                    }
                }
                scored = kept;
            }
            let surfaced_candidate_count = scored.len();

            let result_options = HydrateOptions {
                hydrate_fields: self.hydrate,
                include_edges: hydrate_result_edges,
                include_vectors: self.include_vectors,
                edge_cache: None,
                claim_bodies: Some(&claim_bodies),
                clamp,
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
                    clamp,
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
                clamp,
            };

            if self.include_edges && self.edge_hop > 0 {
                for entity in &mut results {
                    entity.edges = Some(load_entity_edges(
                        &self.vault.store,
                        &rtxn,
                        &entity.id,
                        edge_cache,
                        clamp,
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
            // OF-365 enforcement point 4 — final fail-closed sweep: the pack
            // build FAILS rather than leaks a non-admitted id.
            if let Some(ctx) = clamp {
                validate_pack_disclosure(&self.vault.store, &rtxn, ctx, &results, &neighbors)?;
            }
            resolve_edge_short_ids(&mut results, &mut neighbors);

            let pack_is_empty = results.is_empty() && neighbors.is_empty();
            let candidates_considered = if pack_is_empty {
                total_in_scope
            } else {
                surfaced_candidate_count
            };
            let mut signals_used = self.signals_used;
            signals_used.extend(pipeline_signals.into_iter().map(pack_signal_from_retrieval));
            let stats = PackStats {
                candidates_considered,
                signals_used: dedupe_signals(signals_used),
                query_time_us: started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                entities_hydrated: results.len(),
                neighbors_hydrated: neighbors.len(),
                cosine_ghosts_dampened,
                claims_suppressed,
                tokens: crate::context_pack::PackTokenStats::default(),
                items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
                items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
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
                telemetry,
                clamped_out,
            })
        })();

        if result.is_err() {
            discard_failed_context_pack_telemetry(telemetry, telemetry_run_id);
        }
        result
    }

    pub fn run_serialized(self) -> Result<Vec<u8>> {
        Ok(self.run_serialized_with_telemetry()?.value)
    }

    pub fn run_serialized_with_telemetry(self) -> Result<RetrievalWithTelemetry<Vec<u8>>> {
        let serialized = self.run_serialized_with_stats()?;
        Ok(RetrievalWithTelemetry {
            value: serialized.value.bytes,
            run_id: serialized.run_id,
        })
    }

    pub fn run_serialized_with_stats(
        self,
    ) -> Result<RetrievalWithTelemetry<SerializedContextPack>> {
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
            run.telemetry,
            run.telemetry_run_id,
            telemetry.stats.query_time_us,
            telemetry.stats.claims_suppressed,
            &telemetry.result_ids,
            serialized_context_pack_empty_reason(&run.pack, &telemetry),
        );
        Ok(RetrievalWithTelemetry {
            value: SerializedContextPack {
                bytes,
                stats: telemetry.stats,
            },
            run_id: telemetry_run_id,
        })
    }
}

/// Builds the Eiri Context v4 memory board from an already assembled pack.
///
/// Rows are sorted by slot, source, descending score, and entity id before slot
/// budgets are applied. That order is independent of `HashMap` iteration and
/// remains stable when retrieval returns equal-score rows.
#[must_use]
pub fn assemble_eiri_memory_board(
    pack: &ContextPack,
    budget: EiriMemoryBoardBudget,
    companion: Option<EiriCompanionAssembly>,
    disclosure: Option<DisclosureAssembly>,
) -> EiriMemoryBoard {
    let mut rows = Vec::with_capacity(pack.results.len() + pack.neighbors.len());
    rows.extend(
        pack.results
            .iter()
            .map(|entity| eiri_memory_board_row(entity, EiriMemoryBoardSource::Result)),
    );
    rows.extend(
        pack.neighbors
            .iter()
            .map(|entity| eiri_memory_board_row(entity, EiriMemoryBoardSource::Neighbor)),
    );

    rows.sort_by(eiri_memory_board_row_order);

    let mut used = EiriMemoryBoardBudget::default();
    let mut filtered = Vec::with_capacity(rows.len());
    for mut row in rows {
        if used.get(row.slot) >= budget.get(row.slot) {
            continue;
        }
        used.increment(row.slot);
        row.row_index = filtered.len();
        filtered.push(row);
    }

    EiriMemoryBoard {
        version: EIRI_CONTEXT_VERSION_V4.to_owned(),
        budget,
        rows: filtered,
        companion,
        disclosure,
    }
}

fn eiri_memory_board_row(
    entity: &ContextEntity,
    source: EiriMemoryBoardSource,
) -> EiriMemoryBoardRow {
    EiriMemoryBoardRow {
        row_index: 0,
        slot: eiri_memory_board_slot(entity.entity_type),
        source,
        id: entity.id.to_hex(),
        short_id: entity.short_id.clone(),
        content_hash: format!("{:02x}", entity.content_hash),
        entity_type: entity.entity_type,
        asset_ref: eiri_memory_board_asset_ref(
            entity.entity_type,
            &entity.short_id,
            entity.content_hash,
        ),
        score: entity.score,
    }
}

fn eiri_memory_board_asset_ref(
    entity_type: u8,
    short_id: &str,
    content_hash: u8,
) -> Option<String> {
    matches!(entity_type, ENTITY_TYPE_ASSET | ENTITY_TYPE_ASSET_TEXT)
        .then(|| format!("{short_id}:{content_hash:02x}"))
}

fn eiri_memory_board_slot(entity_type: u8) -> EiriMemoryBoardSlot {
    match entity_type {
        ENTITY_TYPE_CLAIM => EiriMemoryBoardSlot::Claims,
        ENTITY_TYPE_TURN | ENTITY_TYPE_MESSAGE => EiriMemoryBoardSlot::Turns,
        ENTITY_TYPE_SUMMARY => EiriMemoryBoardSlot::Summaries,
        ENTITY_TYPE_FACET => EiriMemoryBoardSlot::Facets,
        ENTITY_TYPE_COMPANION_REGISTER => EiriMemoryBoardSlot::Companions,
        _ => EiriMemoryBoardSlot::Other,
    }
}

fn eiri_memory_board_row_order(
    left: &EiriMemoryBoardRow,
    right: &EiriMemoryBoardRow,
) -> std::cmp::Ordering {
    left.slot
        .sort_rank()
        .cmp(&right.slot.sort_rank())
        .then_with(|| left.source.sort_rank().cmp(&right.source.sort_rank()))
        .then_with(|| right.score.total_cmp(&left.score))
        .then_with(|| left.id.cmp(&right.id))
}

fn context_pack_validation_error(id: EntityId, reason: &'static str) -> Error {
    Error::ContextPackValidation { id, reason }
}

/// OF-365 candidate-sweep admission (enforcement point 1). Fail-closed: a
/// scored id whose payload row is missing is not admitted.
fn disclosure_admits_candidate(
    store: &Store,
    rtxn: &RoTxn<'_>,
    ctx: &DisclosureContext,
    id: &EntityId,
    claim_bodies: &HashMap<EntityId, ClaimBody>,
) -> Result<bool> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity metadata header"));
    };
    ctx.admits(store, rtxn, id, header.entity_type, claim_bodies.get(id))
}

/// OF-365 edge-target admission (enforcement points 2 and 3): a non-admitted
/// target is neither admitted as a neighbor, traversed through, nor exposed
/// in a serialized edge list — even the bare target id names the room.
/// `None` clamp admits everything (legacy behavior).
fn disclosure_admits_target(
    store: &Store,
    rtxn: &RoTxn<'_>,
    clamp: Option<&DisclosureContext>,
    id: &EntityId,
) -> Result<bool> {
    let Some(ctx) = clamp else {
        return Ok(true);
    };
    if ctx.mode() == DisclosureMode::OwnerAlone {
        return Ok(true);
    }
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity metadata header"));
    };
    ctx.admits(store, rtxn, id, header.entity_type, None)
}

/// OF-365 enforcement point 4 — the final fail-closed sweep: re-checks every
/// surviving entity id (results, neighbors, and every edge target inside
/// them) and FAILS the pack build on any non-admitted survivor instead of
/// serving a leaky pack. The red-team suite asserts this cannot fire
/// spuriously.
fn validate_pack_disclosure(
    store: &Store,
    rtxn: &RoTxn<'_>,
    ctx: &DisclosureContext,
    results: &[ContextEntity],
    neighbors: &[ContextEntity],
) -> Result<()> {
    if ctx.mode() == DisclosureMode::OwnerAlone {
        return Ok(());
    }
    for entity in results.iter().chain(neighbors.iter()) {
        if !ctx.admits(store, rtxn, &entity.id, entity.entity_type, None)? {
            return Err(Error::DisclosureClampViolation(
                "non-admitted entity survived pack assembly",
            ));
        }
        let Some(edges) = &entity.edges else {
            continue;
        };
        for edge in edges {
            if !disclosure_admits_target(store, rtxn, Some(ctx), &edge.target)? {
                return Err(Error::DisclosureClampViolation(
                    "non-admitted edge target survived pack assembly",
                ));
            }
        }
    }
    Ok(())
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
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
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
    validate_claim_value_references(store, rtxn, body, quarantine_index)?;

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

fn validate_claim_value_references(
    store: &Store,
    rtxn: &RoTxn<'_>,
    body: &ClaimBody,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    let Some(value) = crate::affect::decode_affect_trigger_claim(body)? else {
        return Ok(());
    };
    validate_pack_payload_reference(store, rtxn, &value.trigger_ref(), quarantine_index)
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
        if !is_quarantine_key(&key) {
            continue;
        }
        let record = rmp_serde::from_slice::<PackQuarantineRecord>(&value)
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
    telemetry: ContextPackTelemetry<'_>,
    telemetry_run_id: Option<RetrievalRunId>,
    elapsed_us: u64,
    claims_suppressed: usize,
    surfaced_result_ids: &[[u8; 16]],
    empty_reason: Option<String>,
) -> Option<RetrievalRunId> {
    let run_id = telemetry_run_id?;
    match telemetry.finalize(
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
            discard_failed_context_pack_telemetry(telemetry, Some(run_id));
            None
        }
    }
}

fn discard_failed_context_pack_telemetry(
    telemetry: ContextPackTelemetry<'_>,
    telemetry_run_id: Option<RetrievalRunId>,
) {
    let Some(run_id) = telemetry_run_id else {
        return;
    };
    if let Err(error) = telemetry.discard(run_id) {
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
        .map_or(EmptyReason::FilterMatchedNone, |empty| empty.reason);
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

fn projected_context_pack_empty_reason(
    pack: &ContextPack,
    pre_projection_stats: &PackStats,
    pre_projection_had_results: bool,
    surfaced_result_ids: &[[u8; 16]],
) -> Option<String> {
    if !surfaced_result_ids.is_empty() {
        return None;
    }
    if pre_projection_had_results
        && pack.stats.items_dropped.count > pre_projection_stats.items_dropped.count
    {
        return Some(format!("{:?}", pack.stats.items_dropped.reason));
    }
    context_pack_empty_reason(pack, surfaced_result_ids)
}

pub fn refresh_projected_empty_context(pack: &mut ContextPack) {
    if !pack.results.is_empty() || !pack.neighbors.is_empty() {
        pack.empty = None;
        return;
    }
    if pack.empty.is_some() {
        return;
    }

    let reason = if pack.stats.candidates_considered == 0 {
        EmptyReason::NoData
    } else {
        EmptyReason::FilterMatchedNone
    };
    let hint = if pack.stats.items_dropped.count > 0 {
        match pack.stats.items_dropped.reason {
            crate::context_pack::PackItemAccountingReason::TokenBudget => {
                "Raise budget.token_budget or request a less restrictive view to return context-pack results"
            }
            crate::context_pack::PackItemAccountingReason::ItemBudget => {
                "Raise budget.max_item_tokens or request a less restrictive view to return context-pack results"
            }
        }
    } else {
        empty_hint(reason)
    };
    pack.empty = Some(EmptyContext {
        reason,
        total_in_scope: pack.stats.candidates_considered,
        hint: hint.to_owned(),
    });
}

fn pack_signal_from_retrieval(signal: RetrievalSignal) -> Signal {
    match signal {
        RetrievalSignal::Vector => Signal::Vector,
        RetrievalSignal::Text => Signal::Text,
        RetrievalSignal::Phonetic => Signal::Phonetic,
        RetrievalSignal::Temporal => Signal::Temporal,
        RetrievalSignal::Ppr => Signal::Ppr,
        RetrievalSignal::Recency
        | RetrievalSignal::Salience
        | RetrievalSignal::Confidence
        | RetrievalSignal::Gravity
        | RetrievalSignal::Rerank => {
            unreachable!("blend/rerank score components are not context-pack retrieval channels")
        }
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

/// Builds a Psych Mirror source candidate from an already decoded Claim body.
///
/// The caller supplies the source revision ref explicitly because hydrated
/// context rows intentionally do not carry revision provenance.
pub fn psych_mirror_source_candidate_from_claim(
    source_id: EntityId,
    source_revision_ref: EntityId,
    connectivity: f32,
    learned_at: u64,
    body: &ClaimBody,
) -> Result<PsychMirrorSourceCandidate> {
    PsychMirrorSourceCandidate::new(
        source_id,
        source_revision_ref,
        connectivity,
        crate::claim::psych_mirror_claim_affect_salience(body)?,
        learned_at,
        psych_mirror_claim_value_entropy(body),
    )
}

/// Builds a Psych Mirror source candidate from a hydrated context entity.
///
/// This is a convenience adapter for fixture and API-read paths. It uses the
/// entity score as connectivity and reads projected `sal` plus text-ish fields
/// when present.
pub fn psych_mirror_source_candidate_from_context_entity(
    entity: &ContextEntity,
    source_revision_ref: EntityId,
    learned_at: u64,
) -> Result<PsychMirrorSourceCandidate> {
    let fields = entity.fields.as_ref();
    PsychMirrorSourceCandidate::new(
        entity.id,
        source_revision_ref,
        entity.score,
        fields.map_or(0.0, psych_mirror_context_fields_affect_salience),
        learned_at,
        fields.map_or(0.0, psych_mirror_context_fields_entropy),
    )
}

fn psych_mirror_claim_value_entropy(body: &ClaimBody) -> f32 {
    let mut leaves = Vec::new();
    collect_psych_mirror_text_leaves(&body.value, &mut leaves);
    if leaves.is_empty() {
        0.0
    } else {
        psych_mirror_text_entropy(&leaves.join(PSYCH_MIRROR_STRUCTURED_TEXT_SEPARATOR))
    }
}

fn collect_psych_mirror_text_leaves<'a>(value: &'a rmpv::Value, leaves: &mut Vec<&'a str>) {
    match value {
        rmpv::Value::String(value) => {
            if let Some(text) = value.as_str().filter(|text| !text.is_empty()) {
                leaves.push(text);
            }
        }
        rmpv::Value::Array(values) => {
            for value in values {
                collect_psych_mirror_text_leaves(value, leaves);
            }
        }
        rmpv::Value::Map(entries) => {
            for (_, value) in entries {
                collect_psych_mirror_text_leaves(value, leaves);
            }
        }
        _ => {}
    }
}

fn psych_mirror_context_fields_affect_salience(fields: &HashMap<String, serde_json::Value>) -> f32 {
    fields
        .get(crate::claim::KEY_SAL)
        .and_then(psych_mirror_json_unit_interval)
        .unwrap_or(0.0)
}

fn psych_mirror_context_fields_entropy(fields: &HashMap<String, serde_json::Value>) -> f32 {
    PSYCH_MIRROR_CONTEXT_TEXT_FIELD_ALIASES
        .into_iter()
        .find_map(|key| fields.get(key).and_then(serde_json::Value::as_str))
        .map_or(0.0, psych_mirror_text_entropy)
}

fn psych_mirror_json_unit_interval(value: &serde_json::Value) -> Option<f32> {
    let value = value.as_f64()?;
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Some(value as f32)
    } else {
        None
    }
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

    let Some(header) = EntityMetadataHeader::parse(&raw) else {
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
            None => decode_entity_fields(&raw, header.entity_type).unwrap_or_default(),
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
            options.clamp,
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

fn decode_entity_fields(raw: &[u8], entity_type: u8) -> Option<HashMap<String, serde_json::Value>> {
    if raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Some(HashMap::new());
    }

    let payload = &raw[ENTITY_METADATA_HEADER_LEN..];
    if entity_type == ENTITY_TYPE_COMPANION_REGISTER {
        return decode_companion_register_fields(payload);
    }

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

fn decode_companion_register_fields(raw: &[u8]) -> Option<HashMap<String, serde_json::Value>> {
    let record = decode_companion_record_body(raw).ok()?;
    let mut out = HashMap::new();
    out.insert(
        "kind".to_owned(),
        serde_json::Value::String(record.kind().as_str().to_owned()),
    );
    out.insert("scope".to_owned(), companion_scope_to_json(&record.scope));
    out.insert(
        "subject".to_owned(),
        companion_subject_to_json(&record.subject),
    );
    out.insert(
        "lifecycle".to_owned(),
        serde_json::Value::String(record.lifecycle.as_str().to_owned()),
    );
    out.insert(
        "export".to_owned(),
        serde_json::Value::String(record.export_classification.as_str().to_owned()),
    );
    out.insert(
        "provenance".to_owned(),
        serde_json::json!({
            "actor_ref": record.provenance.actor_ref.to_hex(),
            "actor_class": record.provenance.actor_class as u8,
            "source": record.provenance.source.as_str(),
            "approval": record.provenance.approval.as_str(),
        }),
    );
    out.insert(
        "lifecycle_events".to_owned(),
        companion_lifecycle_events_to_json(&record.lifecycle_events),
    );
    Some(out)
}

fn companion_lifecycle_events_to_json(events: &[CompanionLifecycleEvent]) -> serde_json::Value {
    serde_json::Value::Array(
        events
            .iter()
            .map(|event| {
                serde_json::json!({
                    "kind": event.kind.as_str(),
                    "at": event.at,
                })
            })
            .collect(),
    )
}

fn companion_scope_to_json(scope: &CompanionScope) -> serde_json::Value {
    match scope {
        CompanionScope::Neutral => serde_json::json!({ "kind": "neutral" }),
        CompanionScope::Personal { person_ref } => {
            serde_json::json!({ "kind": "personal", "person_ref": person_ref.to_hex() })
        }
        CompanionScope::SharedVault { vault_id } => {
            serde_json::json!({ "kind": "shared_vault", "vault_id": vault_id })
        }
    }
}

fn companion_subject_to_json(subject: &CompanionSubject) -> serde_json::Value {
    match subject {
        CompanionSubject::Persona { persona_ref } => {
            serde_json::json!({ "kind": "persona", "persona_ref": persona_ref.to_hex() })
        }
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => serde_json::json!({
            "kind": "relationship",
            "relationship_ref": {
                "source_ref": source_ref.to_hex(),
                "target_ref": target_ref.to_hex(),
            }
        }),
    }
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

    let vector = le_bytes_to_f32_vec(&raw).map_err(|_| Error::CorruptedIndex("entity vector"))?;

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
    clamp: Option<&DisclosureContext>,
) -> Result<Vec<EdgeInfo>> {
    let edges = if let Some(edges) = edge_cache.and_then(|cache| cache.get(id)) {
        edges.clone()
    } else {
        scan_edges_for_entity(store, rtxn, id)?
    };
    // ARCH-0052 P6: no off-record subtraction here. A base edge cannot name a
    // live overlay member — the K4 taint guard rejects that write — and a
    // session's own edges are overlay rows a canonical reader cannot address.
    // The OF-365 clamp below is the only target filter this list needs.
    let mut kept = Vec::with_capacity(edges.len());
    for edge in edges {
        if !disclosure_admits_target(store, rtxn, clamp, &edge.target)? {
            continue;
        }
        kept.push(edge);
    }
    Ok(kept)
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
        edges.push(crate::vault::parse_edge_record(&key, &value)?);
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
    clamp: Option<&DisclosureContext>,
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
                // `child_of` / `assigned_to` / `blocked_by` are STRUCTURAL
                // plumbing with no retrieval scoring (ARCH-0004 edgeKinds:
                // lambda null, "Not traversed.") — never neighbor-expanded
                // regardless of the stored weight bytes. They still hydrate on
                // the seed's own edge list; only the walk skips them.
                if matches!(
                    edge.kind,
                    EdgeKind::ChildOf | EdgeKind::AssignedTo | EdgeKind::BlockedBy
                ) {
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
                // OF-365 clamp (enforcement point 2): a non-admitted entity
                // is never admitted as a neighbor NOR traversed through.
                if !disclosure_admits_target(store, rtxn, clamp, &edge.target)? {
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

/// Output serialization format for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum PackFormat {
    #[default]
    Json,
    Yaml,
    Toon,
    Markdown,
    Plaintext,
}

/// Field selection profile for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum FieldProfile {
    Minimal,
    #[default]
    Standard,
    Full,
}

/// Hydrated entity with decoded fields, edges, and provenance.
#[derive(Debug, Clone)]
pub struct ContextEntity {
    pub id: EntityId,
    pub short_id: String,
    pub content_hash: u8,
    pub entity_type: u8,
    pub score: f32,
    pub fields: Option<HashMap<String, serde_json::Value>>,
    pub edges: Option<Vec<EdgeInfo>>,
    pub vector: Option<Vec<f32>>,
}

/// Stats about the context pack query.
#[derive(Debug, Clone)]
pub struct PackStats {
    pub candidates_considered: usize,
    pub signals_used: Vec<Signal>,
    pub query_time_us: u64,
    pub entities_hydrated: usize,
    pub neighbors_hydrated: usize,
    /// Candidates assigned the low gravity signal because they had vector
    /// similarity above the cosine-ghost threshold and no BM25 text channel
    /// presence.
    pub cosine_ghosts_dampened: usize,
    /// CLAIM records silently excluded by the D19 read-path status gate
    /// (ARCH-0003: surface only `appr ∈ {auto, approved}` ∧ `life = active`
    /// ∧ `stale = false`) or by the fail-closed type-0 body decode, across
    /// the pipeline stage and pack hydration (results + neighbors). A claim
    /// suppressed in both stages counts once per stage.
    pub claims_suppressed: usize,
    /// Token accounting populated by serialization/projection paths.
    ///
    /// Raw `ContextPackBuilder::run()` results are not serialized and leave
    /// this as `PackTokenStats::default()`. Use serialized/projection builder
    /// paths when exact output-token accounting is required.
    pub tokens: PackTokenStats,
    pub items_truncated: PackItemAccounting,
    pub items_dropped: PackItemAccounting,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackTokenStats {
    /// Stable tokenizer identifier used for every count in this struct.
    ///
    /// Empty when stats came from an unserialized raw pack.
    pub tokenizer_id: String,
    /// Exact token count of the final serialized context-pack bytes.
    ///
    /// This includes format envelope, separators, and serialized stats when
    /// they are emitted.
    pub total_tokens: usize,
    /// Per-section row-token accounting.
    ///
    /// Section counts are computed from the row-level accounting text used by
    /// budget allocation. They intentionally exclude format envelope and
    /// separators, so their sum is not expected to equal `total_tokens`.
    pub sections: Vec<PackSectionTokenStats>,
    /// Per-item row-token accounting.
    ///
    /// Item counts use the same row-level basis as `sections`, not exact
    /// emitted substrings for each output format.
    pub items: Vec<PackItemTokenStats>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSectionTokenStats {
    /// Logical section name, for example `results`, `neighbors`, or `merged`.
    pub section: String,
    /// Row-level token count for this section.
    pub tokens: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackItemTokenStats {
    /// Logical section containing this item.
    pub section: String,
    /// Serialized short reference for the item, including the content-hash suffix.
    pub id: String,
    /// Entity type byte used for the serialized row group.
    pub entity_type: u8,
    /// Row-level token count for this item.
    pub tokens: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackItemAccountingReason {
    ItemBudget,
    TokenBudget,
}

impl PackItemAccountingReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ItemBudget => "item_budget",
            Self::TokenBudget => "token_budget",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackItemAccounting {
    pub count: usize,
    pub reason: PackItemAccountingReason,
}

impl PackItemAccounting {
    #[must_use]
    pub fn item_budget() -> Self {
        Self {
            count: 0,
            reason: PackItemAccountingReason::ItemBudget,
        }
    }

    #[must_use]
    pub fn token_budget() -> Self {
        Self {
            count: 0,
            reason: PackItemAccountingReason::TokenBudget,
        }
    }
}

/// Machine-readable reason an otherwise successful context-pack query surfaced
/// no entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyReason {
    FilterMatchedNone,
    NoData,
    AllActivated,
    BelowThreshold,
}

/// Structured context for an empty context-pack response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyContext {
    pub reason: EmptyReason,
    pub total_in_scope: usize,
    pub hint: String,
}

/// A fully hydrated context pack ready for serialization or programmatic use.
#[derive(Debug, Clone)]
pub struct ContextPack {
    pub results: Vec<ContextEntity>,
    pub neighbors: Vec<ContextEntity>,
    pub stats: PackStats,
    pub empty: Option<EmptyContext>,
}

/// Token budget allocation across entity types.
#[derive(Debug, Clone, Copy)]
pub struct TokenAllocation {
    pub claims: f32,
    pub turns: f32,
    pub summaries: f32,
    pub other: f32,
}

impl Default for TokenAllocation {
    fn default() -> Self {
        Self {
            claims: 0.45,
            turns: 0.10,
            summaries: 0.25,
            other: 0.20,
        }
    }
}

/// Item budget for context-pack retrieval before the final global truncation.
///
/// Primary entity budgets are enforced per retrieval kind after query filters
/// and before `limit` truncation. `selected_edges` caps edge-walk neighbor
/// selection; it is not an entity type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextPackRetrievalBudget {
    pub claims: usize,
    pub turns: usize,
    pub summaries: usize,
    pub facets: usize,
    pub other: usize,
    pub selected_edges: usize,
}

impl ContextPackRetrievalBudget {
    #[must_use]
    pub const fn new(
        claims: usize,
        turns: usize,
        summaries: usize,
        facets: usize,
        other: usize,
        selected_edges: usize,
    ) -> Self {
        Self {
            claims,
            turns,
            summaries,
            facets,
            other,
            selected_edges,
        }
    }

    #[must_use]
    pub fn from_limit(
        result_limit: usize,
        allocation: TokenAllocation,
        selected_edges: usize,
    ) -> Self {
        let split_other = allocation.other / 2.0;
        let weights = [
            allocation.claims,
            allocation.turns,
            allocation.summaries,
            split_other,
            split_other,
        ];
        let mut budgets = allocate_context_pack_item_budgets(result_limit, weights);
        if result_limit > 0 {
            for (budget, weight) in budgets.iter_mut().zip(weights) {
                if *budget == 0 && weight.is_finite() && weight > 0.0 {
                    *budget = 1;
                }
            }
        }
        Self {
            claims: budgets[0],
            turns: budgets[1],
            summaries: budgets[2],
            facets: budgets[3],
            other: budgets[4],
            selected_edges,
        }
    }
}

fn allocate_context_pack_item_budgets(limit: usize, weights: [f32; 5]) -> [usize; 5] {
    if limit == 0 {
        return [0; 5];
    }

    let mut sanitized = [0.0_f32; 5];
    for (index, weight) in weights.into_iter().enumerate() {
        if weight.is_finite() && weight > 0.0 {
            sanitized[index] = weight;
        }
    }

    let total_weight: f32 = sanitized.iter().sum();
    if total_weight <= 0.0 {
        let base = limit / sanitized.len();
        let mut budgets = [base; 5];
        for budget in budgets.iter_mut().take(limit % sanitized.len()) {
            *budget = budget.saturating_add(1);
        }
        return budgets;
    }

    let mut budgets = [0_usize; 5];
    let mut remainders = [(0_usize, 0.0_f32); 5];
    let mut allocated = 0_usize;
    for (index, weight) in sanitized.iter().copied().enumerate() {
        if weight <= 0.0 {
            continue;
        }
        let exact = (limit as f32) * (weight / total_weight);
        let whole = exact.floor() as usize;
        budgets[index] = whole;
        remainders[index] = (index, exact - whole as f32);
        allocated = allocated.saturating_add(whole);
    }

    let mut leftover = limit.saturating_sub(allocated);
    remainders.sort_unstable_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (index, _) in remainders {
        if leftover == 0 {
            break;
        }
        if sanitized[index] > 0.0 {
            budgets[index] = budgets[index].saturating_add(1);
            leftover -= 1;
        }
    }
    budgets
}

#[cfg(test)]
mod tests;
