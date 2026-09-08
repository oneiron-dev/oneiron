//! The fluent ContextPackBuilder surface: search, filter, boost, hydration, budget and format configuration.

use crate::Vault;
use crate::agent_def::MemoryProfile;
use crate::codebase::RepoRef;
use crate::disclosure::DisclosureContext;
use crate::entity_id::EntityId;
use crate::pipeline::{PipelineBuilder, Signal, WorldScope};
use crate::psych_profile::PsychProfileKey;
use crate::store::RetrievalAction;
use crate::temporal::{TemporalAnchorMode, TemporalGranularity, TimeRange};

use super::super::types::{
    ContextPackRetrievalBudget, DEFAULT_MAX_FIELD_CHARS, DEFAULT_MAX_NEIGHBORS,
    DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION, DEFAULT_WINDOW_TOKEN_BUDGET, FieldProfile,
    MAX_CONTEXT_NEIGHBORS, MAX_EDGE_HOP, PackFormat, TokenAllocation,
};

#[must_use = "ContextPackBuilder executes no query until a terminal `.run*()` method is called"]
pub struct ContextPackBuilder<'a> {
    pub(super) pipeline: PipelineBuilder<'a>,
    pub(super) vault: &'a Vault,
    pub(super) hydrate: bool,
    pub(super) include_edges: bool,
    pub(in crate::context_pack) edge_hop: u32,
    pub(in crate::context_pack) selected_edge_budget: usize,
    pub(super) retrieval_budget: Option<ContextPackRetrievalBudget>,
    pub(super) include_vectors: bool,
    pub(super) include_stats: bool,
    pub(super) merge_neighbors: bool,
    pub(super) format: PackFormat,
    pub(super) field_profile: FieldProfile,
    pub(super) token_budget: usize,
    pub(super) token_allocation: TokenAllocation,
    pub(super) max_field_chars: usize,
    pub(super) max_item_tokens: usize,
    pub(super) signals_used: Vec<Signal>,
    pub(super) world_scope: WorldScope,
    pub(super) non_base_world_fraction: f32,
    pub(super) disclosure: Option<DisclosureContext>,
    /// Additive session routing (ONE-1570 Arm B). `None` on every canonical
    /// entry, which is therefore behaviorally unchanged. The sibling field on
    /// `PipelineBuilder` routes the PROVISIONAL registration; this one is what
    /// lets the FINALIZE reach the same row, so the two halves of a
    /// context-pack run cannot land on different targets.
    pub(super) session: Option<&'a crate::off_record::SessionRetrievalTelemetry<'a>>,
    pub(super) psych_profile_key: Option<PsychProfileKey>,
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
            token_budget: DEFAULT_WINDOW_TOKEN_BUDGET,
            token_allocation: TokenAllocation::default(),
            max_field_chars: DEFAULT_MAX_FIELD_CHARS,
            max_item_tokens: 0,
            signals_used: Vec::new(),
            world_scope: WorldScope::All,
            non_base_world_fraction: DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION,
            disclosure: None,
            session: None,
            psych_profile_key: None,
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
        self.pipeline = self.pipeline.in_session(session);
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

    /// Includes the addressed stored PsychProfile as an explicit companion section.
    ///
    /// A requested profile always materializes as fresh, stale, or missing; it
    /// is never silently omitted from the returned pack.
    pub fn psych_profile_key(mut self, key: PsychProfileKey) -> Self {
        self.psych_profile_key = Some(key);
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

    /// Overrides the clock this assembly's retrieval resolves
    /// time-dependent scoring against — the pack-surface twin of
    /// [`PipelineBuilder::with_temporal_now`].
    ///
    /// ONE-1402 made read-side decay a scoring input on EVERY retrieval,
    /// not only the ones that ask for a temporal filter or a recency
    /// blend, so a context-pack assembly is now clock-dependent
    /// unconditionally. Without this forwarder the pack surface could
    /// score only against wall-clock seconds and no pack run could be
    /// replayed bit-identically the way a query run can. Production
    /// callers keep the default wall clock; tests and replay fixtures
    /// freeze the timestamp.
    pub fn with_temporal_now(mut self, now: u64) -> Self {
        self.pipeline = self.pipeline.with_temporal_now(now);
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

    /// Applies an agent's RT-05 memory profile as construction-time defaults
    /// (ONE-1687): the window budget and, when present, the per-class split.
    ///
    /// `None` is a NO-OP — today's defaults hold and the assembled pack is
    /// byte-for-byte what it was before the profile existed. Call order is
    /// deliberate: a later explicit [`Self::token_budget`] or
    /// [`Self::token_allocation`] overrides these profile defaults, so a
    /// per-request override always wins over the stored profile.
    pub fn memory_profile(mut self, profile: Option<&MemoryProfile>) -> Self {
        let Some(profile) = profile else {
            return self;
        };
        self.token_budget =
            usize::try_from(profile.window_token_budget).unwrap_or(DEFAULT_WINDOW_TOKEN_BUDGET);
        if let Some(split) = profile.budget_split {
            self.token_allocation = TokenAllocation {
                claims: split.claims,
                turns: split.turns,
                summaries: split.summaries,
                other: split.other,
            };
        }
        self
    }

    /// The effective window budget after defaults and profile application.
    ///
    /// The ONE public read of the assembled budget. A default builder answers
    /// the engine default through the same machinery a profiled builder uses,
    /// so a cross-read never re-spells the constant.
    #[must_use]
    pub const fn effective_token_budget(&self) -> usize {
        self.token_budget
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
}
