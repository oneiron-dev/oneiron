//! The fluent [`ContextPackBuilder`] query API and its assembly pipeline.
//!
//! This is the module hub: it composes [`super::edge_walk`],
//! [`super::hydration`], [`super::validation`], [`super::world_partition`],
//! [`super::quarantine`], [`super::empty_pack`] and [`super::telemetry`] into one
//! run. The chained config methods stay in one file on purpose — a caller reads
//! `.search_vector().filter_types().hydrate().run()` as a single unit.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::Vault;
use crate::claim::ClaimBody;
use crate::codebase::RepoRef;
use crate::disclosure::{DisclosureContext, DisclosureMode};
use crate::edge::EdgeInfo;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::{PipelineBuilder, RetrievalWithTelemetry, Signal, WorldScope};
use crate::psych_profile::PsychProfileKey;
use crate::serialize::{SerializeConfig, serialize_pack_with_telemetry};
use crate::store::{RetrievalAction, RetrievalRunId, Store};
use crate::temporal::{TemporalAnchorMode, TemporalGranularity, TimeRange};

use super::edge_walk::{EdgeWalkOptions, EdgeWalkResult, load_entity_edges, walk_edges};
use super::empty_pack::{
    context_pack_empty_reason, dedupe_signals, empty_context, pack_signal_from_retrieval,
    projected_context_pack_empty_reason, refresh_projected_empty_context,
    serialized_context_pack_empty_reason,
};
use super::hydration::hydrate_entity;
use super::psych_mirror::{PsychProfilePackSection, psych_profile_pack_section};
use super::quarantine::load_pack_quarantine_index;
use super::telemetry::{discard_failed_context_pack_telemetry, finalize_context_pack_telemetry};
use super::types::{
    ContextPack, ContextPackRetrievalBudget, DEFAULT_MAX_FIELD_CHARS, DEFAULT_MAX_NEIGHBORS,
    DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION, DEFAULT_TOKEN_BUDGET, FieldProfile,
    MAX_CONTEXT_NEIGHBORS, MAX_EDGE_HOP, PackFormat, PackStats, TokenAllocation,
};
use super::validation::{
    disclosure_admits_candidate, validate_hydrated_pack_entities, validate_pack_disclosure,
    validate_pack_edge_references, validate_pack_entity_reference, validate_scored_candidates,
};
use super::world_partition::{
    annotate_stale_federated_worlds, partition_results_by_world, resolve_edge_short_ids,
};

#[derive(Debug, Clone)]
pub struct SerializedContextPack {
    pub bytes: Vec<u8>,
    pub stats: PackStats,
}

#[derive(Clone, Copy)]
pub(super) struct HydrateOptions<'a> {
    pub(super) hydrate_fields: bool,
    pub(super) include_edges: bool,
    pub(super) include_vectors: bool,
    pub(super) edge_cache: Option<&'a HashMap<EntityId, Vec<EdgeInfo>>>,
    /// Claim bodies already decoded and accepted before hydration: pipeline
    /// result claims from the D19 gate, plus any neighbor claims decoded by
    /// pre-assembly validation. The hydrator projects fields from these
    /// instead of re-decoding, so each surfaced claim body is decoded once.
    pub(super) claim_bodies: Option<&'a HashMap<EntityId, ClaimBody>>,
    /// OF-365 disclosure clamp: hydrated edge lists filter non-admitted
    /// targets next to the off-record fence check.
    pub(super) clamp: Option<&'a DisclosureContext>,
}

#[must_use = "ContextPackBuilder executes no query until a terminal `.run*()` method is called"]
pub struct ContextPackBuilder<'a> {
    pipeline: PipelineBuilder<'a>,
    vault: &'a Vault,
    hydrate: bool,
    include_edges: bool,
    pub(super) edge_hop: u32,
    pub(super) selected_edge_budget: usize,
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
    psych_profile_key: Option<PsychProfileKey>,
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
pub(super) enum ContextPackTelemetry<'a> {
    /// The canonical base ledger. Every non-session entry takes this arm and
    /// is behaviorally unchanged.
    Base(&'a Store),
    /// A retrieval issued inside a live room (ARCH-0052 K8/K10). Both writes
    /// go back through the room's own registration door, which owns the route
    /// check and the overlay-vs-base decision for the whole assembly — this
    /// enum names WHOSE door, never a resolved target.
    Session(&'a crate::off_record::SessionRetrievalTelemetry<'a>),
}

impl ContextPackTelemetry<'_> {
    /// Whether a failed telemetry write here is a failure of the RETRIEVAL.
    /// It is, for a room: its run row is what close consumes.
    pub(super) const fn is_session(self) -> bool {
        matches!(self, Self::Session(_))
    }

    /// Clears the provisional marker and publishes the final row, against
    /// whichever target registered the provisional.
    pub(super) fn finalize(
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
            Self::Session(session) => session.finalize_run(
                run_id,
                elapsed_us,
                claims_suppressed,
                surfaced_result_ids,
                empty_reason,
            ),
        }
    }

    /// Removes a provisional row whose assembly failed, leaving no residue on
    /// the target that holds it.
    pub(super) fn discard(self, run_id: RetrievalRunId) -> Result<()> {
        match self {
            Self::Base(store) => store.delete_retrieval_run(run_id),
            Self::Session(session) => session.discard_run(run_id),
        }
    }
}

pub(super) struct ContextPackRun<'a> {
    pub(super) pack: ContextPack,
    pub(super) telemetry_run_id: Option<RetrievalRunId>,
    pub(super) telemetry: ContextPackTelemetry<'a>,
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
        // BASE-ONLY by construction: `run_unfinalized_with_telemetry` refuses
        // a room's assembly precisely because this signature has no channel to
        // carry a room's registration failure, and the base arm's posture is
        // best-effort `Ok`. The `Err` arm is therefore unreachable here, and
        // flattening it cannot hide a room's failure.
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
        )
        .ok()
        .flatten();
        RetrievalWithTelemetry {
            value: pack,
            run_id: telemetry_run_id,
        }
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

    /// Runs retrieval and returns the opt-in stored-profile companion section.
    pub fn run_with_psych_profile(self) -> Result<(ContextPack, Option<PsychProfilePackSection>)> {
        let key = self.psych_profile_key;
        let vault = self.vault;
        let pack = self.run()?;
        let section = key
            .map(|key| psych_profile_pack_section(vault, &key))
            .transpose()?;
        Ok((pack, section))
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
        )?;
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

    /// # Errors
    ///
    /// Refuses an assembly issued INSIDE a room (ONE-1570 Arm B). The deferred
    /// door hands the caller an [`UnfinalizedContextPack`] whose finalize runs
    /// in [`UnfinalizedContextPack::finish_projected_json`], which returns no
    /// `Result` — so a room's failed registration would have nowhere to go but
    /// a warning, and a warning past it is the log-and-continue the settle
    /// contract forbids. A room's assembly takes the finalizing doors, which
    /// can fail.
    pub fn run_unfinalized_with_telemetry(self) -> Result<UnfinalizedContextPack<'a>> {
        if self.session.is_some() {
            return Err(Error::InvalidConfig(
                "a context pack assembled inside an off-record session cannot defer \
                 finalization: the deferred door has no channel for a failed registration"
                    .to_owned(),
            ));
        }
        let run = self.run_unfinalized()?;
        Ok(UnfinalizedContextPack {
            value: run.pack,
            telemetry_run_id: run.telemetry_run_id,
            telemetry: run.telemetry,
            clamped_out: run.clamped_out,
        })
    }

    pub(super) fn run_unfinalized(self) -> Result<ContextPackRun<'a>> {
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
        // Captured BEFORE the run, from the same door the pipeline registers
        // the provisional row through, and carried on every outcome — so the
        // finalize and the failure discard both reach the row that was
        // actually written (ONE-1570 Arm B).
        let telemetry = match self.session {
            Some(session) => ContextPackTelemetry::Session(session),
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

            // ONE-1411: read ONCE per pack run and reused by every stage below
            // — the result marker pass, the neighbor exclusion, and the
            // neighbor marker pass.
            let stale_worlds = crate::federation::stale_stamped_worlds(&self.vault.store, &rtxn)?;

            // Mark whatever world rows survived. Scope-independent by design —
            // the pipeline already dropped stale worlds from `All` and `Base`,
            // so in practice this fires for the explicit scopes that
            // deliberately KEEP a dead world, which are exactly the ones owed
            // the warning.
            annotate_stale_federated_worlds(
                &self.vault.store,
                &rtxn,
                &stale_worlds,
                &mut results,
                &claim_bodies,
            )?;

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
            // ONE-1411: edge expansion is the SECOND door onto the same
            // content. The scopes that dropped stale federated claims from the
            // candidate set must not readmit one as a neighbor; the explicit
            // scopes that keep them pass `None` and get the marker instead.
            let stale_neighbor_exclusion = (!stale_worlds.is_empty()
                && matches!(self.world_scope, WorldScope::All | WorldScope::Base))
            .then_some(&stale_worlds);
            let edge_walk = if self.edge_hop > 0 && selected_edge_budget > 0 {
                walk_edges(
                    &self.vault.store,
                    &rtxn,
                    &seed_ids,
                    EdgeWalkOptions {
                        hops: self.edge_hop,
                        budget: selected_edge_budget,
                        exclude: &result_ids,
                        clamp,
                        stale_worlds: stale_neighbor_exclusion,
                    },
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

            // ONE-1411: a stale world that survived the walk did so because the
            // scope named it. Mark it on exactly the rule the results follow.
            annotate_stale_federated_worlds(
                &self.vault.store,
                &rtxn,
                &stale_worlds,
                &mut neighbors,
                &claim_bodies,
            )?;

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
        )?;
        Ok(RetrievalWithTelemetry {
            value: SerializedContextPack {
                bytes,
                stats: telemetry.stats,
            },
            run_id: telemetry_run_id,
        })
    }
}
