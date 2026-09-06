use std::collections::HashMap;

use crate::Vault;
use crate::affect::coping::{
    COPING_OUTCOME_PREDICATE, CopingOutcomeRecord, decode_coping_outcome_claim,
    validate_coping_outcome_claim_structure,
};
use crate::claim::claim_surfaceable;
use crate::codebase::RepoRef;
use crate::context_pack::ContextPackRetrievalBudget;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::query_expansion::{GroundingContext, HydeExpander, HydeOptions};
use crate::rerank::{RerankOptions, Reranker};
use crate::store::RetrievalAction;
use crate::temporal::{TemporalAnchorMode, TemporalGranularity, TimeRange};

use super::support::normalize_range;
use super::types::{
    DEFAULT_RESULT_LIMIT, DEFAULT_SIGMA_SECS, DreamerWorkingSet, DreamerWorkingSetBudget,
    DreamerWorkingSetCursor, DreamerWorkingSetStopReason, FacetMode, PendingVectorEmbedding,
    RelMode, RetrievalWithPendingVectors, RetrievalWithTelemetry, ScoredEntity,
    TemporalSearchConfig, WorldScope,
};

#[must_use = "PipelineBuilder executes no query until a terminal `.run*()` method is called"]
pub struct PipelineBuilder<'a> {
    pub(super) vault: &'a Vault,
    pub(super) vector_search: Option<(Vec<f32>, usize)>,
    pub(super) text_search: Option<(String, usize)>,
    pub(super) rank_profile: Option<crate::config::Bm25RankProfile>,
    pub(super) phonetic_search: Option<Vec<String>>,
    pub(super) temporal_search: Option<TemporalSearchConfig>,
    pub(super) ppr_search: Option<(Vec<EntityId>, u32)>,
    pub(super) ppr_expand: Option<(Vec<EntityId>, u32)>,
    pub(super) community_session_usage: Option<&'a HashMap<crate::ppr_community::CommunityId, u32>>,
    pub(super) recency_blend_enabled: bool,
    pub(super) apply_salience: bool,
    pub(super) apply_confidence: bool,
    pub(super) apply_gravity: bool,
    pub(super) apply_contiguity: bool,
    pub(super) type_filter: Option<Vec<u8>>,
    pub(super) since_filter: Option<u64>,
    pub(super) occurred_range: Option<(u64, u64)>,
    pub(super) learned_range: Option<(u64, u64)>,
    pub(super) repo_ref_filter: Option<RepoRef>,
    pub(super) project_id_filter: Option<String>,
    pub(super) facet_filter: Option<(EntityId, FacetMode)>,
    pub(super) relationship_filter: Option<(EntityId, RelMode)>,
    pub(super) world_scope: WorldScope,
    pub(super) context_pack_budget: Option<ContextPackRetrievalBudget>,
    pub(super) result_limit: usize,
    pub(super) temporal_adaptive_default: bool,
    pub(super) temporal_now: Option<u64>,
    pub(super) telemetry_action: RetrievalAction,
    pub(super) capture_retrieval_trace: bool,
    pub(super) rerank: Option<(&'a dyn Reranker, RerankOptions)>,
    pub(super) hyde: Option<(&'a dyn HydeExpander, GroundingContext, HydeOptions)>,
    pub(super) access_factor_overrides: Option<&'a HashMap<EntityId, f32>>,
    pub(super) skip_vector_rescore: bool,
    /// Additive session routing (ONE-1728 K10). `None` on every canonical
    /// entry, which is therefore behaviorally unchanged; a retrieval issued
    /// inside a room passes the room's registration door so the retrieval-run
    /// row is written under the route the run captured — into the room's
    /// overlay `VaultMeta` while it is off record, and under the same route's
    /// refusal once it is not. Retrieval SCORING is untouched by this field.
    pub(super) session: Option<&'a crate::off_record::SessionRetrievalTelemetry<'a>>,
}

impl<'a> PipelineBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            vector_search: None,
            text_search: None,
            rank_profile: None,
            phonetic_search: None,
            temporal_search: None,
            ppr_search: None,
            ppr_expand: None,
            community_session_usage: None,
            recency_blend_enabled: false,
            apply_salience: false,
            apply_confidence: false,
            apply_gravity: false,
            apply_contiguity: false,
            type_filter: None,
            since_filter: None,
            occurred_range: None,
            learned_range: None,
            repo_ref_filter: None,
            project_id_filter: None,
            facet_filter: None,
            relationship_filter: None,
            world_scope: WorldScope::All,
            context_pack_budget: None,
            result_limit: DEFAULT_RESULT_LIMIT,
            temporal_adaptive_default: true,
            temporal_now: None,
            telemetry_action: RetrievalAction::Pipeline,
            capture_retrieval_trace: false,
            rerank: None,
            hyde: None,
            access_factor_overrides: None,
            skip_vector_rescore: false,
            session: None,
        }
    }

    /// Routes this run's retrieval-run registration through a live room's
    /// door (ONE-1728 K10). Additive: retrieval scoring, filters, and every
    /// base reader stay exactly as they were.
    ///
    /// ONE-1570 Arm B lands the production caller P4a pinned the routing for:
    /// `Memory::recall_in_session` takes the handle from
    /// `OffRecordSession::retrieval_telemetry` and threads it here and
    /// through [`crate::context_pack::ContextPackBuilder::in_session`].
    pub(crate) fn in_session(
        mut self,
        session: &'a crate::off_record::SessionRetrievalTelemetry<'a>,
    ) -> Self {
        self.session = Some(session);
        self
    }

    pub(crate) fn telemetry_action(mut self, action: RetrievalAction) -> Self {
        self.telemetry_action = action;
        self
    }

    pub(crate) fn result_limit(&self) -> usize {
        self.result_limit
    }

    pub(crate) fn context_pack_budget(mut self, budget: ContextPackRetrievalBudget) -> Self {
        self.context_pack_budget = Some(budget);
        self
    }

    /// Enables opt-in per-stage retrieval trace capture for this run.
    pub fn capture_retrieval_trace(mut self, enabled: bool) -> Self {
        self.capture_retrieval_trace = enabled;
        self
    }

    /// Attaches a host-injected top-N reranker for this run (RET-010,
    /// 1186-D2). Presence IS the feature flag: no reranker attached means
    /// rerank is off and the pipeline behaves exactly as before. The block
    /// size is `options.top_n`; the pipeline never overfetches on rerank's
    /// behalf — the reranker only sees more than `result_limit` candidates
    /// when the caller's per-channel limits exceed `result_limit`.
    pub fn rerank(mut self, reranker: &'a dyn Reranker, options: RerankOptions) -> Self {
        self.rerank = Some((reranker, options));
        self
    }

    /// Opts into host-injected HyDE query expansion for this retrieval.
    pub fn hyde(
        mut self,
        expander: &'a dyn HydeExpander,
        grounding: GroundingContext,
        options: HydeOptions,
    ) -> Self {
        self.hyde = Some((expander, grounding, options));
        self
    }

    /// Supplies caller-owned per-entity read-side access-factor overrides
    /// for this run: an input seam only — the map is borrowed for the run,
    /// nothing is persisted, and no claim byte is written.
    ///
    /// Each value replaces the class-derived decay factor of that CLAIM
    /// candidate and must be finite and within `[0, 1]`; an inadmissible
    /// value fails the run closed with [`Error::InvalidConfig`]. Entries
    /// for non-claim entities are inert (non-claims stay at `1.0`), and a
    /// superseded, retracted or validity-expired claim stays at `0.0` — an
    /// override never resurfaces a closed claim.
    pub fn with_access_factor_overrides(mut self, overrides: &'a HashMap<EntityId, f32>) -> Self {
        self.access_factor_overrides = Some(overrides);
        self
    }

    pub fn search_vector(mut self, vector: &[f32], limit: usize) -> Self {
        self.vector_search = Some((vector.to_vec(), limit));
        self
    }

    /// Voice-hot-lane knob (ONE-EMBED E3): score the vector channel on the
    /// `fast_dims` prefix only, skipping the exact full-dim rescore. Inert
    /// when `fast_dims` is not configured.
    pub fn skip_vector_rescore(mut self, skip: bool) -> Self {
        self.skip_vector_rescore = skip;
        self
    }

    pub fn search_text(mut self, query: &str, limit: usize) -> Self {
        self.text_search = Some((query.to_owned(), limit));
        self
    }

    /// Applies a scoring-only BM25F rank profile to the text signal
    /// (ARCH-0031: Okapi default, `Plus { delta }` and per-channel
    /// weight / `b` are non-reindexing options). The profile is
    /// validated fail-closed when the pipeline runs; an invalid
    /// parameter returns [`crate::Error::InvalidRankProfile`], even when
    /// no text search is configured.
    pub fn rank_profile(mut self, profile: crate::config::Bm25RankProfile) -> Self {
        self.rank_profile = Some(profile);
        self
    }

    pub fn search_phonetic(mut self, codes: &[&str]) -> Self {
        self.phonetic_search = Some(codes.iter().map(|code| (*code).to_owned()).collect());
        self
    }

    pub fn search_temporal(mut self, anchor_start: u64, anchor_end: u64, limit: usize) -> Self {
        let (anchor_start, anchor_end) = normalize_range(anchor_start, anchor_end);
        let width = anchor_end.saturating_sub(anchor_start);
        let sigma_secs = width.max(DEFAULT_SIGMA_SECS);
        self.temporal_search = Some(TemporalSearchConfig {
            anchor_start,
            anchor_end,
            learned_start: None,
            learned_end: None,
            sigma_secs,
            anchor_mode: TemporalAnchorMode::Auto,
            adaptive: self.temporal_adaptive_default,
            limit,
        });
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
        let (anchor_start, anchor_end) = normalize_range(anchor_start, anchor_end);
        self.temporal_search = Some(TemporalSearchConfig {
            anchor_start,
            anchor_end,
            learned_start: None,
            learned_end: None,
            sigma_secs,
            anchor_mode,
            adaptive: self.temporal_adaptive_default,
            limit,
        });
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
        let (anchor_start, anchor_end) = normalize_range(anchor_start, anchor_end);
        self.temporal_search = Some(TemporalSearchConfig {
            anchor_start,
            anchor_end,
            learned_start: None,
            learned_end: None,
            sigma_secs: granularity.sigma_secs(),
            anchor_mode,
            adaptive: self.temporal_adaptive_default,
            limit,
        });
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
        let (anchor_start, anchor_end) = normalize_range(occurred_start, occurred_end);
        let (learned_start, learned_end) = normalize_range(learned_start, learned_end);
        self.temporal_search = Some(TemporalSearchConfig {
            anchor_start,
            anchor_end,
            learned_start: Some(learned_start),
            learned_end: Some(learned_end),
            sigma_secs,
            anchor_mode: TemporalAnchorMode::Both,
            adaptive: self.temporal_adaptive_default,
            limit,
        });
        self
    }

    pub fn temporal_adaptive(mut self, enabled: bool) -> Self {
        self.temporal_adaptive_default = enabled;
        if let Some(config) = self.temporal_search.as_mut() {
            config.adaptive = enabled;
        }
        self
    }

    /// Overrides the clock used to resolve natural-language temporal query
    /// hints and time-dependent retrieval scoring. Production callers normally
    /// use the default wall clock; tests and replay fixtures can inject a
    /// frozen Unix timestamp.
    pub fn with_temporal_now(mut self, now: u64) -> Self {
        self.temporal_now = Some(now);
        self
    }

    pub fn search(
        mut self,
        query: &str,
        vector: &[f32],
        time: Option<TimeRange>,
        limit: usize,
    ) -> Self {
        self = self.search_text(query, limit).search_vector(vector, limit);
        if let Some(range) = time {
            self = self
                .search_temporal(range.start, range.end, limit)
                .filter_occurred_range(range.start, range.end);
        }
        self.limit(limit)
    }

    pub fn search_ppr(mut self, seeds: &[EntityId], depth: u32) -> Self {
        self.ppr_search = Some((seeds.to_vec(), depth));
        self
    }

    pub fn expand_ppr(mut self, seeds: &[EntityId], depth: u32) -> Self {
        self.ppr_expand = Some((seeds.to_vec(), depth));
        self
    }

    /// Supplies caller-owned fine-community usage counts for this expansion.
    /// Counts are borrowed for this run, never persisted or shared through PPR
    /// cache rows. Inert at beta zero and on `search_ppr`-only queries.
    pub fn with_community_session_usage(
        mut self,
        usage: &'a HashMap<crate::ppr_community::CommunityId, u32>,
    ) -> Self {
        self.community_session_usage = Some(usage);
        self
    }

    pub(super) fn community_trace_identity(
        &self,
        seeds: &[ScoredEntity],
        version: u64,
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"oneiron.retrieval_trace.community.v0");
        hash.update(version.to_le_bytes());
        let config = &self.vault.config.ppr_community;
        for value in [
            config.beta,
            config.gamma,
            config.multiplier_cap,
            config.max_graph_fraction,
            config.max_top_k_fraction,
        ] {
            hash.update(value.to_bits().to_le_bytes());
        }
        hash.update((seeds.len() as u64).to_le_bytes());
        for seed in seeds {
            hash.update(seed.id.as_bytes());
            hash.update(seed.score.to_bits().to_le_bytes());
        }
        let mut usage: Vec<_> = self
            .community_session_usage
            .into_iter()
            .flat_map(|map| map.iter())
            .collect();
        usage.sort_unstable_by_key(|(id, _)| **id);
        hash.update((usage.len() as u64).to_le_bytes());
        for (id, count) in usage {
            hash.update(id.as_bytes());
            hash.update(count.to_le_bytes());
        }
        hash.finalize().into()
    }

    /// Enables the recency signal for the retrieval blend.
    ///
    /// `half_life_days` is retained as a compatibility toggle: finite
    /// positive values enable recency, but the actual decay half-life comes
    /// from the per-entity-type RET-010c contract table.
    pub fn boost_recency(mut self, half_life_days: f32) -> Self {
        self.recency_blend_enabled = half_life_days.is_finite() && half_life_days > 0.0;
        self
    }

    pub fn boost_salience(mut self) -> Self {
        self.apply_salience = true;
        self
    }

    pub fn boost_confidence(mut self) -> Self {
        self.apply_confidence = true;
        self
    }

    pub fn boost_gravity(mut self) -> Self {
        self.apply_gravity = true;
        self
    }

    pub fn boost_contiguity(mut self) -> Self {
        self.apply_contiguity = true;
        self
    }

    pub fn filter_types(mut self, types: &[u8]) -> Self {
        self.type_filter = Some(types.to_vec());
        self
    }

    pub fn filter_since(mut self, timestamp: u64) -> Self {
        self.since_filter = Some(timestamp);
        self
    }

    pub fn filter_occurred_range(mut self, start: u64, end: u64) -> Self {
        self.occurred_range = Some(normalize_range(start, end));
        self
    }

    pub fn filter_learned_range(mut self, start: u64, end: u64) -> Self {
        self.learned_range = Some(normalize_range(start, end));
        self
    }

    pub fn filter_repo_ref(mut self, repo_ref: RepoRef) -> Self {
        self.repo_ref_filter = Some(repo_ref);
        self
    }

    pub fn filter_project_id(mut self, project_id: impl Into<String>) -> Self {
        self.project_id_filter = Some(project_id.into());
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.result_limit = n;
        self
    }

    /// Activates the ARCH-0039 facet filter for this query: `facet_id` is
    /// the active FACET entity and `mode` selects `strict` (only core +
    /// active-facet claims) or `prefer` (return all, boost active facet).
    /// Not calling this method is the contract's *(no facet)* mode — no
    /// facet filtering at all.
    ///
    /// The filter runs post-fusion/post-boosts, before the
    /// `result_limit` truncation and under the same read transaction, so
    /// claims excluded by `strict` never consume result slots. It reads
    /// each candidate CLAIM's outgoing `FacetOf` (`CLAIM → FACET`) edges;
    /// claim bodies are never decoded by this stage.
    pub fn facet(mut self, facet_id: &EntityId, mode: FacetMode) -> Self {
        self.facet_filter = Some((*facet_id, mode));
        self
    }

    /// Binds this query to a relationship scope.
    pub fn relationship(mut self, rel_id: &EntityId, mode: RelMode) -> Self {
        self.relationship_filter = Some((*rel_id, mode));
        self
    }

    /// Sets the ARCH-0004 / ARCH-0022 world scope for this query. The default
    /// is [`WorldScope::All`] (span every world). [`WorldScope::Base`] keeps
    /// only claims with no `world` key; [`WorldScope::World`] keeps that
    /// world's claims plus base claims. The filter runs post-fusion /
    /// post-boosts, before the `result_limit` truncation and under the same
    /// read transaction — in the same stage as the facet filter — so claims
    /// excluded by scope never consume result slots. Scoring and fusion are
    /// untouched.
    pub fn world(mut self, scope: WorldScope) -> Self {
        self.world_scope = scope;
        self
    }

    pub fn prior_successful_coping_strategies(
        self,
        affected_person: &EntityId,
        limit: usize,
    ) -> Result<Vec<CopingOutcomeRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut records = Vec::new();
        for claim_id in self.vault.claims_for_subject(affected_person)? {
            let Some(body) = self.vault.get_claim(&claim_id)? else {
                continue;
            };
            if body.predicate != COPING_OUTCOME_PREDICATE || !claim_surfaceable(&body) {
                continue;
            }
            validate_coping_outcome_claim_structure(&body)?;
            let Some(value) = decode_coping_outcome_claim(&body)? else {
                continue;
            };
            if !value.successful() {
                continue;
            }
            records.push(CopingOutcomeRecord {
                claim_id,
                learned_at: self.vault.get_learned_at(&claim_id)?,
                valid_from: body.valid_from.ok_or(Error::InvalidClaimBody(
                    "coping.outcome valid_from is required",
                ))?,
                valid_to: body.valid_to,
                value,
            });
        }
        records.sort_by(|a, b| {
            b.learned_at
                .cmp(&a.learned_at)
                .then_with(|| b.claim_id.as_bytes().cmp(a.claim_id.as_bytes()))
        });
        records.truncate(limit);
        Ok(records)
    }

    pub fn run(self) -> Result<Vec<ScoredEntity>> {
        Ok(self.run_with_telemetry()?.value)
    }

    pub fn run_with_telemetry(self) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        let output = self.run_for_pack()?;
        Ok(RetrievalWithTelemetry {
            value: output.scores,
            run_id: output.telemetry_run_id,
        })
    }

    pub fn run_with_pending_vectors(
        self,
    ) -> Result<RetrievalWithPendingVectors<Vec<ScoredEntity>>> {
        #[cfg(feature = "sync")]
        let vault = self.vault;
        // K6: the enqueue arm is BASE-ONLY. A session surfacing returns its
        // pending vectors to the caller for inline handling and never writes
        // a `pe:` marker or an embed job row — there is no overlay `pe:`
        // keyspace, so redirecting is not an option and skipping is the rule.
        // The test is whether rows STAGE, not whether a session is attached:
        // an on-record room's retrieval is an ordinary base one and enqueues
        // like any other.
        #[cfg(feature = "sync")]
        let enqueue = !self
            .session
            .is_some_and(crate::off_record::SessionRetrievalTelemetry::stages_in_overlay);
        let output = self.run_for_pack()?;
        let pending_vector_ids = pending_vector_ids(&output.pending_vectors);
        #[cfg(feature = "sync")]
        if enqueue {
            crate::embed::enqueue_pending_embedding_jobs(
                vault,
                &pending_vector_ids,
                crate::embed::EMBED_PRIORITY_SURFACED_HOT,
            )?;
        }
        Ok(RetrievalWithPendingVectors {
            value: output.scores,
            pending_vector_ids,
            pending_vectors: output.pending_vectors,
            run_id: output.telemetry_run_id,
        })
    }

    pub fn run_dreamer_working_set(
        mut self,
        cursor: DreamerWorkingSetCursor,
        budget: DreamerWorkingSetBudget,
        page_limit: usize,
    ) -> Result<DreamerWorkingSet> {
        if page_limit == 0 {
            return Err(Error::InvalidConfig(
                "dreamer working-set page_limit must be greater than zero".to_owned(),
            ));
        }

        let remaining = budget.max_items().saturating_sub(cursor.offset());
        if remaining == 0 {
            return Ok(DreamerWorkingSet {
                cursor,
                next_cursor: None,
                budget,
                rows: Vec::new(),
                stop_reason: Some(DreamerWorkingSetStopReason::BudgetExhausted),
                telemetry_run_id: None,
            });
        }

        let ingress_limit = page_limit.min(remaining);
        let page_end = cursor.offset().saturating_add(ingress_limit);
        let lookahead = usize::from(page_end < budget.max_items());
        let fetch_limit = page_end.saturating_add(lookahead);
        self.result_limit = fetch_limit;

        let output = self.run_for_pack()?;
        let loaded = output.scores.len();
        let rows: Vec<_> = output
            .scores
            .into_iter()
            .skip(cursor.offset())
            .take(ingress_limit)
            .collect();
        let next_offset = cursor.offset().saturating_add(rows.len());
        let budget_exhausted = next_offset >= budget.max_items();
        let stop_reason = if budget_exhausted {
            Some(DreamerWorkingSetStopReason::BudgetExhausted)
        } else if loaded <= next_offset {
            Some(DreamerWorkingSetStopReason::EndOfWorkingSet)
        } else {
            None
        };
        let next_cursor = stop_reason
            .is_none()
            .then(|| DreamerWorkingSetCursor::from_offset(next_offset));

        Ok(DreamerWorkingSet {
            cursor,
            next_cursor,
            budget,
            rows,
            stop_reason,
            telemetry_run_id: output.telemetry_run_id,
        })
    }
}

fn pending_vector_ids(pending: &[PendingVectorEmbedding]) -> Vec<EntityId> {
    pending.iter().map(|pending| pending.id).collect()
}
