//! Deterministic replay fork-hashing: evidence dispatcher, all fork_hash segments, and primitives.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::analyzer::AnalyzerChannel;
use crate::bm25::{Bm25Config, Bm25Formula};
use crate::codebase::RepoRef;
use crate::context_pack::ContextPackRetrievalBudget;
use crate::corpus::CorpusScope;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::query_expansion::HydeExpansion;
use crate::rerank::{RerankOptions, Reranker};
use crate::store::RetrievalBlendWeights;
use crate::temporal::TemporalAnchorMode;
use crate::vault::RevisionRef;

use super::replay_identity::RetrievalReplayIdentity;

use super::super::builder::PipelineBuilder;
use super::super::types::{
    ALPHA_BASE, ALPHA_RANGE, ALPHA_TAU_SECS, ActiveWorldSelection, COSINE_GHOST_VECTOR_THRESHOLD,
    DEFAULT_RECENCY_HALF_LIFE_DAYS, FacetMode, PPR_DAMPING, RECENCY_DECAY_TAU_SECS,
    RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE, RETRIEVAL_TRACE_RRF_K, RelMode,
    ResolvedWorldAuthority, TEMPORAL_FLOOR, TemporalSearchConfig, WorldAuthoritySet, WorldScope,
};

/// Evidence captured under the retrieval transaction; hashing never rescans claims.
pub(in crate::pipeline) struct RetrievalTraceForkEvidence<'a> {
    pub(in crate::pipeline) candidate_set: &'a [[u8; ENTITY_ID_LEN]],
    pub(in crate::pipeline) candidate_revisions: &'a [([u8; ENTITY_ID_LEN], Option<RevisionRef>)],
    pub(in crate::pipeline) world_authority: Option<&'a ResolvedWorldAuthority>,
    pub(in crate::pipeline) replay_identity: &'a RetrievalReplayIdentity,
    pub(in crate::pipeline) hyde_expansion: Option<&'a HydeExpansion>,
    pub(in crate::pipeline) extra_text_queries: &'a [String],
    pub(in crate::pipeline) widen_channel_limits: bool,
    pub(in crate::pipeline) skip_ret01_abstain: bool,
}

pub(in crate::pipeline) fn retrieval_trace_fork_hash(
    builder: &PipelineBuilder<'_>,
    bm25_config: &Bm25Config,
    blend_weights: RetrievalBlendWeights,
    explicit_time_dependent_now_secs: Option<u64>,
    resolved_occurred_range: Option<(u64, u64)>,
    rerank_query: Option<&str>,
    evidence: RetrievalTraceForkEvidence<'_>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    fork_hash_bytes(&mut hasher, b"oneiron.retrieval_trace.fork_hash.v1");

    fork_hash_vector_query(
        &mut hasher,
        builder.vector_search.as_ref(),
        builder.skip_vector_rescore,
    );
    fork_hash_text_query(&mut hasher, builder.text_search.as_ref());
    fork_hash_phonetic_query(&mut hasher, builder.phonetic_search.as_deref());
    fork_hash_media_queries(&mut hasher, &builder.media_search);
    fork_hash_temporal_query(&mut hasher, builder.temporal_search.as_ref());
    fork_hash_entity_seeds(&mut hasher, builder.ppr_search.as_ref());
    fork_hash_entity_seeds(&mut hasher, builder.ppr_expand.as_ref());
    fork_hash_f32(
        &mut hasher,
        crate::ppr::canonical_vad_alpha(builder.ppr_vad_alpha),
    );
    fork_hash_affect_policy(
        &mut hasher,
        &builder.affect_policy,
        builder.affect_policy.congruence_query(builder.query_affect),
    );

    fork_hash_bm25_config(&mut hasher, bm25_config);
    // The recency the run applies: a host temporal window switches a
    // requested blend off, the effort's default anchor keeps it.
    fork_hash_bool(&mut hasher, builder.recency_blend_applies());
    fork_hash_opt_u64(&mut hasher, explicit_time_dependent_now_secs);
    fork_hash_access_factor_overrides(&mut hasher, builder.access_factor_overrides);
    let profiles = builder.claim_aging_profiles;
    for policy in [profiles.durable, profiles.standard, profiles.ephemeral] {
        fork_hash_f64(&mut hasher, policy.half_life_secs);
        fork_hash_f32(&mut hasher, policy.floor + 0.0);
    }
    fork_hash_bool(&mut hasher, builder.apply_salience);
    fork_hash_bool(&mut hasher, builder.apply_confidence);
    fork_hash_bool(&mut hasher, builder.apply_gravity);
    fork_hash_bool(&mut hasher, builder.apply_contiguity);
    fork_hash_type_filter(&mut hasher, builder.type_filter.as_deref());
    fork_hash_opt_u64(&mut hasher, builder.since_filter);
    fork_hash_opt_range(&mut hasher, resolved_occurred_range);
    fork_hash_opt_range(&mut hasher, builder.learned_range);
    fork_hash_repo_ref(&mut hasher, builder.repo_ref_filter.as_ref());
    fork_hash_opt_str(&mut hasher, builder.project_id_filter.as_deref());
    fork_hash_facet_filter(&mut hasher, builder.facet_filter);
    fork_hash_relationship_filter(&mut hasher, builder.relationship_filter);
    fork_hash_world_scope(
        &mut hasher,
        &builder.world_scope,
        builder.active_world_selection.as_ref(),
        evidence.world_authority,
    );
    fork_hash_corpus_scope(&mut hasher, &builder.corpus_scope);
    fork_hash_bytes(
        &mut hasher,
        match builder.made_by {
            crate::provenance::made_by::MadeByPredicate::All => b"made_by:all",
            crate::provenance::made_by::MadeByPredicate::Stated => b"made_by:stated",
            crate::provenance::made_by::MadeByPredicate::Concluded => b"made_by:concluded",
        },
    );
    fork_hash_authority_filter(&mut hasher, builder.authority_filter.as_ref());
    fork_hash_context_pack_budget(&mut hasher, builder.context_pack_budget);
    fork_hash_bool(&mut hasher, builder.context_pack_world_share.is_some());
    fork_hash_f32(&mut hasher, builder.context_pack_world_share.unwrap_or(0.0));
    fork_hash_len(&mut hasher, builder.result_limit);
    fork_hash_bool(&mut hasher, builder.temporal_adaptive_default);
    fork_hash_recency_weight_table(&mut hasher);
    fork_hash_retrieval_blend_weights(&mut hasher, blend_weights);
    fork_hash_scoring_constants(&mut hasher, builder.vault.config.fast_dims);
    // RET-01 reads the embedding space's own evidence floors, and a folding
    // run returns a matched MESSAGE as its TURN: both change the result.
    let floors = builder.no_match_floors();
    fork_hash_f32(&mut hasher, floors.pair.floor);
    fork_hash_f32(&mut hasher, floors.pair.strong);
    // EMBED-PACK: a kind's own floors in the run's space take the pair's
    // place there; another space's judge nothing here.
    let space = builder.vault.evidence_space();
    fork_hash_str(&mut hasher, space);
    let kinds = floors.keyed.get(space);
    fork_hash_len(
        &mut hasher,
        kinds.map_or(0, std::collections::BTreeMap::len),
    );
    for (kind, kind_floors) in kinds.into_iter().flatten() {
        fork_hash_u8(&mut hasher, *kind);
        fork_hash_f32(&mut hasher, kind_floors.floor);
        fork_hash_f32(&mut hasher, kind_floors.strong);
    }
    fork_hash_str(&mut hasher, builder.turn_fold.as_str());
    fork_hash_rerank(&mut hasher, builder.rerank.as_ref(), rerank_query);
    fork_hash_opt_str(&mut hasher, builder.skill_executor.as_deref());
    fork_hash_bool(&mut hasher, builder.skill_reliability_query.is_some());
    if let Some(query) = &builder.skill_reliability_query {
        fork_hash_str(&mut hasher, &query.type_ref.wire_form());
        fork_hash_str(&mut hasher, &query.axis);
        fork_hash_len(&mut hasher, query.type_parents.len());
        for parent in &query.type_parents {
            fork_hash_str(&mut hasher, &parent.wire_form());
        }
    }
    fork_hash_source_and_model_identity(&mut hasher, builder, evidence.replay_identity);
    fork_hash_hyde_attempt(
        &mut hasher,
        builder,
        evidence.hyde_expansion,
        evidence.extra_text_queries,
        evidence.widen_channel_limits,
        evidence.skip_ret01_abstain,
    );
    fork_hash_candidate_revisions(&mut hasher, evidence.candidate_revisions);
    fork_hash_candidate_set(&mut hasher, evidence.candidate_set);

    hasher.finalize().into()
}

/// ONE-1402 read-side decay segment. The caller-supplied override map is
/// canonicalized before hashing — presence flag, entries sorted by the
/// 16-byte `EntityId` ascending, count, then raw id bytes and `to_bits`
/// per entry — so two requests that differ only in map insertion order
/// keep ONE replay key while any changed factor forks. `EntityId` keys are
/// unique, so the id is already a total order and no value tiebreak is
/// needed. Overrides are validated finite and within `[0, 1]` before any
/// channel work, so `to_bits` is canonical; the resulting `-0.0`/`+0.0`
/// and `None`/`Some({})` over-distinctions are accepted (they separate,
/// never collide).
///
/// The decay CLOCK rides `explicit_time_dependent_now_secs` above: decay
/// consumes the run clock on every run, so an explicitly supplied
/// `temporal_now` is time-dependent scoring input even with recency
/// blending and temporal search off. An implicit wall clock stays unhashed.
///
/// Appending this segment shifts ALL fork hashes relative to earlier
/// binaries; accepted on the same 1186-D5 precedent as the rerank segment
/// below.
fn fork_hash_access_factor_overrides(
    hasher: &mut Sha256,
    overrides: Option<&HashMap<EntityId, f32>>,
) {
    let Some(overrides) = overrides else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    let mut entries: Vec<(&EntityId, &f32)> = overrides.iter().collect();
    entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    fork_hash_len(hasher, entries.len());
    for (id, factor) in entries {
        fork_hash_raw_bytes(hasher, id.as_bytes());
        fork_hash_f32(hasher, *factor);
    }
}

/// RET-010 rerank segment. Appending the active bool shifts ALL fork hashes
/// relative to pre-RET-010 binaries; accepted — 1186-D5 pins
/// schema+determinism within a binary, not cross-version hash stability.
fn fork_hash_rerank(
    hasher: &mut Sha256,
    rerank: Option<&(&dyn Reranker, RerankOptions)>,
    effective_query: Option<&str>,
) {
    let Some((reranker, options)) = rerank else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_str(hasher, reranker.id());
    fork_hash_u64(hasher, options.top_n as u64);
    fork_hash_str(hasher, effective_query.unwrap_or_default());
}

fn fork_hash_authority_filter(
    hasher: &mut Sha256,
    filter: Option<&crate::gate::ResolvedRetrievalFilter>,
) {
    let Some(filter) = filter else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_bool(hasher, filter.deny_all);
    fork_hash_bool(hasher, filter.entity_types.is_some());
    if let Some(types) = &filter.entity_types {
        fork_hash_len(hasher, types.len());
        for kind in types {
            fork_hash_u8(hasher, *kind);
        }
    }
    fork_hash_u8(hasher, filter.max_sensitivity_band);
    fork_hash_bool(hasher, filter.include_stale);
    fork_hash_f32(hasher, filter.min_confidence);
    fork_hash_f32(hasher, filter.min_salience);
}

/// OF-370 typed media queries, in call order: each is its own list.
fn fork_hash_media_queries(
    hasher: &mut Sha256,
    queries: &[super::super::media_channel::MediaQuery],
) {
    fork_hash_len(hasher, queries.len());
    for query in queries {
        fork_hash_bytes(hasher, query.space_id.as_bytes());
        fork_hash_bytes(hasher, format!("{:?}", query.query_kind).as_bytes());
        fork_hash_len(hasher, query.limit);
        fork_hash_len(hasher, query.kinds.len());
        for kind in &query.kinds {
            fork_hash_bytes(hasher, format!("{kind:?}").as_bytes());
        }
        fork_hash_len(hasher, query.vector.len());
        for value in &query.vector {
            fork_hash_f32(hasher, *value);
        }
    }
}

fn fork_hash_vector_query(
    hasher: &mut Sha256,
    query: Option<&(Vec<f32>, usize)>,
    skip_vector_rescore: bool,
) {
    let Some((vector, limit)) = query else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_len(hasher, *limit);
    fork_hash_len(hasher, vector.len());
    for value in vector {
        fork_hash_f32(hasher, *value);
    }
    // EMB-2 hot lane: prefix-only vs rescored orders are different forks.
    fork_hash_bool(hasher, skip_vector_rescore);
}

fn fork_hash_text_query(hasher: &mut Sha256, query: Option<&(String, usize)>) {
    let Some((query, limit)) = query else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_len(hasher, *limit);
    fork_hash_str(hasher, query);
}

fn fork_hash_phonetic_query(hasher: &mut Sha256, codes: Option<&[String]>) {
    let Some(codes) = codes else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    let mut codes = codes.to_vec();
    codes.sort();
    codes.dedup();
    fork_hash_len(hasher, codes.len());
    for code in &codes {
        fork_hash_str(hasher, code);
    }
}

fn fork_hash_temporal_query(hasher: &mut Sha256, config: Option<&TemporalSearchConfig>) {
    let Some(config) = config else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_u64(hasher, config.anchor_start);
    fork_hash_u64(hasher, config.anchor_end);
    fork_hash_opt_u64(hasher, config.learned_start);
    fork_hash_opt_u64(hasher, config.learned_end);
    fork_hash_u64(hasher, config.sigma_secs);
    fork_hash_temporal_anchor_mode(hasher, config.anchor_mode);
    fork_hash_bool(hasher, config.adaptive);
    fork_hash_len(hasher, config.limit);
}

fn fork_hash_temporal_anchor_mode(hasher: &mut Sha256, mode: TemporalAnchorMode) {
    fork_hash_str(
        hasher,
        match mode {
            TemporalAnchorMode::Auto => "auto",
            TemporalAnchorMode::Occurred => "occurred",
            TemporalAnchorMode::Learned => "learned",
            TemporalAnchorMode::Both => "both",
        },
    );
}

fn fork_hash_entity_seeds(hasher: &mut Sha256, seeds: Option<&(Vec<EntityId>, u32)>) {
    let Some((seeds, depth)) = seeds else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_u32(hasher, *depth);
    let mut seed_bytes: Vec<[u8; ENTITY_ID_LEN]> =
        seeds.iter().map(|seed| *seed.as_bytes()).collect();
    seed_bytes.sort_unstable();
    seed_bytes.dedup();
    fork_hash_len(hasher, seed_bytes.len());
    for seed in seed_bytes {
        fork_hash_raw_bytes(hasher, &seed);
    }
}

fn fork_hash_bm25_config(hasher: &mut Sha256, config: &Bm25Config) {
    fork_hash_f64(hasher, config.k1);
    match config.formula {
        Bm25Formula::Okapi => fork_hash_str(hasher, "okapi"),
        Bm25Formula::Plus { delta } => {
            fork_hash_str(hasher, "plus");
            fork_hash_f64(hasher, delta);
        }
    }
    let channels = AnalyzerChannel::ALL_RESERVED;
    fork_hash_len(hasher, channels.len());
    for channel in channels {
        let field = config.field(channel);
        fork_hash_str(hasher, channel.as_str());
        fork_hash_f64(hasher, field.weight);
        fork_hash_f64(hasher, field.b);
        fork_hash_str(hasher, field.length_policy.manifest_tag());
    }
}

fn fork_hash_type_filter(hasher: &mut Sha256, types: Option<&[u8]>) {
    let Some(types) = types else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    let mut types = types.to_vec();
    types.sort_unstable();
    types.dedup();
    fork_hash_len(hasher, types.len());
    for entity_type in types {
        fork_hash_u8(hasher, entity_type);
    }
}

fn fork_hash_repo_ref(hasher: &mut Sha256, repo_ref: Option<&RepoRef>) {
    let Some(repo_ref) = repo_ref else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_str(hasher, &repo_ref.canonical());
}

fn fork_hash_facet_filter(hasher: &mut Sha256, filter: Option<(EntityId, FacetMode)>) {
    let Some((facet_id, mode)) = filter else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_raw_bytes(hasher, facet_id.as_bytes());
    match mode {
        FacetMode::Strict => fork_hash_str(hasher, "strict"),
        FacetMode::Prefer { boost } => {
            fork_hash_str(hasher, "prefer");
            fork_hash_f32(hasher, boost);
        }
    }
}

fn fork_hash_relationship_filter(hasher: &mut Sha256, filter: Option<(EntityId, RelMode)>) {
    let Some((relationship, mode)) = filter else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_raw_bytes(hasher, relationship.as_bytes());
    fork_hash_str(
        hasher,
        match mode {
            RelMode::Filter => "filter",
            RelMode::Demote => "demote",
        },
    );
}

/// ONE-1420 ActiveSet segment: hash the per-turn selection plus the authority
/// and claim provenance captured by the run's single resolution.
///
/// "Use my stored default" remains distinct from an explicit selection, and
/// changes to the resolved default or its authority claims fork the key even
/// when the candidate set is unchanged. Sets and claim ids use canonical order.
fn fork_hash_world_scope(
    hasher: &mut Sha256,
    scope: &WorldScope,
    selection: Option<&ActiveWorldSelection>,
    authority: Option<&ResolvedWorldAuthority>,
) {
    match scope {
        WorldScope::All => fork_hash_str(hasher, "all"),
        WorldScope::Base => fork_hash_str(hasher, "base"),
        WorldScope::World(id) => {
            fork_hash_str(hasher, "world");
            fork_hash_raw_bytes(hasher, id.as_bytes());
        }
        WorldScope::CodebaseSet(scope_key) => {
            fork_hash_str(hasher, "codebase_set");
            fork_hash_raw_bytes(hasher, scope_key);
        }
        WorldScope::WorldSet(worlds) => {
            fork_hash_str(hasher, "world_set");
            fork_hash_world_authority_set(hasher, worlds);
        }
        WorldScope::ActiveSet => {
            fork_hash_str(hasher, "active_set");
            let Some(selection) = selection else {
                fork_hash_bool(hasher, false);
                return;
            };
            fork_hash_bool(hasher, true);
            fork_hash_raw_bytes(hasher, selection.agent_ref.as_bytes());
            if let Some(selected) = selection.selected.as_ref() {
                fork_hash_bool(hasher, true);
                fork_hash_world_authority_set(hasher, selected);
            } else {
                fork_hash_bool(hasher, false);
            }
            fork_hash_world_authority(hasher, authority);
        }
    }
}

fn fork_hash_world_authority(hasher: &mut Sha256, authority: Option<&ResolvedWorldAuthority>) {
    let Some(authority) = authority else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_world_authority_set(hasher, &authority.allowed_set);
    fork_hash_world_authority_set(hasher, &authority.default_subset);
    fork_hash_world_authority_set(hasher, &authority.active_set);

    let mut allowed_claim_ids = authority.allowed_claim_ids.clone();
    allowed_claim_ids.sort_unstable();
    fork_hash_len(hasher, allowed_claim_ids.len());
    for claim_id in allowed_claim_ids {
        fork_hash_raw_bytes(hasher, claim_id.as_bytes());
    }
    if let Some(claim_id) = authority.default_claim_id {
        fork_hash_bool(hasher, true);
        fork_hash_raw_bytes(hasher, claim_id.as_bytes());
    } else {
        fork_hash_bool(hasher, false);
    }
}

fn fork_hash_world_authority_set(hasher: &mut Sha256, set: &WorldAuthoritySet) {
    fork_hash_bool(hasher, set.include_base());
    fork_hash_len(hasher, set.worlds().len());
    for world in set.worlds() {
        fork_hash_raw_bytes(hasher, world.as_bytes());
    }
}

/// Query validation still rejects empty AnyOf before channel work. Hashing only
/// normalizes ordering/duplicates; it neither admits nor repairs invalid input.
fn fork_hash_corpus_scope(hasher: &mut Sha256, scope: &CorpusScope) {
    fork_hash_str(hasher, "corpus_scope");
    match scope {
        CorpusScope::All => fork_hash_str(hasher, "all"),
        CorpusScope::Unscoped => fork_hash_str(hasher, "unscoped"),
        CorpusScope::Corpus(id) => {
            fork_hash_str(hasher, "corpus");
            fork_hash_raw_bytes(hasher, id.as_bytes());
        }
        CorpusScope::AnyOf(ids) => {
            fork_hash_str(hasher, "any_of");
            let mut ids = ids.clone();
            ids.sort_unstable();
            ids.dedup();
            fork_hash_len(hasher, ids.len());
            for id in ids {
                fork_hash_raw_bytes(hasher, id.as_bytes());
            }
        }
    }
}

fn fork_hash_context_pack_budget(hasher: &mut Sha256, budget: Option<ContextPackRetrievalBudget>) {
    let Some(budget) = budget else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_len(hasher, budget.claims);
    fork_hash_len(hasher, budget.turns);
    fork_hash_len(hasher, budget.summaries);
    fork_hash_len(hasher, budget.facets);
    fork_hash_len(hasher, budget.other);
    fork_hash_len(hasher, budget.selected_edges);
}

fn fork_hash_recency_weight_table(hasher: &mut Sha256) {
    fork_hash_len(hasher, RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE.len());
    for (entity_type, half_life_days) in RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE {
        fork_hash_u8(hasher, *entity_type);
        fork_hash_f32(hasher, *half_life_days);
    }
    fork_hash_f32(hasher, DEFAULT_RECENCY_HALF_LIFE_DAYS);
}

fn fork_hash_retrieval_blend_weights(hasher: &mut Sha256, weights: RetrievalBlendWeights) {
    fork_hash_f32(hasher, weights.recency);
    fork_hash_f32(hasher, weights.salience);
    fork_hash_f32(hasher, weights.confidence);
    fork_hash_f32(hasher, weights.gravity);
    fork_hash_f32(hasher, weights.relevance);
}

fn fork_hash_scoring_constants(hasher: &mut Sha256, fast_dims: Option<u16>) {
    fork_hash_f32(hasher, RETRIEVAL_TRACE_RRF_K);
    fork_hash_f32(hasher, PPR_DAMPING);
    fork_hash_f64(hasher, RECENCY_DECAY_TAU_SECS);
    fork_hash_f64(hasher, ALPHA_BASE);
    fork_hash_f64(hasher, ALPHA_RANGE);
    fork_hash_f64(hasher, ALPHA_TAU_SECS);
    fork_hash_f64(hasher, TEMPORAL_FLOOR);
    fork_hash_f32(hasher, COSINE_GHOST_VECTOR_THRESHOLD);
    fork_hash_f32(hasher, crate::fusion::BLEND_SCORE_CEILING);
    // EMBED-PACK: each ranked list's fusion scale is its top
    // FUSION_LIST_LENGTH, and the phonetic list is scored over every
    // candidate; replays keyed before either differ.
    fork_hash_len(hasher, crate::fusion::FUSION_LIST_LENGTH);
    fork_hash_str(hasher, "sparse:phonetic");
    // EMB-2: the funnel prefix changes vector-channel scoring space.
    fork_hash_u32(hasher, u32::from(fast_dims.unwrap_or(0)));
}

fn fork_hash_source_and_model_identity(
    hasher: &mut Sha256,
    builder: &PipelineBuilder<'_>,
    identity: &RetrievalReplayIdentity,
) {
    fork_hash_opt_str(hasher, builder.corpus_snapshot_ref.as_deref());
    fork_hash_opt_str(hasher, builder.vault.config.embedding_transform.as_deref());
    fork_hash_len(hasher, identity.media_spaces.len());
    for media in &identity.media_spaces {
        let space = &media.space;
        fork_hash_str(hasher, &space.id);
        fork_hash_len(hasher, space.dimensions);
        fork_hash_len(hasher, space.accepts.len());
        for kind in &space.accepts {
            fork_hash_str(hasher, &format!("{kind:?}"));
        }
        fork_hash_len(hasher, space.query_towers.len());
        for kind in &space.query_towers {
            fork_hash_str(hasher, &format!("{kind:?}"));
        }
        fork_hash_opt_floors(hasher, space.evidence);
        // The default pair and every keyed pair are the run's effective RET-01
        // inputs for this space, not a later configuration read.
        fork_hash_floors(hasher, media.floors);
        fork_hash_len(hasher, media.kind_overrides.len());
        for (kind, floors) in &media.kind_overrides {
            fork_hash_u8(hasher, *kind);
            fork_hash_floors(hasher, *floors);
        }
    }
    fork_hash_opt_bytes(hasher, identity.analyzer_manifest_hash.as_deref());
    fork_hash_opt_bytes(hasher, identity.bm25_field_schema_hash.as_deref());
}

fn fork_hash_hyde_attempt(
    hasher: &mut Sha256,
    builder: &PipelineBuilder<'_>,
    expansion: Option<&HydeExpansion>,
    extra_text_queries: &[String],
    widen_channel_limits: bool,
    skip_ret01_abstain: bool,
) {
    if let Some((expander, grounding, options)) = builder.hyde.as_ref() {
        fork_hash_bool(hasher, true);
        fork_hash_str(hasher, expander.id());
        fork_hash_len(hasher, options.channel_limit);
        fork_hash_bool(hasher, options.retry_once);
        fork_hash_len(hasher, grounding.bindings.len());
        for (key, value) in &grounding.bindings {
            fork_hash_str(hasher, key);
            fork_hash_str(hasher, value);
        }
    } else {
        fork_hash_bool(hasher, false);
    }
    if let Some(expansion) = expansion {
        fork_hash_bool(hasher, true);
        fork_hash_len(hasher, expansion.embedding.len());
        for value in &expansion.embedding {
            fork_hash_f32(hasher, *value);
        }
        fork_hash_len(hasher, expansion.subqueries.len());
        for query in &expansion.subqueries {
            fork_hash_str(hasher, query);
        }
    } else {
        fork_hash_bool(hasher, false);
    }
    fork_hash_len(hasher, extra_text_queries.len());
    for query in extra_text_queries {
        fork_hash_str(hasher, query);
    }
    fork_hash_bool(hasher, widen_channel_limits);
    fork_hash_bool(hasher, skip_ret01_abstain);
}

fn fork_hash_candidate_revisions(
    hasher: &mut Sha256,
    revisions: &[([u8; ENTITY_ID_LEN], Option<RevisionRef>)],
) {
    fork_hash_len(hasher, revisions.len());
    for (id, revision) in revisions {
        fork_hash_raw_bytes(hasher, id);
        fork_hash_bool(hasher, revision.is_some());
        if let Some(revision) = revision {
            fork_hash_raw_bytes(hasher, &revision.0);
        }
    }
}

fn fork_hash_floors(hasher: &mut Sha256, floors: crate::config::VectorEvidenceFloors) {
    fork_hash_f32(hasher, floors.floor);
    fork_hash_f32(hasher, floors.strong);
}

fn fork_hash_opt_floors(hasher: &mut Sha256, floors: Option<crate::config::VectorEvidenceFloors>) {
    fork_hash_bool(hasher, floors.is_some());
    if let Some(floors) = floors {
        fork_hash_floors(hasher, floors);
    }
}

fn fork_hash_opt_bytes(hasher: &mut Sha256, value: Option<&[u8]>) {
    fork_hash_bool(hasher, value.is_some());
    if let Some(value) = value {
        fork_hash_bytes(hasher, value);
    }
}

fn fork_hash_candidate_set(hasher: &mut Sha256, candidates: &[[u8; ENTITY_ID_LEN]]) {
    fork_hash_len(hasher, candidates.len());
    for candidate in candidates {
        fork_hash_raw_bytes(hasher, candidate);
    }
}

fn fork_hash_opt_range(hasher: &mut Sha256, range: Option<(u64, u64)>) {
    let Some((start, end)) = range else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_u64(hasher, start);
    fork_hash_u64(hasher, end);
}

fn fork_hash_opt_str(hasher: &mut Sha256, value: Option<&str>) {
    let Some(value) = value else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_str(hasher, value);
}

fn fork_hash_opt_u64(hasher: &mut Sha256, value: Option<u64>) {
    let Some(value) = value else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_u64(hasher, value);
}

fn fork_hash_str(hasher: &mut Sha256, value: &str) {
    fork_hash_bytes(hasher, value.as_bytes());
}

fn fork_hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    fork_hash_len(hasher, bytes.len());
    fork_hash_raw_bytes(hasher, bytes);
}

fn fork_hash_raw_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(bytes);
}

/// The OF-423 affect policy and the query VAD its congruence stage uses.
/// `+ 0.0` folds a validated `-0.0` dial onto `0.0`.
fn fork_hash_affect_policy(
    hasher: &mut Sha256,
    policy: &crate::pipeline::AffectRetrievalPolicy,
    query: Option<crate::affect::Vad>,
) {
    fork_hash_f32(hasher, policy.arousal_stretch + 0.0);
    fork_hash_bool(hasher, policy.availability_floor.is_some());
    fork_hash_f32(hasher, policy.availability_floor.unwrap_or(0.0) + 0.0);
    fork_hash_f32(hasher, policy.floor_arousal + 0.0);
    fork_hash_f32(hasher, policy.emotion_weight + 0.0);
    fork_hash_bool(hasher, query.is_some());
    if let Some(query) = query {
        fork_hash_f32(hasher, query.valence + 0.0);
        fork_hash_f32(hasher, query.arousal + 0.0);
        fork_hash_f32(hasher, query.dominance + 0.0);
    }
}

fn fork_hash_bool(hasher: &mut Sha256, value: bool) {
    hasher.update([u8::from(value)]);
}

fn fork_hash_u8(hasher: &mut Sha256, value: u8) {
    hasher.update([value]);
}

fn fork_hash_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

fn fork_hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn fork_hash_len(hasher: &mut Sha256, value: usize) {
    fork_hash_u64(hasher, value as u64);
}

fn fork_hash_f32(hasher: &mut Sha256, value: f32) {
    hasher.update(value.to_bits().to_le_bytes());
}

fn fork_hash_f64(hasher: &mut Sha256, value: f64) {
    hasher.update(value.to_bits().to_le_bytes());
}
