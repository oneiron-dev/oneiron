//! Opt-in replay input capture from the resolved query, never from a fork hash.

use serde_json::json;

use crate::bm25::{Bm25Config, Bm25Formula};
use crate::corpus::CorpusScope;
use crate::gate::ResolvedRetrievalFilter;
use crate::query_expansion::HydeExpansion;
use crate::store::{RetrievalBlendWeights, RetrievalReplayInputs};

use super::super::builder::PipelineBuilder;
use super::super::types::ResolvedWorldAuthority;

#[expect(
    clippy::too_many_arguments,
    reason = "the replay snapshot binds resolved inputs from one read transaction without rescanning mutable state"
)]
pub(in crate::pipeline) fn capture_replay_inputs(
    builder: &PipelineBuilder<'_>,
    bm25: &Bm25Config,
    blend_weights: RetrievalBlendWeights,
    authority: &ResolvedRetrievalFilter,
    world_authority: Option<&ResolvedWorldAuthority>,
    hyde_expansion: Option<&HydeExpansion>,
    extra_text_queries: &[String],
    widen_channel_limits: bool,
    skip_ret01_abstain: bool,
    occurred_range: Option<(u64, u64)>,
    temporal_now: u64,
    rerank_query: Option<&str>,
) -> RetrievalReplayInputs {
    let ids = |seed: &Option<(Vec<crate::EntityId>, u32)>| {
        seed.as_ref().map(|(ids, steps)| {
            json!({"ids": ids.iter().map(crate::EntityId::to_hex).collect::<Vec<_>>(),
                   "steps": steps})
        })
    };
    let corpus_scope = match &builder.corpus_scope {
        CorpusScope::All => json!({"kind": "all"}),
        CorpusScope::Unscoped => json!({"kind": "unscoped"}),
        CorpusScope::Corpus(id) => json!({"kind": "corpus", "ids": [id.entity_id().to_hex()]}),
        CorpusScope::AnyOf(ids) => {
            json!({"kind": "any_of", "ids": ids.iter().map(|id| id.entity_id().to_hex()).collect::<Vec<_>>() })
        }
    };
    let formula = match bm25.formula {
        Bm25Formula::Okapi => json!({"kind": "okapi"}),
        Bm25Formula::Plus { delta } => json!({"kind": "plus", "delta": delta}),
    };
    let fields = bm25
        .fields
        .iter()
        .map(|field| {
            json!({"weight": field.weight, "b": field.b,
               "length_policy": field.length_policy.manifest_tag()})
        })
        .collect::<Vec<_>>();
    let temporal = builder.temporal_search.as_ref().map(|t| {
        json!({
            "anchor_start": t.anchor_start, "anchor_end": t.anchor_end,
            "learned_start": t.learned_start, "learned_end": t.learned_end,
            "sigma_secs": t.sigma_secs, "anchor_mode": format!("{:?}", t.anchor_mode),
            "adaptive": t.adaptive, "limit": t.limit,
            "query_occurred_range": t.query_occurred_range, "effort_anchor": t.effort_anchor,
        })
    });
    RetrievalReplayInputs {
        query: json!({
            "vector": builder.vector_search,
            "text": builder.text_search,
            "phonetic_codes": builder.phonetic_search,
            "temporal": temporal,
            "ppr_search": ids(&builder.ppr_search),
            "ppr_expand": ids(&builder.ppr_expand),
            "rerank_query": rerank_query,
            "hyde_expansion": hyde_expansion.map(|expansion| json!({
                "grounded_query": expansion.grounded_query,
                "hypothetical_answer": expansion.hypothetical_answer,
                "embedding": expansion.embedding,
                "subqueries": expansion.subqueries,
            })),
            "retry_queries": extra_text_queries,
        }),
        config: json!({
            "bm25": {"k1": bm25.k1, "formula": formula, "fields": fields},
            "blend_weights": blend_weights,
            "authority": {
                "entity_types": authority.entity_types,
                "max_sensitivity_band": authority.max_sensitivity_band,
                "include_stale": authority.include_stale,
                "min_confidence": authority.min_confidence,
                "min_salience": authority.min_salience,
                "deny_all": authority.deny_all,
            },
            "world_authority": world_authority.map(|world| json!({
                "active_base": world.active_set.include_base(),
                "active_worlds": world.active_set.worlds().iter().map(crate::EntityId::to_hex).collect::<Vec<_>>(),
                "allowed_claim_ids": world.allowed_claim_ids.iter().map(crate::EntityId::to_hex).collect::<Vec<_>>(),
                "default_claim_id": world.default_claim_id.map(|id| id.to_hex()),
            })),
            "rerank": builder.rerank.as_ref().map(|(reranker, options)| json!({
                "scorer": reranker.id(), "top_n": options.top_n,
                "query_override": options.query,
            })),
            "hyde": builder.hyde.as_ref().map(|(expander, _, options)| json!({
                "expander": expander.id(), "channel_limit": options.channel_limit,
                "retry_once": options.retry_once,
            })),
            "retry_widen_limits": widen_channel_limits,
            "skip_ret01_abstain": skip_ret01_abstain,
            "candidate_filter_present": builder.candidate_filter.is_some(),
            "corpus_scope": corpus_scope,
            "world_scope": format!("{:?}", builder.world_scope),
            "result_limit": builder.result_limit,
            "context_pack_budget": builder.context_pack_budget.map(|b| json!({
                "claims": b.claims, "turns": b.turns, "summaries": b.summaries,
                "facets": b.facets, "other": b.other, "selected_edges": b.selected_edges,
            })),
            "occurred_range": occurred_range,
            "learned_range": builder.learned_range,
            "since": builder.since_filter,
            "temporal_now": temporal_now,
            "explicit_temporal_now": builder.temporal_now,
            "type_filter": builder.type_filter,
            "criticality": builder.criticality,
            "project_id": builder.project_id_filter,
            "repo_ref": builder.repo_ref_filter.as_ref().map(crate::codebase::RepoRef::canonical),
            "facet_filter": builder.facet_filter.map(|f| format!("{f:?}")),
            "relationship_filter": builder.relationship_filter.map(|f| format!("{f:?}")),
            "made_by": format!("{:?}", builder.made_by),
            "recency_blend": builder.recency_blend_applies(),
            "salience": builder.apply_salience,
            "confidence": builder.apply_confidence,
            "gravity": builder.apply_gravity,
            "contiguity": builder.apply_contiguity,
            "skip_vector_rescore": builder.skip_vector_rescore,
            "access_factor_overrides": builder.access_factor_overrides.map(|map| {
                let mut entries: Vec<_> = map.iter().map(|(id, factor)| (id.to_hex(), factor)).collect();
                entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                entries
            }),
        }),
        corpus_snapshot_ref: builder.corpus_snapshot_ref.clone(),
    }
}
