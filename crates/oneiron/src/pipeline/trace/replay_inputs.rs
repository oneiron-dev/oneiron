//! Opt-in replay input capture from the resolved query, never from a fork hash.

use serde_json::json;

use crate::bm25::{Bm25Config, Bm25Formula};
use crate::corpus::CorpusScope;
use crate::gate::ResolvedRetrievalFilter;
use crate::query_expansion::HydeExpansion;
use crate::store::{RetrievalBlendWeights, RetrievalReplayInputs};

use super::super::builder::PipelineBuilder;
use super::super::types::ResolvedWorldAuthority;
use super::replay_identity::RetrievalReplayIdentity;

pub(in crate::pipeline) struct ReplayInputsMemory {
    lease: crate::host_memory::MemoryLease,
    config_bytes: u64,
}

impl ReplayInputsMemory {
    pub(in crate::pipeline) fn track_config(&mut self, inputs: &RetrievalReplayInputs) {
        let bytes = inputs.known_config_backing_bytes();
        self.lease.materialized(0, bytes);
        self.lease.shrink(self.config_bytes);
        self.config_bytes = bytes;
    }
}

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
    replay_identity: &RetrievalReplayIdentity,
    hyde_expansion: Option<&HydeExpansion>,
    extra_text_queries: &[String],
    widen_channel_limits: bool,
    skip_ret01_abstain: bool,
    occurred_range: Option<(u64, u64)>,
    temporal_now: u64,
    rerank_query: Option<&str>,
    replay_inputs_memory: &mut Option<ReplayInputsMemory>,
) -> RetrievalReplayInputs {
    // Seed identities and channel payloads belong in the authorized query
    // packet, not in the local telemetry ledger.
    let seed_shape = |seed: &Option<(Vec<crate::EntityId>, u32)>| {
        seed.as_ref()
            .map(|(ids, steps)| json!({"count": ids.len(), "steps": steps}))
    };
    let mut string_memory = builder
        .media_search
        .memory()
        .map(crate::host_memory::MachineMemory::empty_lease);
    let mut account_string = |value: String| {
        if let Some(memory) = string_memory.as_mut() {
            memory.materialized(0, value.capacity() as u64);
        }
        value
    };
    let corpus_scope = match &builder.corpus_scope {
        CorpusScope::All => json!({"kind": "all"}),
        CorpusScope::Unscoped => json!({"kind": "unscoped"}),
        CorpusScope::Corpus(id) => json!({"kind": "corpus", "ids": [account_string(id.to_hex())]}),
        CorpusScope::AnyOf(ids) => {
            let mut corpus_memory = builder
                .media_search
                .memory()
                .map(crate::host_memory::MachineMemory::empty_lease);
            json!({
                "kind": "any_of",
                "ids": ({
                    let ids = ids.iter().map(crate::EntityId::to_hex).collect::<Vec<_>>();
                    if let Some(memory) = corpus_memory.as_mut() {
                        memory.materialized(
                            0,
                            ids.iter().fold(
                                (ids.capacity() as u64)
                                    .saturating_mul(std::mem::size_of::<String>() as u64),
                                |bytes, id| bytes.saturating_add(id.capacity() as u64),
                            ),
                        );
                    }
                    ids
                }),
            })
        }
    };
    let formula = match bm25.formula {
        Bm25Formula::Okapi => json!({"kind": "okapi"}),
        Bm25Formula::Plus { delta } => json!({"kind": "plus", "delta": delta}),
    };
    let mut fields_memory = builder
        .media_search
        .memory()
        .map(crate::host_memory::MachineMemory::empty_lease);
    let fields = bm25
        .fields
        .iter()
        .map(|field| {
            json!({"weight": field.weight, "b": field.b,
               "length_policy": field.length_policy.manifest_tag()})
        })
        .collect::<Vec<_>>();
    if let Some(memory) = fields_memory.as_mut() {
        memory.materialized(
            0,
            (fields.capacity() as u64)
                .saturating_mul(std::mem::size_of::<serde_json::Value>() as u64),
        );
    }
    let temporal = builder.temporal_search.as_ref().map(|t| {
        json!({
            "anchor_start": t.anchor_start, "anchor_end": t.anchor_end,
            "learned_start": t.learned_start, "learned_end": t.learned_end,
            "sigma_secs": t.sigma_secs, "anchor_mode": account_string(format!("{:?}", t.anchor_mode)),
            "adaptive": t.adaptive, "limit": t.limit,
            "query_occurred_range": t.query_occurred_range, "effort_anchor": t.effort_anchor,
        })
    });
    let affect_retrieval = json!({
        "arousal_stretch": builder.affect_policy.arousal_stretch,
        "availability_floor": builder.affect_policy.availability_floor,
        "floor_arousal": builder.affect_policy.floor_arousal,
        "emotion_weight": builder.affect_policy.emotion_weight,
        "query_affect": builder
            .affect_policy
            .congruence_query(builder.query_affect)
            .map(|vad| [vad.valence, vad.arousal, vad.dominance]),
    });
    let mut session_usage_memory = builder
        .media_search
        .memory()
        .map(crate::host_memory::MachineMemory::empty_lease);
    let mut access_factor_memory = builder
        .media_search
        .memory()
        .map(crate::host_memory::MachineMemory::empty_lease);
    *replay_inputs_memory = builder
        .media_search
        .memory()
        .map(|memory| ReplayInputsMemory {
            lease: memory.empty_lease(),
            config_bytes: 0,
        });
    let mut account_ref = |value: Option<String>| {
        if let (Some(memory), Some(value)) = (replay_inputs_memory.as_mut(), value.as_ref()) {
            memory.lease.materialized(0, value.capacity() as u64);
        }
        value
    };
    let mut inputs = RetrievalReplayInputs {
        query_ref: account_ref(builder.replay_query_ref.clone()),
        config: json!({
            "channels": {
                "vector_limit": builder.vector_search.as_ref().map(|(_, limit)| limit),
                "text_limit": builder.text_search.as_ref().map(|(_, limit)| limit),
                "phonetic_code_count": builder.phonetic_search.as_ref().map(Vec::len),
                "temporal": temporal,
                "ppr_search": seed_shape(&builder.ppr_search),
                "ppr_expand": seed_shape(&builder.ppr_expand),
                "rerank_query_present": rerank_query.is_some(),
                "hyde_expansion_present": hyde_expansion.is_some(),
                "hyde_subquery_count": hyde_expansion.map(|expansion| expansion.subqueries.len()),
                "retry_query_count": extra_text_queries.len(),
            },
            "bm25": {"k1": bm25.k1, "formula": formula, "fields": fields},
            "ppr_vad_alpha": crate::ppr::canonical_vad_alpha(builder.ppr_vad_alpha),
            "ppr_community": {
                "beta": builder.ppr_community.beta,
                "gamma": builder.ppr_community.gamma,
                "multiplier_cap": builder.ppr_community.multiplier_cap,
                "max_graph_fraction": builder.ppr_community.max_graph_fraction,
                "max_top_k_fraction": builder.ppr_community.max_top_k_fraction,
                "session_usage": builder.community_session_usage.map(|usage| {
                    let mut entries: Vec<_> = usage.iter().map(|(id, count)| (id.to_hex(), count)).collect();
                    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                    if let Some(memory) = session_usage_memory.as_mut() {
                        memory.materialized(
                            0,
                            entries.iter().fold(
                                (entries.capacity() as u64)
                                    .saturating_mul(std::mem::size_of::<(String, &u32)>() as u64),
                                |bytes, (id, _)| bytes.saturating_add(id.capacity() as u64),
                            ),
                        );
                    }
                    entries
                }),
            },
            "recency_half_lives": super::super::types::RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE,
            "default_recency_half_life": super::super::types::DEFAULT_RECENCY_HALF_LIFE_DAYS,
            "fast_dims": builder.vault.config.fast_dims,
            "blend_weights": blend_weights,
            "authority": {
                "entity_types": authority.entity_types,
                "max_sensitivity_band": authority.max_sensitivity_band,
                "include_stale": authority.include_stale,
                "min_confidence": authority.min_confidence,
                "min_salience": authority.min_salience,
                "deny_all": authority.deny_all,
            },
            "world_authority": world_authority.map(|world| {
                let mut world_memory = builder
                    .media_search
                    .memory()
                    .map(crate::host_memory::MachineMemory::empty_lease);
                json!({
                    "active_base": world.active_set.include_base(),
                    "active_worlds": ({
                        let ids = world.active_set.worlds().iter().map(crate::EntityId::to_hex).collect::<Vec<_>>();
                        if let Some(memory) = world_memory.as_mut() {
                            memory.materialized(
                                0,
                                ids.iter().fold(
                                    (ids.capacity() as u64)
                                        .saturating_mul(std::mem::size_of::<String>() as u64),
                                    |bytes, id| bytes.saturating_add(id.capacity() as u64),
                                ),
                            );
                        }
                        ids
                    }),
                    "allowed_claim_ids": ({
                        let ids = world.allowed_claim_ids.iter().map(crate::EntityId::to_hex).collect::<Vec<_>>();
                        if let Some(memory) = world_memory.as_mut() {
                            memory.materialized(
                                0,
                                ids.iter().fold(
                                    (ids.capacity() as u64)
                                        .saturating_mul(std::mem::size_of::<String>() as u64),
                                    |bytes, id| bytes.saturating_add(id.capacity() as u64),
                                ),
                            );
                        }
                        ids
                    }),
                    "default_claim_id": world.default_claim_id.map(|id| {
                        let id = id.to_hex();
                        if let Some(memory) = world_memory.as_mut() {
                            memory.materialized(0, id.capacity() as u64);
                        }
                        id
                    }),
                })
            }),
            "rerank": builder.rerank.as_ref().map(|(reranker, options)| json!({
                "scorer": reranker.id(), "top_n": options.top_n,
                "query_override_present": options.query.is_some(),
            })),
            "hyde": builder.hyde.as_ref().map(|(expander, _, options)| json!({
                "expander": expander.id(), "channel_limit": options.channel_limit,
                "retry_once": options.retry_once,
            })),
            "retry_widen_limits": widen_channel_limits,
            "skip_ret01_abstain": skip_ret01_abstain,
            "deadline_present": builder.deadline.is_some(),
            "deadline_cut_short": builder.deadline.is_some_and(crate::retrieval_depth::RetrievalDeadline::was_cut_short),
            "candidate_filter_present": builder.candidate_filter.is_some(),
            "corpus_scope": corpus_scope,
            "world_scope": account_string(format!("{:?}", builder.world_scope)),
            "result_limit": builder.result_limit,
            "skill_executor": builder.skill_executor.as_deref(),
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
            "repo_ref": builder.repo_ref_filter.as_ref().map(|repo| account_string(repo.canonical())),
            "facet_filter": builder.facet_filter.map(|f| account_string(format!("{f:?}"))),
            "relationship_filter": builder.relationship_filter.map(|f| account_string(format!("{f:?}"))),
            "made_by": account_string(format!("{:?}", builder.made_by)),
            "recency_blend": builder.recency_blend_applies(),
            "salience": builder.apply_salience,
            "confidence": builder.apply_confidence,
            "gravity": builder.apply_gravity,
            "contiguity": builder.apply_contiguity,
            "skip_vector_rescore": builder.skip_vector_rescore,
            "access_factor_overrides": builder.access_factor_overrides.map(|map| {
                let mut entries: Vec<_> = map.iter().map(|(id, factor)| (id.to_hex(), factor)).collect();
                entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                if let Some(memory) = access_factor_memory.as_mut() {
                    memory.materialized(
                        0,
                        entries.iter().fold(
                            (entries.capacity() as u64)
                                .saturating_mul(std::mem::size_of::<(String, &f32)>() as u64),
                            |bytes, (id, _)| bytes.saturating_add(id.capacity() as u64),
                        ),
                    );
                }
                entries
            }),
        }),
        corpus_snapshot_ref: account_ref(builder.corpus_snapshot_ref.clone()),
    };
    // `json!` above is at its recursion limit, so these join after it.
    inputs.config["skill_reliability"] = json!(&builder.skill_reliability_query);
    inputs.config["turn_fold"] = json!(builder.turn_fold.as_str());
    inputs.config["affect_retrieval"] = affect_retrieval;
    inputs.config["claim_aging_profiles"] = json!(builder.claim_aging_profiles);
    {
        let media_memory = builder.media_search.memory();
        let mut media_trace_memory =
            media_memory.map(crate::host_memory::MachineMemory::empty_lease);
        let media_trace = builder
            .media_search
            .iter()
            .zip(&replay_identity.media_spaces)
            .map(|(query, identity)| {
                let mut kind_memory =
                    media_memory.map(crate::host_memory::MachineMemory::empty_lease);
                let kind_overrides = identity
                    .kind_overrides
                    .iter()
                    .map(|(kind, floors)| {
                        json!({"entity_type": kind, "floor": floors.floor, "strong": floors.strong})
                    })
                    .collect::<Vec<_>>();
                if let Some(memory) = kind_memory.as_mut() {
                    memory.materialized(
                        0,
                        (kind_overrides.capacity() as u64).saturating_mul(std::mem::size_of::<
                            serde_json::Value,
                        >(
                        )
                            as u64),
                    );
                }
                json!({
                    "space": query.space_id,
                    "query_kind": query.query_kind,
                    "kinds": query.kinds,
                    "limit": query.limit,
                    "floor": identity.floors.floor,
                    "strong": identity.floors.strong,
                    "kind_overrides": kind_overrides,
                    "dimensions": identity.space.dimensions,
                    "query_towers": &identity.space.query_towers,
                    "accepted_kinds": &identity.space.accepts,
                    "declared_evidence": identity.space.evidence,
                })
            })
            .collect::<Vec<_>>();
        if let Some(memory) = media_trace_memory.as_mut() {
            memory.materialized(
                0,
                (media_trace.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<serde_json::Value>() as u64),
            );
        }
        inputs.config["media_search"] = json!(media_trace);
    }
    inputs.config["model_revisions"] = json!({
        "text_embedding_space": builder.vault.config.embedding_model.as_deref(),
        "text_embedding_transform": builder.vault.config.embedding_transform.as_deref(),
        "analyzer_manifest_hash": replay_identity.analyzer_manifest_hash.as_deref().map(|hash| account_string(crate::entity_id::bytes_to_hex_lower(hash))),
        "bm25_field_schema_hash": replay_identity.bm25_field_schema_hash.as_deref().map(|hash| account_string(crate::entity_id::bytes_to_hex_lower(hash))),
    });
    inputs.config["context_pack_world_share"] = json!(builder.context_pack_world_share);
    inputs.config["fusion"] = json!({
        "list_length": crate::fusion::FUSION_LIST_LENGTH,
        "sparse": ["phonetic"],
    });
    let floors = builder.no_match_floors();
    let space = builder.vault.evidence_space();
    let mut kinds_memory = builder
        .media_search
        .memory()
        .map(crate::host_memory::MachineMemory::empty_lease);
    let kinds = floors.keyed.get(space).map(|kinds| {
        kinds
            .iter()
            .map(|(kind, kind_floors)| {
                json!({"entity_type": kind, "floor": kind_floors.floor, "strong": kind_floors.strong})
            })
            .collect::<Vec<_>>()
    });
    if let (Some(memory), Some(kinds)) = (kinds_memory.as_mut(), kinds.as_ref()) {
        memory.materialized(
            0,
            (kinds.capacity() as u64)
                .saturating_mul(std::mem::size_of::<serde_json::Value>() as u64),
        );
    }
    inputs.config["vector_evidence"] = json!({
        "floor": floors.pair.floor,
        "strong": floors.pair.strong,
        "space": space,
        "kinds": kinds.unwrap_or_default(),
    });
    if let Some(memory) = replay_inputs_memory.as_mut() {
        memory.track_config(&inputs);
    }
    inputs
}
