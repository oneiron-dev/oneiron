//! The fork-hash evidence the retrieval transaction captures, and the
//! dispatcher that hashes it without rescanning claims.

use super::*;

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
) -> crate::error::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    fork_hash_bytes(&mut hasher, b"oneiron.retrieval_trace.fork_hash.v1");

    fork_hash_vector_query(
        &mut hasher,
        builder.vector_search.as_ref(),
        builder.skip_vector_rescore,
    );
    fork_hash_text_query(&mut hasher, builder.text_search.as_ref());
    fork_hash_phonetic_query(&mut hasher, builder.phonetic_search.as_deref());
    fork_hash_phonetic_vector_query(&mut hasher, builder.phonetic_vector_search.as_ref());
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
    fork_hash_scoring_constants(&mut hasher, &builder.params, builder.vault.config.fast_dims)?;
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
    // retrieval.vector_evidence: the owner's floors for the run's space judge
    // every kind there. Hashed only when set, so a run with no owner row
    // keeps the fork key it had.
    if let Some(owner) = floors.owner.get(space) {
        fork_hash_str(&mut hasher, "owner-vector-evidence");
        fork_hash_f32(&mut hasher, owner.floor);
        fork_hash_f32(&mut hasher, owner.strong);
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

    Ok(hasher.finalize().into())
}
