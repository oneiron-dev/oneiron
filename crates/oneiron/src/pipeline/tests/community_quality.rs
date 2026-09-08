//! PPR VAD threading, community diversification, and retrieval-quality grading.

use super::*;

fn ppr_vad_pipeline_trace(vault: &Vault, expand: bool) -> Result<RetrievalTrace> {
    let builder = if expand {
        // Expansion requires a real nonempty base retrieval channel.
        vault
            .query()
            .search_text("vadseed", 1)
            .expand_ppr(&[entity_id(1)], 1)
    } else {
        vault.query().search_ppr(&[entity_id(1)], 1)
    };
    captured_retrieval_trace(vault, builder.limit(10))
}

fn ppr_vad_trace_bits(trace: &RetrievalTrace) -> Vec<([u8; 16], u32)> {
    trace
        .per_channel
        .iter()
        .find(|channel| channel.signal == RetrievalSignal::Ppr)
        .expect("PPR channel must execute")
        .candidates
        .iter()
        .map(|row| (row.result_id, row.final_score.to_bits()))
        .collect()
}

#[test]
fn ppr_vad_pipeline_search_and_real_expansion_thread_alpha_and_fork() -> Result<()> {
    let (_dir, mut vault) = open_test_vault();
    put_text(&vault, entity_id(1), "vadseed")?;
    put_text(&vault, entity_id(2), "neutral")?;
    put_text(&vault, entity_id(3), "salient")?;
    vault.put_edge(&entity_id(1), EdgeKind::Mentions, &entity_id(2), 0.5)?;
    vault.put_edge(&entity_id(1), EdgeKind::Mentions, &entity_id(3), 0.5)?;
    vault.set_edge_vad(
        &entity_id(1),
        EdgeKind::Mentions,
        &entity_id(3),
        crate::Vad {
            valence: -1.0,
            arousal: 0.9,
            dominance: 0.0,
        },
    )?;
    for expand in [false, true] {
        vault.config.ppr_vad_alpha = 0.0;
        let zero = ppr_vad_pipeline_trace(&vault, expand)?;
        let cached_zero = ppr_vad_pipeline_trace(&vault, expand)?;
        assert_eq!(ppr_vad_trace_bits(&zero), ppr_vad_trace_bits(&cached_zero));
        if expand {
            assert!(zero.per_channel.iter().any(|channel| {
                channel.signal == RetrievalSignal::Text && !channel.candidates.is_empty()
            }));
        }
        // Pre-change normalized same-kind formula, independent of the new helper.
        let baseline = 1.0_f32 * (0.6 * 0.5 / 1.0) * (1.0 - PPR_DAMPING);
        for id in [entity_id(2), entity_id(3)] {
            assert!(ppr_vad_trace_bits(&zero).contains(&(*id.as_bytes(), baseline.to_bits())));
        }
        vault.config.ppr_vad_alpha = -0.0;
        let negative_zero = ppr_vad_pipeline_trace(&vault, expand)?;
        assert_eq!(
            ppr_vad_trace_bits(&zero),
            ppr_vad_trace_bits(&negative_zero)
        );
        assert_eq!(zero.fork_hash, negative_zero.fork_hash);
        vault.config.ppr_vad_alpha = 0.4;
        let weighted = ppr_vad_pipeline_trace(&vault, expand)?;
        let expected = 1.0_f32 * (0.6 * 0.5 / 1.0) * 1.4 * (1.0 - PPR_DAMPING);
        assert!(
            ppr_vad_trace_bits(&weighted).contains(&(*entity_id(3).as_bytes(), expected.to_bits()))
        );
        assert_ne!(zero.fork_hash, weighted.fork_hash);
        vault.config.ppr_vad_alpha = 0.0;
        let restored = ppr_vad_pipeline_trace(&vault, expand)?;
        assert_eq!(ppr_vad_trace_bits(&zero), ppr_vad_trace_bits(&restored));
        assert_eq!(zero.fork_hash, restored.fork_hash);
    }
    Ok(())
}

#[test]
fn ppr_vad_pipeline_invalid_alpha_is_typed_on_both_paths() -> Result<()> {
    let (_dir, mut vault) = open_test_vault();
    put_text(&vault, entity_id(1), "vadseed")?;
    for alpha in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1, 0.41] {
        vault.config.ppr_vad_alpha = alpha;
        for expand in [false, true] {
            assert!(matches!(
                ppr_vad_pipeline_trace(&vault, expand),
                Err(Error::InvalidConfig(_))
            ));
        }
        assert!(matches!(
            vault.query().expand_ppr(&[], 1).run(),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            vault.query().search_ppr(&[], 1).run(),
            Err(Error::InvalidConfig(_))
        ));
        // Unrelated retrieval channels do not consume this knob.
        assert!(!vault.query().search_text("vadseed", 1).run()?.is_empty());
    }
    Ok(())
}

#[test]
fn ppr_community_pipeline_zero_and_specificity_preserve_vad_and_cache_identity() -> Result<()> {
    let (_dir, mut vault) = open_test_vault();
    put_text(&vault, entity_id(1), "vadseed")?;
    put_text(&vault, entity_id(2), "neighbor")?;
    vault.put_edge(&entity_id(1), EdgeKind::Mentions, &entity_id(2), 1.0)?;
    vault.set_edge_vad(
        &entity_id(1),
        EdgeKind::Mentions,
        &entity_id(2),
        crate::Vad {
            valence: -1.0,
            arousal: 1.0,
            dominance: 0.0,
        },
    )?;
    vault.config.ppr_vad_alpha = 0.4;
    for expand in [false, true] {
        vault.config.ppr_community = crate::PprCommunityConfig::default();
        let baseline = ppr_vad_pipeline_trace(&vault, expand)?;
        let before = {
            let txn = vault.store.env.read_txn()?;
            vault
                .store
                .ppr_cache
                .iter(&txn)?
                .map(|entry| entry.map(|(key, value)| (key.to_vec(), value.to_vec())))
                .collect::<Result<Vec<_>>>()?
        };
        vault.config.ppr_community.gamma = f32::NAN;
        vault.config.ppr_community.beta = if expand { -0.0 } else { 0.2 };
        {
            let mut txn = vault.store.env.write_txn()?;
            vault
                .store
                .vault_meta
                .put(&mut txn, b"ppr_community_cache:v0:meta", b"corrupt")?;
            txn.commit()?;
        }
        let actual = ppr_vad_pipeline_trace(&vault, expand)?;
        assert_eq!(ppr_vad_trace_bits(&actual), ppr_vad_trace_bits(&baseline));
        assert_eq!(
            actual
                .final_stage
                .candidates
                .iter()
                .map(|row| (row.result_id, row.final_score.to_bits()))
                .collect::<Vec<_>>(),
            baseline
                .final_stage
                .candidates
                .iter()
                .map(|row| (row.result_id, row.final_score.to_bits()))
                .collect::<Vec<_>>()
        );
        assert_eq!(actual.fork_hash, baseline.fork_hash);
        let txn = vault.store.env.read_txn()?;
        let after = vault
            .store
            .ppr_cache
            .iter(&txn)?
            .map(|entry| entry.map(|(key, value)| (key.to_vec(), value.to_vec())))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(before, after);
    }
    Ok(())
}

#[test]
fn community_pipeline_uses_fused_evidence_not_sorted_ids_and_borrows_session_usage() -> Result<()> {
    // Preserve fixture order while skipping production-pinned ID bytes.
    let entity_id = |n: u8| {
        let seed = (1..=u8::MAX)
            .filter(|seed| !crate::test_util::PINNED_ID_BYTES.contains(seed))
            .nth(usize::from(n - 1))
            .expect("enough unpinned fixture IDs");
        crate::test_util::entity(seed)
    };
    let (_dir, mut vault) = open_test_vault();
    for n in 1..=100 {
        if n != 1 && n != 30 {
            put_entity(&vault, entity_id(n), 1, 1, 1, 1)?;
        }
    }
    for (n, salience) in [(1, 0.01), (30, 1.0)] {
        vault
            .batch()
            .put(
                &entity_id(n),
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &active_claim_body_with_salience(salience),
            )
            .text(&entity_id(n), &[("body", "communityevidence")])
            .commit()?;
    }
    for (seed, neighbor) in [(1, 2), (30, 31)] {
        for kind in [EdgeKind::BelongsTo, EdgeKind::Mentions] {
            vault.put_edge(&entity_id(seed), kind, &entity_id(neighbor), 1.0)?;
        }
    }
    let seeds = [entity_id(1), entity_id(30)];
    let preliminary = vault
        .query()
        .search_text("communityevidence", 2)
        .boost_salience()
        .with_temporal_now(1)
        .limit(2)
        .run()?;
    assert_eq!(preliminary[0].id, entity_id(30));
    assert!(preliminary[0].score >= 1.5 * preliminary[1].score);
    let trace_for = |vault: &Vault, usage: &HashMap<crate::ppr_community::CommunityId, u32>| {
        captured_retrieval_trace(
            vault,
            vault
                .query()
                .search_text("communityevidence", 2)
                .expand_ppr(&seeds, 1)
                .boost_salience()
                .with_temporal_now(1)
                .with_community_session_usage(usage)
                .limit(10),
        )
    };
    let empty_usage = HashMap::new();
    let baseline = trace_for(&vault, &empty_usage)?;
    vault.config.ppr_community.beta = 0.2;
    let boosted = trace_for(&vault, &empty_usage)?;
    vault.config.ppr_vad_alpha = -0.0;
    let signed_zero = trace_for(&vault, &empty_usage)?;
    assert_eq!(
        ppr_vad_trace_bits(&signed_zero),
        ppr_vad_trace_bits(&boosted)
    );
    assert_eq!(signed_zero.fork_hash, boosted.fork_hash);
    vault.config.ppr_vad_alpha = 0.0;
    let channel_score = |trace: &RetrievalTrace, id: EntityId| {
        ppr_vad_trace_bits(trace)
            .into_iter()
            .find(|(candidate, _)| candidate == id.as_bytes())
            .map(|(_, bits)| f32::from_bits(bits))
            .expect("PPR candidate")
    };
    assert!(channel_score(&boosted, entity_id(31)) > channel_score(&baseline, entity_id(31)));
    assert_eq!(
        channel_score(&boosted, entity_id(2)).to_bits(),
        channel_score(&baseline, entity_id(2)).to_bits()
    );
    assert_ne!(baseline.fork_hash, boosted.fork_hash);
    let fine = vault
        .ppr_community_membership(&entity_id(30))?
        .expect("membership")
        .fine;
    let usage = HashMap::from([(fine, u32::MAX)]);
    let decayed = trace_for(&vault, &usage)?;
    assert_eq!(ppr_vad_trace_bits(&decayed), ppr_vad_trace_bits(&baseline));
    assert_ne!(decayed.fork_hash, boosted.fork_hash);
    assert_eq!(
        usage[&fine],
        u32::MAX,
        "the pipeline never mutates session usage"
    );
    let replay = trace_for(&vault, &empty_usage)?;
    assert_eq!(ppr_vad_trace_bits(&replay), ppr_vad_trace_bits(&boosted));
    assert_eq!(replay.fork_hash, boosted.fork_hash);
    vault.config.ppr_community.beta = 0.0;
    let restored = trace_for(&vault, &usage)?;
    assert_eq!(ppr_vad_trace_bits(&restored), ppr_vad_trace_bits(&baseline));
    assert_eq!(restored.fork_hash, baseline.fork_hash);
    Ok(())
}

#[test]
fn community_pipeline_diversifies_after_fusion_filters_and_rerank_without_resurfacing_rows()
-> Result<()> {
    // Preserve fixture order while skipping production-pinned ID bytes.
    let entity_id = |n: u8| {
        let seed = (1..=u8::MAX)
            .filter(|seed| !crate::test_util::PINNED_ID_BYTES.contains(seed))
            .nth(usize::from(n - 1))
            .expect("enough unpinned fixture IDs");
        crate::test_util::entity(seed)
    };
    let (_dir, mut vault) = open_test_vault();
    for n in 1..=100 {
        put_entity(
            &vault,
            entity_id(n),
            1,
            1,
            1,
            if (11..=13).contains(&n) { 1 } else { 2 },
        )?;
    }
    put_text_at(&vault, entity_id(1), "communityseed", 2)?;
    for a in 1..=10 {
        for b in a + 1..=10 {
            for kind in [EdgeKind::BelongsTo, EdgeKind::Mentions] {
                vault.put_edge(&entity_id(a), kind, &entity_id(b), 1.0)?;
            }
        }
    }
    for n in 11..=18 {
        vault.put_edge(&entity_id(1), EdgeKind::PartOf, &entity_id(n), 1.0)?;
    }
    let dead = entity_id(110);
    put_status_claim(
        &vault,
        dead,
        "deadcommunity",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Retracted,
        false,
    )?;
    vault.put_edge(&entity_id(1), EdgeKind::Mentions, &dead, 1.0)?;
    let ghost = entity_id(111);
    vault.put_edge(&entity_id(1), EdgeKind::Mentions, &ghost, 1.0)?;
    let baseline = vault
        .query()
        .search_text("communityseed", 1)
        .expand_ppr(&[], 1)
        .filter_since(2)
        .with_temporal_now(2)
        .limit(10)
        .run()?;
    assert_eq!(baseline.len(), 10);
    assert!(baseline.iter().all(|row| row.id <= entity_id(10)));
    vault.config.ppr_community.beta = 0.2;
    let reranker = ReversingReranker;
    for rerank in [false, true] {
        let builder = vault
            .query()
            .search_text("communityseed", 1)
            .expand_ppr(&[], 1)
            .filter_since(2)
            .with_temporal_now(2)
            .limit(10);
        let builder = if rerank {
            builder.rerank(
                &reranker,
                RerankOptions {
                    top_n: 100,
                    query: None,
                },
            )
        } else {
            builder
        };
        let rows = builder.run()?;
        assert_eq!(
            rows.len(),
            10,
            "filtered early alternatives must not consume PPR slots"
        );
        let fine = vault
            .ppr_community_membership(&entity_id(1))?
            .expect("seed membership")
            .fine;
        let mut same_fine = 0;
        for row in &rows {
            assert!(row.id <= entity_id(10) || (entity_id(14)..=entity_id(18)).contains(&row.id));
            assert_ne!(row.id, dead);
            assert_ne!(row.id, ghost);
            same_fine += usize::from(
                vault
                    .ppr_community_membership(&row.id)?
                    .is_some_and(|membership| membership.fine == fine),
            );
        }
        assert!(same_fine <= 7);
        assert!(
            rows.iter().any(|row| row.id >= entity_id(14)),
            "retain an unboosted alternative"
        );
        assert!(
            rows.iter()
                .all(|row| row.score.to_bits() == 1.0_f32.to_bits()),
            "diversity must not reapply the prior to fused scores"
        );
    }
    assert!(
        vault
            .query()
            .search_text("communityseed", 1)
            .expand_ppr(&[entity_id(1)], 1)
            .with_temporal_now(2)
            .limit(0)
            .run()?
            .is_empty()
    );
    Ok(())
}

#[test]
fn community_pipeline_rejects_invalid_nonzero_config_even_without_base_channels() {
    let (_dir, mut vault) = open_test_vault();
    for beta in [f32::NAN, f32::INFINITY, -0.1] {
        vault.config.ppr_community.beta = beta;
        assert!(matches!(
            vault.query().expand_ppr(&[], 1).run(),
            Err(Error::InvalidConfig(_))
        ));
        assert!(
            vault.query().search_ppr(&[], 1).run().is_ok(),
            "Specificity ignores community config"
        );
    }
}

#[test]
fn retrieval_quality_counts_completed_empty_channels_without_trace() -> Result<()> {
    use crate::retrieval_quality::{ConfidenceAdjustment, RetrievalQuality};

    let (_dir, vault) = open_test_vault();
    let minimal = vault
        .query()
        .search_text("absent", 10)
        .run_with_telemetry()?;
    assert!(minimal.value.is_empty());
    assert_eq!(
        minimal.retrieval_quality.quality,
        RetrievalQuality::Passthrough
    );
    assert!(minimal.retrieval_quality.degradation.is_empty());
    assert_eq!(
        minimal.retrieval_quality.confidence_adjustment,
        ConfidenceAdjustment::PASSTHROUGH,
    );
    let combined = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .search_text("absent", 10)
        .run_with_telemetry()?;
    assert!(combined.value.is_empty());
    assert_eq!(
        combined.retrieval_quality.quality,
        RetrievalQuality::Degraded
    );
    assert!(combined.retrieval_quality.degradation.is_empty());
    let row = vault
        .retrieval_run(combined.run_id.expect("run id"))?
        .expect("run row");
    assert!(
        row.trace.is_none(),
        "quality does not require trace capture"
    );
    assert!(row.score_breakdown.is_empty());
    assert_eq!(row.quality, Some(RetrievalQuality::Degraded));
    assert_eq!(
        row.confidence_adjustment,
        Some(ConfidenceAdjustment::DEGRADED)
    );
    Ok(())
}

#[test]
fn retrieval_quality_time_filters_and_blend_are_not_completed_temporal_search() -> Result<()> {
    use crate::retrieval_quality::RetrievalQuality;

    let (_dir, vault) = open_test_vault();
    let output = vault
        .query()
        .search_text("absent", 10)
        .filter_occurred_range(1, 10)
        .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
        .boost_salience()
        .boost_confidence()
        .run_for_pack()?;
    assert!(output.signals.contains(&RetrievalSignal::Temporal));
    assert_eq!(
        output.retrieval_quality.quality,
        RetrievalQuality::Passthrough
    );
    assert!(output.retrieval_quality.degradation.is_empty());
    Ok(())
}

#[test]
fn retrieval_quality_full_requires_real_cache_hit_and_does_not_rewrite_ranking() -> Result<()> {
    use crate::retrieval_quality::{ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality};

    let (_dir, vault) = open_test_vault();
    let seed = entity_id(0x71);
    let target = entity_id(0x72);
    put_text_and_vector(&vault, seed, "quality needle", [1.0, 0.0, 0.0, 0.0])?;
    put_text_and_vector(&vault, target, "quality needle", [0.9, 0.1, 0.0, 0.0])?;
    vault.put_edge(&seed, EdgeKind::Supports, &target, 1.0)?;
    let build = || {
        vault
            .query()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .search_text("quality needle", 10)
            // Successful zero-candidate channels still count toward full.
            .search_phonetic(&["NO_MATCH_CODE"])
            .search_temporal(4_000_000_000, 4_000_000_001, 10)
            .search_ppr(&[seed], 1)
            .with_temporal_now(4_000_000_001)
    };
    let cold = build().run_with_telemetry()?;
    let warm = build().run_with_telemetry()?;
    assert!(!cold.value.is_empty());
    assert_eq!(cold.retrieval_quality.quality, RetrievalQuality::Degraded);
    assert_eq!(
        cold.retrieval_quality.degradation,
        vec![RetrievalDegradation::PprCacheMiss]
    );
    assert_eq!(warm.retrieval_quality.quality, RetrievalQuality::Full);
    assert!(warm.retrieval_quality.degradation.is_empty());
    assert_eq!(
        warm.retrieval_quality.confidence_adjustment,
        ConfidenceAdjustment::FULL
    );
    let bits = |scores: &[ScoredEntity]| {
        scores
            .iter()
            .map(|score| (score.id, score.score.to_bits()))
            .collect::<Vec<_>>()
    };
    assert_eq!(bits(&cold.value), bits(&warm.value));
    assert_eq!(bits(&warm.value), bits(&build().run()?));
    let pending = build().run_with_pending_vectors()?;
    assert_eq!(pending.retrieval_quality, warm.retrieval_quality);
    assert_eq!(bits(&pending.value), bits(&warm.value));
    let page = build().run_dreamer_working_set(
        DreamerWorkingSetCursor::start(),
        DreamerWorkingSetBudget::new(10),
        10,
    )?;
    assert_eq!(page.retrieval_quality, warm.retrieval_quality);
    assert_eq!(bits(&page.rows), bits(&warm.value));
    let filtered = build().filter_types(&[0xFE]).run_for_pack()?;
    assert!(filtered.scores.is_empty());
    assert_eq!(filtered.retrieval_quality.quality, RetrievalQuality::Full);
    assert_eq!(
        filtered.empty_reason,
        Some(crate::context_pack::EmptyReason::FilterMatchedNone)
    );
    let cold_row = vault
        .retrieval_run(cold.run_id.expect("cold id"))?
        .expect("cold row");
    assert_eq!(cold_row.quality, Some(RetrievalQuality::Degraded));
    assert_eq!(cold_row.degradation, cold.retrieval_quality.degradation);
    assert_eq!(
        cold_row.confidence_adjustment,
        Some(ConfidenceAdjustment::DEGRADED)
    );
    let degraded_empty = build()
        .search_ppr(&[seed], 2)
        .filter_types(&[0xFE])
        .run_for_pack()?;
    assert!(degraded_empty.scores.is_empty());
    assert_eq!(
        degraded_empty.retrieval_quality.quality,
        RetrievalQuality::Degraded
    );
    assert_eq!(
        degraded_empty.retrieval_quality.degradation,
        vec![RetrievalDegradation::PprCacheMiss]
    );
    assert_eq!(
        degraded_empty.empty_reason,
        Some(crate::context_pack::EmptyReason::FilterMatchedNone)
    );
    Ok(())
}

#[test]
fn retrieval_quality_no_channel_fast_path_and_unseeded_expansion_stay_passthrough() -> Result<()> {
    use crate::retrieval_quality::RetrievalQuality;

    let (_dir, vault) = open_test_vault();
    let no_channels = vault.query().run_with_telemetry()?;
    assert!(no_channels.value.is_empty());
    assert!(no_channels.run_id.is_none());
    assert_eq!(
        no_channels.retrieval_quality.quality,
        RetrievalQuality::Passthrough
    );
    let unseeded = vault
        .query()
        .search_text("absent", 10)
        .expand_ppr(&[], 1)
        .run_with_telemetry()?;
    assert!(unseeded.value.is_empty());
    assert_eq!(
        unseeded.retrieval_quality.quality,
        RetrievalQuality::Passthrough
    );
    // No cache lookup occurred, so do not invent a cache-miss marker.
    assert!(unseeded.retrieval_quality.degradation.is_empty());
    Ok(())
}

#[test]
fn retrieval_quality_hyde_retry_retains_first_ppr_cache_miss() -> Result<()> {
    use crate::retrieval_quality::{RetrievalDegradation, RetrievalQuality};

    let (_dir, vault) = open_test_vault();
    let seed = entity_id(0x73);
    put_text_and_vector(&vault, seed, "quality retry", [1.0, 0.0, 0.0, 0.0])?;
    let host = StubHyde {
        embedding: vec![1.0, 0.0, 0.0, 0.0],
        subqueries: vec!["quality retry".to_owned()],
        insufficient: true,
        assess_calls: std::sync::atomic::AtomicUsize::new(0),
    };
    let output = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .search_text("quality retry", 10)
        .search_phonetic(&[])
        .search_temporal(1, 2, 10)
        .search_ppr(&[seed], 1)
        .hyde(
            &host,
            GroundingContext::default(),
            HydeOptions {
                channel_limit: 10,
                retry_once: true,
            },
        )
        .run_with_telemetry()?;
    assert!(
        output.value.is_empty(),
        "existing HyDE abstention remains intact"
    );
    assert_eq!(
        host.assess_calls.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(output.retrieval_quality.quality, RetrievalQuality::Degraded);
    assert_eq!(
        output.retrieval_quality.degradation,
        vec![RetrievalDegradation::PprCacheMiss]
    );
    let row = vault
        .retrieval_run(output.run_id.expect("id"))?
        .expect("row");
    assert_eq!(row.degradation, output.retrieval_quality.degradation);
    Ok(())
}
