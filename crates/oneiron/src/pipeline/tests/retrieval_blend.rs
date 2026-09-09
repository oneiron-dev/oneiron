//! Vector/PPR channels, recency boost, prefix gates, and temporal hints.

use super::*;

#[test]
fn expand_ppr_uses_blended_results_as_seeds() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = entity_id(20);
    let b = entity_id(21);

    vault
        .batch()
        .put(&a, 1, TimeRange { start: 10, end: 10 }, 10, b"payload")
        .text(&a, &[("body", "alpha")])
        .put(&b, 1, TimeRange { start: 11, end: 11 }, 11, b"payload")
        .edge(&a, crate::edge::EdgeKind::Supports, &b, 1.0)
        .commit()?;

    let baseline = vault.query().search_text("alpha", 10).run()?;
    assert!(!baseline.iter().any(|entry| entry.id == b));

    let expanded = vault
        .query()
        .search_text("alpha", 10)
        .expand_ppr(&[], 3)
        .run()?;
    assert!(expanded.iter().any(|entry| entry.id == b));
    Ok(())
}

#[test]
fn expand_ppr_clamps_internal_seed_growth() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    for i in 0..=crate::ppr::MAX_PPR_SEEDS {
        let id = EntityId::from_bytes((i as u128 + 1).to_be_bytes())?;
        vault
            .batch()
            .put(
                &id,
                1,
                TimeRange {
                    start: 10 + i as u64,
                    end: 10 + i as u64,
                },
                10,
                b"payload",
            )
            .text(&id, &[("body", "alpha")])
            .commit()?;
    }

    let expanded = vault
        .query()
        .search_text("alpha", crate::ppr::MAX_PPR_SEEDS + 1)
        .expand_ppr(&[], 3)
        .run()?;

    assert!(!expanded.is_empty());
    Ok(())
}

#[test]
fn search_ppr_as_blend_candidate_signal() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = entity_id(22);
    let b = entity_id(23);

    vault
        .batch()
        .put(&a, 1, TimeRange { start: 10, end: 10 }, 10, b"payload")
        .put(&b, 1, TimeRange { start: 11, end: 11 }, 11, b"payload")
        .edge(&a, crate::edge::EdgeKind::Supports, &b, 1.0)
        .commit()?;

    let results = vault.query().search_ppr(&[a], 3).run()?;
    assert!(results.iter().any(|entry| entry.id == b));
    Ok(())
}

#[test]
fn search_ppr_rejects_excessive_seed_count_and_depth() {
    let (_dir, vault) = open_test_vault();
    let seeds = vec![entity_id(1); crate::ppr::MAX_PPR_SEEDS + 1];

    let too_many_seeds = vault.query().search_ppr(&seeds, 3).run();
    assert_matches!(too_many_seeds, Err(Error::InvalidConfig(_)));

    let too_deep = vault.query().search_ppr(&[entity_id(1)], 11).run();
    assert_matches!(too_deep, Err(Error::InvalidConfig(_)));
}

#[test]
fn recency_boost_orders_text_channel_before_truncation() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x10);
    let fresh = entity_id(0x20);
    let now = crate::unix_seconds_now();

    put_text_at(&vault, old, "limitrecencyneedle", 1)?;
    put_text_at(&vault, fresh, "limitrecencyneedle", now)?;

    let baseline = vault
        .query()
        .search_text("limitrecencyneedle", 1)
        .filter_types(&[1])
        .run()?;
    assert_eq!(baseline[0].id, old, "baseline tie breaks by entity id");

    let boosted = vault
        .query()
        .search_text("limitrecencyneedle", 1)
        .filter_types(&[1])
        .boost_recency(0.01)
        .run()?;
    assert_eq!(
        boosted[0].id, fresh,
        "fresh text hit must win before the BM25 channel is truncated"
    );
    Ok(())
}

#[test]
fn prefix_probe_claim_gate_does_not_export_pack_stats() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let probe_only_dead_claim = entity_id(0x10);
    let live_result = entity_id(0x20);

    put_status_claim(
        &vault,
        probe_only_dead_claim,
        "probeonlydead",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_text(&vault, live_result, "probeonlylive")?;

    let output = vault.query().search_text("probeonly", 10).run_for_pack()?;

    assert_eq!(output.scores.len(), 1);
    assert_eq!(output.scores[0].id, live_result);
    assert_eq!(output.claims_suppressed, 0);
    assert!(output.claim_bodies.is_empty());
    Ok(())
}

#[test]
fn dead_exact_claim_does_not_truncate_live_prefix_hit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let dead_exact = entity_id(0x12);
    let live_prefix = entity_id(0x22);

    put_status_claim(
        &vault,
        dead_exact,
        "claimgateprefix",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_claim_text(&vault, live_prefix, "claimgateprefixalpha", None)?;

    let results = vault.query().search_text("claimgateprefix", 1).run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, live_prefix);
    Ok(())
}

#[test]
fn dead_prefix_expanded_claim_does_not_truncate_live_prefix_hit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let dead_prefix = entity_id(0x12);
    let live_prefix = entity_id(0x22);

    put_status_claim(
        &vault,
        dead_prefix,
        "prefixgateexpanded prefixgateexpanded prefixgateexpanded",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_claim_text(&vault, live_prefix, "prefixgateexpanded", None)?;

    let results = vault.query().search_text("prefixgate", 1).run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, live_prefix);
    Ok(())
}

#[test]
fn live_exact_claim_preserves_search_text_limit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let live_exact = entity_id(0x12);
    let lower_ranked_exact_doc = entity_id(0x22);
    let live_prefix = entity_id(0x32);

    put_claim_text(&vault, live_exact, "livegateprefix", None)?;
    put_text(&vault, lower_ranked_exact_doc, "livegateprefix")?;
    put_claim_text(&vault, live_prefix, "livegateprefixalpha", None)?;

    let results = vault.query().search_text("livegateprefix", 1).run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, live_exact);
    Ok(())
}

#[test]
fn exact_out_of_scope_text_hit_does_not_suppress_in_scope_prefix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let out_of_scope_exact = entity_id(0x10);
    let in_scope_prefix = entity_id(0x20);

    vault
        .batch()
        .put(
            &out_of_scope_exact,
            2,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(&out_of_scope_exact, &[("body", "scopedprefix")])
        .put(
            &in_scope_prefix,
            1,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(&in_scope_prefix, &[("body", "scopedprefixalpha")])
        .commit()?;

    let results = vault
        .query()
        .search_text("scopedprefix", 1)
        .filter_types(&[1])
        .run()?;

    assert!(results.iter().any(|entry| entry.id == in_scope_prefix));
    assert!(!results.iter().any(|entry| entry.id == out_of_scope_exact));
    Ok(())
}

#[test]
fn prefix_scope_widening_preserves_exact_text_limit_after_type_filter() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let out_of_scope_exact = entity_id(0x10);
    let in_scope_preferred = entity_id(0x20);
    let in_scope_extra = entity_id(0x30);

    vault
        .batch()
        .put(
            &out_of_scope_exact,
            2,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(
            &out_of_scope_exact,
            &[(
                "body",
                "limitfilterneedle limitfilterneedle limitfilterneedle",
            )],
        )
        .put(
            &in_scope_preferred,
            1,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(
            &in_scope_preferred,
            &[("body", "limitfilterneedle limitfilterneedle")],
        )
        .put(
            &in_scope_extra,
            1,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(&in_scope_extra, &[("body", "limitfilterneedle")])
        .commit()?;

    let results = vault
        .query()
        .search_text("limitfilterneedle", 1)
        .filter_types(&[1])
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, in_scope_preferred);
    assert!(!results.iter().any(|entry| entry.id == out_of_scope_exact));
    Ok(())
}

#[test]
fn exact_old_text_hit_does_not_suppress_since_prefix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old_exact = entity_id(0x12);
    let recent_prefix = entity_id(0x22);

    vault
        .batch()
        .put(
            &old_exact,
            1,
            TimeRange { start: 1, end: 1 },
            100,
            b"payload",
        )
        .text(&old_exact, &[("body", "sinceprefix")])
        .put(
            &recent_prefix,
            1,
            TimeRange { start: 1, end: 1 },
            200,
            b"payload",
        )
        .text(&recent_prefix, &[("body", "sinceprefixalpha")])
        .commit()?;

    let results = vault
        .query()
        .search_text("sinceprefix", 1)
        .filter_since(200)
        .run()?;

    assert!(results.iter().any(|entry| entry.id == recent_prefix));
    assert!(!results.iter().any(|entry| entry.id == old_exact));
    Ok(())
}

#[test]
fn parsed_recent_query_bounds_text_retrieval() -> Result<()> {
    const NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x13);
    let recent = entity_id(0x23);

    put_text_with_time(
        &vault,
        old,
        "recent parsedbounds",
        TimeRange {
            start: NOW - 7 * 86_400 - 1,
            end: NOW - 7 * 86_400 - 1,
        },
        NOW - 7 * 86_400 - 1,
    )?;
    put_text_with_time(
        &vault,
        recent,
        "recent parsedbounds",
        TimeRange {
            start: NOW - 60,
            end: NOW - 60,
        },
        NOW - 60,
    )?;

    let results = vault
        .query()
        .search_text("recent parsedbounds", 10)
        .with_temporal_now(NOW)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, recent);
    Ok(())
}

#[test]
fn learned_range_does_not_override_parsed_recent_hint() -> Result<()> {
    const NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x63);
    let recent = entity_id(0x64);

    put_text_with_time(
        &vault,
        old,
        "recent learnedbounds",
        TimeRange {
            start: NOW - 7 * 86_400 - 1,
            end: NOW - 7 * 86_400 - 1,
        },
        200,
    )?;
    put_text_with_time(
        &vault,
        recent,
        "recent learnedbounds",
        TimeRange {
            start: NOW - 60,
            end: NOW - 60,
        },
        200,
    )?;

    let results = vault
        .query()
        .search_text("recent learnedbounds", 10)
        .filter_learned_range(190, 210)
        .with_temporal_now(NOW)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, recent);
    Ok(())
}

#[test]
fn explicit_time_range_overrides_parsed_recent_hint() -> Result<()> {
    const NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

    let (_dir, vault) = open_test_vault();
    let explicit_keep = entity_id(0x14);
    let parsed_recent_drop = entity_id(0x24);
    let vector = [1.0, 0.0, 0.0, 0.0];

    put_text_and_vector_with_time(
        &vault,
        explicit_keep,
        "recent overridebounds",
        vector,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
    )?;
    put_text_and_vector_with_time(
        &vault,
        parsed_recent_drop,
        "recent overridebounds",
        vector,
        TimeRange {
            start: NOW - 60,
            end: NOW - 60,
        },
        NOW - 60,
    )?;

    let results = vault
        .query()
        .search(
            "recent overridebounds",
            &vector,
            Some(TimeRange {
                start: 90,
                end: 110,
            }),
            10,
        )
        .with_temporal_now(NOW)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, explicit_keep);
    Ok(())
}

#[test]
fn explicit_time_range_overrides_unsupported_last_phrase() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let explicit_keep = entity_id(0x34);
    let vector = [1.0, 0.0, 0.0, 0.0];

    put_text_and_vector_with_time(
        &vault,
        explicit_keep,
        "last friday overridebounds",
        vector,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
    )?;

    let results = vault
        .query()
        .search(
            "last friday overridebounds",
            &vector,
            Some(TimeRange {
                start: 90,
                end: 110,
            }),
            10,
        )
        .with_temporal_now(1_710_504_000)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, explicit_keep);
    Ok(())
}

#[test]
fn unsupported_last_friday_query_fails_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x15);
    put_text(&vault, id, "last friday failclosed")?;

    let err = vault
        .query()
        .search_text("last friday failclosed", 10)
        .with_temporal_now(1_710_504_000)
        .run()
        .expect_err("unsupported temporal expression must fail closed");

    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::InvalidTemporalExpression
    );
    assert_matches!(
        err,
        Error::InvalidTemporalExpression(
            TemporalExpressionParseError::Unsupported { expression }
        ) if expression == "last friday"
    );
    Ok(())
}

#[test]
fn unsupported_last_two_weeks_query_fails_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x16);
    put_text(&vault, id, "last 2 weeks failclosed")?;

    let err = vault
        .query()
        .search_text("last 2 weeks failclosed", 10)
        .with_temporal_now(1_710_504_000)
        .run()
        .expect_err("unsupported temporal expression must fail closed");

    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::InvalidTemporalExpression
    );
    assert_matches!(
        err,
        Error::InvalidTemporalExpression(
            TemporalExpressionParseError::Unsupported { expression }
        ) if expression == "last 2 weeks"
    );
    Ok(())
}

#[test]
fn unsupported_last_spelled_quantity_query_fails_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x17);
    put_text(&vault, id, "last two weeks failclosed")?;

    let err = vault
        .query()
        .search_text("last two weeks failclosed", 10)
        .with_temporal_now(1_710_504_000)
        .run()
        .expect_err("unsupported temporal expression must fail closed");

    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::InvalidTemporalExpression
    );
    assert_matches!(
        err,
        Error::InvalidTemporalExpression(
            TemporalExpressionParseError::Unsupported { expression }
        ) if expression == "last two weeks"
    );
    Ok(())
}

#[test]
fn unsupported_last_subday_quantity_query_fails_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    for (offset, query, expected) in [
        (0, "last 24 hours failclosed", "last 24 hours"),
        (
            1,
            "last twenty four hours failclosed",
            "last twenty four hours",
        ),
    ] {
        put_text(&vault, entity_id(0x18 + offset), query)?;

        let err = vault
            .query()
            .search_text(query, 10)
            .with_temporal_now(1_710_504_000)
            .run()
            .expect_err("unsupported temporal expression must fail closed");

        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::InvalidTemporalExpression
        );
        assert_matches!(
            err,
            Error::InvalidTemporalExpression(
                TemporalExpressionParseError::Unsupported { expression }
            ) if expression == expected
        );
    }
    Ok(())
}

#[test]
fn exact_other_facet_text_hit_does_not_suppress_strict_facet_prefix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let facet_active = entity_id(0x91);
    let facet_other = entity_id(0xB1);
    let other_facet_exact = entity_id(0x10);
    let active_facet_prefix = entity_id(0x20);

    vault
        .batch()
        .put(
            &facet_active,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .put(
            &facet_other,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .commit()?;
    put_claim_text(&vault, other_facet_exact, "facetprefix", None)?;
    put_claim_text(&vault, active_facet_prefix, "facetprefixalpha", None)?;
    vault
        .batch()
        .edge(&other_facet_exact, EdgeKind::FacetOf, &facet_other, 0.7)
        .edge(&active_facet_prefix, EdgeKind::FacetOf, &facet_active, 0.7)
        .commit()?;

    let results = vault
        .query()
        .search_text("facetprefix", 1)
        .facet(&facet_active, FacetMode::Strict)
        .run()?;

    assert!(results.iter().any(|entry| entry.id == active_facet_prefix));
    assert!(!results.iter().any(|entry| entry.id == other_facet_exact));
    Ok(())
}

#[test]
fn exact_other_world_text_hit_does_not_suppress_world_prefix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let world_active = entity_id(0x92);
    let world_other = entity_id(0xB2);
    let other_world_exact = entity_id(0x60);
    let active_world_prefix = entity_id(0x21);

    put_claim_text(&vault, other_world_exact, "worldprefix", Some(world_other))?;
    put_claim_text(
        &vault,
        active_world_prefix,
        "worldprefixalpha",
        Some(world_active),
    )?;

    let results = vault
        .query()
        .search_text("worldprefix", 1)
        .world(WorldScope::World(world_active))
        .run()?;

    assert!(results.iter().any(|entry| entry.id == active_world_prefix));
    assert!(!results.iter().any(|entry| entry.id == other_world_exact));
    Ok(())
}

#[test]
fn prefix_probe_claim_gate_runs_before_world_scope_decode() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let world_active = entity_id(0x93);
    let malformed_probe_only = entity_id(0x13);
    let active_world_prefix = entity_id(0x23);

    put_status_claim(
        &vault,
        malformed_probe_only,
        "worldgateprefixdead",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
        false,
    )?;
    let mut junk = Vec::new();
    rmpv::encode::write_value(&mut junk, &rmpv::Value::from("junk")).expect("msgpack encode");
    overwrite_entity_record(&vault, &malformed_probe_only, ENTITY_TYPE_CLAIM, &junk)?;
    put_claim_text(
        &vault,
        active_world_prefix,
        "worldgateprefixlive",
        Some(world_active),
    )?;

    let output = vault
        .query()
        .search_text("worldgateprefix", 10)
        .world(WorldScope::World(world_active))
        .run_for_pack()?;

    assert_eq!(output.scores.len(), 1);
    assert_eq!(output.scores[0].id, active_world_prefix);
    assert_eq!(output.claims_suppressed, 0);
    assert!(output.claim_bodies.contains_key(&active_world_prefix));
    Ok(())
}

#[test]
fn recency_boost_applies_to_vector_only_pipeline() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x10);
    let fresh = entity_id(0x20);
    let now = crate::unix_seconds_now();

    put_vector_at(&vault, old, [1.0, 0.0, 0.0, 0.0], 1)?;
    put_vector_at(&vault, fresh, [0.99, 0.01, 0.0, 0.0], now)?;

    let baseline = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 2)
        .run()?;
    assert_eq!(baseline[0].id, old);

    let boosted = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 2)
        .boost_recency(0.01)
        .run()?;
    assert_eq!(boosted[0].id, fresh);
    Ok(())
}

#[test]
fn recency_boost_applies_to_mixed_text_and_vector_pipeline() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old_text_only = entity_id(0x10);
    let fresh_vector_only = entity_id(0x20);
    let now = crate::unix_seconds_now();

    put_text_at(&vault, old_text_only, "mixedrecencyneedle", 1)?;
    put_vector_at(&vault, fresh_vector_only, [1.0, 0.0, 0.0, 0.0], now)?;

    let baseline = vault
        .query()
        .search_text("mixedrecencyneedle", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()?;
    assert_eq!(baseline[0].id, old_text_only);

    let boosted = vault
        .query()
        .search_text("mixedrecencyneedle", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .boost_recency(0.01)
        .run()?;
    assert_eq!(boosted[0].id, fresh_vector_only);
    Ok(())
}

#[test]
fn recency_boost_orders_non_text_scores_before_ppr_expansion_fusion() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let old = entity_id(0x12);
    let fresh = entity_id(0x22);
    let now = crate::unix_seconds_now();

    put_vector_at(&vault, old, [1.0, 0.0, 0.0, 0.0], 1)?;
    put_vector_at(&vault, fresh, [0.99, 0.01, 0.0, 0.0], now)?;

    let boosted = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 2)
        .boost_recency(0.01)
        .expand_ppr(&[], 2)
        .limit(1)
        .run()?;

    assert_eq!(boosted[0].id, fresh);
    Ok(())
}

#[test]
fn recency_boost_auto_skips_when_temporal_search_present() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000;
    let a = entity_id(30);
    let b = entity_id(31);

    put_entity(&vault, a, 1, anchor, anchor, anchor)?;
    put_entity(&vault, b, 1, anchor + 3_600, anchor + 3_600, anchor + 3_600)?;

    let without_boost = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Auto, 10)
        .run()?;
    let with_boost = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Auto, 10)
        .boost_recency(7.0)
        .run()?;

    assert_eq!(without_boost.len(), with_boost.len());
    for (left, right) in without_boost.iter().zip(with_boost.iter()) {
        assert_eq!(left.id, right.id);
        assert!(approx_eq(left.score, right.score, 1e-6));
    }

    Ok(())
}
