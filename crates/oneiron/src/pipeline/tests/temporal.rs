//! Temporal index scans, sigma scoring, widening, and contiguity pins.

use super::*;

#[test]
fn three_index_scan_discovers_end_only_candidate() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000;
    let candidate = entity_id(40);

    put_entity(&vault, candidate, 1, 1_000_000, 1_500_000, 10_000_000)?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
        .run()?;

    assert!(results.iter().any(|entry| entry.id == candidate));
    Ok(())
}

#[test]
fn long_interval_spanner_is_discovered_via_range_query() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000_u64;
    let candidate = entity_id(41);
    let span = 30_u64 * 86_400;

    put_entity(
        &vault,
        candidate,
        1,
        anchor.saturating_sub(span),
        anchor.saturating_add(span),
        anchor,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
        .run()?;

    assert!(results.iter().any(|entry| entry.id == candidate));
    Ok(())
}

#[test]
fn long_interval_scan_counts_only_spanners_toward_cap() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000_u64;
    let window = 86_400_u64;
    let long_span = LONG_INTERVAL_THRESHOLD_SECS + window;

    for i in 0..PER_SCAN_CAP_FACTOR {
        let id = entity_id(120 + i as u8);
        put_entity(
            &vault,
            id,
            1,
            anchor + i as u64,
            anchor + long_span + i as u64,
            anchor,
        )?;
    }

    let spanner = entity_id(140);
    put_entity(
        &vault,
        spanner,
        1,
        anchor.saturating_sub(long_span),
        anchor + long_span + PER_SCAN_CAP_FACTOR as u64,
        anchor,
    )?;

    let rtxn = vault.store.env.read_txn()?;
    let config = TemporalSearchConfig {
        anchor_start: anchor,
        anchor_end: anchor,
        learned_start: None,
        learned_end: None,
        sigma_secs: window,
        anchor_mode: TemporalAnchorMode::Occurred,
        adaptive: true,
        limit: 1,
    };
    let mut metadata_cache = EntityMetadataCache::default();
    let scoring = TemporalScoringContext {
        sigma: window,
        now: crate::unix_seconds_now(),
        anchor_mid: anchor,
        learned_anchor: (anchor, anchor),
        learned_anchor_mid: anchor,
    };
    let mut candidates = HashSet::new();
    collect_temporal_candidates(
        &vault.store,
        &rtxn,
        &config,
        TemporalCandidateCollectionContext {
            radius: window,
            per_scan_cap: PER_SCAN_CAP_FACTOR,
        },
        &mut metadata_cache,
        &scoring,
        &mut candidates,
    )?;

    assert!(candidates.contains(&spanner));
    Ok(())
}

#[test]
fn long_interval_scan_keeps_best_spanners_beyond_end_order_cap() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = crate::unix_seconds_now();
    let span = LONG_INTERVAL_THRESHOLD_SECS + 86_400;
    let best = entity_id(214);

    for i in 0..5_u8 {
        let id = entity_id(210 + i);
        let learned_at = if id == best {
            anchor
        } else {
            anchor.saturating_sub((30 + u64::from(i)) * 86_400)
        };
        put_entity(
            &vault,
            id,
            1,
            anchor.saturating_sub(span + 10),
            anchor.saturating_add(span + u64::from(i)),
            learned_at,
        )?;
    }

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .run()?;

    assert_eq!(results[0].id, best);
    Ok(())
}

#[test]
fn long_interval_scan_does_not_spend_cap_on_preexisting_ids() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = crate::unix_seconds_now();
    let span = LONG_INTERVAL_THRESHOLD_SECS + 86_400;
    let best = entity_id(224);
    let mut preexisting = HashSet::new();

    for i in 0..5_u8 {
        let id = entity_id(220 + i);
        let learned_at = if id == best {
            anchor
        } else {
            anchor.saturating_sub((30 + u64::from(i)) * 86_400)
        };
        put_entity(
            &vault,
            id,
            1,
            anchor.saturating_sub(span + 10),
            anchor.saturating_add(span + u64::from(i)),
            learned_at,
        )?;
        if id != best {
            preexisting.insert(id);
        }
    }

    let rtxn = vault.store.env.read_txn()?;
    let config = TemporalSearchConfig {
        anchor_start: anchor,
        anchor_end: anchor,
        learned_start: None,
        learned_end: None,
        sigma_secs: 86_400,
        anchor_mode: TemporalAnchorMode::Occurred,
        adaptive: false,
        limit: 1,
    };
    let scoring = TemporalScoringContext {
        sigma: 86_400,
        now: anchor,
        anchor_mid: anchor,
        learned_anchor: (anchor, anchor),
        learned_anchor_mid: anchor,
    };
    let mut metadata_cache = EntityMetadataCache::default();

    collect_temporal_candidates(
        &vault.store,
        &rtxn,
        &config,
        TemporalCandidateCollectionContext {
            radius: 86_400,
            per_scan_cap: PER_SCAN_CAP_FACTOR,
        },
        &mut metadata_cache,
        &scoring,
        &mut preexisting,
    )?;

    assert!(preexisting.contains(&best));
    Ok(())
}

#[test]
fn backward_seek_preserves_lowest_ids_with_same_timestamp() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let timestamp = 99;

    for byte in [40_u8, 41, 42, 43, 44] {
        let id = entity_id(byte);
        put_entity(&vault, id, 1, timestamp, timestamp, timestamp)?;
    }

    let rtxn = vault.store.env.read_txn()?;
    let mut out = HashSet::new();
    collect_index_candidates(
        &vault.store.temporal_occurred_start,
        &rtxn,
        TemporalIndexCollectionContext {
            window_start: 0,
            window_end: timestamp,
            anchor_mid: 100,
            cap: 4,
        },
        &mut out,
    )?;

    assert!(out.contains(&entity_id(40)));
    assert!(out.contains(&entity_id(41)));
    assert!(out.contains(&entity_id(42)));
    assert!(out.contains(&entity_id(43)));
    assert!(!out.contains(&entity_id(44)));
    Ok(())
}

#[test]
fn future_events_are_scored() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let now = crate::unix_seconds_now();
    let start = now + 7 * 86_400;
    let end = now + 8 * 86_400;
    let id = entity_id(50);

    put_entity(&vault, id, 1, start + 3_600, start + 3_600, now)?;

    let config = TemporalSearchConfig {
        anchor_start: start,
        anchor_end: end,
        learned_start: None,
        learned_end: None,
        sigma_secs: TemporalGranularity::Week.sigma_secs(),
        anchor_mode: TemporalAnchorMode::Auto,
        adaptive: true,
        limit: 10,
    };
    let rtxn = vault.store.env.read_txn()?;
    let mut metadata_cache = EntityMetadataCache::default();
    let results = execute_temporal(&vault.store, &rtxn, &config, now, &mut metadata_cache)?;

    let scored = results
        .iter()
        .find(|entry| entry.id == id)
        .expect("missing future entity");
    assert!(scored.score > 0.5_f32);
    Ok(())
}

#[test]
fn temporal_tier_equivalence() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = entity_id(60);
    let b = entity_id(61);
    let start = 1_000_000;
    let end = 1_200_000;
    let sigma = end - start;

    put_entity(&vault, a, 1, start + 10_000, start + 10_000, start + 10_000)?;
    put_entity(&vault, b, 1, end + 500_000, end + 500_000, end + 500_000)?;

    let tier1 = vault.query().search_temporal(start, end, 10).run()?;
    let tier2 = vault
        .query()
        .search_temporal_with_sigma(start, end, sigma.max(86_400), TemporalAnchorMode::Auto, 10)
        .run()?;

    assert_eq!(tier1.len(), tier2.len());
    for (left, right) in tier1.iter().zip(tier2.iter()) {
        assert_eq!(left.id, right.id);
        assert!(approx_eq(left.score, right.score, 1e-6));
    }

    Ok(())
}

#[test]
fn per_scan_cap_isolation_keeps_learned_candidates() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000;
    for i in 0..40_u8 {
        let id = entity_id(80 + i);
        put_entity(
            &vault,
            id,
            1,
            anchor + u64::from(i),
            anchor + u64::from(i),
            9_000_000,
        )?;
    }

    let learned_only = entity_id(70);
    put_entity(
        &vault,
        learned_only,
        1,
        anchor + 10_000_000,
        anchor + 10_000_000,
        anchor,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 3_600, TemporalAnchorMode::Auto, 5)
        .run()?;

    assert!(results.iter().any(|entry| entry.id == learned_only));
    Ok(())
}

#[test]
fn granularity_sigma_ordering() -> Result<()> {
    // For a fixed entity-to-anchor distance, increasing sigma should
    // monotonically increase the temporal-similarity score (wider Gaussian =
    // higher density at the same offset). The two original tests both
    // assert this monotonicity; we collapse them into a single ordering
    // table that walks adjacent sigma pairs.
    //
    // (case_name, distance_secs, sigma_a (smaller), sigma_b (larger))
    // Assertion per case: score_a < score_b for an entity placed
    // `distance_secs` past the anchor.
    let cases: &[(&str, u64, u64, u64)] = &[
        // From sigma_not_clamped_and_granularity_tiers_differ: distance = 20_000s
        (
            "20ks_exact_lt_hour",
            20_000,
            TemporalGranularity::Exact.sigma_secs(),
            TemporalGranularity::Hour.sigma_secs(),
        ),
        (
            "20ks_hour_lt_day",
            20_000,
            TemporalGranularity::Hour.sigma_secs(),
            TemporalGranularity::Day.sigma_secs(),
        ),
        // From granularity_day_vs_year_distributions_differ: distance = 5 days
        (
            "5d_day_lt_year",
            5 * 86_400,
            TemporalGranularity::Day.sigma_secs(),
            TemporalGranularity::Year.sigma_secs(),
        ),
    ];

    // Use a distinct entity per case to keep score lookup unambiguous.
    // entity_id(90) was the original ID in the first test; use 90+i so
    // there's no collision with other tests in this module.
    for (i, (name, distance, sigma_a, sigma_b)) in cases.iter().enumerate() {
        let (_dir, vault) = open_test_vault();
        let anchor: u64 = 1_000_000;
        let id = entity_id(90_u8.saturating_add(i as u8));
        let ts = anchor + *distance;
        put_entity(&vault, id, 1, ts, ts, ts)?;

        let base_config = TemporalSearchConfig {
            anchor_start: anchor,
            anchor_end: anchor,
            learned_start: None,
            learned_end: None,
            sigma_secs: 0,
            anchor_mode: TemporalAnchorMode::Occurred,
            adaptive: true,
            limit: 10,
        };
        let cfg_a = TemporalSearchConfig {
            sigma_secs: *sigma_a,
            ..base_config
        };
        let cfg_b = TemporalSearchConfig {
            sigma_secs: *sigma_b,
            ..base_config
        };

        let rtxn = vault.store.env.read_txn()?;
        let mut metadata_cache = EntityMetadataCache::default();
        let results_a = execute_temporal(&vault.store, &rtxn, &cfg_a, anchor, &mut metadata_cache)?;
        let results_b = execute_temporal(&vault.store, &rtxn, &cfg_b, anchor, &mut metadata_cache)?;

        let score_a = results_a
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("case {name}: entity missing in sigma_a results"))
            .score;
        let score_b = results_b
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("case {name}: entity missing in sigma_b results"))
            .score;

        assert!(
            score_a < score_b,
            "case {name}: expected score_a < score_b (sigma_a={sigma_a}, sigma_b={sigma_b}, distance={distance}); got score_a={score_a}, score_b={score_b}"
        );
    }

    Ok(())
}

#[test]
fn sigma_driven_discovery_for_year_granularity() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 1_000_000;
    let far = entity_id(100);
    let hundred_days = 100 * 86_400;

    put_entity(
        &vault,
        far,
        1,
        anchor + hundred_days,
        anchor + hundred_days,
        anchor + hundred_days,
    )?;

    let day_results = vault
        .query()
        .search_temporal_with_granularity(
            anchor,
            anchor,
            TemporalGranularity::Day,
            TemporalAnchorMode::Occurred,
            10,
        )
        .run()?;
    assert!(!day_results.iter().any(|entry| entry.id == far));

    let year_results = vault
        .query()
        .search_temporal_with_granularity(
            anchor,
            anchor,
            TemporalGranularity::Year,
            TemporalAnchorMode::Occurred,
            10,
        )
        .run()?;
    assert!(year_results.iter().any(|entry| entry.id == far));

    Ok(())
}

#[test]
fn bidirectional_priority_favors_nearest_candidates() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 2_000_000;
    let near = entity_id(110);
    let far_a = entity_id(111);
    let far_b = entity_id(112);

    put_entity(
        &vault,
        near,
        1,
        anchor + 1_000,
        anchor + 1_000,
        anchor + 1_000,
    )?;
    put_entity(
        &vault,
        far_a,
        1,
        anchor - 500_000,
        anchor - 500_000,
        anchor - 500_000,
    )?;
    put_entity(
        &vault,
        far_b,
        1,
        anchor + 500_000,
        anchor + 500_000,
        anchor + 500_000,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .run()?;

    assert_eq!(results[0].id, near);
    Ok(())
}

#[test]
fn adaptive_widening_and_disable() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 5_000_000;
    let target = entity_id(120);

    put_entity(
        &vault,
        target,
        1,
        anchor + 30 * 86_400,
        anchor + 30 * 86_400,
        anchor + 30 * 86_400,
    )?;

    let widened = vault
        .query()
        .search_temporal_with_granularity(
            anchor,
            anchor,
            TemporalGranularity::Week,
            TemporalAnchorMode::Occurred,
            10,
        )
        .run()?;
    assert!(widened.iter().any(|entry| entry.id == target));

    let exact = vault
        .query()
        .search_temporal_with_granularity(
            anchor,
            anchor,
            TemporalGranularity::Week,
            TemporalAnchorMode::Occurred,
            10,
        )
        .temporal_adaptive(false)
        .run()?;
    assert!(!exact.iter().any(|entry| entry.id == target));

    Ok(())
}

#[test]
fn contiguity_boost_behavior() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 3_000_000;
    let cluster_a = entity_id(130);
    let cluster_b = entity_id(131);
    let isolated = entity_id(132);

    put_entity(&vault, cluster_a, 1, anchor, anchor, anchor)?;
    put_entity(
        &vault,
        cluster_b,
        1,
        anchor + 3_600,
        anchor + 3_600,
        anchor + 3_600,
    )?;
    put_entity(
        &vault,
        isolated,
        1,
        anchor + 40 * 86_400,
        anchor + 40 * 86_400,
        anchor + 40 * 86_400,
    )?;

    let base = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
        .run()?;
    let boosted = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
        .boost_contiguity()
        .run()?;

    let base_map = to_score_map(&base);
    let boosted_map = to_score_map(&boosted);

    assert!(boosted_map[&cluster_a] > base_map[&cluster_a]);
    assert!(boosted_map[&cluster_b] > base_map[&cluster_b]);

    let single_base = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .run()?;
    let single_boost = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .boost_contiguity()
        .run()?;
    assert!(approx_eq(single_base[0].score, single_boost[0].score, 1e-6));

    let text_id = entity_id(133);
    put_text(&vault, text_id, "alpha")?;
    let text_base = vault.query().search_text("alpha", 10).run()?;
    let text_boosted = vault
        .query()
        .search_text("alpha", 10)
        .boost_contiguity()
        .run()?;
    assert!(approx_eq(text_base[0].score, text_boosted[0].score, 1e-6));

    Ok(())
}

#[test]
fn overlap_tiebreak_prefers_closer_midpoint() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor_start = 100;
    let anchor_end = 200;
    let closer = entity_id(140);
    let farther = entity_id(141);

    put_entity(&vault, closer, 1, 120, 130, 150)?;
    put_entity(&vault, farther, 1, 180, 190, 150)?;

    let results = vault
        .query()
        .search_temporal_with_sigma(
            anchor_start,
            anchor_end,
            86_400,
            TemporalAnchorMode::Occurred,
            10,
        )
        .run()?;

    assert_eq!(results[0].id, closer);
    Ok(())
}

#[test]
fn learned_overlap_tiebreak_uses_learned_axis() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor_start = crate::unix_seconds_now() + 100;
    let anchor_end = anchor_start + 100;
    let closer = entity_id(142);
    let farther = entity_id(143);

    put_entity(
        &vault,
        closer,
        1,
        anchor_start,
        anchor_start + 10,
        anchor_start + 49,
    )?;
    put_entity(
        &vault,
        farther,
        1,
        anchor_start + 49,
        anchor_start + 50,
        anchor_start + 80,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(
            anchor_start,
            anchor_end,
            86_400,
            TemporalAnchorMode::Learned,
            10,
        )
        .run()?;

    assert_eq!(results[0].id, closer);
    Ok(())
}

#[test]
fn filters_work() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let keep = entity_id(150);
    let drop = entity_id(151);

    put_entity(&vault, keep, 1, 100, 110, 200)?;
    put_entity(&vault, drop, 1, 300, 310, 150)?;

    let results = vault
        .query()
        .search_temporal_with_sigma(105, 105, 86_400, TemporalAnchorMode::Auto, 10)
        .filter_types(&[1])
        .filter_since(190)
        .filter_occurred_range(100, 120)
        .filter_learned_range(190, 210)
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, keep);
    Ok(())
}

#[test]
fn filters_apply_before_contiguity() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor = 5_000_000;
    for index in 0..5_u8 {
        put_entity(&vault, entity_id(170 + index), 2, anchor, anchor, anchor)?;
    }
    let keep = entity_id(180);
    put_entity(
        &vault,
        keep,
        1,
        anchor + 86_400,
        anchor + 86_400,
        anchor + 86_400,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 20)
        .filter_types(&[1])
        .limit(1)
        .boost_contiguity()
        .run()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, keep);
    Ok(())
}

#[test]
fn inverted_ranges_are_rejected_on_put() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // The pre-D3 engine silently swapped reversed intervals into
    // (start: 100, end: 300). The fail-closed gate must reject instead
    // and leave nothing behind (M2 pinned decision D3).
    let id = entity_id(170);
    let err = vault
        .put_entity(
            &id,
            1,
            TimeRange {
                start: 300,
                end: 100,
            },
            400,
            b"payload",
        )
        .expect_err("reversed occurred interval must be rejected");
    assert!(
        matches!(
            err,
            Error::InvalidTimeRange {
                start: 300,
                end: 100
            }
        ),
        "expected InvalidTimeRange {{ start: 300, end: 100 }}, got {err:?}"
    );

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.entities.get(&rtxn, id.as_bytes())?.is_none(),
        "rejected put must not write an entity record"
    );

    Ok(())
}
