//! Scoring constants, blend weights, and dreamer working-set basics.

use super::*;

/// ARCH-0004 §4.5: the recency default is a named 28-day constant
/// (`RECENCY_DECAY`, source timestamp = `learned_at` v1), and the
/// temporal scorer's decay constant is the table-pinned
/// `28.0 * 86_400 = 2_419_200` seconds derived from it.
#[test]
fn default_recency_half_life_is_28_days() {
    assert_eq!(DEFAULT_RECENCY_HALF_LIFE_DAYS, 28.0);
    assert_eq!(RECENCY_DECAY_TAU_SECS, 2_419_200.0);
    assert_eq!(RECENCY_DECAY_TAU_SECS, 28.0 * 86_400.0);
}

#[test]
fn recency_half_life_table_is_contract_pinned() {
    assert_eq!(
        RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE,
        &[
            (ENTITY_TYPE_CLAIM, 28.0),
            (ENTITY_TYPE_TURN, 28.0),
            (crate::registry::ENTITY_TYPE_SESSION, 28.0),
            (crate::registry::ENTITY_TYPE_MESSAGE, 28.0),
            (crate::registry::ENTITY_TYPE_PERSON, 365.0),
            (crate::registry::ENTITY_TYPE_RELATIONSHIP, 180.0),
            (ENTITY_TYPE_EVENT, 30.0),
            (crate::registry::ENTITY_TYPE_SKILL, 90.0),
            (ENTITY_TYPE_SUMMARY, 90.0),
            (crate::registry::ENTITY_TYPE_PLACE, 180.0),
            (crate::registry::ENTITY_TYPE_ASSET_TEXT, 90.0),
            (crate::registry::ENTITY_TYPE_CONVERSATION, 30.0),
            (crate::registry::ENTITY_TYPE_ORG, 180.0),
            (ENTITY_TYPE_FACET, 180.0),
            (crate::registry::ENTITY_TYPE_WORLD, 180.0),
            (crate::registry::ENTITY_TYPE_ASSET, 90.0),
            (crate::registry::ENTITY_TYPE_NOTIFICATION, 7.0),
            (crate::registry::ENTITY_TYPE_TASK_LIST, 30.0),
            (crate::registry::ENTITY_TYPE_TASK, 30.0),
            (crate::registry::ENTITY_TYPE_MACHINE, 180.0),
            (crate::registry::ENTITY_TYPE_CODE_ARTIFACT, 90.0),
            (crate::registry::ENTITY_TYPE_REDACTION_AUDIT, 365.0),
            (crate::registry::ENTITY_TYPE_MODEL, 180.0),
            (crate::registry::ENTITY_TYPE_POLICY_MANIFEST, 365.0),
            (crate::registry::ENTITY_TYPE_FEDERATION_GRANT, 365.0),
            (crate::registry::ENTITY_TYPE_ACCESS_GRANT, 365.0),
            (crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT, 365.0),
            (crate::registry::ENTITY_TYPE_OUTBOUND_GRANT, 365.0),
            (crate::registry::ENTITY_TYPE_PSYCH_PROFILE, 365.0),
        ]
    );
    assert!(
        retrieval_recency_half_life_days_for_type(crate::registry::ENTITY_TYPE_PERSON)
            > DEFAULT_RECENCY_HALF_LIFE_DAYS
    );
    assert_eq!(
        retrieval_recency_half_life_days_for_type(250),
        DEFAULT_RECENCY_HALF_LIFE_DAYS
    );
}

#[test]
fn tuned_weight_table_changes_retrieval_scoring_without_recompile() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let high = entity_id(0xB0);
    let mid = entity_id(0xB1);
    let low = entity_id(0xB2);
    put_claim_text_with_salience(&vault, high, "weighttableneedle", 0.9)?;
    put_claim_text_with_salience(&vault, mid, "weighttableneedle", 0.4)?;
    put_claim_text_with_salience(&vault, low, "weighttableneedle", 0.0)?;

    let baseline = vault
        .query()
        .search_text("weighttableneedle", 10)
        .boost_salience()
        .run()?;
    let baseline_score = *to_score_map(&baseline)
        .get(&high)
        .expect("high-salience result is present");

    let run_id = RetrievalRunId::now();
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        200,
        10,
        vec![RetrievalSignal::Text],
        vec![
            RetrievalScoreBreakdown {
                result_id: *high.as_bytes(),
                final_rank: 1,
                final_score: baseline_score,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Salience,
                    rank: 1,
                    score: 1.0,
                }],
                access_factor: None,
            },
            RetrievalScoreBreakdown {
                result_id: *low.as_bytes(),
                final_rank: 2,
                final_score: 1.0,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Salience,
                    rank: 2,
                    score: -1.0,
                }],
                access_factor: None,
            },
        ],
        2,
        0,
        None,
    );
    vault.store.record_retrieval_run(&record)?;
    vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
        run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    let before = vault.retrieval_blend_weight_table()?;
    let updated = vault.tune_retrieval_blend_weights(crate::store::RetrievalBlendTuningConfig {
        max_runs: 10,
        learning_rate: 0.20,
        min_reward_count: 1,
    })?;
    assert!(updated.weights.salience > before.weights.salience);

    let rescored = vault
        .query()
        .search_text("weighttableneedle", 10)
        .boost_salience()
        .run()?;
    let rescored_score = *to_score_map(&rescored)
        .get(&high)
        .expect("high-salience result remains present");

    assert_ne!(baseline_score.to_bits(), rescored_score.to_bits());
    assert!(rescored_score > baseline_score);
    Ok(())
}

#[test]
fn threshold_boundary() {
    let boundary = entity_id(0x91);
    let above = entity_id(0x92);
    let vector = vec![scored(boundary, 0.30), scored(above, 0.31)];
    let text = Vec::new();
    let ghosts = cosine_ghost_set(&[vector, text], Some(0), Some(1));

    assert_eq!(ghosts.len(), 1);
    assert!(!ghosts.contains(&boundary));
    assert!(ghosts.contains(&above));
}

#[test]
fn single_channel_noop() {
    let ghost = entity_id(0x94);
    let vector = vec![scored(ghost, 0.6)];
    let ghosts = cosine_ghost_set(std::slice::from_ref(&vector), Some(0), None);

    assert!(ghosts.is_empty());
}

#[test]
fn metric_counts_dampened() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let ghost_a = entity_id(0x95);
    let ghost_b = entity_id(0xD6);
    let lexical = entity_id(0xA7);
    let low_similarity = entity_id(0xA8);

    put_vector(&vault, ghost_a, [1.0, 0.0, 0.0, 0.0])?;
    put_vector(&vault, ghost_b, [0.6, 0.8, 0.0, 0.0])?;
    put_text_and_vector(&vault, lexical, "gravityneedle", [0.8, 0.6, 0.0, 0.0])?;
    put_vector(&vault, low_similarity, [0.0, 1.0, 0.0, 0.0])?;

    let output = vault
        .query()
        .search_text("gravityneedle", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .boost_gravity()
        .run_for_pack()?;

    assert_eq!(output.cosine_ghosts_dampened, 2);
    Ok(())
}

#[test]
fn disabled_by_default() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let ghost = entity_id(0xA9);
    let lexical = entity_id(0xAA);

    put_vector(&vault, ghost, [1.0, 0.0, 0.0, 0.0])?;
    put_text(&vault, lexical, "defaultoffneedle")?;

    let baseline = vault
        .query()
        .search_text("defaultoffneedle", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run_for_pack()?;
    let boosted = vault
        .query()
        .search_text("defaultoffneedle", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .boost_gravity()
        .run_for_pack()?;

    let baseline_scores = to_score_map(&baseline.scores);
    let boosted_scores = to_score_map(&boosted.scores);

    assert_eq!(baseline.cosine_ghosts_dampened, 0);
    assert!(approx_eq(baseline_scores[&ghost], 1.0, 1e-7));
    assert_eq!(boosted.cosine_ghosts_dampened, 1);
    assert!(boosted_scores[&ghost] < baseline_scores[&ghost]);
    Ok(())
}

#[test]
fn text_only_query() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = entity_id(3);
    let b = entity_id(4);

    put_text(&vault, a, "alpha world")?;
    put_text(&vault, b, "beta world")?;

    let results = vault.query().search_text("alpha", 10).run()?;
    assert!(!results.is_empty());
    assert_eq!(results[0].id, a);
    Ok(())
}

#[test]
fn dreamer_working_set_cursor_advances_incrementally() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    for seed in [0xD1, 0xD2, 0xD3] {
        put_text(&vault, entity_id(seed), "dreamer cursor needle")?;
    }

    let budget = DreamerWorkingSetBudget::new(10);
    let first = vault
        .query()
        .search_text("dreamer", 10)
        .run_dreamer_working_set(DreamerWorkingSetCursor::start(), budget, 1)?;

    assert_eq!(first.cursor.offset(), 0);
    assert_eq!(first.rows.len(), 1);
    assert_eq!(first.stop_reason, None);
    let next_cursor = first.next_cursor.expect("first page has a cursor");
    assert_eq!(next_cursor.offset(), 1);

    let second = vault
        .query()
        .search_text("dreamer", 10)
        .run_dreamer_working_set(next_cursor, budget, 1)?;

    assert_eq!(second.cursor.offset(), 1);
    assert_eq!(second.rows.len(), 1);
    assert_ne!(first.rows[0].id, second.rows[0].id);
    assert_eq!(
        second
            .next_cursor
            .expect("second page has a cursor")
            .offset(),
        2
    );
    Ok(())
}

#[test]
fn dreamer_working_set_budget_cap_stops_ingress() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    for seed in [0x5E, 0x5F, 0x60] {
        put_text(&vault, entity_id(seed), "dreamer budget needle")?;
    }

    let budget = DreamerWorkingSetBudget::new(2);
    let capped = vault
        .query()
        .search_text("dreamer", 10)
        .run_dreamer_working_set(DreamerWorkingSetCursor::start(), budget, 10)?;

    assert_eq!(capped.rows.len(), 2);
    assert_eq!(
        capped.stop_reason,
        Some(DreamerWorkingSetStopReason::BudgetExhausted)
    );
    assert_eq!(capped.next_cursor, None);

    let stopped = vault
        .query()
        .search_text("dreamer", 10)
        .run_dreamer_working_set(DreamerWorkingSetCursor::from_offset(2), budget, 1)?;

    assert!(stopped.rows.is_empty());
    assert_eq!(
        stopped.stop_reason,
        Some(DreamerWorkingSetStopReason::BudgetExhausted)
    );
    assert_eq!(stopped.telemetry_run_id, None);
    Ok(())
}
