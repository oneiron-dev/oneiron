//! Scoring constants, blend weights, and dreamer working-set basics.

use super::*;

#[test]
fn tuned_weight_table_changes_retrieval_scoring_without_recompile() -> Result<()> {
    let (dir, vault) = open_test_vault();
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
    let mut record = RetrievalRunRecord::new(
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
    record.turn = Some(crate::store::RetrievalTurn {
        turn_id: [7; 16],
        episode_id: [8; 16],
        turn_idx: 0,
    });
    vault.store.record_retrieval_run(&record)?;
    vault.record_retrieval_end_outcome(crate::store::RetrievalEndOutcome {
        run_id,
        key: "beam.reward".to_owned(),
        turn_id: [7; 16],
        activated_memory_id: *high.as_bytes(),
        gate_score: 1.0,
        confirmed_fact_hit: true,
        latency_scale_us: 1,
        cost_weight: 0.0,
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

    let image = dir.path().join("checkpoint");
    vault.snapshot_checkpoint(&image, 300)?;
    let (restored, _) = Vault::restore_checkpoint(
        &image,
        &dir.path().join("restored"),
        embedding_test_config(),
        crate::recovery::checkpoint::RestoreReason::Restore,
        400,
    )?;
    assert_eq!(restored.retrieval_blend_weight_table()?, updated);
    Ok(())
}
