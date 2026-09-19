use super::*;
use crate::VaultConfig;
use crate::test_util::open_test_vault_with;

fn record(started: u64) -> RetrievalRunRecord {
    RetrievalRunRecord::new(
        RetrievalRunId::now(),
        RetrievalAction::Pipeline,
        started,
        started * 10,
        vec![RetrievalSignal::Text],
        Vec::new(),
        0,
        0,
        None,
    )
}

#[test]
fn state_roundtrip_replay_and_ordered_turn_projection_survive_delete() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let state = RetrievalState {
        top_score_norm: 0.7,
        score_gap_ratio: 0.4,
        entity_coverage: 0.25,
        novelty_vs_prior: 0.8,
        frontier_size: 123,
        avg_edge_weight: 0.55,
        graph_degree: 4,
        budget_remaining: 2,
        ..Default::default()
    };
    let bytes = rmp_serde::to_vec_named(&state).unwrap();
    let turn = RetrievalTurn {
        turn_id: [1; 16],
        episode_id: [2; 16],
        turn_idx: 7,
    };
    let mut first = record(10);
    first.state = state;
    first.turn = Some(turn);
    let mut later = record(20);
    later.turn = Some(turn);
    vault.store.record_retrieval_run(&later)?;
    vault.store.record_retrieval_run(&first)?;
    let read = vault.retrieval_run(first.run_id)?.unwrap();
    assert_eq!(rmp_serde::to_vec_named(read.replay_state()).unwrap(), bytes);
    assert_eq!(read.turn, Some(turn));
    assert_eq!(
        vault.retrieval_runs_by_turn(&turn.turn_id)?,
        [first.run_id, later.run_id]
    );
    assert_eq!(vault.retrieval_latency_baseline(20)?, Some((100, 200)));
    vault.store.delete_retrieval_run(first.run_id)?;
    assert_eq!(vault.retrieval_runs_by_turn(&turn.turn_id)?, [later.run_id]);
    Ok(())
}

#[test]
fn provisional_turn_runs_publish_only_on_finalize() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let mut run = record(10);
    let turn = RetrievalTurn {
        turn_id: [4; 16],
        episode_id: [2; 16],
        turn_idx: 8,
    };
    run.turn = Some(turn);
    vault
        .store
        .record_context_pack_provisional_retrieval_run(&run)?;
    assert!(vault.retrieval_runs_by_turn(&turn.turn_id)?.is_empty());
    vault
        .store
        .finalize_context_pack_retrieval_run(RetrievalRunFinalize {
            run_id: run.run_id,
            elapsed_us: 100,
            total_in_scope: 0,
            claims_suppressed: 0,
            surfaced_result_ids: &[],
            empty_reason: None,
        })?;
    assert_eq!(vault.retrieval_runs_by_turn(&turn.turn_id)?, [run.run_id]);
    Ok(())
}

#[test]
fn telemetry_failure_disables_only_that_vault_without_corrupt_rows() -> crate::Result<()> {
    let (dir, vault) = open_test_vault_with(VaultConfig::default());
    let (_other_dir, other) = open_test_vault_with(VaultConfig::default());
    crate::store::test_hooks::fail_next_retrieval_run_write_for(dir.path().canonicalize()?);
    assert!(vault.store.record_retrieval_run(&record(10)).is_err());
    assert!(!vault.store.retrieval_telemetry_writes_enabled());
    assert!(vault.retrieval_runs(10)?.is_empty());
    assert!(vault.store.record_retrieval_run(&record(11)).is_err());
    other.store.record_retrieval_run(&record(12))?;
    assert!(other.store.retrieval_telemetry_writes_enabled());
    assert_eq!(other.retrieval_runs(10)?.len(), 1);
    Ok(())
}

#[test]
fn one_shot_baseline_is_measured_from_stored_runs_without_policy() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let id = crate::test_util::entity(0xB3);
    vault
        .batch()
        .put(
            &id,
            1,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"baseline",
        )
        .text(&id, &[("body", "baseline retrieval needle")])
        .commit()?;
    for _ in 0..100 {
        vault
            .query()
            .search_text("needle", 10)
            .capture_retrieval_trace(true)
            .run()?;
    }
    let (p50, p95) = vault
        .retrieval_latency_baseline(100)?
        .expect("captured runs");
    assert!(p95 >= p50);
    assert_eq!(vault.retrieval_runs(100)?.len(), 100);
    eprintln!("ONE-SHOT-BASELINE p50_us={p50} p95_us={p95} samples=100 bandit=disabled");
    Ok(())
}
