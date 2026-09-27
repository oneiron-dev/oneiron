use super::retention::{RETRIEVAL_RUN_MAX_ROWS, RETRIEVAL_RUN_TTL_SECONDS};
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
    let (_dir, vault) = open_test_vault_with(telemetry_config());
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
    let (_dir, vault) = open_test_vault_with(telemetry_config());
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
    let (dir, vault) = open_test_vault_with(telemetry_config());
    let (_other_dir, other) = open_test_vault_with(telemetry_config());
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
    let (_dir, vault) = open_test_vault_with(telemetry_config());
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

fn breakdown(rank: u32, score: f32, signals: &[RetrievalSignal]) -> RetrievalScoreBreakdown {
    RetrievalScoreBreakdown {
        result_id: [rank as u8; 16],
        final_rank: rank,
        final_score: score,
        components: signals
            .iter()
            .map(|signal| RetrievalScoreComponent {
                signal: *signal,
                rank,
                score,
            })
            .collect(),
        access_factor: None,
    }
}

#[test]
fn one_shot_strength_is_not_a_binary_flag_and_agreement_is_distinct() {
    let weak = RetrievalState::one_shot(&[breakdown(1, 0.2, &[RetrievalSignal::Text])]);
    let strong = RetrievalState::one_shot(&[
        breakdown(2, 1.0, &[RetrievalSignal::Text]),
        breakdown(
            1,
            55.0,
            &[
                RetrievalSignal::Text,
                RetrievalSignal::Vector,
                RetrievalSignal::Text,
                RetrievalSignal::Salience,
                RetrievalSignal::Rerank,
            ],
        ),
    ]);
    assert!(weak.top_score_norm > 0.0 && weak.top_score_norm < 0.5);
    assert!(strong.top_score_norm > 0.9 && strong.top_score_norm < 1.0);
    assert!(strong.mean_score_norm <= strong.top_score_norm);
    assert_eq!(strong.signal_agreement, 3);
    assert_eq!(weak.signal_agreement, 1);
    assert_eq!(strong.result_count, 2);
    assert_eq!(RetrievalState::one_shot(&[]), RetrievalState::default());
    let malformed = RetrievalState::one_shot(&[
        breakdown(1, -3.0, &[]),
        breakdown(2, f32::NAN, &[]),
        breakdown(3, f32::INFINITY, &[]),
    ]);
    assert_eq!(malformed.result_count, 3);
    assert_eq!(malformed.top_score_norm, 0.0);
    assert_eq!(malformed.mean_score_norm, 0.0);
    assert_eq!(malformed.novelty_vs_prior, 1.0);
}

#[test]
fn pipeline_persists_one_shot_signals_and_verbatim_host_override() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(telemetry_config());
    let id = crate::test_util::entity(0xB4);
    vault
        .batch()
        .put(&id, 1, crate::TimeRange { start: 1, end: 1 }, 1, b"needle")
        .text(&id, &[("body", "one shot needle")])
        .commit()?;
    let automatic = vault
        .query()
        .search_text("needle", 10)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    let stored = vault
        .retrieval_run(automatic.run_id.expect("stored"))?
        .expect("readable");
    assert_eq!(automatic.value.len(), 1);
    assert_eq!(stored.state.result_count, 1);
    assert_eq!(stored.state.signal_agreement, 1);
    assert!(stored.state.top_score_norm > 0.0 && stored.state.top_score_norm < 1.0);
    let host = RetrievalState {
        top_score_norm: 0.31,
        score_gap_ratio: 0.11,
        mean_score_norm: 0.22,
        entity_coverage: 0.5,
        novelty_vs_prior: 0.25,
        signal_agreement: 4,
        result_count: 7,
        iteration: 2,
        budget_remaining: 5,
        frontier_size: 9,
        avg_edge_weight: 0.4,
        graph_degree: 6,
        temporal_spread: 0.7,
        hops: 1,
        last_action: 2,
        intent_class: 3,
    };
    let encoded = rmp_serde::to_vec_named(&host).unwrap();
    let overridden = vault
        .query()
        .search_text("needle", 10)
        .retrieval_state(host)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    let stored = vault
        .retrieval_run(overridden.run_id.expect("stored"))?
        .expect("readable");
    assert_eq!(
        rmp_serde::to_vec_named(stored.replay_state()).unwrap(),
        encoded
    );
    Ok(())
}

#[test]
fn invalid_caller_state_does_not_disable_later_pipeline_telemetry() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(telemetry_config());
    let mut invalid = record(10);
    invalid.state.top_score_norm = f32::NAN;
    assert!(matches!(
        vault.store.record_retrieval_run(&invalid),
        Err(crate::Error::InvalidConfig(_))
    ));
    assert!(matches!(
        vault
            .query()
            .search_text("absent", 10)
            .retrieval_state(invalid.state)
            .capture_retrieval_trace(true)
            .run_with_telemetry(),
        Err(crate::Error::InvalidConfig(_))
    ));
    let good_run = vault
        .query()
        .search_text("absent", 10)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    let run_id = good_run.run_id.expect("valid state still persists");
    assert!(vault.retrieval_run(run_id)?.is_some());
    assert_eq!(vault.retrieval_runs(10)?.len(), 1);
    Ok(())
}

#[test]
fn persisted_nonfinite_retrieval_state_is_corruption_at_read_doors() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(telemetry_config());
    let mut run = record(10);
    vault.store.record_retrieval_run(&run)?;
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        run.state.top_score_norm = value;
        let bytes = rmp_serde::to_vec_named(&run).unwrap();
        vault.with_write_txn(|txn| {
            vault
                .store
                .vault_meta
                .put(txn, &retrieval_run_key(run.run_id), &bytes)?;
            Ok(())
        })?;
        assert!(matches!(
            vault.retrieval_run(run.run_id),
            Err(crate::Error::CorruptedIndex(_))
        ));
        assert!(matches!(
            vault.retrieval_runs(10),
            Err(crate::Error::CorruptedIndex(_))
        ));
    }
    Ok(())
}

fn telemetry_config() -> VaultConfig {
    VaultConfig {
        retrieval_telemetry_capture: true,
        ..VaultConfig::default()
    }
}

#[test]
fn durable_telemetry_requires_runtime_opt_in() -> crate::Result<()> {
    for config in [VaultConfig::device(), VaultConfig::server()] {
        assert!(!config.retrieval_telemetry_capture);
        let dir = tempfile::tempdir()?;
        let vault = crate::Vault::open(dir.path(), config)?;
        assert!(!vault.store.retrieval_telemetry_capture_enabled());
        assert!(
            vault
                .query()
                .search_text("nothing", 2)
                .run_with_telemetry()?
                .run_id
                .is_none()
        );
        assert!(vault.retrieval_runs(10)?.is_empty());
    }
    Ok(())
}

#[test]
fn disabled_capture_never_asks_the_telemetry_id_source() -> crate::Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct ToggleIds(AtomicBool);
    impl crate::ports::IdGen for ToggleIds {
        fn ulid(&self) -> [u8; 16] {
            if self.0.load(Ordering::Relaxed) {
                [0; 16] // Invalid EntityId; allocation would fail the query.
            } else {
                uuid::Uuid::now_v7().into_bytes()
            }
        }
    }
    let ids = Arc::new(ToggleIds(AtomicBool::new(false)));
    let mut config = VaultConfig::device();
    config.store_clock =
        crate::ports::StoreClock::new(crate::ports::ManualClock::new(1_000_000), ids.clone());
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), config)?;
    ids.0.store(true, Ordering::Relaxed);
    let result = vault
        .query()
        .search_text("nothing", 2)
        .run_with_telemetry()?;
    assert!(result.run_id.is_none());
    Ok(())
}

#[test]
fn published_retention_evicts_old_runs_and_their_sidecars() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(telemetry_config());
    let turn = RetrievalTurn {
        turn_id: [0xA1; 16],
        episode_id: [0xB1; 16],
        turn_idx: 1,
    };
    let mut first = record(10);
    first.run_id = RetrievalRunId::from_bytes([1; 16]);
    first.turn = Some(turn);
    vault.store.record_retrieval_run(&first)?;
    vault.store.record_retrieval_outcome(RetrievalOutcome {
        run_id: first.run_id,
        key: "reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: Default::default(),
    })?;
    for _ in 0..RETRIEVAL_RUN_MAX_ROWS {
        vault.store.record_retrieval_run(&record(11))?;
    }
    assert_eq!(
        vault.retrieval_runs(RETRIEVAL_RUN_MAX_ROWS + 1)?.len(),
        RETRIEVAL_RUN_MAX_ROWS
    );
    assert!(vault.retrieval_run(first.run_id)?.is_none());
    assert!(vault.retrieval_outcomes(first.run_id)?.is_empty());
    assert!(vault.retrieval_runs_by_turn(&turn.turn_id)?.is_empty());
    Ok(())
}

#[test]
fn telemetry_age_expires_on_write() -> crate::Result<()> {
    let clock = crate::ports::ManualClock::new(1_000_000);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    config.retrieval_telemetry_capture = true;
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), config)?;
    let published = record(1_000_000);
    vault.store.record_retrieval_run(&published)?;
    clock.set(1_000_000 + RETRIEVAL_RUN_TTL_SECONDS + 1);
    vault
        .store
        .record_retrieval_run(&record(1_000_000 + RETRIEVAL_RUN_TTL_SECONDS + 1))?;
    assert!(vault.retrieval_run(published.run_id)?.is_none());
    assert_eq!(vault.retrieval_runs(10)?.len(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn crash_orphans_sweep_on_reopen() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let orphan = record(10);
    {
        let vault = crate::Vault::open(dir.path(), config.clone())?;
        vault
            .store
            .record_context_pack_provisional_retrieval_run(&orphan)?;
    }
    let vault = crate::Vault::open(dir.path(), config)?;
    assert!(
        vault
            .store
            .vault_meta
            .get(
                &vault.store.env.read_txn()?,
                &retrieval_run_key(orphan.run_id)
            )?
            .is_none()
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(
                &vault.store.env.read_txn()?,
                &super::run_store::retrieval_run_provisional_key(orphan.run_id)
            )?
            .is_none()
    );
    Ok(())
}

#[test]
fn disabling_capture_on_reopen_keeps_recent_runs_readable() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let run = record(10);
    {
        let vault = crate::Vault::open(dir.path(), config)?;
        vault.store.record_retrieval_run(&run)?;
    }
    let vault = crate::Vault::open(dir.path(), VaultConfig::device())?;
    assert!(!vault.store.retrieval_telemetry_capture_enabled());
    assert_eq!(vault.retrieval_run(run.run_id)?, Some(run));
    assert!(
        vault
            .query()
            .search_text("nothing", 1)
            .run_with_telemetry()?
            .run_id
            .is_none()
    );
    assert_eq!(vault.retrieval_runs(10)?.len(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn open_does_not_sweep_a_provisional_run_while_another_owner_holds_the_vault() -> crate::Result<()>
{
    use std::os::fd::AsRawFd;

    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let run = record(10);
    {
        let vault = crate::Vault::open(dir.path(), config.clone())?;
        vault
            .store
            .record_context_pack_provisional_retrieval_run(&run)?;
    }
    let lock = std::fs::OpenOptions::new().read(true).write(true).open(
        dir.path()
            .join(super::retention::RETRIEVAL_TELEMETRY_LOCK_FILE),
    )?;
    // SAFETY: `lock` owns this live descriptor and flock receives no pointer.
    let acquired = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    assert_eq!(acquired, 0);
    {
        let vault = crate::Vault::open(dir.path(), config.clone())?;
        assert!(
            vault
                .store
                .vault_meta
                .get(&vault.store.env.read_txn()?, &retrieval_run_key(run.run_id))?
                .is_some()
        );
    }
    // SAFETY: this process still owns the descriptor; explicit unlock mirrors
    // the lease drop and avoids inherited descriptors extending a hold.
    let released = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
    assert_eq!(released, 0);
    drop(lock);
    let vault = crate::Vault::open(dir.path(), config)?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, &retrieval_run_key(run.run_id))?
            .is_none()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn existing_only_open_sweeps_crashed_provisional_row() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let run = record(10);
    {
        let vault = crate::Vault::open(dir.path(), config.clone())?;
        vault
            .store
            .record_context_pack_provisional_retrieval_run(&run)?;
    }
    let vault = crate::Vault::open_existing(dir.path(), config)?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, &retrieval_run_key(run.run_id))?
            .is_none()
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn renamed_root_cannot_redirect_the_orphan_sweep_lock() -> crate::Result<()> {
    let tmp = tempfile::tempdir()?;
    let original = tmp.path().join("vault");
    let renamed = tmp.path().join("renamed");
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let vault = crate::Vault::open(&original, config)?;
    let run = record(10);
    vault
        .store
        .record_context_pack_provisional_retrieval_run(&run)?;

    // This is the interval after LMDB validation but before a second lease
    // acquisition. A pathname-based lock would be taken in the replacement
    // and falsely grant EX, deleting the active row in the original LMDB.
    std::fs::rename(&original, &renamed)?;
    std::fs::create_dir(&original)?;
    vault.store.reconcile_retrieval_telemetry_on_open()?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, &retrieval_run_key(run.run_id))?
            .is_some()
    );
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
    assert!(vault.retrieval_run(run.run_id)?.is_some());
    Ok(())
}
