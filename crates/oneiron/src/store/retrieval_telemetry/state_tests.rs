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
            pack_output: None,
            pack_config: None,
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

#[test]
fn opt_in_turn_round_trips_replay_inputs_and_exact_pack_with_fork_lookup() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(telemetry_config());
    let id = crate::test_util::entity(0xB5);
    vault
        .batch()
        .put(
            &id,
            1,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"replay marker",
        )
        .text(&id, &[("body", "replay marker")])
        .commit()?;
    let turn = RetrievalTurn {
        turn_id: [8; 16],
        episode_id: [9; 16],
        turn_idx: 3,
    };
    let output = vault
        .context_pack()
        .search_text("replay marker", 5)
        .corpus_snapshot_ref("eval://corpus/fixture-v1")
        .replay_query_ref("eval://query/turn-3")
        .retrieval_turn(turn)
        .capture_retrieval_trace(true)
        .run_serialized_with_telemetry()?;
    let run_id = output.run_id.expect("captured run");
    let row = vault.retrieval_run(run_id)?.expect("stored turn");
    assert_eq!(vault.retrieval_runs_by_turn(&turn.turn_id)?, vec![run_id]);
    let inputs = row.replay_inputs.expect("complete query inputs");
    assert_eq!(inputs.query_ref.as_deref(), Some("eval://query/turn-3"));
    assert_eq!(inputs.config["channels"]["text_limit"], 5);
    assert!(
        !serde_json::to_string(&inputs)
            .unwrap()
            .contains("replay marker")
    );
    assert!(inputs.config["bm25"]["fields"].is_array());
    assert_eq!(inputs.config["corpus_scope"]["kind"], "all");
    assert_eq!(inputs.config["pack"]["assembly"]["edge_hop"], 0);
    assert_eq!(inputs.config["pack"]["projection"]["format"], "Json");
    assert_eq!(
        inputs.corpus_snapshot_ref.as_deref(),
        Some("eval://corpus/fixture-v1")
    );
    let pack = row.pack_output.expect("final pack");
    assert_eq!(pack.bytes, output.value);
    assert_eq!(pack.format, "Json");
    let trace = row.trace.expect("trace");
    assert_eq!(
        vault.retrieval_trace_by_fork_hash(trace.fork_hash)?,
        Some(trace)
    );
    let untraced = vault
        .context_pack()
        .search_text("replay marker", 5)
        .corpus_snapshot_ref("eval://corpus/fixture-v1")
        .run_serialized_with_telemetry()?;
    let row = vault.retrieval_run(untraced.run_id.expect("run"))?.unwrap();
    assert!(row.replay_inputs.is_none());
    assert!(row.pack_output.is_none());
    Ok(())
}

#[test]
fn raw_pack_snapshot_preserves_unprojected_fields_and_resolved_config() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(telemetry_config());
    let id = crate::test_util::entity(0xB6);
    let payload = rmp_serde::to_vec_named(&serde_json::json!({
        "txt": "raw replay marker", "spkr": "user", "at": 1_u64,
    }))
    .unwrap();
    vault
        .batch()
        .put(
            &id,
            crate::registry::ENTITY_TYPE_TURN,
            crate::TimeRange { start: 1, end: 1 },
            1,
            &payload,
        )
        .text(&id, &[("body", "raw replay marker")])
        .commit()?;
    let raw = vault
        .context_pack()
        .search_text("raw replay marker", 5)
        .corpus_snapshot_ref("eval://corpus/raw-fixture")
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    let row = vault.retrieval_run(raw.run_id.expect("captured"))?.unwrap();
    let replay = row.replay_inputs.unwrap();
    assert_eq!(
        replay.config["blend_weights"]["recency"]
            .as_f64()
            .map(|v| v as f32),
        Some(0.35_f32)
    );
    assert_eq!(replay.config["authority"]["deny_all"], false);
    assert_eq!(replay.config["candidate_filter_present"], false);
    let output = row.pack_output.expect("full raw pack");
    assert_eq!(output.format, "msgpack.context-pack.v1");
    let restored: serde_json::Value = rmp_serde::from_slice(&output.bytes).unwrap();
    assert_eq!(
        restored["results"].as_array().unwrap().len(),
        raw.value.results.len()
    );
    assert_eq!(restored["results"][0]["fields"]["txt"], "raw replay marker");
    assert_eq!(
        restored["results"][0]["id"],
        serde_json::json!(id.as_bytes())
    );
    assert_eq!(
        restored["stats"]["candidates_considered"],
        raw.value.stats.candidates_considered
    );
    Ok(())
}

#[test]
fn opted_in_no_channel_and_expired_deadline_publish_empty_turns() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(telemetry_config());
    let deadline = crate::retrieval_depth::RetrievalDeadline::at(
        std::time::Instant::now() - std::time::Duration::from_secs(1),
    );
    for (index, skip_text) in [false, true].into_iter().enumerate() {
        let turn = RetrievalTurn {
            turn_id: [index as u8 + 30; 16],
            episode_id: [42; 16],
            turn_idx: index as u64,
        };
        let mut builder = vault
            .context_pack()
            .retrieval_turn(turn)
            .replay_query_ref(format!("eval://queries/empty-{index}"))
            .corpus_snapshot_ref("eval://corpus/empty")
            .capture_retrieval_trace(true);
        if skip_text {
            builder = builder
                .search_text("private unexecuted query", 5)
                .deadline(&deadline);
        }
        let result = builder.run_with_telemetry()?;
        assert!(result.value.results.is_empty());
        let run_id = result.run_id.expect("opted-in empty run has a row");
        assert_eq!(vault.retrieval_runs_by_turn(&turn.turn_id)?, vec![run_id]);
        let row = vault.retrieval_run(run_id)?.unwrap();
        let inputs = row.replay_inputs.expect("query-free input reference");
        assert_eq!(
            inputs.query_ref,
            Some(format!("eval://queries/empty-{index}"))
        );
        assert_eq!(
            inputs.config["channels"]["text_limit"],
            if skip_text {
                serde_json::json!(5)
            } else {
                serde_json::Value::Null
            }
        );
        assert!(
            !serde_json::to_string(&inputs)
                .unwrap()
                .contains("private unexecuted query")
        );
        assert!(row.result_ids.is_empty());
        assert!(row.pack_output.is_some());
    }
    assert!(deadline.was_cut_short());
    let uncaptured = vault.context_pack().run_with_telemetry()?;
    assert!(uncaptured.run_id.is_none());
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
#[test]
fn failed_unleased_creation_cleans_bound_root_not_replacement() -> crate::Result<()> {
    let temp = tempfile::tempdir()?;
    let original = temp.path().join("new-vault");
    let replacement = temp.path().join("existing-vault");
    let moved = temp.path().join("moved-new-vault");
    let config = VaultConfig::device();
    {
        let _existing = crate::Vault::open(&replacement, config.clone())?;
    }
    let data_before = std::fs::read(replacement.join("data.mdb"))?;
    let lock_before = std::fs::read(replacement.join("lock.mdb"))?;
    std::fs::create_dir(&original)?;
    let canonical = original.canonicalize()?;
    crate::store::test_hooks::arm_after_create_root_bind(canonical.clone(), move |path| {
        std::fs::rename(path, &moved).expect("rename captured empty root");
        std::fs::rename(&replacement, path).expect("install existing replacement");
    });
    crate::store::test_hooks::fail_initial_seed_commit_for(canonical);
    assert!(matches!(
        crate::Vault::open(&original, config),
        Err(crate::Error::InvalidConfig(_))
    ));
    assert_eq!(std::fs::read(original.join("data.mdb"))?, data_before);
    assert_eq!(std::fs::read(original.join("lock.mdb"))?, lock_before);
    assert!(!temp.path().join("moved-new-vault/data.mdb").exists());
    assert!(!temp.path().join("moved-new-vault/lock.mdb").exists());
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
#[test]
fn pathname_open_cannot_sweep_a_live_replacement_with_unbound_lock() -> crate::Result<()> {
    use std::os::fd::AsRawFd;
    let temp = tempfile::tempdir()?;
    let original = temp.path().join("original");
    let replacement = temp.path().join("replacement");
    let moved = temp.path().join("moved-original");
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let live = record(10);
    {
        let vault = crate::Vault::open(&replacement, config.clone())?;
        vault
            .store
            .record_context_pack_provisional_retrieval_run(&live)?;
    }
    // A shared lock models a live owner in another process. This process
    // must never use EX on the captured empty root as authority to delete B.
    let owner_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(replacement.join("oneiron.retrieval-telemetry.lock"))?;
    // SAFETY: owner_lock holds a live fd and flock takes no pointer.
    let acquired = unsafe { libc::flock(owner_lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    assert_eq!(acquired, 0);
    std::fs::create_dir(&original)?;
    let canonical = original.canonicalize()?;
    crate::store::test_hooks::arm_after_create_root_bind(canonical, move |path| {
        std::fs::rename(path, &moved).expect("rename captured root");
        std::fs::rename(&replacement, path).expect("install live vault");
    });
    let vault = crate::Vault::open(&original, config)?;
    assert!(
        vault
            .store
            .vault_meta
            .get(
                &vault.store.env.read_txn()?,
                &retrieval_run_key(live.run_id)
            )?
            .is_some()
    );
    assert!(vault.retrieval_run(live.run_id)?.is_none());
    drop(vault);
    // SAFETY: this process still owns the descriptor; release the test hold.
    let released = unsafe { libc::flock(owner_lock.as_raw_fd(), libc::LOCK_UN) };
    assert_eq!(released, 0);
    Ok(())
}

#[test]
fn trace_request_cannot_override_disabled_vault_capture() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let result = vault
        .context_pack()
        .search_text("not stored", 10)
        .replay_query_ref("eval://queries/disabled")
        .corpus_snapshot_ref("eval://corpus/disabled")
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    assert!(result.run_id.is_none());
    assert!(vault.retrieval_runs(10)?.is_empty());
    Ok(())
}
