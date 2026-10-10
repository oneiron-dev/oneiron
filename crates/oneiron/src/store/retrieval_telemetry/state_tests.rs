use super::*;
use crate::VaultConfig;
use crate::gate::retrieval_retention::DEFAULT_RETRIEVAL_AGE_SECS;
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

fn telemetry_config() -> VaultConfig {
    VaultConfig {
        retrieval_telemetry_capture: true,
        ..VaultConfig::default()
    }
}

fn install_retention_rows(
    vault: &crate::Vault,
    vault_age_secs: u64,
    vault_max_runs: u64,
    holder_age_secs: u64,
    holder_max_runs: u64,
) -> crate::Result<()> {
    use crate::gate::retrieval_retention::RETRIEVAL_RETENTION_ROWS_KEY;
    let mut value =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().unwrap().as_slice())
            .expect("shipped manifest decodes");
    let rmpv::Value::Map(entries) = &mut value else {
        unreachable!("default manifest map")
    };
    let rows = rmpv::Value::Array(vec![
        rmpv::Value::Map(vec![
            ("scope".into(), "vault".into()),
            ("max_age_secs".into(), vault_age_secs.into()),
            ("max_runs".into(), vault_max_runs.into()),
        ]),
        rmpv::Value::Map(vec![
            ("scope".into(), "holder".into()),
            ("max_age_secs".into(), holder_age_secs.into()),
            ("max_runs".into(), holder_max_runs.into()),
        ]),
        rmpv::Value::Map(vec![
            ("scope".into(), "precedence".into()),
            ("order".into(), "nested_narrowing".into()),
        ]),
    ]);
    let row = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(RETRIEVAL_RETENTION_ROWS_KEY))
        .expect("default manifest ships retention rows");
    row.1 = rows;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).expect("encode policy rows");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

/// Test the resolver boundary with a trusted row whose loaded diagnostics
/// reject the policy. Raw fixture insertion models replay/corruption; the
/// normal owner write door still validates before admission.
fn install_unusable_retention_manifest(vault: &crate::Vault, mode: &str) -> crate::Result<()> {
    let mut value =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().unwrap().as_slice())
            .expect("shipped manifest decodes");
    let rmpv::Value::Map(entries) = &mut value else {
        unreachable!("manifest map")
    };
    let row = entries
        .iter_mut()
        .find(|(key, _)| {
            key.as_str() == Some(crate::gate::retrieval_retention::RETRIEVAL_RETENTION_ROWS_KEY)
        })
        .expect("shipped retention rows");
    row.1 = rmpv::Value::Array(vec![
        rmpv::Value::Map(vec![
            ("scope".into(), "vault".into()),
            ("max_age_secs".into(), 1_u64.into()),
            (
                "max_runs".into(),
                if mode == "malformed_rows" {
                    "not a count".into()
                } else {
                    1_u64.into()
                },
            ),
        ]),
        rmpv::Value::Map(vec![
            ("scope".into(), "precedence".into()),
            ("order".into(), "nested_narrowing".into()),
        ]),
    ]);
    match mode {
        "unsupported_schema" | "unsupported_engine" => {
            let key = if mode == "unsupported_schema" {
                "schema_version"
            } else {
                "min_engine_version"
            };
            entries
                .iter_mut()
                .find(|(k, _)| k.as_str() == Some(key))
                .expect("manifest field")
                .1 = "999.0.0".into();
        }
        "malformed_rows" => {}
        _ => unreachable!("test mode"),
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).expect("encode rejected policy");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

#[test]
fn rejected_retention_policy_never_authorizes_deletion_or_blocks_reopen() -> crate::Result<()> {
    for mode in ["malformed_rows", "unsupported_schema", "unsupported_engine"] {
        let clock = crate::ports::ManualClock::new(1_000_000);
        let mut config = telemetry_config();
        config.store_clock = clock.bundle();
        let dir = tempfile::tempdir()?;
        let first = record(1_000_000);
        let second = record(1_000_000);
        let provisional = record(1_000_000);
        let attempted = record(1_000_000);
        {
            let vault = crate::Vault::open(dir.path(), config.clone())?;
            vault.store.record_retrieval_run(&first)?;
            vault.store.record_retrieval_run(&second)?;
            vault
                .store
                .record_context_pack_provisional_retrieval_run(&provisional)?;
            install_unusable_retention_manifest(&vault, mode)?;
            let txn = vault.store.env.read_txn()?;
            let resolved = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
            assert!(
                resolved.diagnostics.loaded_manifest_forces_fail_closed(),
                "{mode}"
            );
            assert!(resolved.retrieval_retention_policy().is_none(), "{mode}");
            drop(txn);
            clock.set(1_000_000 + DEFAULT_RETRIEVAL_AGE_SECS + 1);
            assert!(
                vault.store.record_retrieval_run(&attempted).is_err(),
                "{mode}"
            );
            assert!(
                vault
                    .store
                    .finalize_context_pack_retrieval_run(RetrievalRunFinalize {
                        run_id: provisional.run_id,
                        elapsed_us: 1,
                        total_in_scope: 0,
                        claims_suppressed: 0,
                        surfaced_result_ids: &[],
                        empty_reason: None,
                        pack_output: None,
                        pack_config: None,
                    })
                    .is_err(),
                "{mode}"
            );
            assert_eq!(vault.retrieval_runs(10)?.len(), 2, "{mode}");
        }
        let vault = crate::Vault::open(dir.path(), config)?;
        assert!(vault.retrieval_run(first.run_id)?.is_some(), "{mode}");
        assert!(vault.retrieval_run(second.run_id)?.is_some(), "{mode}");
        assert!(vault.retrieval_run(attempted.run_id)?.is_none(), "{mode}");
    }
    Ok(())
}

#[test]
fn published_retention_evicts_old_runs_and_their_sidecars() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault_with(telemetry_config());
    // The holder asks for more rows; the vault ceiling still wins.
    install_retention_rows(
        &vault,
        DEFAULT_RETRIEVAL_AGE_SECS,
        3,
        DEFAULT_RETRIEVAL_AGE_SECS,
        9,
    )?;
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
    for _ in 0..3 {
        vault.store.record_retrieval_run(&record(11))?;
    }
    assert_eq!(vault.retrieval_runs(10)?.len(), 3);
    assert!(vault.retrieval_run(first.run_id)?.is_none());
    assert!(vault.retrieval_outcomes(first.run_id)?.is_empty());
    assert!(vault.retrieval_runs_by_turn(&turn.turn_id)?.is_empty());
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
    assert!(!super::run_store::RETRIEVAL_RUN_PROVISIONAL.contains(
        &vault.store,
        &vault.store.env.read_txn()?,
        &orphan.run_id
    )?);
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
            pack_output: None,
            pack_config: None,
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
    // The already-bound A cannot be used to open B. Refusal happens before
    // reconciliation; it is not permission to discard B's live run.
    assert!(matches!(
        crate::Vault::open(&original, config.clone()),
        Err(crate::Error::InvalidConfig(_))
    ));
    let vault = crate::Vault::open(&original, config.clone())?;
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
    // Even without another owner's lock, non-Linux cannot prove that an
    // unfinished row is orphaned, so another fresh open must not sweep it.
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
