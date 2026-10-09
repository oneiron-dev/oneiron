//! Retrieval telemetry, outcome records, and trace capture/fork-hash pins.

use super::*;

#[test]
fn retrieval_outcome_rejects_unknown_run_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let unknown_run_id = RetrievalRunId::now();

    let error = vault
        .record_retrieval_outcome(crate::store::RetrievalOutcome {
            run_id: unknown_run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })
        .expect_err("unknown run id should be rejected");
    assert!(matches!(error, Error::InvalidConfig(_)));
    assert!(vault.retrieval_outcomes(unknown_run_id)?.is_empty());
    Ok(())
}

#[test]
fn retrieval_outcome_rejects_active_write_transaction() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x3C);
    put_text(&vault, id, "outcome active transaction")?;

    let results = vault
        .query()
        .search_text("outcome active", 10)
        .run_with_telemetry()?;
    assert!(!results.value.is_empty());
    let run_id = results.run_id.expect("outcome telemetry run id");

    let error = vault
        .with_write_txn(|_wtxn| {
            vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
                run_id,
                key: "click".to_owned(),
                reward: Some(1.0),
                accepted: Some(true),
                metadata: BTreeMap::new(),
            })
        })
        .expect_err("outcome write should fail fast inside active write transaction");
    assert!(matches!(error, Error::ConcurrentWrite(_)));
    assert!(vault.retrieval_outcomes(run_id)?.is_empty());
    Ok(())
}

#[test]
fn phonetic_context_pack_candidate_without_vector_scores_remains_eligible() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x3C);
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .phonetic(&id, &["VAKYUOUS"])
        .commit()?;

    let pack = vault
        .context_pack()
        .search_text("", 10)
        .search_vector(&query, 10)
        .search_phonetic(&["VAKYUOUS"])
        .run()?;

    assert_eq!(
        pack.results
            .iter()
            .map(|entity| entity.id)
            .collect::<Vec<_>>(),
        [id]
    );
    assert!(pack.empty.is_none());
    Ok(())
}

#[test]
fn does_not_delete_stored_memory() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x37);
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    put_text_and_vector(
        &vault,
        id,
        "stored memory remains available after an abstention",
        [0.2, 0.979_795_9, 0.0, 0.0],
    )?;

    let pack = vault
        .context_pack()
        .search_text("", 10)
        .search_vector(&query, 10)
        .run()?;
    assert!(pack.results.is_empty());

    let direct_results = vault.query().search_vector(&query, 10).run()?;
    assert!(
        direct_results.iter().any(|scored| scored.id == id),
        "abstention must not change ordinary retrieval or remove the vector"
    );
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.entities.get(&rtxn, id.as_bytes())?.is_some(),
        "abstention must not delete the stored entity"
    );
    Ok(())
}

#[test]
fn direct_vault_zero_limit_telemetry_has_no_empty_reason() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x37);
    put_text_and_vector(&vault, id, "zero limit telemetry", [1.0, 0.0, 0.0, 0.0])?;

    let text = vault.search_text_with_telemetry("zero limit", 0)?;
    let vector = vault.search_vector_with_telemetry(&[1.0, 0.0, 0.0, 0.0], 0)?;
    assert!(text.value.is_empty());
    assert!(vector.value.is_empty());
    let text_run_id = text.run_id.expect("text zero-limit telemetry run id");
    let vector_run_id = vector.run_id.expect("vector zero-limit telemetry run id");

    let runs = vault.retrieval_runs(10)?;
    let text_run = runs
        .iter()
        .find(|run| run.run_id == text_run_id)
        .expect("text zero-limit telemetry row");
    let vector_run = runs
        .iter()
        .find(|run| run.run_id == vector_run_id)
        .expect("vector zero-limit telemetry row");
    assert!(text_run.result_ids.is_empty());
    assert!(vector_run.result_ids.is_empty());
    assert_eq!(text_run.empty_reason, None);
    assert_eq!(vector_run.empty_reason, None);
    Ok(())
}

#[test]
fn retrieval_telemetry_records_no_hit_empty_reason() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let results = vault
        .query()
        .search_text("definitelymissing", 10)
        .run_with_telemetry()?;
    assert!(results.value.is_empty());
    let run_id = results.run_id.expect("no-hit telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert!(runs[0].result_ids.is_empty());
    assert_eq!(runs[0].empty_reason.as_deref(), Some("NoData"));
    Ok(())
}

#[test]
fn retrieval_trace_fork_hash_replay_key_is_stable_for_same_inputs() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let first = entity_id(0xD3);
    let second = entity_id(0xD4);
    put_text_and_vector(&vault, first, "forkhash stable alpha", [1.0, 0.0, 0.0, 0.0])?;
    put_text_and_vector(&vault, second, "forkhash stable beta", [0.9, 0.1, 0.0, 0.0])?;

    let (first_run_id, first_trace) = captured_retrieval_run_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash stable", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(10),
    )?;
    let (second_run_id, second_trace) = captured_retrieval_run_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash stable", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(10),
    )?;

    assert_eq!(first_trace.fork_hash, second_trace.fork_hash);
    assert_eq!(
        rmp_serde::to_vec_named(&first_trace).expect("trace msgpack encode"),
        rmp_serde::to_vec_named(&second_trace).expect("trace msgpack encode")
    );
    assert_eq!(
        vault
            .retrieval_trace_by_fork_hash(first_trace.fork_hash)?
            .expect("trace by fork hash"),
        second_trace
    );
    vault.store.delete_retrieval_run(second_run_id)?;
    assert_eq!(
        vault
            .retrieval_trace_by_fork_hash(first_trace.fork_hash)?
            .expect("trace by fork hash after latest delete"),
        first_trace
    );
    vault.store.delete_retrieval_run(first_run_id)?;
    assert!(
        vault
            .retrieval_trace_by_fork_hash(first_trace.fork_hash)?
            .is_none()
    );
    Ok(())
}

#[test]
fn retrieval_telemetry_zero_limit_pipeline_has_no_empty_reason() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x3E);
    put_text_and_vector(
        &vault,
        id,
        "pipeline zero limit telemetry",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    let results = vault
        .query()
        .search_text("pipeline zero limit", 0)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 0)
        .run_with_telemetry()?;
    assert!(results.value.is_empty());
    let run_id = results.run_id.expect("zero-limit telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert!(runs[0].result_ids.is_empty());
    assert_eq!(runs[0].empty_reason, None);
    Ok(())
}

#[test]
fn retrieval_telemetry_omits_noop_ppr_and_phonetic_signals() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let phonetic = vault.query().search_phonetic(&[]).run_with_telemetry()?;
    assert!(phonetic.value.is_empty());
    let phonetic_run_id = phonetic.run_id.expect("phonetic noop telemetry run id");

    let ppr = vault.query().search_ppr(&[], 2).run_with_telemetry()?;
    assert!(ppr.value.is_empty());
    let ppr_run_id = ppr.run_id.expect("ppr noop telemetry run id");

    let combined_ppr = vault
        .query()
        .search_ppr(&[], 2)
        .expand_ppr(&[], 2)
        .run_with_telemetry()?;
    assert!(combined_ppr.value.is_empty());
    let combined_ppr_run_id = combined_ppr
        .run_id
        .expect("combined ppr noop telemetry run id");

    let runs = vault.retrieval_runs(10)?;
    let phonetic_run = runs
        .iter()
        .find(|run| run.run_id == phonetic_run_id)
        .expect("phonetic noop telemetry row");
    let ppr_run = runs
        .iter()
        .find(|run| run.run_id == ppr_run_id)
        .expect("ppr noop telemetry row");
    let combined_ppr_run = runs
        .iter()
        .find(|run| run.run_id == combined_ppr_run_id)
        .expect("combined ppr noop telemetry row");

    assert!(!phonetic_run.signals.contains(&RetrievalSignal::Phonetic));
    assert!(phonetic_run.score_breakdown.is_empty());
    assert!(!ppr_run.signals.contains(&RetrievalSignal::Ppr));
    assert!(ppr_run.score_breakdown.is_empty());
    assert!(!combined_ppr_run.signals.contains(&RetrievalSignal::Ppr));
    assert!(combined_ppr_run.score_breakdown.is_empty());
    Ok(())
}

#[test]
fn retrieval_telemetry_omits_ppr_for_noop_expansion() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let dead = entity_id(0x3D);
    put_status_claim(
        &vault,
        dead,
        "noop ppr telemetry",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;

    let results = vault
        .query()
        .search_text("noop ppr telemetry", 10)
        .expand_ppr(&[], 2)
        .run_with_telemetry()?;
    assert!(results.value.is_empty());
    let run_id = results.run_id.expect("noop ppr telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].signals, vec![RetrievalSignal::Text]);
    assert!(!runs[0].signals.contains(&RetrievalSignal::Ppr));
    assert_eq!(runs[0].claims_suppressed, 1);
    assert_eq!(runs[0].empty_reason.as_deref(), Some("AllActivated"));
    Ok(())
}

#[test]
fn telemetry_write_failure_is_best_effort_for_retrieval() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let id = entity_id(0x3A);
    put_text(&vault, id, "best effort telemetry")?;
    let vault_path = dir.path().canonicalize()?;

    crate::store::test_hooks::fail_next_retrieval_run_write_for(vault_path.clone());
    let pipeline = vault.query().search_text("best effort", 10).run()?;
    assert_eq!(pipeline.len(), 1);
    assert!(vault.retrieval_runs(1)?.is_empty());

    crate::store::test_hooks::fail_next_retrieval_run_write_for(vault_path);
    let direct = vault.search_text("best effort", 10)?;
    assert_eq!(direct.len(), 1);
    assert!(vault.retrieval_runs(1)?.is_empty());
    Ok(())
}

#[test]
fn retrieval_telemetry_skips_active_write_transaction() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x3B);
    put_text(&vault, id, "active write telemetry")?;

    vault.with_write_txn(|_wtxn| {
        let direct = vault.search_text("active", 10)?;
        assert_eq!(direct.len(), 1);
        let pipeline = vault.query().search_text("active", 10).run()?;
        assert_eq!(pipeline.len(), 1);
        Ok(())
    })?;

    assert!(vault.retrieval_runs(10)?.is_empty());
    Ok(())
}

#[test]
fn retrieval_telemetry_does_not_mutate_short_id_counters() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x35);
    put_text(&vault, id, "counter telemetry")?;

    let counter_key = crate::store::short_id_counter_key(1);
    let before = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&rtxn, &counter_key)?
            .map(|value| value.to_vec())
    };

    let results = vault.query().search_text("counter", 10).run()?;
    assert!(!results.is_empty());
    assert_eq!(vault.retrieval_runs(1)?.len(), 1);

    let after = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&rtxn, &counter_key)?
            .map(|value| value.to_vec())
    };
    assert_eq!(before, after);
    Ok(())
}

#[test]
fn pipeline_search_fails_closed_on_untrusted_text_index() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let a = entity_id(7);

    {
        let vault = Vault::open(temp_dir.path(), embedding_test_config())?;
        put_text(&vault, a, "alpha world")?;
    }

    let mut cfg = embedding_test_config();
    cfg.skip_text_index_manifest_check = true;
    let vault = Vault::open(temp_dir.path(), cfg)?;
    let err = vault
        .query()
        .search_text("alpha", 10)
        .run()
        .expect_err("pipeline text search must refuse untrusted index");
    assert!(
        matches!(err, Error::CorruptedIndex(_)),
        "expected CorruptedIndex, got {err:?}",
    );
    Ok(())
}

#[test]
fn replay_inputs_never_persist_text_from_any_query_channel() -> Result<()> {
    struct PrivateHyde;
    impl HydeExpander for PrivateHyde {
        fn id(&self) -> &str {
            "test/private-hyde"
        }
        fn expand(&self, _: &HydeRequest) -> Result<HydeExpansion> {
            Ok(HydeExpansion {
                grounded_query: "secret grounded query 2182".into(),
                hypothetical_answer: "secret hypothetical answer 2182".into(),
                embedding: vec![1.0, 0.0, 0.0, 0.0],
                subqueries: vec!["secret generated subquery 2182".into()],
            })
        }
        fn assess_evidence(&self, _: &CompletionRequest) -> Result<EvidenceVerdict> {
            Ok(EvidenceVerdict::Sufficient)
        }
    }
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0xC7);
    put_text_and_vector(&vault, id, "secret text query 2182", [1.0, 0.0, 0.0, 0.0])?;
    let run = vault
        .query()
        .search_text("secret text query 2182", 10)
        .rerank(
            &ReversingReranker,
            RerankOptions {
                top_n: 2,
                query: Some("secret rerank override 2182".into()),
            },
        )
        .hyde(
            &PrivateHyde,
            GroundingContext::default(),
            HydeOptions {
                channel_limit: 10,
                retry_once: true,
            },
        )
        .replay_query_ref("eval://queries/private-2182")
        .corpus_snapshot_ref("eval://corpus/private-2182")
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    let row = vault.retrieval_run(run.run_id.expect("captured"))?.unwrap();
    let inputs = row.replay_inputs.expect("query-free capture");
    assert_eq!(
        inputs.query_ref.as_deref(),
        Some("eval://queries/private-2182")
    );
    assert_eq!(inputs.config["channels"]["hyde_subquery_count"], 1);
    let encoded = serde_json::to_string(&inputs).unwrap();
    for text in [
        "secret text query",
        "secret rerank override",
        "secret grounded query",
        "secret hypothetical answer",
        "secret generated subquery",
    ] {
        assert!(!encoded.contains(text), "raw query leaked through {text}");
    }
    Ok(())
}

#[test]
fn opted_in_search_persists_retrieval_telemetry_across_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = crate::config::VaultConfig {
        retrieval_telemetry_capture: true,
        ..crate::config::VaultConfig::default()
    };
    let vault = crate::Vault::open(dir.path(), config)?;
    let id = entity_id(0xE7);
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"entity")
        .text(&id, &[("name", "amberlantern")])
        .commit()?;
    let result = vault.search_text_with_telemetry("amberlantern", 5)?;
    assert!(result.value.iter().any(|hit| hit.id == id));
    let run_id = result.run_id.expect("explicit capture must persist a run");
    assert!(
        vault
            .retrieval_run(run_id)?
            .expect("persisted run")
            .result_ids
            .contains(id.as_bytes())
    );
    drop(vault);
    let reopened = crate::Vault::open(dir.path(), crate::config::VaultConfig::default())?;
    assert!(reopened.retrieval_run(run_id)?.is_some());
    assert!(
        reopened
            .search_text_with_telemetry("amberlantern", 5)?
            .run_id
            .is_none()
    );
    assert_eq!(reopened.retrieval_runs(10)?.len(), 1);
    Ok(())
}
