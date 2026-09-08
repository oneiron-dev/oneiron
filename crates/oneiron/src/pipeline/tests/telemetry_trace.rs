//! Retrieval telemetry, outcome records, and trace capture/fork-hash pins.

use super::*;

#[test]
fn retrieval_telemetry_records_vector_text_and_ppr_runs() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = entity_id(0x31);
    let b = entity_id(0x32);

    vault
        .batch()
        .put(&a, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&a, &[("body", "telemetry alpha")])
        .vector(&a, &[1.0, 0.0, 0.0, 0.0])
        .put(&b, 1, TimeRange { start: 2, end: 2 }, 2, b"payload")
        .vector(&b, &[0.0, 1.0, 0.0, 0.0])
        .edge(&a, EdgeKind::Supports, &b, 1.0)
        .commit()?;

    let vector = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()?;
    let text = vault.query().search_text("alpha", 10).run()?;
    let ppr = vault.query().search_ppr(&[a], 2).run()?;
    assert!(!vector.is_empty());
    assert!(!text.is_empty());
    assert!(!ppr.is_empty());

    let runs = vault.retrieval_runs(10)?;
    let vector_run = runs
        .iter()
        .find(|run| run.signals == vec![RetrievalSignal::Vector])
        .expect("vector telemetry run");
    assert_eq!(vector_run.action, RetrievalAction::Pipeline);
    assert!(vector_run.result_ids.contains(a.as_bytes()));
    assert!(vector_run.score_breakdown.iter().any(|entry| {
        entry
            .components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Vector)
    }));

    let text_run = runs
        .iter()
        .find(|run| run.signals == vec![RetrievalSignal::Text])
        .expect("text telemetry run");
    assert!(text_run.result_ids.contains(a.as_bytes()));
    assert!(text_run.score_breakdown.iter().any(|entry| {
        entry
            .components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Text)
    }));

    let ppr_run = runs
        .iter()
        .find(|run| run.signals == vec![RetrievalSignal::Ppr])
        .expect("ppr telemetry run");
    assert!(ppr_run.score_breakdown.iter().any(|entry| {
        entry
            .components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Ppr)
    }));
    Ok(())
}

#[test]
fn retrieval_outcome_writer_is_idempotent() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x33);
    put_text(&vault, id, "outcome telemetry")?;

    let results = vault
        .query()
        .search_text("outcome", 10)
        .run_with_telemetry()?;
    assert!(!results.value.is_empty());
    let run_id = results.run_id.expect("outcome telemetry run id");

    let mut metadata = BTreeMap::new();
    metadata.insert("source".to_owned(), "unit-test".to_owned());
    vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
        run_id,
        key: "click".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: metadata.clone(),
    })?;
    metadata.insert("revision".to_owned(), "2".to_owned());
    vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
        run_id,
        key: "click".to_owned(),
        reward: Some(0.5),
        accepted: Some(false),
        metadata,
    })?;

    let outcomes = vault.retrieval_outcomes(run_id)?;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].key, "click");
    assert_eq!(outcomes[0].reward, Some(0.5));
    assert_eq!(outcomes[0].accepted, Some(false));
    assert_eq!(
        outcomes[0].metadata.get("revision").map(String::as_str),
        Some("2")
    );
    Ok(())
}

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
fn context_pack_records_context_pack_telemetry() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x34);
    put_text(&vault, id, "context telemetry")?;

    let pack = vault.context_pack().search_text("context", 10).run()?;
    assert_eq!(pack.results.len(), 1);

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].action, RetrievalAction::ContextPack);
    assert_eq!(runs[0].signals, vec![RetrievalSignal::Text]);
    assert_eq!(runs[0].elapsed_us, pack.stats.query_time_us);
    assert!(runs[0].result_ids.contains(id.as_bytes()));
    Ok(())
}

#[test]
fn weak_evidence_abstains() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x36);
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    put_text_and_vector(
        &vault,
        id,
        "stored evidence unrelated to the requested keyword",
        [0.2, 0.979_795_9, 0.0, 0.0],
    )?;

    let pack = vault
        .context_pack()
        .search_text("", 10)
        .search_vector(&query, 10)
        .run()?;

    assert!(
        pack.results.is_empty(),
        "the context pack must structurally withhold weak evidence"
    );
    assert!(pack.neighbors.is_empty());
    assert_eq!(pack.stats.candidates_considered, 1);
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
fn confidence_surfaced() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x38);
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    put_text_and_vector(
        &vault,
        id,
        "stored evidence with an insufficient semantic match",
        [0.2, 0.979_795_9, 0.0, 0.0],
    )?;

    let pack = vault
        .context_pack()
        .search_text("", 10)
        .search_vector(&query, 10)
        .run()?;

    let empty = pack
        .empty
        .as_ref()
        .expect("abstention must surface a typed empty-context response");
    assert_eq!(
        empty.reason,
        crate::context_pack::EmptyReason::BelowThreshold
    );
    let encoded = serde_json::to_value(empty).expect("empty context serializes");
    assert_eq!(encoded["reason"], "below_threshold");
    Ok(())
}

#[test]
fn poor_score_gap_abstains() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    put_vector(&vault, entity_id(0x39), [0.4, 1.0, 0.0, 0.0])?;
    put_vector(&vault, entity_id(0x3A), [0.39, 1.0, 0.0, 0.0])?;

    let pack = vault.context_pack().search_vector(&query, 10).run()?;

    assert!(pack.results.is_empty());
    assert_eq!(
        pack.empty.as_ref().map(|empty| empty.reason),
        Some(crate::context_pack::EmptyReason::BelowThreshold)
    );
    Ok(())
}

#[test]
fn anomalous_text_abstains() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x3B);
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    put_text_and_vector(
        &vault,
        id,
        "strong vector candidate must still be withheld for anomalous text",
        [1.0, 0.0, 0.0, 0.0],
    )?;

    let pack = vault
        .context_pack()
        .search_text("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 10)
        .search_vector(&query, 10)
        .run()?;

    assert!(pack.results.is_empty());
    assert_eq!(
        pack.empty.as_ref().map(|empty| empty.reason),
        Some(crate::context_pack::EmptyReason::BelowThreshold)
    );
    Ok(())
}

#[test]
fn parsed_temporal_bounds_record_temporal_telemetry_signal() -> Result<()> {
    const NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x35);
    put_text_with_time(
        &vault,
        id,
        "recent temporal telemetry",
        TimeRange {
            start: NOW - 60,
            end: NOW - 60,
        },
        NOW - 60,
    )?;

    let results = vault
        .query()
        .search_text("recent temporal telemetry", 10)
        .with_temporal_now(NOW)
        .run_with_telemetry()?;
    assert_eq!(results.value.len(), 1);
    let run_id = results.run_id.expect("parsed temporal telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(
        runs[0].signals,
        vec![RetrievalSignal::Text, RetrievalSignal::Temporal]
    );
    Ok(())
}

#[test]
fn direct_vault_searches_emit_retrieval_telemetry() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x36);
    put_text_and_vector(&vault, id, "direct telemetry", [1.0, 0.0, 0.0, 0.0])?;

    let vector = vault.search_vector_with_telemetry(&[1.0, 0.0, 0.0, 0.0], 10)?;
    let text = vault.search_text_with_telemetry("direct", 10)?;
    assert_eq!(vector.value.len(), 1);
    assert_eq!(text.value.len(), 1);
    let vector_run_id = vector.run_id.expect("direct vector telemetry run id");
    let text_run_id = text.run_id.expect("direct text telemetry run id");

    let runs = vault.retrieval_runs(10)?;
    let vector_run = runs
        .iter()
        .find(|run| {
            run.action == RetrievalAction::VaultSearch
                && run.signals == vec![RetrievalSignal::Vector]
        })
        .expect("direct vector telemetry run");
    assert_eq!(vector_run.run_id, vector_run_id);
    assert_eq!(vector_run.claims_suppressed, 0);
    assert_eq!(vector_run.result_ids, vec![*id.as_bytes()]);
    assert!(vector_run.score_breakdown.iter().any(|entry| {
        entry
            .components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Vector)
    }));

    let text_run = runs
        .iter()
        .find(|run| {
            run.action == RetrievalAction::VaultSearch && run.signals == vec![RetrievalSignal::Text]
        })
        .expect("direct text telemetry run");
    assert_eq!(text_run.run_id, text_run_id);
    assert_eq!(text_run.claims_suppressed, 0);
    assert_eq!(text_run.result_ids, vec![*id.as_bytes()]);
    assert!(text_run.score_breakdown.iter().any(|entry| {
        entry
            .components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Text)
    }));
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
fn retrieval_trace_capture_is_flag_off_by_default() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0xB0);
    put_text_and_vector(&vault, id, "trace default off", [1.0, 0.0, 0.0, 0.0])?;

    let results = vault
        .query()
        .search_text("trace default", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run_with_telemetry()?;
    assert_eq!(results.value.len(), 1);
    let run_id = results.run_id.expect("trace default off run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].trace, None);
    assert_eq!(runs[0].result_ids, vec![*id.as_bytes()]);
    Ok(())
}

#[test]
fn retrieval_trace_capture_records_all_pipeline_stages() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let text_id = entity_id(0xB1);
    let vector_id = entity_id(0xB2);

    put_text_and_vector(&vault, text_id, "trace stage fixture", [1.0, 0.0, 0.0, 0.0])?;
    put_text_and_vector(
        &vault,
        vector_id,
        "trace stage neighbor",
        [0.8, 0.2, 0.0, 0.0],
    )?;

    let results = vault
        .query()
        .search_text("trace stage fixture", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    assert!(!results.value.is_empty());
    let run_id = results.run_id.expect("trace capture run id");

    let run = vault
        .retrieval_run(run_id)?
        .expect("trace capture telemetry run");
    let trace = run.trace.expect("trace should be captured");

    assert!(trace.per_channel.len() >= 2);
    assert!(
        trace
            .per_channel
            .iter()
            .any(|channel| channel.signal == RetrievalSignal::Text)
    );
    assert!(
        trace
            .per_channel
            .iter()
            .any(|channel| channel.signal == RetrievalSignal::Vector)
    );
    for channel in &trace.per_channel {
        assert_eq!(channel.stage, RetrievalTraceStage::PerChannel);
        assert!(!channel.candidates.is_empty());
        assert!(channel.candidates.iter().all(|candidate| {
            candidate.final_score.is_finite()
                && candidate
                    .components
                    .iter()
                    .any(|component| component.signal == channel.signal)
        }));
    }

    for stage in [
        &trace.fused,
        &trace.blended,
        &trace.reranked,
        &trace.final_stage,
    ] {
        assert!(!stage.candidates.is_empty());
        assert!(
            stage
                .candidates
                .iter()
                .all(|candidate| candidate.final_score.is_finite())
        );
    }
    assert_eq!(trace.fused.stage, RetrievalTraceStage::Fused);
    assert!(
        trace
            .fused
            .candidates
            .iter()
            .all(|candidate| candidate.final_score > 0.0 && candidate.final_score < 1.0),
        "fused trace should carry rank-fusion scores, not neutral blend placeholders"
    );
    assert_eq!(trace.blended.stage, RetrievalTraceStage::Blended);
    assert_eq!(trace.reranked.stage, RetrievalTraceStage::Reranked);
    assert_eq!(trace.final_stage.stage, RetrievalTraceStage::Final);
    assert_eq!(trace.reranked.candidates, trace.final_stage.candidates);
    assert_eq!(
        trace
            .final_stage
            .candidates
            .iter()
            .map(|candidate| candidate.result_id)
            .collect::<Vec<_>>(),
        run.result_ids
    );
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
fn retrieval_trace_fork_hash_canonicalizes_phonetic_query_codes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0xDA);
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .phonetic(&id, &["ALFA", "BETA"])
        .commit()?;

    let first = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_phonetic(&["BETA", "ALFA", "ALFA"])
            .limit(10),
    )?;
    let second = captured_retrieval_trace(
        &vault,
        vault.query().search_phonetic(&["ALFA", "BETA"]).limit(10),
    )?;

    assert_eq!(first.fork_hash, second.fork_hash);
    assert_eq!(
        rmp_serde::to_vec_named(&first).expect("trace msgpack encode"),
        rmp_serde::to_vec_named(&second).expect("trace msgpack encode")
    );
    Ok(())
}

#[test]
fn retrieval_trace_fork_hash_uses_effective_trace_candidate_set() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let live = entity_id(0xDB);
    vault
        .batch()
        .put(
            &live,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &claim_body_bytes(
                crate::claim::ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Active,
                false,
            ),
        )
        .phonetic(&live, &["EFFECTIVE"])
        .commit()?;

    let before = captured_retrieval_trace(
        &vault,
        vault.query().search_phonetic(&["EFFECTIVE"]).limit(10),
    )?;

    let hidden = entity_id(0xDC);
    vault
        .batch()
        .put(
            &hidden,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &claim_body_bytes(
                crate::claim::ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Retracted,
                false,
            ),
        )
        .phonetic(&hidden, &["EFFECTIVE"])
        .commit()?;

    let after = captured_retrieval_trace(
        &vault,
        vault.query().search_phonetic(&["EFFECTIVE"]).limit(10),
    )?;

    assert_eq!(
        rmp_serde::to_vec_named(&before).expect("trace msgpack encode"),
        rmp_serde::to_vec_named(&after).expect("trace msgpack encode"),
        "a D19-suppressed raw posting must not enter the emitted trace"
    );
    assert_eq!(
        before.fork_hash, after.fork_hash,
        "fork hash must follow the emitted trace candidate set, not raw pre-gate postings"
    );
    Ok(())
}

#[test]
fn retrieval_trace_fork_hash_changes_for_query_config_flags_weights_and_candidates() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let first = entity_id(0xD5);
    let second = entity_id(0xD6);
    put_text_and_vector(&vault, first, "forkhash alpha base", [1.0, 0.0, 0.0, 0.0])?;
    put_text_and_vector(
        &vault,
        second,
        "forkhash alpha neighbor",
        [0.8, 0.2, 0.0, 0.0],
    )?;

    let base = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash alpha", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(10),
    )?;
    let query_changed = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash base", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(10),
    )?;
    let config_changed = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash alpha", 1)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
            .limit(1),
    )?;
    let flags_changed = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash alpha", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .boost_salience()
            .limit(10),
    )?;
    let weights_changed = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash alpha", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .rank_profile(
                crate::config::Bm25RankProfile::default()
                    .with_channel_weight(crate::analyzer::AnalyzerChannel::Surface, 0.5),
            )
            .limit(10),
    )?;

    let added_candidate = entity_id(0x57);
    put_text_and_vector(
        &vault,
        added_candidate,
        "forkhash alpha extra",
        [0.7, 0.3, 0.0, 0.0],
    )?;
    let candidates_changed = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("forkhash alpha", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .limit(10),
    )?;

    assert_ne!(base.fork_hash, query_changed.fork_hash);
    assert_ne!(base.fork_hash, config_changed.fork_hash);
    assert_ne!(base.fork_hash, flags_changed.fork_hash);
    assert_ne!(base.fork_hash, weights_changed.fork_hash);
    assert_ne!(base.fork_hash, candidates_changed.fork_hash);
    Ok(())
}

#[test]
fn retrieval_trace_filters_d19_suppressed_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let live = entity_id(0xC3);
    let retracted = entity_id(0xC4);
    put_status_claim(
        &vault,
        live,
        "tracegate tracegate",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
        false,
    )?;
    put_status_claim(
        &vault,
        retracted,
        "tracegate tracegate tracegate",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;

    let results = vault
        .query()
        .search_text("tracegate", 10)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    assert!(results.value.iter().any(|scored| scored.id == live));
    assert!(!results.value.iter().any(|scored| scored.id == retracted));
    let run = vault
        .retrieval_run(results.run_id.expect("trace run id"))?
        .expect("trace run");
    let trace = run.trace.expect("trace captured");

    let text_channel = trace
        .per_channel
        .iter()
        .find(|channel| channel.signal == RetrievalSignal::Text)
        .expect("text trace channel");
    assert!(trace_candidates_contain(&text_channel.candidates, live));
    assert!(!trace_candidates_contain(
        &text_channel.candidates,
        retracted
    ));
    for stage in [
        &trace.fused,
        &trace.blended,
        &trace.reranked,
        &trace.final_stage,
    ] {
        assert!(!trace_candidates_contain(&stage.candidates, retracted));
    }
    Ok(())
}

#[test]
fn retrieval_trace_filters_scoped_vector_candidates() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let out_of_scope = entity_id(0xC5);
    let in_scope = entity_id(0xC6);
    let repo_a =
        RepoRef::parse("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277")?;
    let repo_b =
        RepoRef::parse("github:oneiron-dev/other#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
    put_codebase_vector(
        &vault,
        out_of_scope,
        "project.alpha",
        repo_a,
        [1.0, 0.0, 0.0, 0.0],
    )?;
    put_codebase_vector(
        &vault,
        in_scope,
        "project.beta",
        repo_b,
        [0.0, 1.0, 0.0, 0.0],
    )?;

    let results = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .filter_project_id("project.beta")
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    assert_eq!(results.value.len(), 1);
    assert_eq!(results.value[0].id, in_scope);
    let run = vault
        .retrieval_run(results.run_id.expect("trace run id"))?
        .expect("trace run");
    let trace = run.trace.expect("trace captured");

    let vector_channel = trace
        .per_channel
        .iter()
        .find(|channel| channel.signal == RetrievalSignal::Vector)
        .expect("vector trace channel");
    assert!(trace_candidates_contain(
        &vector_channel.candidates,
        in_scope
    ));
    assert!(!trace_candidates_contain(
        &vector_channel.candidates,
        out_of_scope
    ));
    for stage in [
        &trace.fused,
        &trace.blended,
        &trace.reranked,
        &trace.final_stage,
    ] {
        assert!(!trace_candidates_contain(&stage.candidates, out_of_scope));
    }
    Ok(())
}

#[test]
fn retrieval_trace_fused_scores_are_bounded_by_trace_limit() {
    let first = entity_id(0xC1);
    let ignored = entity_id(0xC2);

    let fused = retrieval_trace_fused_scores(
        &[vec![
            ScoredEntity {
                id: first,
                score: 1.0,
            },
            ScoredEntity {
                id: ignored,
                score: 0.9,
            },
        ]],
        1,
    );

    assert_eq!(fused.len(), 1);
    assert_eq!(fused[0].id, first);
}

#[test]
fn retrieval_trace_is_decoupled_from_outcome_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let traced_id = entity_id(0xB3);
    let outcome_only_id = entity_id(0xB4);
    put_text(&vault, traced_id, "traceonlyalpha")?;
    put_text(&vault, outcome_only_id, "outcomeonlybeta")?;

    let traced = vault
        .query()
        .search_text("traceonlyalpha", 10)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    assert_eq!(traced.value.len(), 1);
    let traced_run_id = traced.run_id.expect("traced run id");
    let traced_run = vault
        .retrieval_run(traced_run_id)?
        .expect("traced telemetry row");
    assert!(traced_run.trace.is_some());
    assert!(vault.retrieval_outcomes(traced_run_id)?.is_empty());

    let outcome_only = vault
        .query()
        .search_text("outcomeonlybeta", 10)
        .run_with_telemetry()?;
    assert_eq!(outcome_only.value.len(), 1);
    let outcome_run_id = outcome_only.run_id.expect("outcome-only run id");
    vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
        run_id: outcome_run_id,
        key: "click".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;
    let outcome_run = vault
        .retrieval_run(outcome_run_id)?
        .expect("outcome-only telemetry row");
    assert!(outcome_run.trace.is_none());
    assert_eq!(vault.retrieval_outcomes(outcome_run_id)?.len(), 1);
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
fn retrieval_runs_returns_bounded_newest_first() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let first_id = entity_id(0x38);
    let second_id = entity_id(0x39);
    let third_id = entity_id(0x3A);

    put_text(&vault, first_id, "alphaone")?;
    assert_eq!(vault.search_text("alphaone", 10)?.len(), 1);
    let first_run = vault.retrieval_runs(1)?[0].run_id;
    std::thread::sleep(std::time::Duration::from_millis(2));

    put_text(&vault, second_id, "betatwo")?;
    assert_eq!(vault.search_text("betatwo", 10)?.len(), 1);
    let second_run = vault.retrieval_runs(1)?[0].run_id;
    std::thread::sleep(std::time::Duration::from_millis(2));

    put_text(&vault, third_id, "gammathree")?;
    assert_eq!(vault.search_text("gammathree", 10)?.len(), 1);
    let third_run = vault.retrieval_runs(1)?[0].run_id;

    let newest_two = vault.retrieval_runs(2)?;
    assert_eq!(newest_two.len(), 2);
    assert_eq!(newest_two[0].run_id, third_run);
    assert_eq!(newest_two[1].run_id, second_run);
    assert!(!newest_two.iter().any(|run| run.run_id == first_run));
    assert!(vault.retrieval_runs(0)?.is_empty());
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
