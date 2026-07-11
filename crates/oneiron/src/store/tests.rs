use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::job_queue::{EnqueueJob, EnqueueOutcome, JobQueue};
use crate::receipt::MAX_RECEIPT_QUERY_SCAN;
use crate::temporal::TimeRange;
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn entity_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("test ids should be valid")
}

#[test]
fn storage_abi_gate_is_strictly_symmetric_for_every_stored_version() {
    for stored in 0..=u16::MAX {
        let result = gate_storage_abi_value(Some(stored), STORAGE_ABI_VERSION, false);
        if stored == STORAGE_ABI_VERSION {
            assert!(!result.expect("equal ABI versions must open"));
        } else {
            assert!(
                matches!(
                    result,
                    Err(Error::StorageAbiVersionChanged {
                        stored: Some(actual),
                        current: STORAGE_ABI_VERSION,
                    }) if actual == stored
                ),
                "stored ABI {stored} must fail against current ABI {STORAGE_ABI_VERSION}",
            );
        }
    }

    assert!(
        gate_storage_abi_value(None, STORAGE_ABI_VERSION, true)
            .expect("a genuinely new vault initializes its ABI row"),
    );
    assert!(matches!(
        gate_storage_abi_value(None, STORAGE_ABI_VERSION, false),
        Err(Error::StorageAbiVersionChanged {
            stored: None,
            current: STORAGE_ABI_VERSION,
        })
    ));
}

fn put_text(vault: &Vault, id: EntityId, text: &str) -> Result<()> {
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&id, &[("body", text)])
        .commit()
}

fn raw_retrieval_run_row(vault: &Vault, run_id: RetrievalRunId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .get(&rtxn, &retrieval_run_key(run_id))?
        .map(<[u8]>::to_vec)
        .ok_or(Error::CorruptedIndex("retrieval run telemetry"))
}

fn raw_retrieval_outcome_row(
    vault: &Vault,
    run_id: RetrievalRunId,
    outcome_key: &str,
) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .get(&rtxn, &retrieval_outcome_key(run_id, outcome_key))?
        .map(<[u8]>::to_vec)
        .ok_or(Error::CorruptedIndex("retrieval outcome telemetry"))
}

fn record_click_outcome(vault: &Vault, run_id: RetrievalRunId) -> Result<()> {
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id,
        key: "click".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })
}

fn assert_secret_scan_rejected(error: Error, expected_reason: &'static str) {
    match error {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert_eq!(outcome, "deny");
            assert_eq!(
                reason_codes.as_slice(),
                &["gate.secret_scan.detected", expected_reason]
            );
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
}

fn synthetic_gate_decision_id(prefix: u8, value: u64) -> GateDecisionId {
    let mut bytes = [prefix; 16];
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    GateDecisionId::from_bytes(&bytes)
}

fn gate_decision(
    decision_id: GateDecisionId,
    created_at: u64,
    grant_ref: Option<&str>,
) -> GateDecisionRecord {
    GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id,
        created_at,
        outcome: "approved".to_owned(),
        reason_codes: vec!["gate.test.receipt_family".to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: "agent".to_owned(),
        actor_ref: None,
        content_kind: "claim".to_owned(),
        policy_manifest_version: "v0".to_owned(),
        claim_id: None,
        grant_ref: grant_ref.map(str::to_owned),
        diff_handle: vec![0xAA],
        read_frontier_hash: [0xBB; 32],
    }
}

#[test]
fn grant_ref_index_reaches_a_receipt_beyond_the_legacy_scan_budget() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let grant_ref = "bundle:dreamer_run:older-target";
    // The old ledger query reads newest-first.  Keep the matching record
    // below 100,001 newer unrelated records so a bounded global scan cannot
    // rediscover it by accident.
    let target = gate_decision(synthetic_gate_decision_id(0x01, 1), 1, Some(grant_ref));
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &target)?;
        for offset in 0..=MAX_RECEIPT_QUERY_SCAN {
            let filler = gate_decision(
                synthetic_gate_decision_id(0xF1, offset as u64),
                10 + offset as u64,
                None,
            );
            vault.store.append_gate_decision_in_txn(wtxn, &filler)?;
        }
        Ok(())
    })?;

    let legacy_scan = vault.store.gate_decisions(MAX_RECEIPT_QUERY_SCAN)?;
    assert_eq!(legacy_scan.len(), MAX_RECEIPT_QUERY_SCAN);
    assert!(
        legacy_scan
            .iter()
            .all(|record| record.grant_ref.as_deref() != Some(grant_ref))
    );
    assert_eq!(
        vault.store.gate_decisions_for_grant_ref(grant_ref)?,
        vec![target]
    );
    Ok(())
}

#[test]
fn open_backfills_receipt_family_sidecars_without_a_storage_abi_change() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = VaultConfig::device();
    let run_id = "legacy-receipt-family-run";
    let grant_ref = "bundle:dreamer_run:legacy-receipt-family-run";
    let decision = gate_decision(synthetic_gate_decision_id(0x44, 7), 7, Some(grant_ref));
    let pending = PendingGateConsentRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        claim_id: [0x77; 16],
        decision_id: decision.decision_id,
        created_at: 7,
        diff_handle: decision.diff_handle.clone(),
        read_frontier_hash: decision.read_frontier_hash,
        reason_codes: vec!["gate.pending.receipt_family".to_owned()],
        dreamer_run_id: Some(run_id.to_owned()),
    };

    let vault = Vault::open(dir.path(), config.clone())?;
    let queue = JobQueue::new(&vault);
    let EnqueueOutcome::Enqueued(job) = queue.enqueue(EnqueueJob {
        kind: "legacy-receipt-family".to_owned(),
        payload: b"legacy".to_vec(),
        dedupe_key: None,
        run_id: Some(run_id.to_owned()),
        now: 7,
    })?
    else {
        panic!("expected a fresh legacy job");
    };
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &decision)?;
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &pending)?;

        for prefix in [
            GATE_DECISION_GRANT_REF_INDEX_PREFIX,
            PENDING_GATE_CONSENT_RUN_INDEX_PREFIX,
            PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX,
            PENDING_GATE_CONSENT_HASH_INDEX_PREFIX,
            PENDING_GATE_CONSENT_INDEX_STATE_PREFIX,
            JOB_RUN_INDEX_PREFIX,
        ] {
            let mut keys = Vec::new();
            for row in vault.store.vault_meta.prefix_iter(&*wtxn, prefix)? {
                let (key, _) = row?;
                keys.push(key.to_vec());
            }
            for key in keys {
                vault.store.vault_meta.delete(wtxn, &key)?;
            }
        }
        vault
            .store
            .vault_meta
            .delete(wtxn, RECEIPT_FAMILY_INDEX_VERSION_KEY)?;
        Ok(())
    })?;
    drop(vault);

    let reopened = Vault::open(dir.path(), config)?;
    assert_eq!(
        JobQueue::new(&reopened).list_run(run_id)?,
        vec![
            JobQueue::new(&reopened)
                .get(job.id)?
                .expect("backfilled job")
        ]
    );
    assert_eq!(
        reopened.store.gate_decisions_for_grant_ref(grant_ref)?,
        vec![decision]
    );
    assert_eq!(
        reopened.store.pending_gate_consents_for_run(run_id)?,
        vec![pending.clone()]
    );
    assert_eq!(
        reopened.store.pending_gate_consents_for_group_key(run_id)?,
        vec![pending]
    );
    let rtxn = reopened.store.env.read_txn()?;
    assert_eq!(
        reopened
            .store
            .vault_meta
            .get(&rtxn, RECEIPT_FAMILY_INDEX_VERSION_KEY)?,
        Some(&[RECEIPT_FAMILY_INDEX_VERSION][..])
    );
    Ok(())
}

#[test]
fn retrieval_run_without_trace_omits_trace_field_from_msgpack() -> Result<()> {
    let record = RetrievalRunRecord::new(
        RetrievalRunId::now(),
        RetrievalAction::Pipeline,
        1,
        2,
        vec![RetrievalSignal::Text],
        Vec::new(),
        0,
        0,
        None,
    );

    assert!(record.trace.is_none());
    let encoded = encode_retrieval_run(&record)?;
    let encoded_value =
        rmpv::decode::read_value(&mut &encoded[..]).expect("encoded retrieval run msgpack");
    let rmpv::Value::Map(fields) = encoded_value else {
        panic!("encoded retrieval run must be a msgpack map");
    };
    assert!(
        fields.iter().all(|(key, _)| key.as_str() != Some("trace")),
        "flag-off trace extension must omit the top-level trace key"
    );
    let decoded = decode_retrieval_run(&encoded)?;
    assert_eq!(decoded.trace, None);
    Ok(())
}

#[test]
fn context_pack_finalization_preserves_reranked_trace_stage() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let kept = entity_id(0xD1);
    let dropped = entity_id(0xD2);
    let score_breakdown = vec![
        RetrievalScoreBreakdown {
            result_id: *kept.as_bytes(),
            final_rank: 1,
            final_score: 2.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Text,
                rank: 1,
                score: 2.0,
            }],
        },
        RetrievalScoreBreakdown {
            result_id: *dropped.as_bytes(),
            final_rank: 2,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Text,
                rank: 2,
                score: 1.0,
            }],
        },
    ];
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::ContextPack,
        1,
        2,
        vec![RetrievalSignal::Text],
        score_breakdown.clone(),
        0,
        0,
        None,
    )
    .with_trace(Some(RetrievalTrace {
        fork_hash: [0xD0; 32],
        per_channel: Vec::new(),
        fused: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Fused,
            candidates: score_breakdown.clone(),
        },
        blended: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Blended,
            candidates: score_breakdown.clone(),
        },
        reranked: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Reranked,
            candidates: score_breakdown.clone(),
        },
        final_stage: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Final,
            candidates: score_breakdown,
        },
    }));
    vault.store.record_retrieval_run(&record)?;

    vault
        .store
        .finalize_context_pack_retrieval_run(run_id, 10, 0, &[*kept.as_bytes()], None)?;

    let finalized = vault
        .retrieval_run(run_id)?
        .expect("finalized context-pack run");
    let trace = finalized.trace.expect("trace remains present");
    assert_eq!(trace.reranked.candidates.len(), 2);
    assert_eq!(trace.final_stage.candidates.len(), 1);
    assert_eq!(trace.reranked.candidates[1].result_id, *dropped.as_bytes());
    assert_eq!(trace.final_stage.candidates[0].result_id, *kept.as_bytes());
    Ok(())
}

#[test]
fn provisional_context_pack_trace_is_hidden_until_finalized() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let kept = entity_id(0xD3);
    let score_breakdown = vec![RetrievalScoreBreakdown {
        result_id: *kept.as_bytes(),
        final_rank: 1,
        final_score: 2.0,
        components: vec![RetrievalScoreComponent {
            signal: RetrievalSignal::Text,
            rank: 1,
            score: 2.0,
        }],
    }];
    let fork_hash = [0xD3; 32];
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::ContextPack,
        1,
        2,
        vec![RetrievalSignal::Text],
        score_breakdown.clone(),
        0,
        0,
        None,
    )
    .with_trace(Some(RetrievalTrace {
        fork_hash,
        per_channel: Vec::new(),
        fused: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Fused,
            candidates: score_breakdown.clone(),
        },
        blended: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Blended,
            candidates: score_breakdown.clone(),
        },
        reranked: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Reranked,
            candidates: score_breakdown.clone(),
        },
        final_stage: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Final,
            candidates: score_breakdown,
        },
    }));

    vault
        .store
        .record_context_pack_provisional_retrieval_run(&record)?;
    assert!(
        vault.retrieval_trace_by_fork_hash(fork_hash)?.is_none(),
        "provisional context-pack traces must not be fork-hash visible"
    );

    vault
        .store
        .finalize_context_pack_retrieval_run(run_id, 10, 0, &[*kept.as_bytes()], None)?;

    assert_eq!(
        vault
            .retrieval_trace_by_fork_hash(fork_hash)?
            .expect("finalized trace should be fork-hash visible")
            .fork_hash,
        fork_hash
    );
    Ok(())
}

#[test]
fn unknown_zero_retrieval_trace_fork_hash_is_not_indexed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let id = entity_id(0xD4);
    let score_breakdown = vec![RetrievalScoreBreakdown {
        result_id: *id.as_bytes(),
        final_rank: 1,
        final_score: 1.0,
        components: vec![RetrievalScoreComponent {
            signal: RetrievalSignal::Text,
            rank: 1,
            score: 1.0,
        }],
    }];
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        1,
        2,
        vec![RetrievalSignal::Text],
        score_breakdown.clone(),
        0,
        0,
        None,
    )
    .with_trace(Some(RetrievalTrace {
        fork_hash: [0; 32],
        per_channel: Vec::new(),
        fused: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Fused,
            candidates: score_breakdown.clone(),
        },
        blended: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Blended,
            candidates: score_breakdown.clone(),
        },
        reranked: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Reranked,
            candidates: score_breakdown.clone(),
        },
        final_stage: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Final,
            candidates: score_breakdown,
        },
    }));

    vault.store.record_retrieval_run(&record)?;

    assert!(
        vault.retrieval_trace_by_fork_hash([0; 32])?.is_none(),
        "all-zero fork hash is the legacy unknown sentinel, not an index key"
    );
    Ok(())
}

#[test]
fn delete_retrieval_run_removes_fork_index_when_run_row_is_corrupt() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let id = entity_id(0xD5);
    let score_breakdown = vec![RetrievalScoreBreakdown {
        result_id: *id.as_bytes(),
        final_rank: 1,
        final_score: 1.0,
        components: vec![RetrievalScoreComponent {
            signal: RetrievalSignal::Text,
            rank: 1,
            score: 1.0,
        }],
    }];
    let fork_hash = [0xD5; 32];
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        1,
        2,
        vec![RetrievalSignal::Text],
        score_breakdown.clone(),
        0,
        0,
        None,
    )
    .with_trace(Some(RetrievalTrace {
        fork_hash,
        per_channel: Vec::new(),
        fused: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Fused,
            candidates: score_breakdown.clone(),
        },
        blended: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Blended,
            candidates: score_breakdown.clone(),
        },
        reranked: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Reranked,
            candidates: score_breakdown.clone(),
        },
        final_stage: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Final,
            candidates: score_breakdown,
        },
    }));

    vault.store.record_retrieval_run(&record)?;
    assert!(vault.retrieval_trace_by_fork_hash(fork_hash)?.is_some());

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &retrieval_run_key(run_id), b"not-msgpack")?;
    wtxn.commit()?;

    vault.store.delete_retrieval_run(run_id)?;
    assert!(
        vault.retrieval_trace_by_fork_hash(fork_hash)?.is_none(),
        "delete must self-heal stale fork-index rows even when the run row is undecodable"
    );
    Ok(())
}

#[test]
fn delete_retrieval_run_removes_fork_index_when_run_has_no_trace() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let fork_hash = [0xD6; 32];
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        1,
        2,
        vec![RetrievalSignal::Text],
        Vec::new(),
        0,
        0,
        None,
    );

    vault.store.record_retrieval_run(&record)?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &retrieval_trace_fork_key(&fork_hash, run_id),
        b"1",
    )?;
    wtxn.commit()?;

    vault.store.delete_retrieval_run(run_id)?;
    assert!(
        vault.retrieval_trace_by_fork_hash(fork_hash)?.is_none(),
        "delete must self-heal stale fork-index rows when the run row has no trace"
    );
    Ok(())
}

#[test]
fn register_structural_kind_rejects_secret_pack_before_vault_meta_write() {
    let (_dir, vault) = open_test_vault();

    let error = vault
        .register_structural_kind(
            65,
            "zz",
            TypeByteBand::Companion,
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        )
        .expect_err("secret-shaped structural pack must reject");

    assert_secret_scan_rejected(error, "gate.secret_scan.github_token");
    assert!(vault.structural_kind_registration(65).is_none());
    assert!(vault.store.structural_kind_registrations().is_empty());
}

#[test]
fn store_metadata_allows_secret_prefix_embedded_in_larger_identifier() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let registration = vault.register_structural_kind(
        65,
        "zz",
        TypeByteBand::Companion,
        "myghp_0123456789abcdefghijklmnopqrstuvwxyz_label",
    )?;
    assert_eq!(
        registration.pack,
        "myghp_0123456789abcdefghijklmnopqrstuvwxyz_label"
    );

    let id = entity_id(0x47);
    put_text(&vault, id, "retrieval outcome embedded prefix")?;
    let result = vault
        .query()
        .search_text("retrieval outcome embedded prefix", 10)
        .run_with_telemetry()?;
    let run_id = result.run_id.expect("telemetry run id");
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "source".to_owned(),
        "myghp_0123456789abcdefghijklmnopqrstuvwxyz_label".to_owned(),
    );
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id,
        key: "click".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata,
    })?;

    let outcomes = vault.retrieval_outcomes(run_id)?;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0].metadata.get("source").map(String::as_str),
        Some("myghp_0123456789abcdefghijklmnopqrstuvwxyz_label")
    );

    Ok(())
}

#[test]
fn record_retrieval_outcome_rejects_secret_key_and_metadata_before_vault_meta_write() -> Result<()>
{
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x46);
    put_text(&vault, id, "retrieval outcome secret scan")?;
    let result = vault
        .query()
        .search_text("retrieval outcome secret scan", 10)
        .run_with_telemetry()?;
    let run_id = result.run_id.expect("telemetry run id");

    let secret_key_error = vault
        .record_retrieval_outcome(RetrievalOutcome {
            run_id,
            key: "ghp_0123456789abcdefghijklmnopqrstuvwxyz_suffix".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })
        .expect_err("secret-shaped retrieval outcome key must reject");
    assert_secret_scan_rejected(secret_key_error, "gate.secret_scan.github_token");
    assert!(vault.retrieval_outcomes(run_id)?.is_empty());

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "source".to_owned(),
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_owned(),
    );
    let metadata_error = vault
        .record_retrieval_outcome(RetrievalOutcome {
            run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata,
        })
        .expect_err("secret-shaped retrieval outcome metadata must reject");
    assert_secret_scan_rejected(metadata_error, "gate.secret_scan.github_token");
    assert!(vault.retrieval_outcomes(run_id)?.is_empty());

    Ok(())
}

#[test]
fn retrieval_runs_rejects_malformed_key_shape_and_run_id_mismatch() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x40);
    put_text(&vault, id, "telemetry key shape")?;
    assert_eq!(vault.search_text("telemetry key shape", 10)?.len(), 1);
    let run_id = vault.retrieval_runs(1)?[0].run_id;
    let raw = raw_retrieval_run_row(&vault, run_id)?;
    let mut malformed_key = retrieval_run_key(run_id);
    malformed_key.push(0);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &malformed_key, &raw)?;
        Ok(())
    })?;
    let error = vault
        .retrieval_runs(10)
        .expect_err("malformed retrieval run key should fail closed");
    assert!(matches!(
        error,
        Error::CorruptedIndex("retrieval run telemetry")
    ));

    let (_dir, vault) = open_test_vault();
    let first_id = entity_id(0x41);
    let second_id = entity_id(0x42);
    put_text(&vault, first_id, "telemetrykeyfirst")?;
    put_text(&vault, second_id, "telemetrykeysecond")?;
    assert_eq!(vault.search_text("telemetrykeyfirst", 10)?.len(), 1);
    let first_run_id = vault.retrieval_runs(1)?[0].run_id;
    let first_raw = raw_retrieval_run_row(&vault, first_run_id)?;
    std::thread::sleep(std::time::Duration::from_millis(2));
    assert_eq!(vault.search_text("telemetrykeysecond", 10)?.len(), 1);
    let second_run_id = vault.retrieval_runs(1)?[0].run_id;
    let second_key = retrieval_run_key(second_run_id);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &second_key, &first_raw)?;
        Ok(())
    })?;
    let error = vault
        .retrieval_runs(10)
        .expect_err("retrieval run key/value id mismatch should fail closed");
    assert!(matches!(
        error,
        Error::CorruptedIndex("retrieval run telemetry")
    ));
    Ok(())
}

#[test]
fn retrieval_outcomes_rejects_key_value_mismatches() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x43);
    put_text(&vault, id, "outcomekeymismatch")?;
    let first = vault
        .query()
        .search_text("outcomekeymismatch", 10)
        .run_with_telemetry()?;
    assert_eq!(first.value.len(), 1);
    let run_id = first.run_id.expect("outcome key mismatch run id");
    record_click_outcome(&vault, run_id)?;
    let raw = raw_retrieval_outcome_row(&vault, run_id, "click")?;
    let wrong_key = retrieval_outcome_key(run_id, "dismiss");
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &wrong_key, &raw)?;
        Ok(())
    })?;
    let error = vault
        .retrieval_outcomes(run_id)
        .expect_err("outcome key/value key mismatch should fail closed");
    assert!(matches!(
        error,
        Error::CorruptedIndex("retrieval outcome telemetry")
    ));

    let (_dir, vault) = open_test_vault();
    let first_id = entity_id(0x44);
    let second_id = entity_id(0x45);
    put_text(&vault, first_id, "outcomerunfirst")?;
    put_text(&vault, second_id, "outcomerunsecond")?;
    let first = vault
        .query()
        .search_text("outcomerunfirst", 10)
        .run_with_telemetry()?;
    assert_eq!(first.value.len(), 1);
    let first_run_id = first.run_id.expect("first outcome run id");
    record_click_outcome(&vault, first_run_id)?;
    let first_raw = raw_retrieval_outcome_row(&vault, first_run_id, "click")?;
    let second = vault
        .query()
        .search_text("outcomerunsecond", 10)
        .run_with_telemetry()?;
    assert_eq!(second.value.len(), 1);
    let second_run_id = second.run_id.expect("second outcome run id");
    let second_key = retrieval_outcome_key(second_run_id, "click");
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &second_key, &first_raw)?;
        Ok(())
    })?;
    let error = vault
        .retrieval_outcomes(second_run_id)
        .expect_err("outcome key/value run id mismatch should fail closed");
    assert!(matches!(
        error,
        Error::CorruptedIndex("retrieval outcome telemetry")
    ));
    Ok(())
}

#[test]
fn search_falls_back_to_bootstrap_when_blend_weight_table_is_corrupt() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x4E);
    put_text(&vault, id, "corrupt blend fallback")?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY, b"not-msgpack")?;
        Ok(())
    })?;

    let table_error = vault
        .retrieval_blend_weight_table()
        .expect_err("administrative table read should still report corruption");
    assert!(matches!(
        table_error,
        Error::CorruptedIndex("retrieval blend weight table")
    ));

    let result = vault
        .query()
        .search_text("corrupt blend fallback", 10)
        .run_with_telemetry()?;
    assert_eq!(result.value.len(), 1);
    assert_eq!(result.value[0].id, id);
    Ok(())
}

#[test]
fn retrieval_blend_tuning_updates_weight_table_from_rewarded_breakdowns() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let positive = entity_id(0x48);
    let negative = entity_id(0x49);
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        100,
        10,
        vec![RetrievalSignal::Text],
        vec![
            RetrievalScoreBreakdown {
                result_id: *positive.as_bytes(),
                final_rank: 1,
                final_score: 2.0,
                components: vec![
                    RetrievalScoreComponent {
                        signal: RetrievalSignal::Recency,
                        rank: 1,
                        score: 1.0,
                    },
                    RetrievalScoreComponent {
                        signal: RetrievalSignal::Salience,
                        rank: 2,
                        score: -1.0,
                    },
                ],
            },
            RetrievalScoreBreakdown {
                result_id: *negative.as_bytes(),
                final_rank: 2,
                final_score: 1.0,
                components: vec![
                    RetrievalScoreComponent {
                        signal: RetrievalSignal::Recency,
                        rank: 2,
                        score: -1.0,
                    },
                    RetrievalScoreComponent {
                        signal: RetrievalSignal::Salience,
                        rank: 1,
                        score: 1.0,
                    },
                ],
            },
        ],
        2,
        0,
        None,
    );
    vault.store.record_retrieval_run(&record)?;
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    let before = vault.retrieval_blend_weight_table()?;
    let updated = vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
        max_runs: 10,
        learning_rate: 0.10,
        min_reward_count: 1,
    })?;

    assert!(updated.weights.recency > before.weights.recency);
    assert!(updated.weights.salience < before.weights.salience);
    assert_eq!(updated.data_window.run_count, 1);
    assert_eq!(updated.data_window.outcome_count, 1);
    assert_eq!(updated.data_window.candidate_count, 2);
    assert_eq!(updated.data_window.started_at_min, Some(100));
    assert_eq!(updated.data_window.started_at_max, Some(100));
    assert_eq!(
        updated.provenance.get("algorithm").map(String::as_str),
        Some(RETRIEVAL_BLEND_TUNER_ALGORITHM)
    );
    assert_eq!(vault.retrieval_blend_weight_table()?, updated);
    Ok(())
}

#[test]
fn concurrent_retrieval_blend_tuning_applies_both_gradient_steps() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        200,
        10,
        vec![RetrievalSignal::Text],
        vec![RetrievalScoreBreakdown {
            result_id: *entity_id(0x4F).as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Recency,
                rank: 1,
                score: 1.0,
            }],
        }],
        1,
        0,
        None,
    );
    vault.store.record_retrieval_run(&record)?;
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    let before = vault.retrieval_blend_weight_table()?;
    let expected_once =
        apply_retrieval_blend_weight_update(before.weights, [1.0, 0.0, 0.0, 0.0], 0.10, 1)?;
    let expected_twice =
        apply_retrieval_blend_weight_update(expected_once, [1.0, 0.0, 0.0, 0.0], 0.10, 1)?;

    let vault = Arc::new(vault);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let vault = Arc::clone(&vault);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
                max_runs: 1,
                learning_rate: 0.10,
                min_reward_count: 1,
            })
        }));
    }
    barrier.wait();
    for handle in handles {
        handle.join().expect("tuning thread should not panic")?;
    }

    let final_entry = vault.retrieval_blend_weight_table()?;
    assert_eq!(final_entry.weights, expected_twice);
    Ok(())
}

#[test]
fn retrieval_blend_tuning_max_runs_counts_completed_runs_not_provisional_rows() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let completed_run_id = RetrievalRunId::now();
    let completed = RetrievalRunRecord::new(
        completed_run_id,
        RetrievalAction::Pipeline,
        300,
        10,
        vec![RetrievalSignal::Text],
        vec![RetrievalScoreBreakdown {
            result_id: *entity_id(0x4A).as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Recency,
                rank: 1,
                score: 1.0,
            }],
        }],
        1,
        0,
        None,
    );
    vault.store.record_retrieval_run(&completed)?;
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id: completed_run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    std::thread::sleep(std::time::Duration::from_millis(2));
    let provisional_run_id = RetrievalRunId::now();
    let provisional = RetrievalRunRecord::new(
        provisional_run_id,
        RetrievalAction::ContextPack,
        400,
        10,
        vec![RetrievalSignal::Text],
        vec![RetrievalScoreBreakdown {
            result_id: *entity_id(0x4B).as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Salience,
                rank: 1,
                score: 1.0,
            }],
        }],
        1,
        0,
        None,
    );
    vault
        .store
        .record_context_pack_provisional_retrieval_run(&provisional)?;

    let before = vault.retrieval_blend_weight_table()?;
    let updated = vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
        max_runs: 1,
        learning_rate: 0.10,
        min_reward_count: 1,
    })?;

    assert!(updated.weights.recency > before.weights.recency);
    assert_eq!(updated.data_window.run_count, 1);
    assert_eq!(updated.data_window.outcome_count, 1);
    assert_eq!(updated.data_window.started_at_min, Some(300));
    assert_eq!(updated.data_window.started_at_max, Some(300));
    Ok(())
}

#[test]
fn retrieval_blend_tuning_counts_only_blend_contributing_rewards() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let blend_run_id = RetrievalRunId::now();
    let blend = RetrievalRunRecord::new(
        blend_run_id,
        RetrievalAction::Pipeline,
        500,
        10,
        vec![RetrievalSignal::Text],
        vec![RetrievalScoreBreakdown {
            result_id: *entity_id(0x4C).as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Recency,
                rank: 1,
                score: 1.0,
            }],
        }],
        1,
        0,
        None,
    );
    vault.store.record_retrieval_run(&blend)?;
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id: blend_run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    std::thread::sleep(std::time::Duration::from_millis(2));
    let text_only_run_id = RetrievalRunId::now();
    let text_only = RetrievalRunRecord::new(
        text_only_run_id,
        RetrievalAction::VaultSearch,
        600,
        10,
        vec![RetrievalSignal::Text],
        vec![RetrievalScoreBreakdown {
            result_id: *entity_id(0x4D).as_bytes(),
            final_rank: 1,
            final_score: 10.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Text,
                rank: 1,
                score: 10.0,
            }],
        }],
        1,
        0,
        None,
    );
    vault.store.record_retrieval_run(&text_only)?;
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id: text_only_run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    let error = vault
        .tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
            max_runs: 2,
            learning_rate: 0.10,
            min_reward_count: 2,
        })
        .expect_err("text-only reward should not satisfy min_reward_count");
    assert!(matches!(error, Error::InvalidConfig(message) if message.contains("found 1")));

    let before = vault.retrieval_blend_weight_table()?;
    let expected_weights =
        apply_retrieval_blend_weight_update(before.weights, [1.0, 0.0, 0.0, 0.0], 0.10, 1)?;
    let updated = vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
        max_runs: 2,
        learning_rate: 0.10,
        min_reward_count: 1,
    })?;

    assert_eq!(updated.weights, expected_weights);
    assert_eq!(updated.data_window.run_count, 1);
    assert_eq!(updated.data_window.outcome_count, 1);
    assert_eq!(updated.data_window.candidate_count, 1);
    assert_eq!(updated.data_window.started_at_min, Some(500));
    assert_eq!(updated.data_window.started_at_max, Some(500));
    Ok(())
}

#[test]
fn retrieval_blend_weight_table_load_normalizes_persisted_weights() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let mut provenance = BTreeMap::new();
    provenance.insert("source".to_owned(), "test".to_owned());
    provenance.insert("algorithm".to_owned(), "test.unnormalized".to_owned());
    let entry = RetrievalBlendWeightTableEntry {
        version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
        weights: RetrievalBlendWeights::new(2.0, 3.0, 4.0, 1.0),
        tuned_at: 123,
        provenance,
        data_window: RetrievalBlendWeightDataWindow::default(),
    };
    let raw = rmp_serde::to_vec_named(&entry).expect("encode synthetic blend table");
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY, &raw)?;
        Ok(())
    })?;

    let loaded = vault.retrieval_blend_weight_table()?;
    let sum = loaded.weights.recency
        + loaded.weights.salience
        + loaded.weights.confidence
        + loaded.weights.gravity;
    assert!((sum - 1.0).abs() < 1.0e-6);
    assert!((loaded.weights.recency - 0.2).abs() < 1.0e-6);
    assert!((loaded.weights.salience - 0.3).abs() < 1.0e-6);
    assert!((loaded.weights.confidence - 0.4).abs() < 1.0e-6);
    assert!((loaded.weights.gravity - 0.1).abs() < 1.0e-6);
    assert_eq!(loaded.tuned_at, 123);
    Ok(())
}

// ===== EMB-2 (ONE-1334) HNSW compatibility record v3 =====

fn funnel_compat_config(fast_dims: Option<u16>) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.fast_dims = fast_dims;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.map_size = 32 * 1024 * 1024;
    config
}

#[test]
fn v2_hnsw_compat_record_opens_as_current_with_no_fast_dims() -> Result<()> {
    let dir = tempfile::tempdir()?;
    {
        let vault = Vault::open(dir.path(), funnel_compat_config(None))?;
        // Populate vector data: a Legacy classification would hard-error a
        // populated vault, which is exactly what the v2->Current rule must
        // prevent.
        let id = entity_id(0x71);
        vault.put_entity(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

        // Overwrite the fresh v3 record with a hand-rolled v2 (27-byte)
        // record, simulating a vault written by a pre-EMB-2 binary.
        let hnsw = funnel_compat_config(None).hnsw;
        let mut encoded = [0_u8; HNSW_COMPATIBILITY_V2_LEN];
        encoded[0] = HNSW_COMPATIBILITY_V2_VERSION;
        encoded[1..9].copy_from_slice(&4_u64.to_le_bytes());
        encoded[9..17].copy_from_slice(&(hnsw.m_max_0 as u64).to_le_bytes());
        encoded[17..25].copy_from_slice(&(hnsw.ef_construction as u64).to_le_bytes());
        encoded[25] = HNSW_DISTANCE_METRIC_COSINE;
        encoded[26] = HNSW_INDEX_STRUCTURE_FLAT_NSW;
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, HNSW_CONFIG_KEY, &encoded)?;
        wtxn.commit()?;
    }

    {
        let vault = Vault::open(dir.path(), funnel_compat_config(None))?;
        let results = vault.search_vector(&[1.0, 0.0, 0.0, 0.0], 4)?;
        assert_eq!(results.len(), 1, "populated v2 vault must stay searchable");
        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .hnsw_meta
            .get(&rtxn, HNSW_CONFIG_KEY)?
            .expect("compat record");
        assert_eq!(
            raw.len(),
            HNSW_COMPATIBILITY_V2_LEN,
            "v2 records are never rewritten in place"
        );
    }

    let Err(err) = Vault::open(dir.path(), funnel_compat_config(Some(2))) else {
        panic!("enabling fast_dims on a v2 vault must fail HnswConfigChanged");
    };
    match err {
        Error::HnswConfigChanged { stored, requested } => {
            assert!(stored.contains("fast_dims=none"), "stored: {stored}");
            assert!(requested.contains("fast_dims=2"), "requested: {requested}");
        }
        other => panic!("expected HnswConfigChanged, got {other:?}"),
    }
    Ok(())
}

#[test]
fn v3_hnsw_compat_record_round_trips_fast_dims() -> Result<()> {
    let dir = tempfile::tempdir()?;
    {
        let vault = Vault::open(dir.path(), funnel_compat_config(Some(2)))?;
        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .hnsw_meta
            .get(&rtxn, HNSW_CONFIG_KEY)?
            .expect("compat record");
        assert_eq!(raw.len(), HNSW_COMPATIBILITY_LEN, "29-byte v3 record");
        assert_eq!(raw[0], HNSW_COMPATIBILITY_VERSION);
        assert_eq!(
            u16::from_le_bytes(raw[27..29].try_into().expect("fast_dims tail")),
            2
        );
    }

    drop(Vault::open(dir.path(), funnel_compat_config(Some(2)))?);

    let Err(err) = Vault::open(dir.path(), funnel_compat_config(Some(3))) else {
        panic!("changed fast_dims must fail");
    };
    assert!(matches!(err, Error::HnswConfigChanged { .. }));

    let Err(err) = Vault::open(dir.path(), funnel_compat_config(None)) else {
        panic!("removing fast_dims must fail");
    };
    assert!(matches!(err, Error::HnswConfigChanged { .. }));
    Ok(())
}

#[test]
fn invalid_fast_dims_fails_closed_at_open() -> Result<()> {
    for fd in [0_u16, 4, 5] {
        let dir = tempfile::tempdir()?;
        let Err(err) = Vault::open(dir.path(), funnel_compat_config(Some(fd))) else {
            panic!("fast_dims {fd} must be rejected at open (dimensions = 4)");
        };
        assert!(
            matches!(err, Error::InvalidConfig(ref msg)
                if msg == "fast_dims must be greater than zero and less than dimensions"),
            "fast_dims {fd}: got {err:?}"
        );
    }
    Ok(())
}
