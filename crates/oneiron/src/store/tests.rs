use super::*;
use crate::Vault;
use crate::attempt_queue::{ATTEMPT_RECORD_VERSION, AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::entity_id::EntityId;
use crate::receipt::MAX_RECEIPT_QUERY_SCAN;
use crate::temporal::TimeRange;
use crate::test_util::assert_secret_scan_rejected;
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

#[test]
fn receipt_family_versions_require_a_storage_abi_bump() {
    const RECEIPT_FAMILY_VERSION_ABI_PINS: &[(u16, [u8; 4])] = &[(15, [0, 2, 1, 1])];

    let receipt_versions = [
        GATE_DECISION_LEDGER_VERSION,
        ATTEMPT_RECORD_VERSION,
        PENDING_GATE_CONSENT_INDEX_STATE_VERSION,
        RECEIPT_FAMILY_INDEX_VERSION,
    ];
    assert!(
        RECEIPT_FAMILY_VERSION_ABI_PINS.contains(&(STORAGE_ABI_VERSION, receipt_versions)),
        "receipt-family versions must be explicitly pinned to STORAGE_ABI_VERSION",
    );

    assert!(receipt_family_version_abi_pins_are_strictly_monotonic(
        RECEIPT_FAMILY_VERSION_ABI_PINS
    ));
    for (axis, changed_versions) in [
        ("gate decision ledger", [1, 2, 1, 1]),
        ("attempt record", [0, 3, 1, 1]),
        ("pending consent index state", [0, 2, 2, 1]),
        ("receipt family index", [0, 2, 1, 2]),
    ] {
        assert!(
            !RECEIPT_FAMILY_VERSION_ABI_PINS.contains(&(STORAGE_ABI_VERSION, changed_versions)),
            "an unbumped {axis} version must not satisfy the ABI pin",
        );
    }
    assert!(!receipt_family_version_abi_pins_are_strictly_monotonic(&[
        (11, [0, 2, 1, 1]),
        (11, [2, 4, 3, 3]),
    ]));
    assert!(!receipt_family_version_abi_pins_are_strictly_monotonic(&[
        (11, [0, 2, 1, 1]),
        (12, [0, 1, 3, 2]),
    ]));
    assert!(receipt_family_version_abi_pins_are_strictly_monotonic(&[
        (11, [0, 2, 1, 1]),
        (12, [1, 3, 2, 2]),
    ]));
}

fn receipt_family_version_abi_pins_are_strictly_monotonic(pins: &[(u16, [u8; 4])]) -> bool {
    pins.windows(2).all(|pair| {
        let (previous_abi, previous_versions) = pair[0];
        let (current_abi, current_versions) = pair[1];
        current_abi > previous_abi
            && current_versions
                .iter()
                .zip(previous_versions)
                .all(|(current, previous)| current >= &previous)
            && current_versions != previous_versions
    })
}

#[test]
fn abi_15_vault_is_rejected_before_an_abi_12_reader_checks_receipt_markers() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    {
        let vault = Vault::open(path, VaultConfig::device())?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            RECEIPT_FAMILY_INDEX_VERSION_KEY,
            &[RECEIPT_FAMILY_INDEX_VERSION + 1],
        )?;
        wtxn.commit()?;
    }

    let err = match Store::open_with_storage_abi_version_for_test(path, &VaultConfig::device(), 12)
    {
        Ok(_) => panic!("an ABI-12 reader must reject an ABI-15 vault at the ABI gate"),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        Error::StorageAbiVersionChanged {
            stored: Some(15),
            current: 12,
        }
    ));
    Ok(())
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
        .map(|value| value.to_vec())
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
        .map(|value| value.to_vec())
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

fn synthetic_gate_decision_id(prefix: u8, value: u64) -> GateDecisionId {
    let mut bytes = [prefix; 16];
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    GateDecisionId::from_bytes(bytes)
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
        redacted_at: None,
    }
}

#[test]
fn rollback_deletes_the_grant_ref_index_row_with_the_primary() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let grant_ref = "bundle:dreamer_run:p6-rollback";
    let d1 = gate_decision(synthetic_gate_decision_id(0x61, 1), 1, Some(grant_ref));
    let d2 = gate_decision(synthetic_gate_decision_id(0x62, 2), 2, None);
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &d1)?;
        vault.store.append_gate_decision_in_txn(wtxn, &d2)?;
        Ok(())
    })?;

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .delete_gate_decision_in_txn(wtxn, d1.decision_id)?;
        vault
            .store
            .delete_gate_decision_in_txn(wtxn, d2.decision_id)?;
        Ok(())
    })?;

    assert!(
        vault
            .store
            .gate_decisions_for_grant_ref(grant_ref)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn off_record_purge_deletes_the_grant_ref_index_rows_with_the_primaries() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let turn_id = entity_id(0x5A);
    let grant_ref = "bundle:dreamer_run:p6-purge";
    let mut decision = gate_decision(synthetic_gate_decision_id(0x63, 3), 3, Some(grant_ref));
    decision.claim_id = Some(*turn_id.as_bytes());
    let survivor = gate_decision(synthetic_gate_decision_id(0x64, 4), 4, Some(grant_ref));
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &decision)?;
        vault.store.append_gate_decision_in_txn(wtxn, &survivor)?;
        Ok(())
    })?;

    vault.with_write_txn(|wtxn| {
        assert_eq!(
            vault
                .store
                .delete_gate_decisions_for_missing_off_record_turn_in_txn(wtxn, &turn_id)?,
            1
        );
        Ok(())
    })?;

    assert_eq!(
        vault.store.gate_decisions_for_grant_ref(grant_ref)?,
        vec![survivor]
    );
    Ok(())
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
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "legacy-receipt-family".to_owned(),
        payload: b"legacy".to_vec(),
        dedupe_key: None,
        run_id: Some(run_id.to_owned()),
        now: 7,
    })?
    else {
        panic!("expected a fresh legacy attempt");
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
            ATTEMPT_RUN_INDEX_PREFIX,
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
        AttemptQueue::new(&reopened).list_run(run_id)?,
        vec![
            AttemptQueue::new(&reopened)
                .get(attempt.id)?
                .expect("backfilled attempt")
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
            .get(&rtxn, RECEIPT_FAMILY_INDEX_VERSION_KEY)?
            .as_deref(),
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

// ---- ERASE-A (ONE-1637) claim index ----------------------------------------

fn claim_bound_gate_decision(
    decision_id: GateDecisionId,
    created_at: u64,
    claim_id: &[u8; 16],
) -> GateDecisionRecord {
    let mut record = gate_decision(decision_id, created_at, None);
    record.claim_id = Some(*claim_id);
    record
}

fn append_gate_decisions(vault: &Vault, records: &[GateDecisionRecord]) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        for record in records {
            vault.store.append_gate_decision_in_txn(wtxn, record)?;
        }
        Ok(())
    })
}

fn claim_index_decision_ids(vault: &Vault, claim_id: &[u8; 16]) -> Result<Vec<GateDecisionId>> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = gate_decision_claim_index_prefix(claim_id);
    let mut ids = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
        let (key, value) = row?;
        assert!(value.is_empty(), "claim index rows carry no value");
        ids.push(GateDecisionId::from_bytes(index_suffix_id(
            &key,
            &prefix,
            "gate decision claim index",
        )?));
    }
    Ok(ids)
}

fn claim_index_row_count(vault: &Vault) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, GATE_DECISION_CLAIM_INDEX_PREFIX)?
        .count())
}

/// Deletes every claim-index row inside an already-open write txn. Collects
/// first: LMDB forbids mutating a DB while one of its iterators is live.
fn delete_claim_index_rows_in_txn(vault: &Vault, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let mut keys = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(wtxn, GATE_DECISION_CLAIM_INDEX_PREFIX)?
    {
        keys.push(row?.0.to_vec());
    }
    for key in &keys {
        vault.store.vault_meta.delete(wtxn, key)?;
    }
    Ok(())
}

/// The v1 retention skeleton the ONE-1638 erase coupling leaves in place of a
/// redacted primary: accountability fields kept, claim-bearing fields scrubbed.
fn redacted_skeleton(record: &GateDecisionRecord, at: u64) -> GateDecisionRecord {
    GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION_REDACTED,
        reason_codes: Vec::new(),
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_ref: None,
        grant_ref: None,
        diff_handle: Vec::new(),
        redacted_at: Some(at),
        ..record.clone()
    }
}

/// Rewinds a vault to its pre-ERASE-A shape: primaries intact, zero claim-index
/// rows, no backfill flag.
fn strip_claim_index_and_flag(vault: &Vault) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    delete_claim_index_rows_in_txn(vault, &mut wtxn)?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY)?;
    wtxn.commit()?;
    Ok(())
}

#[test]
fn append_writes_claim_index_row_for_claim_bound_decisions() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x11; 16];
    let bound = claim_bound_gate_decision(synthetic_gate_decision_id(0x71, 1), 1, &claim);
    let unbound = gate_decision(synthetic_gate_decision_id(0x72, 2), 2, None);
    append_gate_decisions(&vault, &[bound.clone(), unbound])?;

    assert_eq!(
        claim_index_decision_ids(&vault, &claim)?,
        vec![bound.decision_id]
    );
    assert_eq!(claim_index_row_count(&vault)?, 1);
    Ok(())
}

#[test]
fn rollback_deletes_the_claim_index_row_with_the_primary() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x12; 16];
    let bound = claim_bound_gate_decision(synthetic_gate_decision_id(0x73, 3), 3, &claim);
    append_gate_decisions(&vault, std::slice::from_ref(&bound))?;
    assert_eq!(claim_index_row_count(&vault)?, 1);

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .delete_gate_decision_in_txn(wtxn, bound.decision_id)
    })?;

    assert!(claim_index_decision_ids(&vault, &claim)?.is_empty());
    assert_eq!(claim_index_row_count(&vault)?, 0);
    Ok(())
}

#[test]
fn off_record_purge_deletes_claim_index_rows_with_the_primaries() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let turn_id = entity_id(0x5B);
    let turn_claim = *turn_id.as_bytes();
    let other_claim = [0x13; 16];
    let purged = claim_bound_gate_decision(synthetic_gate_decision_id(0x74, 4), 4, &turn_claim);
    let survivor = claim_bound_gate_decision(synthetic_gate_decision_id(0x75, 5), 5, &other_claim);
    append_gate_decisions(&vault, &[purged, survivor.clone()])?;

    vault.with_write_txn(|wtxn| {
        assert_eq!(
            vault
                .store
                .delete_gate_decisions_for_missing_off_record_turn_in_txn(wtxn, &turn_id)?,
            1
        );
        Ok(())
    })?;

    assert!(claim_index_decision_ids(&vault, &turn_claim)?.is_empty());
    assert_eq!(
        claim_index_decision_ids(&vault, &other_claim)?,
        vec![survivor.decision_id]
    );
    assert_eq!(claim_index_row_count(&vault)?, 1);
    Ok(())
}

/// A mixed ledger: two claims interleaved with unbound rows, appended out of
/// decision_id order so ascending-order parity is a real assertion.
fn mixed_claim_ledger(vault: &Vault, left: &[u8; 16], right: &[u8; 16]) -> Result<()> {
    append_gate_decisions(
        vault,
        &[
            claim_bound_gate_decision(synthetic_gate_decision_id(0x83, 3), 3, left),
            gate_decision(synthetic_gate_decision_id(0x86, 6), 6, None),
            claim_bound_gate_decision(synthetic_gate_decision_id(0x81, 1), 1, left),
            claim_bound_gate_decision(synthetic_gate_decision_id(0x84, 4), 4, right),
            claim_bound_gate_decision(synthetic_gate_decision_id(0x82, 2), 2, left),
            gate_decision(synthetic_gate_decision_id(0x87, 7), 7, None),
        ],
    )
}

#[test]
fn claim_discovery_index_and_scan_paths_are_result_identical() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let left = [0x21; 16];
    let right = [0x22; 16];
    mixed_claim_ledger(&vault, &left, &right)?;
    vault.store.backfill_gate_decision_claim_index()?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)?
    );
    for claim in [left, right, [0x23; 16]] {
        let indexed = vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim)?;
        let scanned = vault
            .store
            .scan_gate_decisions_for_claim_in_txn(&rtxn, &claim)?;
        assert_eq!(indexed, scanned, "paths must agree for claim {claim:?}");
        assert!(
            indexed
                .windows(2)
                .all(|pair| pair[0].decision_id.as_bytes() < pair[1].decision_id.as_bytes()),
            "discovery must be ascending by decision_id",
        );
        assert!(indexed.iter().all(|record| record.claim_id == Some(claim)));
    }
    assert_eq!(
        vault
            .store
            .gate_decisions_for_claim_in_txn(&rtxn, &left)?
            .len(),
        3
    );
    Ok(())
}

#[test]
fn claim_discovery_falls_back_to_scan_while_backfill_incomplete() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let left = [0x24; 16];
    let right = [0x25; 16];
    mixed_claim_ledger(&vault, &left, &right)?;

    let expected = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.gate_decisions_for_claim_in_txn(&rtxn, &left)?
    };
    assert_eq!(expected.len(), 3);

    // Simulate a pre-ERASE-A vault: rows exist, index does not.
    strip_claim_index_and_flag(&vault)?;
    assert_eq!(claim_index_row_count(&vault)?, 0);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        !vault
            .store
            .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)?
    );
    // The kill-shot: un-backfilled rows stay visible to erase discovery.
    assert_eq!(
        vault.store.gate_decisions_for_claim_in_txn(&rtxn, &left)?,
        expected
    );
    Ok(())
}

#[test]
fn backfill_indexes_preexisting_rows_and_sets_flag_atomically() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let left = [0x26; 16];
    let right = [0x27; 16];
    mixed_claim_ledger(&vault, &left, &right)?;
    strip_claim_index_and_flag(&vault)?;

    let first = vault.store.backfill_gate_decision_claim_index()?;
    assert!(!first.already_complete);
    assert_eq!(first.rows_indexed, 4);
    assert_eq!(claim_index_row_count(&vault)?, 4);
    assert_eq!(claim_index_decision_ids(&vault, &left)?.len(), 3);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .store
                .vault_meta
                .get(&rtxn, GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY)?
                .as_deref(),
            Some(GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE.as_slice()),
        );
    }

    let second = vault.store.backfill_gate_decision_claim_index()?;
    assert!(second.already_complete);
    assert_eq!(second.rows_indexed, 0);
    assert_eq!(claim_index_row_count(&vault)?, 4);
    Ok(())
}

#[test]
fn empty_ledger_vault_opens_with_backfill_flag_set() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = VaultConfig::device();
    {
        let vault = Vault::open(dir.path(), config.clone())?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)?,
            "a fresh vault's ledger is vacuously fully indexed",
        );
        drop(rtxn);
        append_gate_decisions(
            &vault,
            &[claim_bound_gate_decision(
                synthetic_gate_decision_id(0x88, 8),
                8,
                &[0x28; 16],
            )],
        )?;
        strip_claim_index_and_flag(&vault)?;
    }

    let vault = Vault::open(dir.path(), config)?;
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        !vault
            .store
            .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)?,
        "a populated ledger must not self-flag: it needs the maintenance op",
    );
    Ok(())
}

#[test]
fn erasure_verify_scans_keyspace_and_never_trusts_the_index() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x29; 16];
    let other = [0x2A; 16];
    mixed_claim_ledger(&vault, &claim, &other)?;
    let expected: Vec<GateDecisionId> = (1..=3)
        .map(|value| synthetic_gate_decision_id(0x80 + value as u8, value))
        .collect();

    // A LYING index: rows removed, flag set. Index-accelerated discovery would
    // report the claim as already empty.
    let mut wtxn = vault.store.env.write_txn()?;
    delete_claim_index_rows_in_txn(&vault, &mut wtxn)?;
    vault.store.vault_meta.put(
        &mut wtxn,
        GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
        &GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE,
    )?;
    // A bogus index row with no primary: fatal to the index reader, invisible
    // to the verify.
    vault.store.vault_meta.put(
        &mut wtxn,
        &gate_decision_claim_index_key(&claim, synthetic_gate_decision_id(0xEE, 99)),
        b"",
    )?;
    wtxn.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .verify_claim_erasure_by_scan_in_txn(&rtxn, &claim)?,
        expected,
        "the verify must scan the ledger, not the index it would certify",
    );
    assert!(matches!(
        vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim),
        Err(Error::CorruptedIndex("gate decision claim index")),
    ));
    Ok(())
}

#[test]
fn erasure_verify_excludes_redacted_rows_and_other_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x2B; 16];
    let live = claim_bound_gate_decision(synthetic_gate_decision_id(0x91, 1), 1, &claim);
    let to_redact = claim_bound_gate_decision(synthetic_gate_decision_id(0x92, 2), 2, &claim);
    let other = claim_bound_gate_decision(synthetic_gate_decision_id(0x93, 3), 3, &[0x2C; 16]);
    append_gate_decisions(&vault, &[live.clone(), to_redact.clone(), other])?;

    // Stand in for the ONE-1638 in-place redaction: primary rewritten to a v1
    // skeleton, claim-index row deliberately retained.
    let skeleton = redacted_skeleton(&to_redact, 42);
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &gate_decision_key(to_redact.decision_id),
        &encode_gate_decision(&skeleton)?,
    )?;
    wtxn.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .verify_claim_erasure_by_scan_in_txn(&rtxn, &claim)?,
        vec![live.decision_id],
        "only unredacted claim-bound rows block completeness",
    );
    assert_eq!(
        vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim)?,
        vec![live, skeleton],
        "discovery still surfaces the retained skeleton",
    );
    Ok(())
}

#[test]
fn record_schema_v0_bytes_stable_and_v1_skeleton_vets() -> Result<()> {
    // Golden msgpack of the shared fixture, captured BEFORE `redacted_at`
    // existed. `skip_serializing_if` keeps a `None` field off the wire, so v0
    // rows written by any prior build are byte-identical to today's.
    const GOLDEN_V0: &str = "8DA776657273696F6E00AB6465636973696F6E5F696481A56279746573DC00106161616161616161000000000\
0000001AA637265617465645F617401A76F7574636F6D65A8617070726F766564AC726561736F6E5F636F64657391B8676174652E746573742E7\
26563656970745F66616D696C79AB6163746F725F636C617373A56167656E74A96163746F725F726566C0AC636F6E74656E745F6B696E64A5636\
C61696DB7706F6C6963795F6D616E69666573745F76657273696F6EA27630A8636C61696D5F6964C0A96772616E745F726566A8673A676F6C646\
56EAB646966665F68616E646C6591CCAAB2726561645F66726F6E746965725F68617368DC0020CCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCB\
BCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBB";
    let golden: Vec<u8> = (0..GOLDEN_V0.len() / 2)
        .map(|index| {
            u8::from_str_radix(&GOLDEN_V0[index * 2..index * 2 + 2], 16).expect("golden hex")
        })
        .collect();
    let live = gate_decision(synthetic_gate_decision_id(0x61, 1), 1, Some("g:golden"));
    assert_eq!(
        encode_gate_decision(&live)?,
        golden,
        "v0 bytes must not move"
    );
    assert_eq!(decode_gate_decision(&golden)?, live);
    assert!(live.redacted_at.is_none(), "pre-field bytes decode as None");

    let skeleton = redacted_skeleton(&live, 7);
    assert_eq!(
        decode_gate_decision(&encode_gate_decision(&skeleton)?)?,
        skeleton
    );

    let (_dir, vault) = open_test_vault();
    for born_redacted in [
        skeleton.clone(),
        GateDecisionRecord {
            redacted_at: Some(7),
            ..live.clone()
        },
    ] {
        let result = vault.with_write_txn(|wtxn| {
            vault
                .store
                .append_gate_decision_in_txn(wtxn, &born_redacted)
        });
        assert!(
            matches!(
                result,
                Err(Error::InvariantViolation("gate decision born redacted"))
            ),
            "appends stay version-0-and-unredacted only: {result:?}",
        );
    }

    let rejects = [
        GateDecisionRecord {
            redacted_at: Some(7),
            ..live.clone()
        },
        // Half of the deliberate `actor_class` asymmetry: fatal on the v1
        // skeleton, where the field is ours and the retention design keeps it.
        // The v0 half is pinned positively below.
        GateDecisionRecord {
            actor_class: String::new(),
            ..skeleton.clone()
        },
        GateDecisionRecord {
            version: 2,
            ..live.clone()
        },
        GateDecisionRecord {
            redacted_at: None,
            ..skeleton.clone()
        },
        GateDecisionRecord {
            redacted_at: Some(0),
            ..skeleton.clone()
        },
        GateDecisionRecord {
            reason_codes: vec!["gate.x".to_owned()],
            ..skeleton.clone()
        },
        GateDecisionRecord {
            grant_ref: Some("g:leak".to_owned()),
            ..skeleton.clone()
        },
        GateDecisionRecord {
            actor_ref: Some("agent-leak".to_owned()),
            ..skeleton.clone()
        },
        GateDecisionRecord {
            content_kind: String::new(),
            ..skeleton
        },
    ];
    for reject in rejects {
        let encoded = rmp_serde::to_vec_named(&reject).expect("test encode");
        assert!(
            matches!(
                decode_gate_decision(&encoded),
                Err(Error::CorruptedIndex("gate decision ledger"))
            ),
            "malformed record must not decode: {reject:?}",
        );
    }

    // The other half of the asymmetry, pinned POSITIVELY so a later
    // "symmetrize the vet" edit has to delete an assertion rather than silently
    // pass. On v0 the class is caller-asserted: the gate answers an empty one
    // with a recorded `gate.deny.missing_actor_class` denial, and that denial
    // row must round-trip. Vetting it fatal would let any caller trade an
    // auditable deny for a torn write txn — and leave a decode-fatal row that
    // aborts every later ledger scan.
    let empty_class = GateDecisionRecord {
        actor_class: String::new(),
        ..live
    };
    let encoded = rmp_serde::to_vec_named(&empty_class).expect("test encode");
    assert_eq!(
        decode_gate_decision(&encoded)?,
        empty_class,
        "a recorded deny-missing-actor-class row must survive the round trip",
    );
    let (_dir, vault) = open_test_vault();
    vault.with_write_txn(|wtxn| vault.store.append_gate_decision_in_txn(wtxn, &empty_class))?;
    Ok(())
}

/// A v1 skeleton may NOT retain a `diff_handle`.
///
/// E-A's D1 table only length-capped the field on the redacted column, so a row
/// that called itself redacted could keep a live binding to the exact body the
/// redaction exists to scrub — a length cap cannot tell a scrubbed sentinel from
/// a real handle. Empty is the only self-evidently scrubbed value, and this is
/// the test that makes a later "just cap the length" relaxation fail.
///
/// The planted-row half is the one that bites: skeletons reach disk by in-place
/// primary overwrite (never through `append_gate_decision_in_txn`), so the vet
/// only protects anything if the READERS refuse a retained handle too.
#[test]
fn redacted_skeleton_must_not_retain_a_diff_handle() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x3D; 16];
    let live = claim_bound_gate_decision(synthetic_gate_decision_id(0x95, 1), 1, &claim);
    append_gate_decisions(&vault, std::slice::from_ref(&live))?;
    assert!(
        !live.diff_handle.is_empty(),
        "v0 must still REQUIRE a handle — the tightening is v1-only",
    );

    let scrubbed = redacted_skeleton(&live, 9);
    assert!(scrubbed.diff_handle.is_empty());
    assert_eq!(
        decode_gate_decision(&encode_gate_decision(&scrubbed)?)?,
        scrubbed,
        "the empty-handle skeleton is the accepted shape",
    );

    // The live binding itself, a one-byte stub, and a blob that exactly
    // saturates the old length cap: all three are retained handles.
    for handle in [
        live.diff_handle,
        vec![0x00],
        vec![0x5A; GATE_DIFF_HANDLE_MAX_LEN],
    ] {
        let retained = GateDecisionRecord {
            diff_handle: handle.clone(),
            ..scrubbed.clone()
        };
        let encoded = rmp_serde::to_vec_named(&retained).expect("test encode");
        assert!(
            matches!(
                decode_gate_decision(&encoded),
                Err(Error::CorruptedIndex("gate decision ledger"))
            ),
            "a redacted skeleton keeping {} handle bytes must not vet",
            handle.len(),
        );

        // Planted straight onto the primary, exactly as an in-place redaction
        // writes. Every reader must fail closed instead of serving the binding.
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            &gate_decision_key(retained.decision_id),
            &encoded,
        )?;
        wtxn.commit()?;
        let rtxn = vault.store.env.read_txn()?;
        for (reader, result) in [
            (
                "point read",
                vault
                    .store
                    .gate_decision_in_txn(&rtxn, retained.decision_id)
                    .map(|_| ()),
            ),
            (
                "claim discovery",
                vault
                    .store
                    .gate_decisions_for_claim_in_txn(&rtxn, &claim)
                    .map(|_| ()),
            ),
            (
                "erasure verify",
                vault
                    .store
                    .verify_claim_erasure_by_scan_in_txn(&rtxn, &claim)
                    .map(|_| ()),
            ),
        ] {
            assert!(
                matches!(result, Err(Error::CorruptedIndex("gate decision ledger"))),
                "{reader} must refuse a handle-retaining skeleton: {result:?}",
            );
        }
        drop(rtxn);

        // And the append door stays shut on it as well (born-redacted guard).
        let appended =
            vault.with_write_txn(|wtxn| vault.store.append_gate_decision_in_txn(wtxn, &retained));
        assert!(
            matches!(
                appended,
                Err(Error::InvariantViolation("gate decision born redacted"))
            ),
            "append must never mint a skeleton, handle-bearing or not: {appended:?}",
        );
    }

    // Overwrite the corrupt primary with the properly scrubbed skeleton: the
    // same readers recover, so the refusals above were about the handle and not
    // about the row being redacted at all.
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &gate_decision_key(scrubbed.decision_id),
        &encode_gate_decision(&scrubbed)?,
    )?;
    wtxn.commit()?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim)?,
        vec![scrubbed],
        "discovery still surfaces a correctly scrubbed skeleton",
    );
    assert!(
        vault
            .store
            .verify_claim_erasure_by_scan_in_txn(&rtxn, &claim)?
            .is_empty(),
        "a scrubbed skeleton does not block erasure completeness",
    );
    Ok(())
}

/// The pushdown pin: the caller's filter runs DURING the cursor walk, so a
/// filtered read never materializes the whole ledger first.
///
/// Two halves, and the second is the one that bites. (a) an early `Err` from
/// the visitor stops the walk at the row that raised it — impossible if every
/// record were decoded into a `Vec` before the filter saw any of them. (b) the
/// live filtered readers observe the SAME early-stop, which is what pins them
/// to the streaming helper rather than to a collect-then-filter that merely
/// returns the same values.
#[test]
fn ledger_scan_applies_the_caller_filter_during_the_cursor_walk() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x31; 16];
    // Row 1 is claim-bound; rows 2..=4 are not. A collect-first scan decodes
    // all four before any filter runs; a streaming scan visits them in order.
    append_gate_decisions(
        &vault,
        &[
            claim_bound_gate_decision(synthetic_gate_decision_id(0xA1, 1), 1, &claim),
            gate_decision(synthetic_gate_decision_id(0xA2, 2), 2, None),
            gate_decision(synthetic_gate_decision_id(0xA3, 3), 3, None),
            gate_decision(synthetic_gate_decision_id(0xA4, 4), 4, None),
        ],
    )?;

    {
        let rtxn = vault.store.env.read_txn()?;
        let mut visited = 0_usize;
        let result = vault.store.for_each_gate_decision_in_txn(&rtxn, |_record| {
            visited += 1;
            if visited == 2 {
                return Err(Error::InvariantViolation("probe stop"));
            }
            Ok(())
        });
        assert!(
            matches!(result, Err(Error::InvariantViolation("probe stop"))),
            "the visitor's error must propagate: {result:?}",
        );
        assert_eq!(
            visited, 2,
            "the walk must stop AT the refusing row, not after decoding the ledger",
        );
    }

    // A row whose bytes cannot decode. An unfiltered walk must hit it; a walk
    // that stops earlier proves rows past the stop were never decoded.
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &gate_decision_key(synthetic_gate_decision_id(0xA5, 5)),
        b"not-msgpack",
    )?;
    wtxn.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let mut seen = 0_usize;
    assert!(
        matches!(
            vault.store.for_each_gate_decision_in_txn(&rtxn, |_record| {
                seen += 1;
                Ok(())
            }),
            Err(Error::CorruptedIndex("gate decision ledger")),
        ),
        "an unfiltered walk reaches the malformed trailing row and aborts",
    );
    assert_eq!(seen, 4, "the four decodable rows precede the malformed one");

    // Both filtered readers stop at the first refusing row too: they are the
    // same walk, not a collect-then-filter wearing its shape.
    let mut discovered = 0_usize;
    assert!(
        matches!(
            vault.store.for_each_gate_decision_in_txn(&rtxn, |record| {
                discovered += 1;
                if record.claim_id == Some(claim) {
                    return Err(Error::InvariantViolation("probe stop"));
                }
                Ok(())
            }),
            Err(Error::InvariantViolation("probe stop")),
        ),
        "the claim-bound first row must halt the walk immediately",
    );
    assert_eq!(
        discovered, 1,
        "matching on row 1 must not require decoding rows 2..=5",
    );
    Ok(())
}

#[test]
fn claim_index_keyspace_is_disjoint_from_ledger_and_grant_ref_ranges() {
    let claim = [0x2D; 16];
    let decision_id = synthetic_gate_decision_id(0x94, 4);
    let ledger_lower = GATE_DECISION_KEY_PREFIX;
    let ledger_upper = gate_decision_upper_bound();
    let grant_ref_key = gate_decision_grant_ref_index_key("g:disjoint", decision_id);

    for key in [
        gate_decision_claim_index_key(&claim, decision_id),
        gate_decision_claim_index_prefix(&claim),
        GATE_DECISION_CLAIM_INDEX_PREFIX.to_vec(),
        GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY.to_vec(),
    ] {
        assert!(
            key.as_slice() >= ledger_upper.as_slice(),
            "{key:?} must sort at or past the ledger upper bound",
        );
        assert!(!key.starts_with(ledger_lower));
        assert!(!key.starts_with(GATE_DECISION_GRANT_REF_INDEX_PREFIX));
        assert!(!GATE_DECISION_GRANT_REF_INDEX_PREFIX.starts_with(&key));
    }

    // The sibling index sorts BELOW the primary range, so neither the primary
    // full-scan nor either prefix-iter can ever see the other's rows.
    assert!(grant_ref_key.as_slice() < ledger_lower);
    assert!(gate_decision_key(decision_id).starts_with(ledger_lower));
}

#[test]
fn claim_index_corruption_fails_loud_instead_of_answering() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x2E; 16];
    let foreign = [0x2F; 16];
    let mine = claim_bound_gate_decision(synthetic_gate_decision_id(0x95, 5), 5, &claim);
    let theirs = claim_bound_gate_decision(synthetic_gate_decision_id(0x96, 6), 6, &foreign);
    append_gate_decisions(&vault, &[mine, theirs.clone()])?;
    vault.store.backfill_gate_decision_claim_index()?;

    // A row filed under the wrong claim: its primary EXISTS, so only the
    // claim-back check can catch the mis-binding.
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &gate_decision_claim_index_key(&claim, theirs.decision_id),
        b"",
    )?;
    wtxn.commit()?;
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(matches!(
            vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim),
            Err(Error::CorruptedIndex("gate decision claim index")),
        ));
        // The scan path never consults the index, so it stays truthful.
        assert_eq!(
            vault
                .store
                .scan_gate_decisions_for_claim_in_txn(&rtxn, &claim)?
                .len(),
            1
        );
    }

    // A flag byte we never write is corruption, not a soft "incomplete" that
    // would silently downgrade discovery to a scan.
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
        &[2],
    )?;
    wtxn.commit()?;
    let rtxn = vault.store.env.read_txn()?;
    for result in [
        vault
            .store
            .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)
            .map(|_| ()),
        vault
            .store
            .gate_decisions_for_claim_in_txn(&rtxn, &claim)
            .map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(Error::CorruptedIndex(
                "gate decision claim index backfill flag"
            )),
        ));
    }
    Ok(())
}
