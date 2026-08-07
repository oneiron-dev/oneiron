use rmpv::Value;

use super::*;
use crate::test_util::{embedding_test_config, entity, entity_record};
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY;
use crate::{
    ClaimSubject, EdgeActorClass, WriteActor,
    receipt::{ReceiptKind, ReceiptQuery},
    registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST},
};

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), embedding_test_config()).expect("open vault");
    (dir, vault)
}

fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn seed_person(vault: &Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("entity id");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
        .expect("seed person");
    id
}

fn seed_machine(vault: &Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("entity id");
    vault
        .put_entity(&id, ENTITY_TYPE_MACHINE, range(1), 1, b"machine")
        .expect("seed machine");
    id
}

fn seed_first_party_actor(vault: &Vault) -> EntityId {
    let id = EntityId::from_bytes(crate::gate::FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
        .expect("first-party actor id");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"first-party actor")
        .expect("seed first-party actor");
    id
}

fn clear_policy_manifests_for_test(vault: &Vault) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        let mut ids = Vec::new();
        for row in vault
            .store
            .type_index
            .prefix_iter(wtxn, &[ENTITY_TYPE_POLICY_MANIFEST])?
        {
            let (key, _) = row?;
            let id = EntityId::from_bytes(
                key[1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("type index key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("type index key"))?;
            ids.push(id);
        }
        for id in ids {
            crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
        }
        Ok(())
    })
}

fn put_indexed_manifest_at_two(vault: &Vault, id: EntityId, data: &[u8]) -> Result<()> {
    let learned_at = 2_u64;
    let payload = entity_record(
        ENTITY_TYPE_POLICY_MANIFEST,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        data,
    );

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)?;
    let type_key = crate::store::Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    let temporal_key = crate::store::Store::encode_temporal_key(learned_at, &id);
    vault
        .store
        .temporal_occurred_start
        .put(&mut wtxn, &temporal_key, &[])?;
    vault
        .store
        .temporal_learned
        .put(&mut wtxn, &temporal_key, &[])?;
    Ok(wtxn.commit()?)
}

fn put_malformed_policy_manifest(vault: &Vault, seed: u8) -> Result<()> {
    put_indexed_manifest_at_two(vault, entity(seed), b"not-msgpack")
}

fn install_self_memory_allow_policy(vault: &Vault, actor: EntityId) -> Result<()> {
    install_self_memory_policy_trusting_source(vault, actor, ClaimSource::Generated)
}

fn install_self_memory_policy_trusting_source(
    vault: &Vault,
    actor: EntityId,
    source: ClaimSource,
) -> Result<()> {
    clear_policy_manifests_for_test(vault)?;
    let manifest = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("code-run-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (
            Value::from("rules"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("prefix"), Value::from("self.memory.")),
                (
                    Value::from("axes"),
                    Value::Map(vec![
                        (Value::from("criticality"), Value::from("normal")),
                        (Value::from("sensitivity"), Value::from("normal")),
                    ]),
                ),
            ])]),
        ),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("agent")),
                (Value::from("actor_ref"), Value::from(actor.to_hex())),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (
            Value::from("source_trust"),
            Value::Map(vec![(
                Value::from(source.as_str()),
                // Band 2, not 0. These fixtures' subject is write-trap
                // ROUTING — that each self-memory op emits its own gate
                // decision and receipt, and that a source outside the trusted
                // row is refused. The gate bodies for the edge and supersede
                // traps are built by production `operation_gate_body`, which
                // records no `sensitivity` scope, so under the ONE-1645
                // provenance floor they read the unstamped band 2 and a
                // ceiling of 0 would queue EVERY op — erasing the routing
                // signal these tests measure. Admitting band 2 here keeps the
                // trusted-source arm auto-writable while
                // `code_run_edge_and_supersede_traps_force_generated_source_into_g2`
                // still pins the untrusted-source rejection. This is a
                // test-local manifest; the SHIPPED `default_policy_manifest()`
                // ToolOutput ceiling stays 0 on purpose.
                Value::Map(vec![
                    (Value::from("max_auto_sensitivity"), Value::from(2_u64)),
                    (Value::from("receipted"), Value::Boolean(true)),
                    (Value::from("warned"), Value::Boolean(true)),
                ]),
            )]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest)
        .map_err(|_| Error::InvariantViolation("failed to encode policy manifest fixture"))?;
    put_indexed_manifest_at_two(vault, entity(0xE8), &data)
}

fn gate_decision_count(vault: &Vault) -> Result<usize> {
    Ok(vault.store.gate_decisions(100)?.len())
}

fn gate_receipt_count(vault: &Vault) -> Result<usize> {
    Ok(vault
        .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?
        .len())
}

fn assert_latest_gate_decision(vault: &Vault, expected_id: EntityId) -> Result<()> {
    let decisions = vault.store.gate_decisions(1)?;
    let latest = decisions.first().expect("latest gate decision");
    assert_eq!(latest.content_kind, "claim");
    assert_eq!(latest.claim_id, Some(*expected_id.as_bytes()));
    assert!(latest.actor_ref.is_some());
    assert!(
        latest
            .reason_codes
            .iter()
            .all(|code| code.starts_with("gate."))
    );
    Ok(())
}

fn assert_gate_receipts_for_claim(
    vault: &Vault,
    expected_id: EntityId,
    expected_actor: EntityId,
    expected_outcome: &str,
    expected_count: usize,
) -> Result<()> {
    let expected_trigger = format!("claim:{}", expected_id.to_hex());
    let expected_actor = expected_actor.to_hex();
    let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    let matching_receipts = receipts
        .iter()
        .filter(|receipt| {
            receipt.trigger_ref.as_deref() == Some(expected_trigger.as_str())
                && receipt.outcome == expected_outcome
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matching_receipts.len(),
        expected_count,
        "unexpected gate receipt count for {expected_trigger}"
    );

    for receipt in matching_receipts {
        assert_eq!(receipt.receipt_kind, ReceiptKind::Gate);
        assert_eq!(receipt.actor.as_deref(), Some(expected_actor.as_str()));
        assert_eq!(
            receipt.fields.get("content_kind").map(String::as_str),
            Some("claim")
        );
        assert!(
            receipt
                .fields
                .get("diff_handle")
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            receipt
                .fields
                .get("read_frontier_hash")
                .is_some_and(|value| !value.is_empty())
        );
    }
    Ok(())
}

fn assert_latest_gate_decision_reasons(
    vault: &Vault,
    expected_id: EntityId,
    expected_outcome: &str,
    expected_reasons: &[&str],
) -> Result<()> {
    let decisions = vault.store.gate_decisions(1)?;
    let latest = decisions.first().expect("latest gate decision");
    assert_eq!(latest.outcome, expected_outcome);
    assert_eq!(latest.claim_id, Some(*expected_id.as_bytes()));
    assert_eq!(
        latest.reason_codes,
        expected_reasons
            .iter()
            .map(|reason| (*reason).to_owned())
            .collect::<Vec<_>>()
    );
    Ok(())
}

fn assert_source_trust_gate_rejection(err: Error) {
    match err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert_eq!(outcome, "pending");
            assert_eq!(reason_codes, vec!["gate.pending.source_trust"]);
        }
        other => panic!("expected source-trust gate rejection, got {other:?}"),
    }
}

fn assert_recent_gate_decision_ids(vault: &Vault, expected: &[EntityId]) -> Result<()> {
    let decisions = vault.store.gate_decisions(expected.len())?;
    let actual = decisions
        .iter()
        .map(|decision| decision.claim_id.expect("gate decision claim id"))
        .collect::<Vec<_>>();
    let expected = expected.iter().map(|id| *id.as_bytes()).collect::<Vec<_>>();
    assert_eq!(actual, expected);
    Ok(())
}

fn map_value<'a>(entries: &'a [(Value, Value)], key: &str) -> &'a Value {
    entries
        .iter()
        .find_map(|(entry_key, entry_value)| {
            (entry_key.as_str() == Some(key)).then_some(entry_value)
        })
        .expect("map entry")
}

#[test]
fn code_run_replay_record_round_trips_and_replays_bridge_log_without_dispatch() -> Result<()> {
    let run_id = EntityId::from_bytes([0x91; 16]).expect("run id");
    let src = EntityId::from_bytes([0x92; 16]).expect("src id");
    let tgt = EntityId::from_bytes([0x93; 16]).expect("tgt id");
    let wait_id = EntityId::from_bytes([0x94; 16]).expect("wait id");
    let determinism = CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]);

    let edge_call = SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
        src,
        EdgeKind::Mentions,
        tgt,
        0.7,
    ));
    let edge_outcome = SelfDispatchOutcome::MemoryEdgeWrite(SelfMemoryEdgeWriteResult {
        src,
        kind: EdgeKind::Mentions,
        tgt,
    });
    let human_call = SelfCall::AskHuman(SelfAskHumanCall::new("continue?"));
    let human_outcome = SelfDispatchOutcome::DurableWait(SelfDurableWait {
        wait_id,
        effect: SelfEffect::AskHuman,
        reason: SelfDurableWaitReason::HumanInput,
        prompt: Some("continue?".to_owned()),
    });

    let mut record = CodeRunReplayRecord::new(run_id, determinism);
    record.bridge_calls.push(CodeRunBridgeCall::record(
        0,
        &edge_call,
        &edge_outcome,
        determinism.frozen_unix_ms,
        determinism.frozen_unix_ms + 1,
    )?);
    record.bridge_calls.push(CodeRunBridgeCall::record(
        1,
        &human_call,
        &human_outcome,
        determinism.frozen_unix_ms + 2,
        determinism.frozen_unix_ms + 3,
    )?);
    record.step_checkpoints.push(CodeRunStepCheckpoint::new(
        0,
        "after-edge",
        [0xCD; 32],
        determinism.frozen_unix_ms + 4,
    )?);

    let encoded = encode_code_run_replay_record(&record)?;
    let decoded = decode_code_run_replay_record(&encoded)?;
    assert_eq!(decoded, record);
    assert_eq!(encode_code_run_replay_record(&decoded)?, encoded);

    let replay = decoded.replay_cursor();
    assert_eq!(replay.dispatch(edge_call)?, edge_outcome);
    assert_eq!(replay.dispatch(human_call.clone())?, human_outcome);
    assert!(replay.is_complete());

    let reordered = decoded.replay_cursor();
    let err = reordered
        .dispatch(human_call)
        .expect_err("replay must reject out-of-order bridge calls");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidCodeArtifactBody);
    assert_eq!(reordered.consumed(), 0);

    let changed_call = SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
        src,
        EdgeKind::Mentions,
        tgt,
        0.8,
    ));
    let changed = decoded.replay_cursor();
    let _err = changed
        .dispatch(changed_call)
        .expect_err("replay must reject changed typed trap arguments");
    assert_eq!(changed.consumed(), 0);
    Ok(())
}

#[test]
fn code_run_replay_denied_and_failed_bridge_rows_return_errors() -> Result<()> {
    let run_id = EntityId::from_bytes([0x71; 16]).expect("run id");
    let src = EntityId::from_bytes([0x72; 16]).expect("src id");
    let tgt = EntityId::from_bytes([0x73; 16]).expect("tgt id");
    let determinism = CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]);
    let call = SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
        src,
        EdgeKind::Mentions,
        tgt,
        0.7,
    ));

    let mut denied_record = CodeRunReplayRecord::new(run_id, determinism);
    denied_record.bridge_calls.push(CodeRunBridgeCall::record(
        0,
        &call,
        &SelfDispatchOutcome::Denied(SelfDeniedResult {
            effect: SelfEffect::MemoryPutEdge,
            outcome: "pending".to_owned(),
            reason_codes: vec!["gate.pending.actor_ceiling".to_owned()],
        }),
        determinism.frozen_unix_ms,
        determinism.frozen_unix_ms,
    )?);
    let denied_replay = denied_record.replay_cursor();
    let err = denied_replay
        .dispatch(call.clone())
        .expect_err("denied trap replay must throw");
    assert!(matches!(
        err,
        Error::GateWriteRejected {
            outcome: "pending",
            ref reason_codes
        } if reason_codes == &vec!["gate.pending.actor_ceiling"]
    ));
    assert_eq!(denied_replay.consumed(), 1);

    let failed_run = EntityId::from_bytes([0x74; 16]).expect("run id");
    let mut failed_record = CodeRunReplayRecord::new(failed_run, determinism);
    failed_record.bridge_calls.push(CodeRunBridgeCall::record(
        0,
        &call,
        &SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: SelfEffect::MemoryPutEdge,
            error: "entity not found".to_owned(),
        }),
        determinism.frozen_unix_ms,
        determinism.frozen_unix_ms,
    )?);
    let failed_replay = failed_record.replay_cursor();
    let err = failed_replay
        .dispatch(call)
        .expect_err("failed trap replay must throw");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidCodeArtifactBody);
    assert_eq!(failed_replay.consumed(), 1);
    Ok(())
}

#[test]
fn code_run_replay_large_output_persists_raw_bytes_and_compact_preview() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = EntityId::from_bytes([0x95; 16]).expect("run id");
    let raw = (0..1024)
        .map(|i| format!("row {i}: large output payload with whitespace\n\n"))
        .collect::<String>()
        .into_bytes();
    let output = CodeRunRawOutput::from_bytes("/mnt/outputs/large.txt", &raw)?;
    let same_raw_other_path = CodeRunRawOutput::from_bytes("/mnt/outputs/large-copy.txt", &raw)?;

    assert_eq!(output.raw_len, raw.len() as u64);
    assert_eq!(output.handle, same_raw_other_path.handle);
    assert_ne!(output.path, same_raw_other_path.path);
    assert!(output.preview.truncated);
    assert!(
        output.preview.text.chars().count() <= crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS
    );
    assert!(!output.preview.text.contains("\n\n"));

    vault.put_code_run_raw_output(&output, &raw)?;
    vault.put_code_run_raw_output(&same_raw_other_path, &raw)?;
    let mut record = CodeRunReplayRecord::new(
        run_id,
        CodeRunDeterminism::new(1_719_000_002_000, [0xBC; 32]),
    );
    record.outputs.push(output.clone());
    record.outputs.push(same_raw_other_path.clone());
    vault.put_code_run_replay_record(&record)?;

    let loaded = vault
        .get_code_run_replay_record(&run_id)?
        .expect("stored replay record");
    assert_eq!(
        loaded.outputs,
        vec![output.clone(), same_raw_other_path.clone()]
    );
    for stored_output in [&output, &same_raw_other_path] {
        let loaded_raw = vault
            .get_code_run_raw_output(stored_output)?
            .expect("stored raw output");
        assert_eq!(loaded_raw, raw);
    }

    let mut duplicate_path = loaded;
    duplicate_path.outputs.push(CodeRunRawOutput::from_bytes(
        "/mnt/outputs/large.txt",
        b"different bytes",
    )?);
    let err = vault
        .put_code_run_replay_record(&duplicate_path)
        .expect_err("duplicate output path rejected");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidCodeArtifactBody);
    Ok(())
}

#[test]
fn code_run_replay_abi_layout_keys_are_pinned_and_hash_checked() {
    assert_eq!(
        CODE_RUN_REPLAY_RECORD_KEYS,
        [
            "schema_version",
            "run_id",
            "determinism",
            "bridge_calls",
            "step_checkpoints",
            "outputs",
            "abi_layout_checks",
        ]
    );
    assert_eq!(
        CODE_RUN_BRIDGE_CALL_KEYS,
        [
            "seq",
            "effect",
            "request",
            "outcome",
            "started_at_ms",
            "finished_at_ms",
        ]
    );
    assert_eq!(
        CODE_RUN_RAW_OUTPUT_KEYS,
        ["handle", "path", "raw_sha256", "raw_len", "preview"]
    );
    assert_eq!(CODE_RUN_OUTPUT_PREVIEW_KEYS, ["codec", "text", "truncated"]);

    let checks = code_run_replay_abi_layout_checks();
    assert!(checks.iter().any(|check| {
        check.name == "code_run.bridge_call"
            && check.fields == CODE_RUN_BRIDGE_CALL_KEYS.map(str::to_owned)
    }));

    let mut record = CodeRunReplayRecord::new(
        EntityId::from_bytes([0x96; 16]).expect("run id"),
        CodeRunDeterminism::new(1_719_000_003_000, [0xDD; 32]),
    );
    record.abi_layout_checks[0]
        .fields
        .push("bulk_write".to_owned());
    let err = encode_code_run_replay_record(&record)
        .expect_err("layout field drift must fail before persistence");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidCodeArtifactBody);
}

#[test]
fn code_run_memory_search_routes_through_dispatcher() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0x61);
    let memory = EntityId::from_bytes([0xB1; 16]).expect("memory id");
    vault
        .batch()
        .put(&memory, ENTITY_TYPE_PERSON, range(2), 2, b"matcha note")
        .text(&memory, &[("body", "matcha preference")])
        .commit()?;

    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-search",
    )?;
    let outcome = dispatcher.dispatch(SelfCall::MemorySearch(SelfMemorySearchCall::new(
        "matcha", 5,
    )))?;

    let SelfDispatchOutcome::MemorySearch(result) = outcome else {
        panic!("expected memory search outcome");
    };
    assert_eq!(result.query, "matcha");
    assert!(result.results.iter().any(|hit| hit.id == memory));
    Ok(())
}

#[test]
fn code_run_memory_search_caps_guest_limit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0x63);
    for index in 0..(SELF_MEMORY_SEARCH_MAX_RESULTS + 4) {
        let byte = 0xB0_u8 + u8::try_from(index).expect("test index fits in u8");
        let timestamp = 2 + u64::try_from(index).expect("test index fits in u64");
        let memory = EntityId::from_bytes([byte; 16]).expect("memory id");
        vault
            .batch()
            .put(
                &memory,
                ENTITY_TYPE_PERSON,
                range(timestamp),
                timestamp,
                b"matcha note",
            )
            .text(&memory, &[("body", "matcha preference")])
            .commit()?;
    }

    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-search-cap",
    )?;
    let outcome = dispatcher.dispatch(SelfCall::MemorySearch(SelfMemorySearchCall::new(
        "matcha",
        SELF_MEMORY_SEARCH_MAX_RESULTS + 10_000,
    )))?;

    let SelfDispatchOutcome::MemorySearch(result) = outcome else {
        panic!("expected memory search outcome");
    };
    assert_eq!(result.query, "matcha");
    assert_eq!(result.results.len(), SELF_MEMORY_SEARCH_MAX_RESULTS);
    Ok(())
}

#[test]
fn code_run_fixture_write_stamps_actor_source_and_approval() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0x62);
    let subject = seed_person(&vault, 0xB2);
    let claim = EntityId::from_bytes([0xC2; 16]).expect("claim id");
    let candidate = ClaimCandidate::new(
        "profile.favorite_drink",
        ClaimSubject::Entity(subject),
        Value::from("matcha"),
        0.8,
    )
    .with_evidence(Value::Map(vec![(
        Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
        Value::from("guest-spoof-attempt"),
    )]));

    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-write",
    )?;
    let outcome = dispatcher.dispatch(SelfCall::MemoryWriteFixture(
        SelfMemoryWriteFixtureCall::new(claim, candidate, range(3), 4),
    ))?;

    assert_eq!(
        outcome,
        SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: claim })
    );
    let stored = vault.get_claim(&claim)?.expect("stored claim");
    assert_eq!(stored.source, Some(ClaimSource::Generated));
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);

    let Some(Value::Map(evidence)) = stored.evidence else {
        panic!("expected write envelope evidence");
    };
    let stamped_actor = evidence
        .iter()
        .find_map(|(key, value)| {
            (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)).then_some(value)
        })
        .expect("stamped actor");
    assert_eq!(stamped_actor, &Value::Binary(actor.as_bytes().to_vec()));

    let provenance = evidence
        .iter()
        .find_map(|(key, value)| {
            (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY)).then_some(value)
        })
        .expect("stamped provenance");
    let Value::Map(provenance) = provenance else {
        panic!("expected provenance map");
    };
    let call = provenance
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(SELF_PROVENANCE_CALL_KEY)).then_some(value))
        .expect("call provenance");
    assert_eq!(call.as_str(), Some(SelfEffect::MemoryWriteFixture.as_str()));

    let candidate_evidence = evidence
        .iter()
        .find_map(|(key, value)| {
            (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY)).then_some(value)
        })
        .expect("nested candidate evidence");
    let Value::Map(candidate_evidence) = candidate_evidence else {
        panic!("expected candidate evidence map");
    };
    let spoofed_actor = candidate_evidence
        .iter()
        .find_map(|(key, value)| {
            (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)).then_some(value)
        })
        .expect("spoofed actor remains nested");
    assert_eq!(spoofed_actor.as_str(), Some("guest-spoof-attempt"));
    Ok(())
}

#[test]
fn code_run_public_put_claim_trap_stamps_host_fields() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0x64);
    let subject = seed_person(&vault, 0xB4);
    let claim = EntityId::from_bytes([0xC4; 16]).expect("claim id");
    let candidate = ClaimCandidate::new(
        "profile.favorite_drink",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    )
    .with_evidence(Value::Map(vec![(
        Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
        Value::from("guest-spoof-attempt"),
    )]));

    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-put-claim",
    )?;
    let outcome = dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        claim,
        candidate,
        range(5),
        6,
    )))?;

    assert_eq!(
        outcome,
        SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: claim })
    );
    assert_latest_gate_decision(&vault, claim)?;
    let stored = vault.get_claim(&claim)?.expect("stored claim");
    assert_eq!(stored.source, Some(ClaimSource::Generated));
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);

    let Some(Value::Map(evidence)) = stored.evidence else {
        panic!("expected write envelope evidence");
    };
    assert_eq!(
        map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
        &Value::Binary(actor.as_bytes().to_vec())
    );

    let provenance = map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY);
    let Value::Map(provenance) = provenance else {
        panic!("expected provenance map");
    };
    assert_eq!(
        map_value(provenance, SELF_PROVENANCE_CALL_KEY).as_str(),
        Some(SelfEffect::MemoryPutClaim.as_str())
    );

    let candidate_evidence = map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY);
    let Value::Map(candidate_evidence) = candidate_evidence else {
        panic!("expected candidate evidence map");
    };
    assert_eq!(
        map_value(candidate_evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY).as_str(),
        Some("guest-spoof-attempt")
    );
    Ok(())
}

#[test]
fn code_run_put_claim_trap_ignores_guest_source_and_g2_sees_generated() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xAA);
    install_self_memory_policy_trusting_source(&vault, actor, ClaimSource::UserStated)?;
    let subject = seed_person(&vault, 0xBA);
    let claim = EntityId::from_bytes([0xCA; 16]).expect("claim id");
    let candidate = ClaimCandidate::new(
        "profile.favorite_drink",
        ClaimSubject::Entity(subject),
        Value::from("gyokuro"),
        0.9,
    )
    .with_evidence(Value::Map(vec![(
        Value::from("source"),
        Value::from(ClaimSource::UserStated.as_str()),
    )]));

    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-guest-source-spoof",
    )?;
    dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        claim,
        candidate,
        range(7),
        8,
    )))?;

    assert_latest_gate_decision_reasons(&vault, claim, "pending", &["gate.pending.source_trust"])?;
    let stored = vault.get_claim(&claim)?.expect("stored claim");
    assert_eq!(stored.source, Some(ClaimSource::Generated));
    let pending = vault.pending_gate_consents(10)?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].claim_id, *claim.as_bytes());
    assert_eq!(pending[0].reason_codes, vec!["gate.pending.source_trust"]);

    let Some(Value::Map(evidence)) = stored.evidence else {
        panic!("expected write envelope evidence");
    };
    let candidate_evidence = map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY);
    let Value::Map(candidate_evidence) = candidate_evidence else {
        panic!("expected candidate evidence map");
    };
    assert_eq!(
        map_value(candidate_evidence, "source").as_str(),
        Some(ClaimSource::UserStated.as_str())
    );
    Ok(())
}

#[test]
fn code_run_full_access_write_traps_route_per_op_through_gate_and_receipts() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_first_party_actor(&vault);
    install_self_memory_allow_policy(&vault, actor)?;
    let subject = seed_person(&vault, 0xB5);
    let edge_target = seed_person(&vault, 0xC5);
    let old = EntityId::from_bytes([0xD5; 16]).expect("old claim id");
    let new = EntityId::from_bytes([0xE5; 16]).expect("new claim id");
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-write-traps",
    )?;

    let before_old_decisions = gate_decision_count(&vault)?;
    let before_old_receipts = gate_receipt_count(&vault)?;
    dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        old,
        ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.8,
        ),
        range(10),
        11,
    )))?;
    assert_eq!(gate_decision_count(&vault)?, before_old_decisions + 1);
    assert_eq!(gate_receipt_count(&vault)?, before_old_receipts + 1);
    assert_latest_gate_decision(&vault, old)?;
    assert_gate_receipts_for_claim(&vault, old, actor, "allow", 1)?;

    let before_new_decisions = gate_decision_count(&vault)?;
    let before_new_receipts = gate_receipt_count(&vault)?;
    dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        new,
        ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("matcha"),
            0.9,
        ),
        range(12),
        13,
    )))?;
    assert_eq!(gate_decision_count(&vault)?, before_new_decisions + 1);
    assert_eq!(gate_receipt_count(&vault)?, before_new_receipts + 1);
    assert_latest_gate_decision(&vault, new)?;
    assert_gate_receipts_for_claim(&vault, new, actor, "allow", 1)?;

    let before_supersede_decisions = gate_decision_count(&vault)?;
    let before_supersede_receipts = gate_receipt_count(&vault)?;
    let supersedes_edge_gate_id = edge_operation_gate_id(
        SelfEffect::MemorySupersedeClaim,
        new,
        EdgeKind::Supersedes,
        old,
    )?;
    let supersede_outcome = dispatcher.dispatch(SelfCall::MemorySupersedeClaim(
        SelfMemorySupersedeClaimCall::new(new, old, 20),
    ))?;
    assert_eq!(
        supersede_outcome,
        SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: new })
    );
    assert_eq!(gate_decision_count(&vault)?, before_supersede_decisions + 2);
    assert_eq!(gate_receipt_count(&vault)?, before_supersede_receipts + 2);
    assert_recent_gate_decision_ids(&vault, &[supersedes_edge_gate_id, old])?;
    assert_gate_receipts_for_claim(&vault, supersedes_edge_gate_id, actor, "allow", 1)?;
    assert_gate_receipts_for_claim(&vault, old, actor, "allow", 2)?;
    let old_read = vault.get_claim(&old)?.expect("superseded claim");
    assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_read.valid_to, Some(20));
    assert_eq!(vault.targets(&new, EdgeKind::Supersedes, None)?, vec![old]);

    let before_edge_decisions = gate_decision_count(&vault)?;
    let before_edge_receipts = gate_receipt_count(&vault)?;
    let edge_gate_id = edge_operation_gate_id(
        SelfEffect::MemoryPutEdge,
        subject,
        EdgeKind::Mentions,
        edge_target,
    )?;
    let edge_outcome = dispatcher.dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
        subject,
        EdgeKind::Mentions,
        edge_target,
        0.7,
    )))?;
    assert_eq!(
        edge_outcome,
        SelfDispatchOutcome::MemoryEdgeWrite(SelfMemoryEdgeWriteResult {
            src: subject,
            kind: EdgeKind::Mentions,
            tgt: edge_target,
        })
    );
    assert_eq!(gate_decision_count(&vault)?, before_edge_decisions + 1);
    assert_eq!(gate_receipt_count(&vault)?, before_edge_receipts + 1);
    assert_latest_gate_decision(&vault, edge_gate_id)?;
    assert_gate_receipts_for_claim(&vault, edge_gate_id, actor, "allow", 1)?;
    assert_eq!(
        vault.targets(&subject, EdgeKind::Mentions, None)?,
        vec![edge_target]
    );

    let read_after_write = vault.get_claim(&new)?.expect("new claim after traps");
    assert_eq!(read_after_write.value, Value::from("matcha"));
    assert_eq!(read_after_write.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

#[test]
fn code_run_edge_and_supersede_traps_force_generated_source_into_g2() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xAB);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-generated-source-g2",
    )?;
    let subject = seed_person(&vault, 0xBB);
    let edge_target = seed_person(&vault, 0xCB);
    let old = EntityId::from_bytes([0xDB; 16]).expect("old claim id");
    let new = EntityId::from_bytes([0xEB; 16]).expect("new claim id");

    install_self_memory_allow_policy(&vault, actor)?;
    dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        old,
        ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.8,
        ),
        range(10),
        11,
    )))?;
    dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        new,
        ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("matcha"),
            0.9,
        ),
        range(12),
        13,
    )))?;

    install_self_memory_policy_trusting_source(&vault, actor, ClaimSource::UserStated)?;
    let edge_gate_id = edge_operation_gate_id(
        SelfEffect::MemoryPutEdge,
        subject,
        EdgeKind::Mentions,
        edge_target,
    )?;
    let edge_err = dispatcher
        .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            subject,
            EdgeKind::Mentions,
            edge_target,
            0.7,
        )))
        .expect_err("generated source must be evaluated by G2");
    assert_source_trust_gate_rejection(edge_err);
    assert_latest_gate_decision_reasons(
        &vault,
        edge_gate_id,
        "pending",
        &["gate.pending.source_trust"],
    )?;
    assert!(
        vault
            .targets(&subject, EdgeKind::Mentions, None)?
            .is_empty()
    );

    let supersede_err = dispatcher
        .dispatch(SelfCall::MemorySupersedeClaim(
            SelfMemorySupersedeClaimCall::new(new, old, 20),
        ))
        .expect_err("generated source must be evaluated by G2");
    assert_source_trust_gate_rejection(supersede_err);
    assert_latest_gate_decision_reasons(&vault, old, "pending", &["gate.pending.source_trust"])?;
    let old_read = vault.get_claim(&old)?.expect("old claim remains");
    assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Active);
    assert!(vault.targets(&new, EdgeKind::Supersedes, None)?.is_empty());
    Ok(())
}

#[test]
fn code_run_immediate_write_traps_reject_pending_gate() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xD6);
    let src = seed_person(&vault, 0xB6);
    let tgt = seed_person(&vault, 0xC6);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-pending-write",
    )?;
    let gate_id = edge_operation_gate_id(SelfEffect::MemoryPutEdge, src, EdgeKind::Mentions, tgt)?;
    let before = gate_decision_count(&vault)?;

    let _err = dispatcher
        .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            src,
            EdgeKind::Mentions,
            tgt,
            0.7,
        )))
        .expect_err("pending immediate write must not commit");

    assert_eq!(gate_decision_count(&vault)?, before + 1);
    let decisions = vault.store.gate_decisions(1)?;
    let latest = decisions.first().expect("latest gate decision");
    assert_eq!(latest.outcome, "pending");
    assert_eq!(latest.claim_id, Some(*gate_id.as_bytes()));
    assert!(
        latest
            .reason_codes
            .iter()
            .any(|code| code.starts_with("gate.pending."))
    );
    assert!(vault.targets(&src, EdgeKind::Mentions, None)?.is_empty());
    Ok(())
}

#[test]
fn code_run_write_traps_validate_bound_actor() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_machine(&vault, 0xA8);
    let src = seed_person(&vault, 0xB8);
    let tgt = seed_person(&vault, 0xC8);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-invalid-actor",
    )?;
    let before = gate_decision_count(&vault)?;

    let _err = dispatcher
        .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            src,
            EdgeKind::Mentions,
            tgt,
            0.7,
        )))
        .expect_err("wrong actor class must reject before write");

    assert_eq!(gate_decision_count(&vault)?, before);
    assert!(vault.targets(&src, EdgeKind::Mentions, None)?.is_empty());
    Ok(())
}

#[test]
fn code_run_put_edge_rejects_structural_edge_kinds() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_first_party_actor(&vault);
    let src = seed_person(&vault, 0xB9);
    let tgt = seed_person(&vault, 0xC9);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-structural-edge",
    )?;
    let before = gate_decision_count(&vault)?;

    let err = dispatcher
        .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            src,
            EdgeKind::ClaimOf,
            tgt,
            1.0,
        )))
        .expect_err("structural edge kind must reject");
    assert!(
        matches!(
            err,
            Error::InvalidClaimBody("self.memory.put_edge rejects structural edge kinds")
        ),
        "{err:?}"
    );

    assert_eq!(gate_decision_count(&vault)?, before);
    assert!(vault.targets(&src, EdgeKind::ClaimOf, None)?.is_empty());
    Ok(())
}

#[test]
fn code_run_write_gate_denial_persists_decision() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_malformed_policy_manifest(&vault, 0xE7)?;
    let actor = seed_person(&vault, 0xA7);
    let src = seed_person(&vault, 0xB7);
    let tgt = seed_person(&vault, 0xC7);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-denied-write",
    )?;
    let gate_id = edge_operation_gate_id(SelfEffect::MemoryPutEdge, src, EdgeKind::Mentions, tgt)?;
    let before = gate_decision_count(&vault)?;

    let _err = dispatcher
        .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            src,
            EdgeKind::Mentions,
            tgt,
            0.7,
        )))
        .expect_err("fail-closed policy must reject write");

    assert_eq!(gate_decision_count(&vault)?, before + 1);
    let decisions = vault.store.gate_decisions(1)?;
    let latest = decisions.first().expect("latest gate decision");
    assert_eq!(latest.outcome, "deny");
    assert_eq!(latest.claim_id, Some(*gate_id.as_bytes()));
    assert_eq!(latest.reason_codes, vec!["gate.deny.policy_fail_closed"]);
    assert!(vault.targets(&src, EdgeKind::Mentions, None)?.is_empty());
    Ok(())
}

#[test]
fn code_run_human_destructive_and_outbound_effects_become_durable_waits() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0x63);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-waits",
    )?;

    let cases = [
        (
            SelfCall::AskHuman(SelfAskHumanCall::new("continue?")),
            SelfEffect::AskHuman,
            SelfDurableWaitReason::HumanInput,
        ),
        (
            SelfCall::DestructiveFixture(SelfFixtureEffectCall::new("delete memory")),
            SelfEffect::DestructiveFixture,
            SelfDurableWaitReason::DestructiveEffect,
        ),
        (
            SelfCall::OutboundFixture(SelfFixtureEffectCall::new("send message")),
            SelfEffect::OutboundFixture,
            SelfDurableWaitReason::OutboundEffect,
        ),
    ];

    for (call, effect, reason) in cases {
        let outcome = dispatcher.dispatch(call)?;
        let SelfDispatchOutcome::DurableWait(wait) = outcome else {
            panic!("expected durable wait");
        };
        assert_eq!(wait.effect, effect);
        assert_eq!(wait.reason, reason);
        assert!(wait.prompt.is_some());
    }

    Ok(())
}

/// ONE-1414 done-means 5 (self-memory half) — `self.memory.put_edge` REFUSES
/// to mint a `same_as` link.
///
/// `same_as` is structural, so it lands with the rest of the structural kinds
/// on this trap's refusal side. The refusal is what keeps
/// `federation::put_coreference_link` the owning write door: a link minted
/// here would carry no status claim, no per-pact consent surface, and no
/// owner-gated actor, while still steering what the export filter discloses.
#[test]
fn self_memory_put_edge_refuses_same_as() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xAC);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-same-as-refusal",
    )?;
    let subject = seed_person(&vault, 0xBC);
    let other = seed_person(&vault, 0xCC);
    install_self_memory_allow_policy(&vault, actor)?;

    // The trap admits an ordinary semantic kind, so the refusal below is about
    // `same_as` and not about this dispatcher being unable to write at all.
    dispatcher.dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
        subject,
        EdgeKind::Mentions,
        other,
        0.7,
    )))?;

    let err = dispatcher
        .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            subject,
            EdgeKind::SameAs,
            other,
            0.0,
        )))
        .expect_err("self.memory.put_edge must refuse the structural same_as kind");
    assert!(matches!(err, Error::InvalidClaimBody(_)));
    assert!(
        vault.targets(&subject, EdgeKind::SameAs, None)?.is_empty(),
        "a refused trap must leave no link behind"
    );
    Ok(())
}
