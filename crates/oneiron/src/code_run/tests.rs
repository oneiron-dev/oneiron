use rmpv::Value;

use super::*;
use crate::error::ErrorKind;
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

fn install_exact_actor_ceiling(vault: &Vault, actor: EntityId, ceiling: &str) -> Result<()> {
    clear_policy_manifests_for_test(vault)?;
    let mut cursor = std::io::Cursor::new(crate::gate::default_policy_manifest());
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvariantViolation("default policy manifest failed to decode"))?
    else {
        return Err(Error::InvariantViolation(
            "default policy manifest is not a map",
        ));
    };
    let ceilings = entries
        .iter_mut()
        .find_map(|(key, value)| (key.as_str() == Some("actor_ceilings")).then_some(value))
        .ok_or(Error::InvariantViolation(
            "default policy manifest has no actor ceilings",
        ))?;
    let Value::Array(rows) = ceilings else {
        return Err(Error::InvariantViolation(
            "default policy actor ceilings are not an array",
        ));
    };
    rows.push(Value::Map(vec![
        (Value::from("actor_class"), Value::from("agent")),
        (Value::from("actor_ref"), Value::from(actor.to_hex())),
        (Value::from("ceiling"), Value::from(ceiling)),
    ]));
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("policy manifest failed to encode"))?;
    put_indexed_manifest_at_two(vault, entity(0xE9), &data)
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

fn map_value_mut<'a>(value: &'a mut Value, key: &str) -> &'a mut Value {
    let Value::Map(entries) = value else {
        panic!("value is a map");
    };
    &mut entries
        .iter_mut()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .unwrap_or_else(|| panic!("map carries {key}"))
        .1
}

fn set_map_value(value: &mut Value, key: &str, replacement: Value) {
    *map_value_mut(value, key) = replacement;
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

/// ONE-1936: the code-run supersede trap guards its NAMED target before the
/// gate runs, because the gate deliberately commits its decision receipts even
/// on rejection. A stale target must leave no receipt, no lifecycle write, and
/// no edge — and must never be re-aimed at the successor.
#[test]
fn code_run_stale_supersede_fails_loudly() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_first_party_actor(&vault);
    install_self_memory_allow_policy(&vault, actor)?;
    let subject = seed_person(&vault, 0x34);
    let old = EntityId::from_bytes([0x31; 16]).expect("old claim id");
    let replacement = EntityId::from_bytes([0x32; 16]).expect("replacement claim id");
    let latecomer = EntityId::from_bytes([0x33; 16]).expect("latecomer claim id");
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-stale-supersede",
    )?;

    for (id, value, at) in [
        (old, "sencha", 10_u64),
        (replacement, "matcha", 12),
        (latecomer, "hojicha", 14),
    ] {
        dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from(value),
                0.8,
            ),
            range(at),
            at + 1,
        )))?;
    }

    dispatcher.dispatch(SelfCall::MemorySupersedeClaim(
        SelfMemorySupersedeClaimCall::new(replacement, old, 20),
    ))?;

    let before_decisions = gate_decision_count(&vault)?;
    let before_receipts = gate_receipt_count(&vault)?;
    let err = dispatcher
        .dispatch(SelfCall::MemorySupersedeClaim(
            SelfMemorySupersedeClaimCall::new(latecomer, old, 30),
        ))
        .expect_err("the named target is no longer the head");

    assert_eq!(err.kind(), ErrorKind::WriteVerbTargetStale);
    let Error::WriteVerbTargetStale {
        target,
        lifecycle,
        successor_short_id,
    } = err
    else {
        panic!("expected a typed stale-target refusal");
    };
    assert_eq!(target, old);
    assert_eq!(lifecycle, ClaimLifecycleStatus::Superseded);
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        successor_short_id,
        vault.claim_short_ref_in(&rtxn, &replacement)?
    );
    drop(rtxn);

    // Guard before gate: not one decision or receipt was emitted.
    assert_eq!(gate_decision_count(&vault)?, before_decisions);
    assert_eq!(gate_receipt_count(&vault)?, before_receipts);

    // Nothing was written and nothing was retargeted.
    let old_read = vault.get_claim(&old)?.expect("old claim");
    assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_read.valid_to, Some(20), "the first close survives");
    assert_eq!(
        vault
            .get_claim(&replacement)?
            .expect("replacement")
            .lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(
        vault
            .targets(&latecomer, EdgeKind::Supersedes, None)?
            .is_empty(),
        "a refused supersede must write no supersedes edge"
    );
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

/// The ONE-1700 additions round-trip through the replay codec, and adding them
/// changed none of the landed effect or reason tokens.
#[test]
fn task_delegate_and_peer_result_round_trip_without_disturbing_landed_tokens() {
    let effects = [
        SelfEffect::MemorySearch,
        SelfEffect::MemoryWriteFixture,
        SelfEffect::MemoryPutClaim,
        SelfEffect::MemorySupersedeClaim,
        SelfEffect::MemoryPutEdge,
        SelfEffect::AskHuman,
        SelfEffect::DestructiveFixture,
        SelfEffect::OutboundFixture,
        SelfEffect::TaskDelegate,
    ];
    let reasons = [
        SelfDurableWaitReason::HumanInput,
        SelfDurableWaitReason::DestructiveEffect,
        SelfDurableWaitReason::OutboundEffect,
        SelfDurableWaitReason::PeerResult,
    ];

    let effect_tokens: Vec<&str> = effects.iter().map(|effect| effect.as_str()).collect();
    let effects_back: Vec<SelfEffect> = effect_tokens
        .iter()
        .map(|token| self_effect_from_str(token).expect("effect token round-trips"))
        .collect();
    let reason_tokens: Vec<&str> = reasons
        .iter()
        .copied()
        .map(durable_wait_reason_str)
        .collect();
    let reasons_back: Vec<SelfDurableWaitReason> = reason_tokens
        .iter()
        .map(|token| durable_wait_reason_from_str(token).expect("reason token round-trips"))
        .collect();

    assert_eq!(effects_back, effects);
    assert_eq!(reasons_back, reasons);
    assert_eq!(
        effect_tokens,
        vec![
            "self.memory.search",
            "self.memory.write_fixture",
            "self.memory.put_claim",
            "self.memory.supersede_claim",
            "self.memory.put_edge",
            "self.ask_human",
            "self.fixture.destructive",
            "self.fixture.outbound",
            "self.tasks.delegate",
        ]
    );
    assert_eq!(
        reason_tokens,
        vec![
            "human_input",
            "destructive_effect",
            "outbound_effect",
            "peer_result",
        ]
    );
    assert_eq!(
        usize::from(self_effect_from_str("self.tasks.delegated").is_err()),
        1
    );
    assert_eq!(
        usize::from(durable_wait_reason_from_str("peer-result").is_err()),
        1
    );
}

/// The delegation wait names the delegated TASK as its wait id and carries no
/// prompt: nobody is being asked for permission.
#[test]
fn peer_result_wait_is_keyed_on_the_delegated_task() {
    let task_ref = crate::test_util::entity(0x2B);
    let wait = peer_result_wait(task_ref);

    assert_eq!(wait.wait_id, task_ref);
    assert_eq!(wait.effect, SelfEffect::TaskDelegate);
    assert_eq!(wait.reason, SelfDurableWaitReason::PeerResult);
    assert_eq!(wait.prompt, None);
}

// ── ONE-1709: the `self.context` descriptor bridge ──────────────────────

/// `self.context(spec)` hands the descriptor back after normalization and
/// touches no storage: the vault is byte-identical across the call, and a
/// second pass over the returned spec is a fixed point.
#[test]
fn self_context_round_trips_the_descriptor_without_reading_the_vault() -> Result<()> {
    use crate::context_projection::{ChatProjection, ContextSpec, MemoryProjection};

    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0x51);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-context",
    )?;

    // A durable claim and a durable turn exist. If `self.context` resolved
    // anything, they would show up in the answer; the descriptor comes back
    // naming only what the caller asked for.
    let turn = entity(0x52);
    vault.put_entity(&turn, crate::registry::ENTITY_TYPE_TURN, range(3), 3, b"t")?;

    let before: Vec<EntityId> = vault.entities_by_type(crate::registry::ENTITY_TYPE_TURN)?;
    let authored = ContextSpec {
        layers: vec!["  identity ".to_owned(), "identity".to_owned()],
        memory: MemoryProjection::Scoped {
            domains: vec![" health ".to_owned()],
            limit: 2,
        },
        chat: ChatProjection::Recent { last_n: 1 },
        briefing: Some(" delegate the weight question ".to_owned()),
        annotation: Some(" dev note ".to_owned()),
    };

    let outcome = dispatcher.dispatch(SelfCall::Context(SelfContextCall::new(authored)))?;

    let SelfDispatchOutcome::Context(result) = outcome else {
        panic!("expected the context descriptor outcome");
    };
    assert_eq!(result.spec.layers, ["identity"]);
    assert_eq!(
        result.spec.memory,
        MemoryProjection::Scoped {
            domains: vec!["health".to_owned()],
            limit: 2,
        }
    );
    assert_eq!(result.spec.chat, ChatProjection::Recent { last_n: 1 });
    assert_eq!(
        result.spec.briefing.as_deref(),
        Some("delegate the weight question")
    );
    // `_annotation` survives the DESCRIPTOR (it is stripped at resolution).
    assert_eq!(result.spec.annotation.as_deref(), Some("dev note"));

    // Re-dispatching the returned descriptor is a fixed point.
    let again =
        dispatcher.dispatch(SelfCall::Context(SelfContextCall::new(result.spec.clone())))?;
    let SelfDispatchOutcome::Context(second) = again else {
        panic!("expected the context descriptor outcome");
    };
    assert_eq!(second.spec, result.spec);

    // Nothing was written, and no receipt was minted for a non-effect.
    assert_eq!(
        vault.entities_by_type(crate::registry::ENTITY_TYPE_TURN)?,
        before
    );
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
            .len(),
        0
    );
    Ok(())
}

/// A malformed descriptor is refused at the bridge, before it can ride a
/// spawn payload.
#[test]
fn self_context_refuses_a_malformed_descriptor() -> Result<()> {
    use crate::context_projection::{ContextSpec, MemoryProjection};

    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0x53);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-context-invalid",
    )?;

    let error = dispatcher
        .dispatch(SelfCall::Context(SelfContextCall::new(ContextSpec {
            memory: MemoryProjection::Scoped {
                domains: vec!["health".to_owned()],
                limit: 0,
            },
            ..ContextSpec::default()
        })))
        .expect_err("a zero-limit scoped projection is malformed");
    assert_eq!(error.kind(), ErrorKind::InvalidAgentDispatchInput);
    Ok(())
}

/// The bridge call is a first-class replay-log entry: request and outcome
/// both round-trip through the pinned codec under the `self.context` effect.
#[test]
fn self_context_calls_replay_through_the_pinned_codec() -> Result<()> {
    use crate::context_projection::{ChatProjection, ContextSpec};

    let spec = ContextSpec {
        layers: vec!["identity".to_owned()],
        chat: ChatProjection::Recent { last_n: 2 },
        ..ContextSpec::default()
    };
    let call = SelfCall::Context(SelfContextCall::new(spec.clone()));
    assert_eq!(call.effect(), SelfEffect::Context);
    assert_eq!(SelfEffect::Context.as_str(), "self.context");

    let request = self_call_request_value(&call)?;
    assert_eq!(self_call_request_value(&call)?, request);

    let outcome = SelfDispatchOutcome::Context(SelfContextResult { spec });
    let encoded = self_dispatch_outcome_value(&outcome);
    assert_eq!(decode_self_dispatch_outcome(&encoded)?, outcome);
    Ok(())
}

/// ONE-1686 RT-04: the three speech verbs are stable typed calls with stable
/// wire labels, and both halves of a bridge row round-trip through the pinned
/// codec — while every landed effect token keeps the exact string it had.
#[test]
fn self_speech_calls_round_trip_without_disturbing_landed_tokens() -> Result<()> {
    let speech = [
        (SelfEffect::Speak, "self.speak", true),
        (SelfEffect::Think, "self.think", false),
        (SelfEffect::Express, "self.express", true),
    ];

    for (effect, token, is_visible) in speech {
        assert_eq!(effect.as_str(), token);
        assert_eq!(self_effect_from_str(token)?, effect);
        assert!(effect.is_speech());
        assert_eq!(
            effect
                .speech_utterance()
                .expect("speech utterance")
                .is_visible(),
            is_visible,
            "{token} visibility is decided once, by the utterance"
        );
    }

    // No non-speech effect drifted into the family.
    for effect in [
        SelfEffect::MemorySearch,
        SelfEffect::MemoryWriteFixture,
        SelfEffect::MemoryPutClaim,
        SelfEffect::MemorySupersedeClaim,
        SelfEffect::MemoryPutEdge,
        SelfEffect::AskHuman,
        SelfEffect::DestructiveFixture,
        SelfEffect::OutboundFixture,
        SelfEffect::TaskDelegate,
        SelfEffect::Context,
    ] {
        assert!(!effect.is_speech(), "{} is not speech", effect.as_str());
        assert_eq!(effect.speech_utterance(), None);
    }

    // The landed tokens are untouched by the addition.
    assert_eq!(
        [
            SelfEffect::MemorySearch,
            SelfEffect::MemoryWriteFixture,
            SelfEffect::MemoryPutClaim,
            SelfEffect::MemorySupersedeClaim,
            SelfEffect::MemoryPutEdge,
            SelfEffect::AskHuman,
            SelfEffect::DestructiveFixture,
            SelfEffect::OutboundFixture,
            SelfEffect::TaskDelegate,
            SelfEffect::Context,
        ]
        .map(SelfEffect::as_str)
        .to_vec(),
        vec![
            "self.memory.search",
            "self.memory.write_fixture",
            "self.memory.put_claim",
            "self.memory.supersede_claim",
            "self.memory.put_edge",
            "self.ask_human",
            "self.fixture.destructive",
            "self.fixture.outbound",
            "self.tasks.delegate",
            "self.context",
        ]
    );

    let calls = [
        SelfCall::Speak(SelfSpeechCall::new("hello")),
        SelfCall::Think(SelfSpeechCall::new("hmm")),
        SelfCall::Express(SelfSpeechCall::new("*waves*")),
    ];
    for (index, call) in calls.into_iter().enumerate() {
        let effect = call.effect();
        let seq = index as u64;
        let stamped = call.with_bridge_stamp(seq, 1_719_000_000_000 + seq);
        let (SelfCall::Speak(inner) | SelfCall::Think(inner) | SelfCall::Express(inner)) = &stamped
        else {
            panic!("speech call stays in the speech family after stamping");
        };
        assert_eq!(inner.order, index as u32);
        assert_eq!(inner.occurred_at, (1_719_000_000_000 + seq) / 1000);

        let request = self_call_request_value(&stamped)?;
        assert_eq!(self_call_request_value(&stamped)?, request);

        let outcome = SelfDispatchOutcome::Speech(SelfSpeechResult {
            effect,
            order: index as u32,
            is_visible: effect.speech_utterance().expect("utterance").is_visible(),
            emitted: true,
        });
        let encoded = self_dispatch_outcome_value(&outcome);
        assert_eq!(decode_self_dispatch_outcome(&encoded)?, outcome);
    }

    // A speech OUTCOME naming a non-speech effect is rejected, not coerced.
    let forged = self_dispatch_outcome_value(&SelfDispatchOutcome::Speech(SelfSpeechResult {
        effect: SelfEffect::Speak,
        order: 0,
        is_visible: true,
        emitted: true,
    }));
    let Value::Map(mut entries) = forged else {
        panic!("speech outcome encodes as a map");
    };
    for entry in &mut entries {
        if entry.0.as_str() == Some("effect") {
            entry.1 = Value::from("self.memory.search");
        }
    }
    assert!(decode_self_dispatch_outcome(&Value::Map(entries)).is_err());
    Ok(())
}

/// Speech replay rows bind the outer effect, host-stamped request and complete
/// result. Construction, encode/decode and a cursor over an in-memory record all
/// reject cross-axis forgeries instead of replaying an outcome the writer could
/// never have produced.
#[test]
fn speech_replay_refuses_incoherent_effect_order_visibility_emission_and_host_stamp() -> Result<()>
{
    let started_at_ms = 1_719_000_123_456;
    let call =
        SelfCall::Speak(SelfSpeechCall::new("coherent answer")).with_bridge_stamp(0, started_at_ms);
    let outcome = SelfDispatchOutcome::Speech(SelfSpeechResult {
        effect: SelfEffect::Speak,
        order: 0,
        is_visible: true,
        emitted: true,
    });
    let row = CodeRunBridgeCall::record(0, &call, &outcome, started_at_ms, started_at_ms)?;
    let mut record = CodeRunReplayRecord::new(
        entity(0xD0),
        CodeRunDeterminism::new(started_at_ms, [0xD0; 32]),
    );
    record.bridge_calls.push(row);
    let valid_encoded = encode_code_run_replay_record(&record)?;
    assert_eq!(decode_code_run_replay_record(&valid_encoded)?, record);
    assert_eq!(
        record
            .replay_cursor()
            .dispatch(SelfCall::Speak(SelfSpeechCall::new("coherent answer")))?,
        outcome,
    );

    let mismatched_at_construction = SelfDispatchOutcome::Speech(SelfSpeechResult {
        effect: SelfEffect::Think,
        order: 0,
        is_visible: false,
        emitted: true,
    });
    CodeRunBridgeCall::record(
        0,
        &call,
        &mismatched_at_construction,
        started_at_ms,
        started_at_ms,
    )
    .expect_err("record construction binds inner and outer speech effects");

    for axis in [
        "outcome effect",
        "outcome order",
        "outcome visibility",
        "outcome emitted",
        "request order",
        "request occurred_at",
    ] {
        let mut forged = record.clone();
        let row = &mut forged.bridge_calls[0];
        match axis {
            "outcome effect" => {
                set_map_value(&mut row.outcome, "effect", Value::from("self.think"));
                set_map_value(&mut row.outcome, "is_visible", Value::Boolean(false));
            }
            "outcome order" => set_map_value(&mut row.outcome, "order", Value::from(1_u64)),
            "outcome visibility" => {
                set_map_value(&mut row.outcome, "is_visible", Value::Boolean(false));
            }
            "outcome emitted" => {
                set_map_value(&mut row.outcome, "emitted", Value::Boolean(false));
            }
            "request order" => set_map_value(&mut row.request, "order", Value::from(1_u64)),
            "request occurred_at" => set_map_value(
                &mut row.request,
                "occurred_at",
                Value::from(started_at_ms / 1000 + 1),
            ),
            _ => unreachable!(),
        }

        assert!(
            encode_code_run_replay_record(&forged).is_err(),
            "encode must reject {axis}",
        );
        let cursor = forged.replay_cursor();
        assert!(
            cursor
                .dispatch(SelfCall::Speak(SelfSpeechCall::new("coherent answer")))
                .is_err(),
            "cursor must reject {axis}",
        );
        assert_eq!(cursor.consumed(), 0, "{axis}");
    }

    // Decode runs the same row-context validator. Mutate a valid wire record
    // directly so the forged bytes did not first pass the encoder.
    let mut cursor = valid_encoded.as_slice();
    let mut wire = rmpv::decode::read_value(&mut cursor).expect("decode valid wire value");
    let Value::Array(calls) = map_value_mut(&mut wire, "bridge_calls") else {
        panic!("bridge_calls is an array");
    };
    let outcome = map_value_mut(&mut calls[0], "outcome");
    set_map_value(outcome, "effect", Value::from("self.think"));
    set_map_value(outcome, "is_visible", Value::Boolean(false));
    let mut forged_wire = Vec::new();
    rmpv::encode::write_value(&mut forged_wire, &wire).expect("encode forged wire value");
    decode_code_run_replay_record(&forged_wire)
        .expect_err("decode must reject cross-axis speech outcome forgery");
    Ok(())
}

/// A speech request may end in a denied/failed/barrier row, but never in a
/// successful non-speech outcome. The cursor and codec must reject that
/// impossible cross-effect row before it can reach the guest.
#[test]
fn speech_replay_rejects_successful_non_speech_outcome() -> Result<()> {
    let started_at_ms = 1_719_000_123_456;
    let call =
        SelfCall::Speak(SelfSpeechCall::new("coherent answer")).with_bridge_stamp(0, started_at_ms);
    let outcome = SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
        query: "forged search".to_owned(),
        results: Vec::new(),
    });
    let row = CodeRunBridgeCall {
        seq: 0,
        effect: SelfEffect::Speak,
        request: self_call_request_value(&call)?,
        outcome: self_dispatch_outcome_value(&outcome),
        started_at_ms,
        finished_at_ms: started_at_ms,
    };
    let mut record = CodeRunReplayRecord::new(
        entity(0xD1),
        CodeRunDeterminism::new(started_at_ms, [0xD1; 32]),
    );
    record.bridge_calls.push(row);

    assert!(
        encode_code_run_replay_record(&record).is_err(),
        "codec must reject a successful non-speech result on a speech row",
    );
    let cursor = record.replay_cursor();
    assert!(
        cursor
            .dispatch(SelfCall::Speak(SelfSpeechCall::new("coherent answer")))
            .is_err(),
        "cursor must reject a successful non-speech result on a speech row",
    );
    assert_eq!(
        cursor.consumed(),
        0,
        "rejection must not consume the cursor"
    );
    Ok(())
}

/// ONE-1686: a CANONICAL run's speech materializes one complete MESSAGE per
/// call, through the same witness door the session arm uses.
///
/// Every axis is asserted, because the ceiling door binds every axis: the
/// Companion author, the family's message type, the guest's text, the family's
/// visibility, and the HOST's bridge order. The rows land in the run-scoped
/// conversation and turn derived from the run ref — a canonical run is not a
/// mute run, and `emitted` is not a field that can say "spoken" with nothing
/// behind it.
#[test]
fn canonical_speech_materializes_one_complete_bubble_per_call() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xB7);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-canonical-speech",
    )?;

    assert_eq!(message_entity_count(&vault)?, 0);
    for (index, (call, effect, is_visible, text, message_type)) in [
        (
            SelfCall::Speak(SelfSpeechCall::new("addressed")),
            SelfEffect::Speak,
            true,
            "addressed",
            "executor.speak",
        ),
        (
            SelfCall::Think(SelfSpeechCall::new("private")),
            SelfEffect::Think,
            false,
            "private",
            "executor.think",
        ),
        (
            SelfCall::Express(SelfSpeechCall::new("*nods*")),
            SelfEffect::Express,
            true,
            "*nods*",
            "executor.express",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let order = index as u32;
        let outcome =
            dispatcher.dispatch(call.with_bridge_stamp(order.into(), 1_719_000_000_000))?;
        assert_eq!(
            outcome,
            SelfDispatchOutcome::Speech(SelfSpeechResult {
                effect,
                order,
                is_visible,
                // A canonical bubble EXISTS, so the outcome says so.
                emitted: true,
            })
        );

        // The bubble is at the derived id, and its body is the complete
        // canonical envelope the ceiling door authorized.
        let id = crate::code_run::executor_speech_message_id("run-canonical-speech", order)?;
        let view = vault
            .memory(actor, EdgeActorClass::Agent)
            .get_entity(&id.to_hex())
            .expect("get bubble")
            .expect("bubble exists");
        let body = view.body.expect("bubble body decodes");
        assert_eq!(body["author"], serde_json::json!("companion"));
        assert_eq!(body["type"], serde_json::json!(message_type));
        assert_eq!(body["content"], serde_json::json!(text));
        assert_eq!(body["is_visible"], serde_json::json!(is_visible));
        assert_eq!(body["order"], serde_json::json!(order));
    }
    assert_eq!(
        message_entity_count(&vault)?,
        3,
        "one bubble per speech call, and no more"
    );
    assert_eq!(
        gate_decision_rows(&vault)?,
        0,
        "speech opens no memory-write gate"
    );
    Ok(())
}

/// ONE-1686 idempotency by IDENTITY: re-dispatching the same speech position
/// — the shape a step re-run after a failed replay-record persist takes —
/// converges on the SAME bubble instead of growing a second one.
#[test]
fn canonical_speech_redispatch_at_the_same_order_writes_no_second_bubble() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xB8);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-canonical-speech-retry",
    )?;

    for _ in 0..3 {
        dispatcher.dispatch(
            SelfCall::Speak(SelfSpeechCall::new("said once"))
                .with_bridge_stamp(2, 1_719_000_000_000),
        )?;
    }

    assert_eq!(
        message_entity_count(&vault)?,
        1,
        "three attempts at one position leave one bubble"
    );
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TURN)?
            .len(),
        1,
        "and one turn, not one per attempt"
    );
    let id = crate::code_run::executor_speech_message_id("run-canonical-speech-retry", 2)?;
    let body = vault
        .memory(actor, EdgeActorClass::Agent)
        .get_entity(&id.to_hex())
        .expect("get bubble")
        .expect("bubble exists")
        .body
        .expect("bubble body decodes");
    assert_eq!(body["content"], serde_json::json!("said once"));
    assert_eq!(body["order"], serde_json::json!(2));
    Ok(())
}

/// A deterministic MESSAGE id is create-or-verify, never an overwrite handle.
/// Exact retries leave both MESSAGE and TURN bytes unchanged; changed text or a
/// changed speech family at the same run/order is refused and cannot reparent
/// or replace the winner.
#[test]
fn canonical_speech_retry_refuses_a_divergent_same_id_body() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xBA);
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-canonical-divergent-retry",
    )?;
    let stamp = |call: SelfCall| call.with_bridge_stamp(7, 1_719_000_007_000);

    dispatcher.dispatch(stamp(SelfCall::Speak(SelfSpeechCall::new("winner"))))?;
    let message_id = executor_speech_message_id("run-canonical-divergent-retry", 7)?;
    let message_before = vault.get_raw(&message_id)?.expect("message exists");
    let turns = vault.entities_by_type(crate::registry::ENTITY_TYPE_TURN)?;
    assert_eq!(turns.len(), 1);
    let turn_id = turns[0];
    let turn_before = vault.get_raw(&turn_id)?.expect("turn exists");

    dispatcher.dispatch(stamp(SelfCall::Speak(SelfSpeechCall::new("winner"))))?;
    assert_eq!(
        vault.get_raw(&message_id)?.as_deref(),
        Some(message_before.as_slice())
    );
    assert_eq!(
        vault.get_raw(&turn_id)?.as_deref(),
        Some(turn_before.as_slice())
    );

    for divergent in [
        SelfCall::Speak(SelfSpeechCall::new("loser overwrite")),
        SelfCall::Think(SelfSpeechCall::new("winner")),
    ] {
        dispatcher
            .dispatch(stamp(divergent))
            .expect_err("same-id divergent speech retry must be refused");
        assert_eq!(
            vault.get_raw(&message_id)?.as_deref(),
            Some(message_before.as_slice()),
            "the winning MESSAGE body stays immutable",
        );
        assert_eq!(
            vault
                .entities_by_type(crate::registry::ENTITY_TYPE_TURN)?
                .len(),
            1
        );
        let part_of = vault
            .edges_out(&message_id)?
            .into_iter()
            .filter(|edge| edge.kind == crate::edge::EdgeKind::PartOf)
            .map(|edge| edge.target)
            .collect::<Vec<_>>();
        assert_eq!(part_of, vec![turn_id], "the winner keeps one TURN parent");
    }
    Ok(())
}

/// The session storage arm uses the same host-derived TURN on every attempt.
/// An exact off-record retry is a graph no-op; a divergent retry at that
/// MESSAGE id is refused before the overlay or typed journal can gain another
/// turn, parent edge, or body.
#[test]
fn off_record_session_speech_retry_converges_on_one_turn_and_one_message() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xBB);
    let session = vault.off_record_session_vault().enter(
        "session-speech-idempotency",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    let dispatcher = HostSelfDispatcher::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-session-idempotency",
    )?;
    let stamped = |text: &str| {
        SelfCall::Speak(SelfSpeechCall::new(text)).with_bridge_stamp(3, 1_719_000_003_000)
    };

    dispatcher.dispatch(stamped("one bubble"))?;
    dispatcher.dispatch(stamped("one bubble"))?;
    let message_id = executor_speech_message_id("run-session-idempotency", 3)?;

    let snapshot = || -> Result<(usize, usize, Vec<EntityId>, Vec<u8>)> {
        let view = session.read_view()?;
        let rtxn = vault.store.env.read_txn()?;
        let turns = view
            .type_index
            .prefix_iter(&rtxn, &[crate::registry::ENTITY_TYPE_TURN])?
            .count();
        let messages = view
            .type_index
            .prefix_iter(&rtxn, &[crate::registry::ENTITY_TYPE_MESSAGE])?
            .count();
        let prefix = crate::vault::edge_kind_prefix(&message_id, crate::edge::EdgeKind::PartOf);
        let mut parents = Vec::new();
        for row in view.edges_out.prefix_iter(&rtxn, &prefix)? {
            let (key, _) = row?;
            let (_, _, target) = crate::edge::parse_strict_edge_record_key(&key)?;
            parents.push(target);
        }
        let raw = view
            .entities
            .get(&rtxn, message_id.as_bytes())?
            .expect("session MESSAGE exists")
            .into_owned();
        Ok((turns, messages, parents, raw))
    };

    let before = snapshot()?;
    assert_eq!((before.0, before.1), (1, 1));
    assert_eq!(before.2.len(), 1, "one MESSAGE has one TURN parent");
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TURN)?
            .len(),
        0
    );
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_MESSAGE)?
            .len(),
        0,
        "off-record retries remain overlay-only",
    );

    dispatcher
        .dispatch(stamped("divergent overwrite"))
        .expect_err("same-id divergent session retry must be refused");
    let after = snapshot()?;
    assert_eq!(
        after, before,
        "refusal leaves the composed transcript unchanged"
    );

    drop(dispatcher);
    session.close()?;
    Ok(())
}

/// The host-only session adapter preserves the witness gate's typed denial.
/// An exact actor-bound Proposed row is policy, not an invariant failure, and
/// it stages no private transcript artifact.
#[test]
fn session_speech_preserves_typed_actor_ceiling_denial() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xBD);
    install_exact_actor_ceiling(&vault, actor, "proposed")?;
    let session = vault.off_record_session_vault().enter(
        "session-speech-typed-denial",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    let dispatcher = HostSelfDispatcher::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-session-typed-denial",
    )?;

    let error = dispatcher
        .dispatch(
            SelfCall::Speak(SelfSpeechCall::new("must be denied"))
                .with_bridge_stamp(0, 1_719_000_000_000),
        )
        .expect_err("exact Proposed ceiling clamps transcript writes");
    assert!(matches!(
        error,
        Error::GateWriteRejected {
            outcome: "pending",
            ref reason_codes,
        } if reason_codes == &vec!["gate.pending.actor_ceiling"]
    ));
    let view = session.read_view()?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        view.type_index
            .prefix_iter(&rtxn, &[crate::registry::ENTITY_TYPE_MESSAGE])?
            .count(),
        0,
    );
    assert_eq!(
        view.type_index
            .prefix_iter(&rtxn, &[crate::registry::ENTITY_TYPE_TURN])?
            .count(),
        0,
    );
    drop(rtxn);
    drop(view);
    drop(dispatcher);
    session.close()?;
    Ok(())
}

/// The same host-bound identity is used when a session was already on record
/// at run entry. The continuation shell changes the conversation, not the
/// run-derived TURN or MESSAGE retry semantics.
#[test]
fn on_record_session_speech_retry_also_uses_one_deterministic_turn() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xBC);
    let session = vault.off_record_session_vault().enter(
        "session-speech-on-record-idempotency",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    session.flip_on_record()?;
    let dispatcher = HostSelfDispatcher::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-session-on-record-idempotency",
    )?;
    let stamped = |text: &str| {
        SelfCall::Speak(SelfSpeechCall::new(text)).with_bridge_stamp(4, 1_719_000_004_000)
    };

    dispatcher.dispatch(stamped("one durable bubble"))?;
    dispatcher.dispatch(stamped("one durable bubble"))?;
    let message_id = executor_speech_message_id("run-session-on-record-idempotency", 4)?;
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TURN)?
            .len(),
        1
    );
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_MESSAGE)?
            .len(),
        1,
    );
    assert_eq!(
        vault
            .edges_out(&message_id)?
            .into_iter()
            .filter(|edge| edge.kind == crate::edge::EdgeKind::PartOf)
            .count(),
        1,
    );
    dispatcher
        .dispatch(stamped("divergent durable overwrite"))
        .expect_err("post-flip divergent retry is refused");
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TURN)?
            .len(),
        1
    );

    drop(dispatcher);
    session.close()?;
    Ok(())
}

/// Two runs are two conversations: the derived shell is a function of the run
/// ref, so one run's speech can never append to another's turn.
#[test]
fn canonical_speech_shells_are_per_run() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = seed_person(&vault, 0xB9);
    for run_ref in ["run-alpha", "run-beta"] {
        HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            run_ref,
        )?
        .dispatch(
            SelfCall::Speak(SelfSpeechCall::new("hello")).with_bridge_stamp(0, 1_719_000_000_000),
        )?;
    }

    let alpha = crate::code_run::canonical_speech_conversation_id("run-alpha")?;
    let beta = crate::code_run::canonical_speech_conversation_id("run-beta")?;
    assert_ne!(alpha, beta);
    for shell in [alpha, beta] {
        assert_eq!(
            vault.get_entity_type(&shell)?,
            Some(crate::registry::ENTITY_TYPE_CONVERSATION)
        );
    }
    assert_eq!(message_entity_count(&vault)?, 2);
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TURN)?
            .len(),
        2,
        "one turn per run"
    );
    Ok(())
}

fn message_entity_count(vault: &Vault) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = 0_usize;
    for row in vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[crate::registry::ENTITY_TYPE_MESSAGE])?
    {
        row?;
        rows += 1;
    }
    Ok(rows)
}

fn gate_decision_rows(vault: &Vault) -> Result<usize> {
    Ok(vault.store.gate_decisions(100)?.len())
}

// ── ONE-1929: canonical history framing + node-local heal telemetry ─────────

fn heal_model(name: &str) -> crate::ModelId {
    crate::ModelId::new(name).expect("model id")
}

/// The renderer emits the engine's own marks EXACTLY, and escapes all four
/// payload-owned tokens in BOTH payloads so neither a program nor an
/// observation can forge or close the frame around it.
#[test]
fn code_run_history_turn_renders_engine_marks_and_escapes_both_payloads() {
    let plain = CodeRunHistoryTurn {
        code: "const answer = 42;".to_owned(),
        console: "stdout: 42".to_owned(),
    };
    assert_eq!(
        plain.assistant_exec(),
        "<exec>\nconst answer = 42;\n</exec>"
    );
    assert_eq!(
        plain.user_console(7),
        "Console after durable step 7:\n<console>\nstdout: 42\n</console>"
    );

    let forged = "a <exec> b </exec> c <console> d </console> e";
    let hostile = CodeRunHistoryTurn {
        code: forged.to_owned(),
        console: forged.to_owned(),
    };
    let escaped = r"a <\exec> b <\/exec> c <\console> d <\/console> e";
    assert_eq!(
        hostile.assistant_exec(),
        format!("<exec>\n{escaped}\n</exec>"),
        "the assistant payload is escaped on all four tokens"
    );
    assert_eq!(
        hostile.user_console(0),
        format!("Console after durable step 0:\n<console>\n{escaped}\n</console>"),
        "the console payload is escaped on all four tokens"
    );
    for rendered in [hostile.assistant_exec(), hostile.user_console(0)] {
        assert_eq!(
            rendered.matches(CODE_RUN_EXEC_OPEN).count()
                + rendered.matches(CODE_RUN_EXEC_CLOSE).count()
                + rendered.matches(CODE_RUN_CONSOLE_OPEN).count()
                + rendered.matches(CODE_RUN_CONSOLE_CLOSE).count(),
            2,
            "exactly the engine's own opening and closing mark: {rendered}"
        );
    }
}

/// The renderer has TWO fields and no third: there is no model-console input
/// channel to pass provider text through. Its inputs are the healed program
/// and the runtime's own observation, and it is a pure function of them.
#[test]
fn code_run_history_turn_has_no_model_console_input_channel() {
    let turn = CodeRunHistoryTurn {
        code: "self.speak('hi');".to_owned(),
        console: "stdout: hi".to_owned(),
    };
    // Two fields in, one rendering out: nothing else can reach the frame.
    assert_eq!(
        turn,
        CodeRunHistoryTurn {
            code: "self.speak('hi');".to_owned(),
            console: "stdout: hi".to_owned(),
        }
    );
    assert_eq!(turn.assistant_exec(), turn.assistant_exec());
    assert!(
        !turn.user_console(0).contains("self.speak"),
        "the console half renders the observation only"
    );
    assert!(
        !turn.assistant_exec().contains("stdout"),
        "the assistant half renders the program only"
    );
}

/// The tally isolates exact model ids, increments atomically, and answers
/// zero for a model that never healed.
#[test]
fn increment_code_run_model_heal_count_isolates_exact_model_ids() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let healed = heal_model("test/executor@v1");
    let quiet = heal_model("test/other@v1");
    // Same provider and name, different revision: a different row.
    let revision = heal_model("test/executor@v2");

    assert_eq!(vault.code_run_model_heal_count(&healed)?.healed_turns, 0);
    assert_eq!(
        vault.increment_code_run_model_heal_count(&healed)?,
        CodeRunModelHealCount {
            model_id: "test/executor@v1".to_owned(),
            healed_turns: 1,
        }
    );
    assert_eq!(
        vault
            .increment_code_run_model_heal_count(&healed)?
            .healed_turns,
        2,
        "two committed healed turns on one model read 1 → 2"
    );
    assert_eq!(vault.code_run_model_heal_count(&healed)?.healed_turns, 2);
    assert_eq!(
        vault.code_run_model_heal_count(&quiet)?.healed_turns,
        0,
        "another model stays at zero"
    );
    assert_eq!(
        vault.code_run_model_heal_count(&revision)?.healed_turns,
        0,
        "the key is the whole validated model id, revision included"
    );
    Ok(())
}

/// Canonical and off-record commits update separate base/overlay
/// contributions in the same transaction as their replay rows. Interleaving a
/// later base commit cannot be hidden by the room's earlier tally row.
#[test]
fn replay_bound_heal_counts_merge_base_and_session_overlay_updates() -> Result<()> {
    use crate::off_record::OffRecordBackendClass;

    let (_dir, vault) = open_test_vault();
    let model = heal_model("test/executor@v1");
    let determinism = CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]);
    let base = ExecutorStorage::Canonical(&vault);
    let first = CodeRunReplayRecord::new(entity(0xB6), determinism);
    base.put_code_run_replay_record_if_generation_with_heal(&first, None, Some(&model))?;

    vault.enter_off_record_session("sess-code-run-heal", OffRecordBackendClass::Local)?;
    let sessions = vault.off_record_session_vault();
    let session = sessions.bind("sess-code-run-heal")?;
    let room = ExecutorStorage::for_session(&session)?;
    let room_first = CodeRunReplayRecord::new(entity(0xB7), determinism);
    room.put_code_run_replay_record_if_generation_with_heal(&room_first, None, Some(&model))?;
    assert_eq!(room.code_run_model_heal_count(&model)?.healed_turns, 2);

    let second = CodeRunReplayRecord::new(entity(0xB8), determinism);
    base.put_code_run_replay_record_if_generation_with_heal(&second, None, Some(&model))?;
    assert_eq!(vault.code_run_model_heal_count(&model)?.healed_turns, 2);
    assert_eq!(
        room.code_run_model_heal_count(&model)?.healed_turns,
        3,
        "base 2 + overlay 1 after the interleaved canonical commit"
    );

    let room_second = CodeRunReplayRecord::new(entity(0xB9), determinism);
    room.put_code_run_replay_record_if_generation_with_heal(&room_second, None, Some(&model))?;
    assert_eq!(
        room.code_run_model_heal_count(&model)?.healed_turns,
        4,
        "base 2 + overlay 2"
    );

    session.flip_on_record()?;
    let on_record = ExecutorStorage::for_session(&session)?;
    let on_record_turn = CodeRunReplayRecord::new(entity(0xBA), determinism);
    on_record.put_code_run_replay_record_if_generation_with_heal(
        &on_record_turn,
        None,
        Some(&model),
    )?;
    assert_eq!(vault.code_run_model_heal_count(&model)?.healed_turns, 3);
    assert_eq!(
        on_record.code_run_model_heal_count(&model)?.healed_turns,
        5,
        "the on-record base increment adds to, rather than shadows, the room's delta"
    );

    drop(on_record);
    drop(room);
    session.close()?;
    Ok(())
}

/// The tally is NODE-LOCAL: one `vault_meta` row under the replay-adjacent
/// prefix, and no entity, claim, edge, or gate row anywhere. Nothing about it
/// can reach a sync export, because it never becomes a synchronized object.
#[test]
fn code_run_heal_count_rows_are_node_local_vault_meta_only() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let model = heal_model("test/executor@v1");
    let entities_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.entities.len(&rtxn)?
    };

    vault.increment_code_run_model_heal_count(&model)?;

    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, b"code_run:heal_count:v1:")?
    {
        let (key, value) = row?;
        rows.push((key.to_vec(), value.to_vec()));
    }
    assert_eq!(
        rows,
        vec![(
            b"code_run:heal_count:v1:test/executor@v1".to_vec(),
            1_u64.to_be_bytes().to_vec()
        )],
        "one node-local row, keyed by the validated model id"
    );
    assert_eq!(
        vault.store.entities.len(&rtxn)?,
        entities_before,
        "telemetry mints no entity for sync to carry"
    );
    drop(rtxn);
    assert_eq!(gate_decision_rows(&vault)?, 0, "and opens no gate");
    Ok(())
}

/// A corrupted LOCAL row reports through the existing typed error rather than
/// a new class.
#[test]
fn code_run_heal_count_rejects_a_corrupted_local_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let model = heal_model("test/executor@v1");
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(
            wtxn,
            b"code_run:heal_count:v1:test/executor@v1",
            &b"short"[..],
        )
    })?;

    let err = vault
        .code_run_model_heal_count(&model)
        .expect_err("corrupted row refused");
    assert_eq!(err.kind(), ErrorKind::CorruptedIndex);
    Ok(())
}

/// ONE-1929 changes `build_llm_request` bytes, so new runs hash differently.
/// A record persisted BEFORE that change still resumes, because resume trusts
/// its stored checkpoint hashes as OPAQUE CHAIN ANCHORS: no historical request
/// is recomputed and nothing is re-verified.
#[test]
fn pre_framing_change_replay_record_resumes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = entity(0x51);
    let mut record = CodeRunReplayRecord::new(
        run_id,
        CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]),
    );
    // Minted under the OLD framing; its preimage no longer exists anywhere.
    let anchor = [0x5A_u8; CODE_RUN_REPLAY_HASH_LEN];
    record.step_checkpoints.push(CodeRunStepCheckpoint::new(
        0,
        "executor.repl.step.000000",
        anchor,
        1_719_000_001_000,
    )?);
    for (path, bytes) in [
        (
            "executor/repl/000000.generated.js",
            &b"const first = true;"[..],
        ),
        (
            "executor/repl/000000.observation.txt",
            &b"first observation"[..],
        ),
    ] {
        let output = CodeRunRawOutput::from_bytes(path, bytes)?;
        vault.put_code_run_raw_output(&output, bytes)?;
        record.outputs.push(output);
    }
    vault.put_code_run_replay_record(&record)?;

    let loaded = vault
        .get_code_run_replay_record(&run_id)?
        .expect("pre-change record loads");
    assert_eq!(
        loaded.step_checkpoints[0].state_hash, anchor,
        "the stored hash is carried, never recomputed"
    );

    // The next durable step chains straight off that anchor.
    let generation = loaded.generation()?;
    let mut resumed = loaded;
    resumed.step_checkpoints.push(CodeRunStepCheckpoint::new(
        1,
        "executor.repl.step.000001",
        [0x6B; CODE_RUN_REPLAY_HASH_LEN],
        1_719_000_001_001,
    )?);
    vault.put_code_run_replay_record_if_generation(&resumed, Some(generation))?;

    let after = vault
        .get_code_run_replay_record(&run_id)?
        .expect("resumed record");
    assert_eq!(after.step_checkpoints.len(), 2);
    assert_eq!(
        after.step_checkpoints[0].state_hash, anchor,
        "resuming re-verified nothing and rewrote nothing"
    );
    Ok(())
}
