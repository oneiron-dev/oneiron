use super::*;
use crate::code_run::{CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord};
use crate::config::VaultConfig;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{Error, ErrorKind};
use crate::facade::NeighborOpts;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchError,
    OutboundDispatchGate, OutboundDispatchPipeline, OutboundDispatchRequest,
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent,
    OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::pipeline::{DreamerWorkingSetBudget, DreamerWorkingSetCursor};
use crate::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_REDACTION_AUDIT,
    ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::store::{GateDecisionId, GateDecisionRecord};
#[cfg(feature = "sync")]
use crate::sync::queue::SyncQueue;
use crate::temporal::TimeRange;

const TEST_OWNER_REF: &str = "principal:test-owner";

fn test_owner_actor() -> crate::genui::ConsentActorIdentity {
    crate::genui::ConsentActorIdentity::SurfaceActor {
        actor_ref: TEST_OWNER_REF.to_owned(),
    }
}

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn seed_turn(vault: &Vault, at: u64) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            b"off-record fixture turn",
        )
        .expect("seed turn");
    id
}

#[cfg(feature = "sync")]
#[test]
fn off_record_tag_scrubs_offline_updates_and_preserves_ordinary_state() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault =
        std::sync::Arc::new(Vault::open(tmp.path(), VaultConfig::default()).expect("open vault"));
    let fenced = seed_turn(&vault, 1_775_000_000);
    let ordinary = seed_turn(&vault, 1_775_000_001);
    let queue = SyncQueue::new(std::sync::Arc::clone(&vault)).unwrap();
    queue
        .push("2026-04", b"private queued fenced carrier")
        .unwrap();
    queue.push("2026-05", b"ordinary queued control").unwrap();

    vault
        .enter_off_record_session("sess-offline-queue", OffRecordBackendClass::Local)
        .unwrap();
    vault
        .tag_turn_off_record("sess-offline-queue", &fenced)
        .unwrap();

    assert!(
        queue.drain_updates().unwrap().is_empty(),
        "opaque ordinary queue rows may retain fenced history and must be dropped"
    );
    for key in ["2026-04", "2026-05"] {
        assert_eq!(
            vault.sync_state_get(&format!("fr:w:{key}")).unwrap(),
            Some(vec![1]),
            "every affected window must be healed by full resync"
        );
    }
    assert!(
        vault.get_entity_type(&ordinary).unwrap().is_some(),
        "ordinary durable state survives queue scrubbing and remains available to full resync"
    );
}

fn surfaced_turns(vault: &Vault) -> Vec<EntityId> {
    vault
        .query()
        .search_temporal(900, 1100, 16)
        .filter_types(&[ENTITY_TYPE_TURN])
        .limit(16)
        .run()
        .expect("pipeline run")
        .into_iter()
        .map(|scored| scored.id)
        .collect()
}

fn surfaced_messages(vault: &Vault) -> Vec<EntityId> {
    vault
        .query()
        .search_temporal(900, 1100, 16)
        .filter_types(&[ENTITY_TYPE_MESSAGE])
        .limit(16)
        .run()
        .expect("pipeline run")
        .into_iter()
        .map(|scored| scored.id)
        .collect()
}

fn dreamer_working_set_turns(vault: &Vault) -> Vec<EntityId> {
    vault
        .query()
        .search_temporal(900, 1100, 16)
        .filter_types(&[ENTITY_TYPE_TURN])
        .run_dreamer_working_set(
            DreamerWorkingSetCursor::start(),
            DreamerWorkingSetBudget::new(16),
            16,
        )
        .expect("dreamer working set")
        .rows
        .into_iter()
        .map(|scored| scored.id)
        .collect()
}

fn floor_gate_decision() -> GateDecisionRecord {
    GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at: 10,
        outcome: "allow".to_owned(),
        reason_codes: vec!["gate.policy_model.allow".to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: "agent".to_owned(),
        actor_ref: Some("agent-alpha".to_owned()),
        content_kind: "outbound_content".to_owned(),
        policy_manifest_version: "test-policy".to_owned(),
        claim_id: None,
        grant_ref: None,
        diff_handle: vec![0xA5],
        read_frontier_hash: [0xB6; 32],
    }
}

struct PanicSink;

impl OutboundExecutionSink for PanicSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        panic!("execution sink must not run in these tests");
    }
}

fn talk_only_request(session_ref: &str) -> OutboundDispatchRequest {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com"),
        OutboundIntentTrigger::agent_immediate("intent:off-record-test"),
    );
    OutboundDispatchRequest::new(
        "receipt-off-record-test",
        "intent-off-record-test",
        intent,
        OutboundDispatchActor::agent(EntityId::now()),
        OutboundDispatchGate::allow_when_policy_grants(),
        100,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .originating_session(session_ref)
}

#[test]
fn off_record_enter_is_explicit_marked_and_single_shot() {
    let (_tmp, vault) = temp_vault();
    let record = vault
        .enter_off_record_session("sess-enter", OffRecordBackendClass::Local)
        .expect("enter");
    assert_eq!(record.mode, OffRecordMode::OffRecord);
    assert_eq!(record.backend, OffRecordBackendClass::Local);
    assert!(record.fenced_turns.is_empty());

    let double_enter = vault
        .enter_off_record_session("sess-enter", OffRecordBackendClass::Local)
        .expect_err("enter is single-shot");
    assert_eq!(
        double_enter.kind(),
        ErrorKind::OffRecordSessionAlreadyExists
    );

    // Disclosure honesty is backend-relative and rides the marker.
    let local = off_record_context_marker(OffRecordBackendClass::Local);
    let remote = off_record_context_marker(OffRecordBackendClass::RemoteProvider);
    assert!(local.contains(OFF_RECORD_SESSION_MARKER_LINE));
    assert!(remote.contains(OFF_RECORD_SESSION_MARKER_LINE));
    assert!(local.contains(OffRecordBackendClass::Local.disclosure_line()));
    assert!(remote.contains(OffRecordBackendClass::RemoteProvider.disclosure_line()));
    assert_ne!(local, remote);
}

#[test]
fn off_record_fenced_turns_are_unextractable_including_post_flip() {
    let (_tmp, vault) = temp_vault();
    let fenced = seed_turn(&vault, 1000);
    let plain = seed_turn(&vault, 1001);
    vault
        .enter_off_record_session("sess-fence", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-fence", &fenced)
        .expect("tag");
    assert!(vault.is_turn_off_record_fenced(&fenced).expect("probe"));

    let surfaced = surfaced_turns(&vault);
    assert!(!surfaced.contains(&fenced), "fenced turn surfaced");
    assert!(surfaced.contains(&plain), "plain turn missing");

    let working_set = dreamer_working_set_turns(&vault);
    assert!(
        !working_set.contains(&fenced),
        "fenced turn reached the dreamer working set"
    );
    assert!(working_set.contains(&plain));

    // Flip back on-record: the fence holds on the lingering turn, new
    // turns are ordinary, and tagging is rejected outside the mode.
    vault
        .set_off_record_session_mode("sess-fence", OffRecordMode::OnRecord)
        .expect("flip");
    let post_flip = seed_turn(&vault, 1002);
    let surfaced = surfaced_turns(&vault);
    assert!(
        !surfaced.contains(&fenced),
        "fence must outlive the flip back on-record"
    );
    assert!(surfaced.contains(&post_flip));
    vault
        .tag_turn_off_record("sess-fence", &post_flip)
        .expect_err("tagging requires off-record mode");
    // Post-flip retrieval runs belong to on-record turns whose context
    // receipts must persist — registering one for delete-at-close is
    // rejected the same way tagging is.
    vault
        .note_off_record_context_receipt("sess-fence", crate::store::RetrievalRunId::now())
        .expect_err("context receipt registration requires off-record mode");
}

#[test]
fn off_record_turn_fence_hides_and_close_cascades_message_children() {
    let (_tmp, vault) = temp_vault();
    let turn = seed_turn(&vault, 1000);
    let message_a = EntityId::now();
    let message_b = EntityId::now();
    for (message, body) in [
        (message_a, b"private message a".as_slice()),
        (message_b, b"private message b".as_slice()),
    ] {
        vault
            .batch()
            .put(
                &message,
                ENTITY_TYPE_MESSAGE,
                TimeRange {
                    start: 1000,
                    end: 1000,
                },
                1000,
                body,
            )
            .edge(&message, EdgeKind::PartOf, &turn, 1.0)
            .commit()
            .expect("seed message child");
    }
    assert_eq!(surfaced_messages(&vault).len(), 2);

    vault
        .enter_off_record_session("sess-message-cascade", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-message-cascade", &turn)
        .expect("tag");
    assert!(
        vault
            .is_turn_off_record_fenced(&message_a)
            .expect("child fence")
    );
    assert!(
        vault
            .is_turn_off_record_fenced(&message_b)
            .expect("child fence")
    );
    assert!(
        surfaced_messages(&vault).is_empty(),
        "MESSAGE children must inherit the TURN retrieval fence"
    );

    let log = vault
        .off_record_receipt_log("sess-message-cascade")
        .expect("receipt log");
    let outcome = vault
        .close_off_record_session("sess-message-cascade", log)
        .expect("close");
    assert_eq!(outcome.turns_deleted, 1);
    let rtxn = vault.store.env.read_txn().expect("read entities");
    for id in [turn, message_a, message_b] {
        assert!(
            vault
                .store
                .entities
                .get(&rtxn, id.as_bytes())
                .expect("entity row")
                .is_none(),
            "transcript entity must be absent from LMDB after close"
        );
    }
}

#[test]
fn off_record_close_pages_past_one_reverse_carrier_page() {
    let (_tmp, vault) = temp_vault();
    let turn = seed_turn(&vault, 1000);
    let mut messages = Vec::new();
    let mut batch = vault.batch();
    for index in 0..=OFF_RECORD_CLOSE_CARRIER_PAGE_SIZE {
        let message = EntityId::now();
        messages.push(message);
        batch = batch
            .put(
                &message,
                ENTITY_TYPE_MESSAGE,
                TimeRange {
                    start: 1000,
                    end: 1000,
                },
                1000,
                format!("private page child {index}").as_bytes(),
            )
            .edge(&message, EdgeKind::PartOf, &turn, 1.0);
    }
    batch.commit().expect("seed paged message children");
    assert_eq!(
        vault
            .sources(&turn, EdgeKind::PartOf, Some(ENTITY_TYPE_MESSAGE))
            .expect("message children")
            .len(),
        OFF_RECORD_CLOSE_CARRIER_PAGE_SIZE + 1
    );

    vault
        .enter_off_record_session("sess-paged-close", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-paged-close", &turn)
        .expect("tag");
    let log = vault
        .off_record_receipt_log("sess-paged-close")
        .expect("receipt log");
    let outcome = vault
        .close_off_record_session("sess-paged-close", log)
        .expect("close must traverse every page");
    assert_eq!(outcome.turns_deleted, 1);

    let rtxn = vault.store.env.read_txn().expect("read entities");
    let remaining = messages
        .iter()
        .filter(|message| {
            vault
                .store
                .entities
                .get(&rtxn, message.as_bytes())
                .expect("message row")
                .is_some()
        })
        .count();
    assert_eq!(remaining, 0, "every paged child must be purged");
}

#[test]
fn production_summary_batch_rejects_a_live_fenced_source_atomically() {
    let (_tmp, vault) = temp_vault();
    let source = seed_turn(&vault, 1000);
    let summary = EntityId::now();
    vault
        .enter_off_record_session("sess-summary", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-summary", &source)
        .expect("tag");
    let rejected = vault
        .batch()
        .put(
            &summary,
            ENTITY_TYPE_SUMMARY,
            TimeRange {
                start: 1000,
                end: 1000,
            },
            1000,
            b"private summary",
        )
        .edge(&summary, EdgeKind::DerivedFrom, &source, 1.0)
        .commit()
        .expect_err("production summary batch must reject a fenced source");
    assert_eq!(rejected.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    assert!(vault.get(&summary).expect("summary lookup").is_none());
    assert_eq!(
        vault
            .sources(&source, EdgeKind::DerivedFrom, Some(ENTITY_TYPE_SUMMARY))
            .expect("derived summaries")
            .len(),
        0,
        "the rejected transaction must leave neither body nor edge"
    );
}

#[test]
fn same_batch_inheritance_chain_sidecars_summary_until_close_or_promotion() {
    let (_tmp, vault) = temp_vault();
    let close_turn = seed_turn(&vault, 1000);
    let promote_turn = seed_turn(&vault, 1001);
    let close_message = EntityId::now();
    let close_summary = EntityId::now();
    let promote_message = EntityId::now();
    let promote_summary = EntityId::now();
    let occurred = TimeRange {
        start: 1000,
        end: 1001,
    };
    vault
        .enter_off_record_session("sess-transitive-batch", OffRecordBackendClass::Local)
        .expect("enter");
    for turn in [close_turn, promote_turn] {
        vault
            .tag_turn_off_record("sess-transitive-batch", &turn)
            .expect("tag root");
    }

    vault
        .batch()
        .put(
            &close_message,
            ENTITY_TYPE_MESSAGE,
            occurred,
            1001,
            b"private close message",
        )
        .put(
            &close_summary,
            ENTITY_TYPE_SUMMARY,
            occurred,
            1001,
            b"private close summary",
        )
        .put(
            &promote_message,
            ENTITY_TYPE_MESSAGE,
            occurred,
            1001,
            b"private promote message",
        )
        .put(
            &promote_summary,
            ENTITY_TYPE_SUMMARY,
            occurred,
            1001,
            b"private promote summary",
        )
        .edge(&close_message, EdgeKind::PartOf, &close_turn, 1.0)
        .edge(&close_summary, EdgeKind::DerivedFrom, &close_message, 1.0)
        .edge(&promote_message, EdgeKind::PartOf, &promote_turn, 1.0)
        .edge(
            &promote_summary,
            EdgeKind::DerivedFrom,
            &promote_message,
            1.0,
        )
        .commit()
        .expect("commit both same-batch chains");

    assert_eq!(
        inherited_off_record_fence_carriers(&vault.store)
            .expect("sidecar inventory")
            .len(),
        4,
        "both MESSAGEs and both transitively-derived SUMMARYs need sidecars"
    );
    let rtxn = vault.store.env.read_txn().expect("summary root read");
    assert_eq!(
        [(close_summary, close_turn), (promote_summary, promote_turn),]
            .into_iter()
            .filter(|(summary, root)| {
                inherited_off_record_fence_roots_in_txn(&vault.store, &rtxn, summary)
                    .expect("summary roots")
                    == std::collections::BTreeSet::from([*root])
            })
            .count(),
        2
    );
    drop(rtxn);
    assert_eq!(
        [close_summary, promote_summary]
            .into_iter()
            .filter(|summary| vault.get(summary).expect("hidden summary read").is_some())
            .count(),
        0,
        "both summaries stay hidden while their roots are fenced"
    );

    vault
        .promote_off_record_turn(
            "sess-transitive-batch",
            &promote_turn,
            TEST_OWNER_REF,
            &test_owner_actor(),
        )
        .expect("promote one chain");
    assert_eq!(
        [promote_message, promote_summary]
            .into_iter()
            .filter(|carrier| vault.get(carrier).expect("promoted carrier read").is_some())
            .count(),
        2,
        "promotion releases the complete transitive chain"
    );
    assert_eq!(
        inherited_off_record_fence_carriers(&vault.store)
            .expect("post-promotion sidecars")
            .len(),
        2
    );

    let log = vault
        .off_record_receipt_log("sess-transitive-batch")
        .expect("receipt log");
    let close = vault
        .close_off_record_session("sess-transitive-batch", log)
        .expect("close remaining chain");
    assert_eq!(close.turns_deleted, 1);
    assert_eq!(close.promoted_turns_kept, 1);
    assert_eq!(
        [close_turn, close_message, close_summary]
            .into_iter()
            .filter(|id| vault.entity_exists(id).expect("closed-chain existence"))
            .count(),
        0,
        "close deletes the transitively-derived summary"
    );
    assert_eq!(
        [promote_turn, promote_message, promote_summary]
            .into_iter()
            .filter(|id| vault.entity_exists(id).expect("promoted-chain existence"))
            .count(),
        3,
        "the promoted chain survives close"
    );
    assert_eq!(
        inherited_off_record_fence_carriers(&vault.store)
            .expect("final sidecar inventory")
            .len(),
        0
    );
}

#[test]
fn off_record_close_cascades_preexisting_derived_summaries_recursively() {
    let (_tmp, vault) = temp_vault();
    let turn = seed_turn(&vault, 1000);
    let summary = EntityId::now();
    let nested_summary = EntityId::now();
    for (id, source, body) in [
        (summary, turn, b"private summary".as_slice()),
        (
            nested_summary,
            summary,
            b"private nested summary".as_slice(),
        ),
    ] {
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_SUMMARY,
                TimeRange {
                    start: 1000,
                    end: 1000,
                },
                1000,
                body,
            )
            .edge(&id, EdgeKind::DerivedFrom, &source, 1.0)
            .commit()
            .expect("seed derived summary");
    }

    vault
        .enter_off_record_session("sess-summary-close", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-summary-close", &turn)
        .expect("tag");
    assert!(
        vault
            .is_turn_off_record_fenced(&nested_summary)
            .expect("nested summary fence")
    );

    let log = vault
        .off_record_receipt_log("sess-summary-close")
        .expect("receipt log");
    vault
        .close_off_record_session("sess-summary-close", log)
        .expect("close");

    let rtxn = vault.store.env.read_txn().expect("read entities");
    for id in [turn, summary, nested_summary] {
        assert!(
            vault
                .store
                .entities
                .get(&rtxn, id.as_bytes())
                .expect("entity row")
                .is_none(),
            "turn and recursively derived summaries must be absent from LMDB after close"
        );
    }
}

#[test]
fn off_record_fence_inheritance_cycles_terminate_and_still_find_a_fence() {
    let (_tmp, vault) = temp_vault();
    let message_a = EntityId::now();
    let message_b = EntityId::now();
    for (id, body) in [
        (message_a, b"cycle message a".as_slice()),
        (message_b, b"cycle message b".as_slice()),
    ] {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_MESSAGE,
                TimeRange {
                    start: 1000,
                    end: 1000,
                },
                1000,
                body,
            )
            .expect("seed cyclic message");
    }
    vault
        .put_edge(&message_a, EdgeKind::PartOf, &message_b, 1.0)
        .expect("edge a to b");
    vault
        .put_edge(&message_b, EdgeKind::PartOf, &message_a, 1.0)
        .expect("edge b to a");

    let facade = vault.memory_facade(EntityId::now(), EdgeActorClass::Human);
    assert!(
        facade
            .get_entity(&message_a.to_hex())
            .expect("cyclic unfenced read must succeed")
            .is_some()
    );

    vault
        .enter_off_record_session("sess-cycle", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-cycle", &message_b)
        .expect("fence cycle member");
    assert!(
        facade
            .get_entity(&message_a.to_hex())
            .expect("cyclic fenced read must succeed")
            .is_none(),
        "a fence reachable through a cycle must still hide the carrier"
    );
}

#[test]
fn off_record_close_sweeps_session_bound_code_run_replay_and_raw_output() {
    let (_tmp, vault) = temp_vault();
    let session_ref = "sess-code-run";
    let run_id = EntityId::now();
    let raw = b"private code-run output";
    vault
        .enter_off_record_session(session_ref, OffRecordBackendClass::Local)
        .expect("enter");

    let output =
        CodeRunRawOutput::for_off_record_session(session_ref, "/mnt/outputs/private.txt", raw)
            .expect("raw metadata");
    vault
        .put_code_run_raw_output(&output, raw)
        .expect("put raw output");
    let mut replay = CodeRunReplayRecord::for_off_record_session(
        run_id,
        CodeRunDeterminism::new(1000, [0xA5; 32]),
        session_ref,
    )
    .expect("replay record");
    replay.outputs.push(output.clone());
    vault
        .put_code_run_replay_record(&replay)
        .expect("put replay record");
    assert!(
        vault
            .get_off_record_code_run_replay_record(session_ref, &run_id)
            .expect("get replay")
            .is_some()
    );
    assert!(
        vault
            .get_code_run_raw_output(&output)
            .expect("get raw")
            .is_some()
    );

    let log = vault
        .off_record_receipt_log(session_ref)
        .expect("receipt log");
    vault
        .close_off_record_session(session_ref, log)
        .expect("close");
    assert!(
        vault
            .get_off_record_code_run_replay_record(session_ref, &run_id)
            .expect("get swept replay")
            .is_none()
    );
    assert!(
        vault
            .get_code_run_raw_output(&output)
            .expect("get swept raw")
            .is_none()
    );
}

#[test]
fn off_record_outbound_rejected_in_mode_with_typed_error() {
    let (_tmp, vault) = temp_vault();
    vault
        .enter_off_record_session("sess-talk", OffRecordBackendClass::RemoteProvider)
        .expect("enter");

    let error = OutboundDispatchPipeline
        .dispatch(&vault, talk_only_request("sess-talk"), &mut PanicSink)
        .expect_err("in-mode outbound must be rejected");
    match error {
        OutboundDispatchError::Engine(Error::OffRecordTalkOnly { session_ref }) => {
            assert_eq!(session_ref, "sess-talk");
        }
        other => panic!("expected OffRecordTalkOnly, got {other:?}"),
    }

    // Flipped back on-record the rejection lifts, and the OF-333 floor
    // classifies the egress (gate decision = persistent floor receipt).
    vault
        .set_off_record_session_mode("sess-talk", OffRecordMode::OnRecord)
        .expect("flip");
    let result = OutboundDispatchPipeline
        .dispatch(&vault, talk_only_request("sess-talk"), &mut PanicSink)
        .expect("post-flip dispatch reaches the gate");
    drop(result);
    assert!(
        !vault.gate_decisions(10).expect("gate decisions").is_empty(),
        "floor must classify post-flip egress"
    );
}

#[test]
fn off_record_close_deletes_transcript_and_context_receipts_keeps_floor_receipts() {
    let (_tmp, vault) = temp_vault();
    let fenced_a = seed_turn(&vault, 1000);
    let fenced_b = seed_turn(&vault, 1001);
    vault
        .enter_off_record_session("sess-close", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-close", &fenced_a)
        .expect("tag a");
    vault
        .tag_turn_off_record("sess-close", &fenced_b)
        .expect("tag b");

    // Emit-adjacent context receipt: a real retrieval run (result_ids =
    // activated memory ids), registered session-local.
    let telemetry = vault
        .query()
        .search_temporal(900, 1100, 16)
        .filter_types(&[ENTITY_TYPE_TURN])
        .limit(16)
        .run_with_telemetry()
        .expect("retrieval with telemetry");
    let run_id = telemetry.run_id.expect("telemetry run id");
    vault
        .note_off_record_context_receipt("sess-close", run_id)
        .expect("note context receipt");
    assert!(vault.retrieval_run(run_id).expect("run lookup").is_some());

    // Emit-adjacent dispatch receipt: rides the session-local log that
    // close consumes (RECEIPTS-FOLLOW-TRANSCRIPT, ONE-1544 seam).
    let mut receipt_log = vault
        .off_record_receipt_log("sess-close")
        .expect("mint receipt log");
    let emit_receipt = crate::receipt::outbound_intent_receipt(
        "receipt-off-record-close",
        "intent-off-record-close",
        &OutboundIntent::from_trigger(
            OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com"),
            OutboundIntentTrigger::agent_immediate("intent:off-record-close"),
        ),
        100,
        "delivered_to_channel",
    );
    receipt_log.record(emit_receipt).expect("log emit receipt");
    assert_eq!(receipt_log.receipts().len(), 1);

    // Floor receipt (OF-333 egress classification): persists.
    let floor = floor_gate_decision();
    vault
        .with_write_txn(|wtxn| vault.store.append_gate_decision_in_txn(wtxn, &floor))
        .expect("record floor receipt");

    // Binding is validated: another session's log or an on-record log
    // cannot close this session.
    let foreign_log = SessionLocalReceiptLog::off_record("sess-other");
    let mismatch = vault
        .close_off_record_session("sess-close", foreign_log)
        .expect_err("foreign log rejected");
    assert_eq!(mismatch.kind(), ErrorKind::InvariantViolation);
    let on_record_log = SessionLocalReceiptLog::on_record("sess-close");
    let wrong_mode = vault
        .close_off_record_session("sess-close", on_record_log)
        .expect_err("on-record log rejected");
    assert_eq!(wrong_mode.kind(), ErrorKind::InvariantViolation);

    let outcome = vault
        .close_off_record_session("sess-close", receipt_log)
        .expect("close");
    assert_eq!(outcome.turns_deleted, 2);
    assert_eq!(outcome.turns_missing, 0);
    assert_eq!(outcome.context_receipts_deleted, 1);
    assert_eq!(outcome.emit_receipts_deleted, 1);
    assert_eq!(outcome.fence_rows_retained, 0);
    assert_eq!(outcome.promoted_turns_kept, 0);
    assert_eq!(outcome.redaction_receipt_ids.len(), 2);

    // Transcript gone (ARCH-0038 PolicyDelete hard purge)...
    assert!(vault.get(&fenced_a).expect("read a").is_none());
    assert!(vault.get(&fenced_b).expect("read b").is_none());
    // ...context receipts gone with it...
    assert!(vault.retrieval_run(run_id).expect("run lookup").is_none());
    // ...floor receipts remain: the gate decision, and the opaque
    // redaction-audit receipts minted by the deletion itself.
    assert!(!vault.gate_decisions(10).expect("gate decisions").is_empty());
    for receipt_id in &outcome.redaction_receipt_ids {
        assert_eq!(
            vault.get_entity_type(receipt_id).expect("receipt type"),
            Some(ENTITY_TYPE_REDACTION_AUDIT)
        );
    }
    // Session record and fence rows are gone; close is not replayable.
    assert!(
        vault
            .off_record_session("sess-close")
            .expect("session lookup")
            .is_none()
    );
    assert!(!vault.is_turn_off_record_fenced(&fenced_a).expect("probe"));
    let reclose = vault
        .close_off_record_session(
            "sess-close",
            SessionLocalReceiptLog::off_record("sess-close"),
        )
        .expect_err("second close");
    assert_eq!(reclose.kind(), ErrorKind::OffRecordSessionNotFound);
    // The log helper is bound to a live session too.
    let stale_log = vault
        .off_record_receipt_log("sess-close")
        .expect_err("log requires live session");
    assert_eq!(stale_log.kind(), ErrorKind::OffRecordSessionNotFound);
}

#[test]
fn off_record_promote_writes_exactly_one_turn() {
    let (_tmp, vault) = temp_vault();
    let kept = seed_turn(&vault, 1000);
    let dropped_a = seed_turn(&vault, 1001);
    let dropped_b = seed_turn(&vault, 1002);
    vault
        .enter_off_record_session("sess-promote", OffRecordBackendClass::Local)
        .expect("enter");
    for id in [&kept, &dropped_a, &dropped_b] {
        vault.tag_turn_off_record("sess-promote", id).expect("tag");
    }
    assert!(surfaced_turns(&vault).is_empty());

    let impostor = crate::genui::ConsentActorIdentity::SurfaceActor {
        actor_ref: "principal:impostor".to_owned(),
    };
    let rejected = vault
        .promote_off_record_turn("sess-promote", &kept, TEST_OWNER_REF, &impostor)
        .expect_err("non-owner promotion must fail before mutation");
    assert_eq!(rejected.kind(), ErrorKind::InvariantViolation);
    let unchanged = vault
        .off_record_session("sess-promote")
        .expect("session lookup")
        .expect("session record");
    assert!(unchanged.fenced_turns.contains(kept.as_bytes()));
    assert!(unchanged.promoted_turns.is_empty());
    assert!(
        vault
            .is_turn_off_record_fenced(&kept)
            .expect("fence remains")
    );
    assert!(
        vault
            .off_record_promote_receipt(&kept)
            .expect("receipt lookup")
            .is_none(),
        "rejected actor must not mint a promote receipt"
    );

    let actor = test_owner_actor();
    let receipt = vault
        .promote_off_record_turn("sess-promote", &kept, TEST_OWNER_REF, &actor)
        .expect("promote");
    assert_eq!(receipt.turn, *kept.as_bytes());
    assert_eq!(receipt.session_ref, "sess-promote");
    assert_eq!(receipt.initiator, actor.actor_ref());

    // Exactly one turn crossed the fence.
    let record = vault
        .off_record_session("sess-promote")
        .expect("session lookup")
        .expect("session record");
    assert_eq!(record.fenced_turns.len(), 2);
    assert_eq!(record.promoted_turns, vec![*kept.as_bytes()]);
    let surfaced = surfaced_turns(&vault);
    assert_eq!(surfaced, vec![kept]);

    let repromote = vault
        .promote_off_record_turn("sess-promote", &kept, TEST_OWNER_REF, &actor)
        .expect_err("promote lifts one live fence");
    assert_eq!(repromote.kind(), ErrorKind::OffRecordTurnNotFenced);

    // Re-fencing a promoted turn would let close delete a turn whose
    // durable promote receipt pins its survival — rejected.
    let retag = vault
        .tag_turn_off_record("sess-promote", &kept)
        .expect_err("re-tag of a promoted turn");
    assert_eq!(retag.kind(), ErrorKind::InvariantViolation);

    let receipt_log = vault
        .off_record_receipt_log("sess-promote")
        .expect("mint receipt log");
    let outcome = vault
        .close_off_record_session("sess-promote", receipt_log)
        .expect("close");
    assert_eq!(outcome.turns_deleted, 2);
    assert_eq!(outcome.emit_receipts_deleted, 0);
    assert_eq!(outcome.promoted_turns_kept, 1);

    // The promoted turn and its user-initiated receipt survive close.
    assert!(vault.get(&kept).expect("read kept").is_some());
    assert!(vault.get(&dropped_a).expect("read a").is_none());
    assert!(vault.get(&dropped_b).expect("read b").is_none());
    assert_eq!(surfaced_turns(&vault), vec![kept]);
    let persisted = vault
        .off_record_promote_receipt(&kept)
        .expect("receipt lookup")
        .expect("promote receipt persists");
    assert_eq!(persisted, receipt);
}

#[test]
fn promotion_requires_materialized_turn_then_releases_witness_carriers() {
    let (_tmp, vault) = temp_vault();
    let turn = EntityId::now();
    let message = EntityId::now();
    let conversation = EntityId::now();
    let author = EntityId::now();
    let occurred = TimeRange {
        start: 1000,
        end: 1000,
    };
    vault
        .put_entity(&author, ENTITY_TYPE_PERSON, occurred, 1000, b"author")
        .expect("author");
    vault
        .enter_off_record_session("sess-promote-materialized", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-promote-materialized", &turn)
        .expect("tag before witness");
    assert_eq!(
        [vault
            .register_off_record_conversation_shell("sess-promote-materialized", &conversation)
            .expect("reserve fresh conversation shell")]
        .into_iter()
        .filter(|owned| *owned)
        .count(),
        1
    );

    let early = vault
        .promote_off_record_turn(
            "sess-promote-materialized",
            &turn,
            TEST_OWNER_REF,
            &test_owner_actor(),
        )
        .expect_err("a tagged but unmaterialized turn cannot be promoted");
    assert_eq!(
        [early]
            .into_iter()
            .filter(|error| error.kind() == ErrorKind::InvariantViolation)
            .count(),
        1
    );
    let unchanged = vault
        .off_record_session("sess-promote-materialized")
        .expect("session read")
        .expect("live session");
    assert_eq!(unchanged.fenced_turns.len(), 1);
    assert_eq!(unchanged.promoted_turns.len(), 0);

    vault
        .memory_facade(author, EdgeActorClass::Human)
        .witness(&crate::facade::WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![crate::facade::WitnessMessage {
                id: Some(message.to_hex()),
                author: crate::facade::WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "private witness after tag".to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: 1000,
        })
        .expect("materialize witness");
    vault
        .promote_off_record_turn(
            "sess-promote-materialized",
            &turn,
            TEST_OWNER_REF,
            &test_owner_actor(),
        )
        .expect("promote materialized turn");

    assert_eq!(
        [turn, message, conversation]
            .into_iter()
            .filter(|id| vault.get(id).expect("released entity read").is_some())
            .count(),
        3,
        "the materialized turn, MESSAGE carrier, and fresh conversation shell are released"
    );
    assert_eq!(
        inherited_off_record_fence_carriers(&vault.store)
            .expect("released sidecar inventory")
            .len(),
        0
    );
    let promoted = vault
        .off_record_session("sess-promote-materialized")
        .expect("session read")
        .expect("live session");
    assert_eq!(promoted.fenced_turns.len(), 0);
    assert_eq!(promoted.conversation_shells.len(), 0);
    assert_eq!(promoted.promoted_turns.len(), 1);
}

#[test]
fn vault_search_and_short_id_hydration_hide_fenced_message_until_promotion() {
    let (_tmp, vault) = temp_vault();
    let turn = EntityId::now();
    let message = EntityId::now();
    let conversation = EntityId::now();
    let author = EntityId::now();
    let occurred = TimeRange {
        start: 1000,
        end: 1000,
    };
    vault
        .put_entity(&author, ENTITY_TYPE_PERSON, occurred, 1000, b"author")
        .expect("author");
    vault
        .enter_off_record_session("sess-search-hydrate", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-search-hydrate", &turn)
        .expect("tag before witness");
    assert_eq!(
        [vault
            .register_off_record_conversation_shell("sess-search-hydrate", &conversation)
            .expect("reserve conversation shell")]
        .into_iter()
        .filter(|owned| *owned)
        .count(),
        1
    );
    vault
        .memory_facade(author, EdgeActorClass::Human)
        .witness(&crate::facade::WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![crate::facade::WitnessMessage {
                id: Some(message.to_hex()),
                author: crate::facade::WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "fencedsearchhydrateunique".to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: 1000,
        })
        .expect("materialize fenced witness");
    let (short_id, content_hash) = {
        let rtxn = vault.store.env.read_txn().expect("short-ref read");
        let encoded = vault
            .store
            .short_ids_reverse
            .get(&rtxn, message.as_bytes())
            .expect("short-ref lookup")
            .expect("message short ref");
        let (short_id, content_hash) =
            crate::batch::parse_short_id_value(encoded).expect("decode message short ref");
        (short_id.to_owned(), content_hash)
    };

    assert_eq!(
        vault
            .search_text("fencedsearchhydrateunique", 10)
            .expect("hidden search")
            .len(),
        0
    );
    assert_eq!(
        vault
            .hydrate_short_id(&short_id, content_hash)
            .expect("hidden hydrate")
            .iter()
            .count(),
        0
    );

    vault
        .promote_off_record_turn(
            "sess-search-hydrate",
            &turn,
            TEST_OWNER_REF,
            &test_owner_actor(),
        )
        .expect("promote");
    let released_hits = vault
        .search_text("fencedsearchhydrateunique", 10)
        .expect("released search");
    assert_eq!(released_hits.len(), 1);
    assert_eq!(
        released_hits.iter().filter(|hit| hit.id == message).count(),
        1
    );
    let hydrated = vault
        .hydrate_short_id(&short_id, content_hash)
        .expect("released hydrate");
    assert_eq!(
        hydrated
            .iter()
            .filter(|result| result.id == message && result.body.is_some())
            .count(),
        1
    );
}

#[test]
fn public_edge_readers_hide_direct_fenced_endpoint_until_promotion() {
    let (_tmp, vault) = temp_vault();
    let ordinary = seed_turn(&vault, 999);
    let fenced = seed_turn(&vault, 1000);
    vault
        .enter_off_record_session("sess-reader-promote", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-reader-promote", &fenced)
        .expect("tag");
    vault
        .put_edge(&ordinary, EdgeKind::Mentions, &fenced, 0.75)
        .expect("local deferred edge is legal");

    assert_eq!(
        vault
            .edges_out_unfiltered(&ordinary)
            .expect("raw outbound")
            .len(),
        1,
        "the deferred edge remains durable"
    );
    assert_eq!(
        vault.edges_out(&ordinary).expect("public outbound").len(),
        0
    );
    assert_eq!(
        vault
            .targets(&ordinary, EdgeKind::Mentions, None)
            .expect("public targets")
            .len(),
        0
    );
    assert_eq!(
        vault
            .sources(&fenced, EdgeKind::Mentions, None)
            .expect("public sources")
            .len(),
        0
    );
    assert_eq!(
        vault
            .sources_page(&fenced, EdgeKind::Mentions, None, None, 1)
            .expect("public source page")
            .len(),
        0
    );

    vault
        .promote_off_record_turn(
            "sess-reader-promote",
            &fenced,
            TEST_OWNER_REF,
            &test_owner_actor(),
        )
        .expect("promote");
    let edges = vault.edges_out(&ordinary).expect("released outbound");
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, EdgeKind::Mentions);
    assert_eq!(edges[0].target, fenced);
    assert_eq!(
        vault
            .targets(&ordinary, EdgeKind::Mentions, None)
            .expect("released targets"),
        vec![fenced]
    );
    assert_eq!(
        vault
            .sources(&fenced, EdgeKind::Mentions, None)
            .expect("released sources"),
        vec![ordinary]
    );
    assert_eq!(
        vault
            .sources_page(&fenced, EdgeKind::Mentions, None, None, 1)
            .expect("released source page"),
        vec![ordinary]
    );
}

#[test]
fn neighbors_facade_hides_fenced_anchor_and_peers() {
    let (_tmp, vault) = temp_vault();
    let anchor = seed_turn(&vault, 1000);
    let hidden = seed_turn(&vault, 1001);
    let visible = seed_turn(&vault, 1002);
    let actor = EntityId::now();
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 1000,
                end: 1000,
            },
            1000,
            b"neighbor reader",
        )
        .expect("seed neighbor reader");
    vault
        .put_edge(&anchor, EdgeKind::Mentions, &hidden, 0.9)
        .expect("hidden outbound edge");
    vault
        .put_edge(&anchor, EdgeKind::Mentions, &visible, 0.8)
        .expect("visible outbound edge");
    vault
        .put_edge(&hidden, EdgeKind::Mentions, &anchor, 0.7)
        .expect("hidden inbound edge");
    vault
        .enter_off_record_session("sess-neighbor-filter", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-neighbor-filter", &hidden)
        .expect("tag hidden peer");
    let facade = vault.memory_facade(actor, EdgeActorClass::Human);
    let opts = NeighborOpts {
        edge_kind: Some("mentions".to_owned()),
        min_weight: None,
        limit: 10,
    };

    let hits = facade
        .neighbors(&anchor.to_hex(), &opts)
        .expect("visible-anchor neighbors");
    assert_eq!(hits.len(), 1);
    let hydrated = facade
        .hydrate(
            &hits
                .iter()
                .map(|hit| hit.short_id.clone())
                .collect::<Vec<_>>(),
        )
        .expect("hydrate visible neighbor set");
    assert_eq!(
        hydrated
            .iter()
            .filter(|view| view.id_hex == visible.to_hex())
            .count(),
        1
    );

    assert_eq!(
        facade
            .neighbors(&hidden.to_hex(), &opts)
            .expect("hidden-anchor neighbors")
            .len(),
        0
    );
}

#[test]
fn witness_edges_survive_fence_and_reappear_as_exact_set_on_promotion() {
    let (_tmp, vault) = temp_vault();
    let turn = seed_turn(&vault, 1000);
    let message = EntityId::now();
    let conversation = EntityId::now();
    let author = EntityId::now();
    let occurred = TimeRange {
        start: 1000,
        end: 1000,
    };
    vault
        .put_entity(
            &conversation,
            ENTITY_TYPE_CONVERSATION,
            occurred,
            1000,
            b"conversation",
        )
        .expect("conversation");
    vault
        .put_entity(&author, ENTITY_TYPE_PERSON, occurred, 1000, b"author")
        .expect("author");
    vault
        .enter_off_record_session("sess-witness-links", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-witness-links", &turn)
        .expect("tag");

    vault
        .memory_facade(author, EdgeActorClass::Human)
        .witness(&crate::facade::WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![crate::facade::WitnessMessage {
                id: Some(message.to_hex()),
                author: crate::facade::WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "private witness message".to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: 1000,
        })
        .expect("witness to live-fenced turn");

    let raw = vault
        .edges_out_unfiltered(&message)
        .expect("raw witness edges");
    assert_eq!(raw.len(), 3, "no witness relationship is suppressed");
    assert_eq!(
        vault
            .edges_out(&message)
            .expect("hidden public edges")
            .len(),
        0
    );
    let rtxn = vault.store.env.read_txn().expect("sidecar read");
    assert_eq!(
        inherited_off_record_fence_roots_in_txn(&vault.store, &rtxn, &message)
            .expect("message sidecar"),
        std::collections::BTreeSet::from([turn])
    );
    drop(rtxn);

    vault
        .promote_off_record_turn(
            "sess-witness-links",
            &turn,
            TEST_OWNER_REF,
            &test_owner_actor(),
        )
        .expect("promote");
    let released = vault.edges_out(&message).expect("released witness edges");
    assert_eq!(released.len(), 3);
    let exact = released
        .into_iter()
        .map(|edge| (edge.kind as u8, edge.target))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        exact,
        std::collections::BTreeSet::from([
            (EdgeKind::PartOf as u8, turn),
            (EdgeKind::BelongsTo as u8, conversation),
            (EdgeKind::AuthoredBy as u8, author),
        ])
    );
    let rtxn = vault.store.env.read_txn().expect("released sidecar read");
    assert_eq!(
        inherited_off_record_fence_roots_in_txn(&vault.store, &rtxn, &message)
            .expect("released message sidecar")
            .len(),
        0
    );
}

#[test]
fn inherited_fenced_carrier_reput_is_rejected_and_promotion_releases_original() {
    let (_tmp, vault) = temp_vault();
    let turn = seed_turn(&vault, 1000);
    let message = EntityId::now();
    let occurred = TimeRange {
        start: 1000,
        end: 1000,
    };
    let original = b"private carrier body";
    vault
        .batch()
        .put(&message, ENTITY_TYPE_MESSAGE, occurred, 1000, original)
        .edge(&message, EdgeKind::PartOf, &turn, 1.0)
        .commit()
        .expect("seed private carrier");
    vault
        .enter_off_record_session("sess-carrier-reput", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-carrier-reput", &turn)
        .expect("tag");

    let error = vault
        .put_entity(
            &message,
            ENTITY_TYPE_MESSAGE,
            occurred,
            1000,
            b"divergent rematerialized body",
        )
        .expect_err("a sidecar-hidden carrier must reject a divergent re-put");
    assert_eq!(error.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    assert_eq!(
        [message]
            .into_iter()
            .filter(|id| vault.get_raw(id).expect("raw carrier read").is_some())
            .count(),
        1
    );

    vault
        .promote_off_record_turn(
            "sess-carrier-reput",
            &turn,
            TEST_OWNER_REF,
            &test_owner_actor(),
        )
        .expect("promote");
    assert_eq!(
        vault.get(&message).expect("released carrier read"),
        Some(original.to_vec())
    );
    assert_eq!(
        inherited_off_record_fence_carriers(&vault.store)
            .expect("released sidecars")
            .len(),
        0
    );
}

#[test]
fn materialized_direct_fenced_root_allows_only_byte_exact_reput() {
    let (_tmp, vault) = temp_vault();
    let turn = EntityId::now();
    let occurred = TimeRange {
        start: 1000,
        end: 1000,
    };
    let original = b"original private root body";
    vault
        .put_entity(&turn, ENTITY_TYPE_TURN, occurred, 1000, original)
        .expect("seed materialized root");
    vault
        .enter_off_record_session("sess-root-reput", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-root-reput", &turn)
        .expect("tag materialized root");

    let changed = vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            occurred,
            1000,
            b"attacker replacement body",
        )
        .expect_err("body-changing fenced-root put must reject");
    assert_eq!(
        [changed]
            .into_iter()
            .filter(|error| error.kind() == ErrorKind::OffRecordFencedTurnWriteRejected)
            .count(),
        1
    );

    vault
        .put_entity(&turn, ENTITY_TYPE_TURN, occurred, 1000, original)
        .expect("byte-exact retry remains idempotent");
    vault
        .promote_off_record_turn(
            "sess-root-reput",
            &turn,
            TEST_OWNER_REF,
            &test_owner_actor(),
        )
        .expect("promote original root");
    assert_eq!(
        vault.get(&turn).expect("released root body"),
        Some(original.to_vec())
    );
}

#[test]
fn scoped_direct_read_surfaces_hide_direct_and_inherited_fences() {
    let (_tmp, vault) = temp_vault();
    let turn = seed_turn(&vault, 1000);
    let message = EntityId::now();
    let occurred = TimeRange {
        start: 1000,
        end: 1000,
    };
    vault
        .batch()
        .put(
            &message,
            ENTITY_TYPE_MESSAGE,
            occurred,
            1000,
            b"private message",
        )
        .edge(&message, EdgeKind::PartOf, &turn, 1.0)
        .commit()
        .expect("seed carrier");
    let short_refs = [turn, message].map(|id| {
        let rtxn = vault.store.env.read_txn().expect("short-ref read");
        let encoded = vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())
            .expect("short-ref lookup")
            .expect("assigned short ref");
        let (short_id, content_hash) =
            crate::batch::parse_short_id_value(encoded).expect("decode assigned short ref");
        (short_id.to_owned(), content_hash)
    });
    vault
        .enter_off_record_session("sess-scoped-direct", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-scoped-direct", &turn)
        .expect("tag");
    let scoped = vault.scoped_read(
        crate::claim::ScopedReadActorKey::new("off-record-regression-reader").expect("reader key"),
    );

    assert_eq!(
        [turn, message]
            .into_iter()
            .filter(|id| scoped.get_entity_parts(id).expect("scoped parts").is_some())
            .count(),
        0
    );
    assert_eq!(
        short_refs
            .iter()
            .filter(|(short_id, content_hash)| {
                scoped
                    .hydrate_short_id(short_id, *content_hash)
                    .expect("scoped hydrate")
                    .is_some()
            })
            .count(),
        0
    );
    assert_eq!(
        [turn, message]
            .into_iter()
            .map(|id| {
                scoped
                    .memory_timeline(&id)
                    .expect("scoped timeline")
                    .records
                    .len()
            })
            .sum::<usize>(),
        0
    );
    assert_eq!(
        [turn, message]
            .into_iter()
            .filter(|id| vault.get_raw(id).expect("raw control").is_some())
            .count(),
        2
    );
}

#[test]
fn retagging_existing_fence_backfills_descendant_sidecars() {
    let (_tmp, vault) = temp_vault();
    let turn = seed_turn(&vault, 1000);
    let message = EntityId::now();
    let summary = EntityId::now();
    let occurred = TimeRange {
        start: 1000,
        end: 1000,
    };
    vault
        .batch()
        .put(
            &message,
            ENTITY_TYPE_MESSAGE,
            occurred,
            1000,
            b"legacy private message",
        )
        .put(
            &summary,
            ENTITY_TYPE_SUMMARY,
            occurred,
            1000,
            b"legacy private summary",
        )
        .edge(&message, EdgeKind::PartOf, &turn, 1.0)
        .edge(&summary, EdgeKind::DerivedFrom, &message, 1.0)
        .commit()
        .expect("seed legacy descendants");
    vault
        .enter_off_record_session("sess-retag-backfill", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-retag-backfill", &turn)
        .expect("initial tag");
    vault
        .with_write_txn(|wtxn| {
            for carrier in [message, summary] {
                vault
                    .store
                    .vault_meta
                    .delete(wtxn, &off_record_inherited_fence_key(&carrier))?;
            }
            Ok(())
        })
        .expect("simulate pre-sidecar fence");
    assert_eq!(
        inherited_off_record_fence_carriers(&vault.store)
            .expect("legacy carrier inventory")
            .len(),
        0
    );

    vault
        .tag_turn_off_record("sess-retag-backfill", &turn)
        .expect("idempotent repair tag");
    assert_eq!(
        inherited_off_record_fence_carriers(&vault.store)
            .expect("repaired carrier inventory")
            .len(),
        2
    );
    let rtxn = vault.store.env.read_txn().expect("repaired roots read");
    assert_eq!(
        [message, summary]
            .into_iter()
            .filter(|carrier| {
                inherited_off_record_fence_roots_in_txn(&vault.store, &rtxn, carrier)
                    .expect("repaired roots")
                    == std::collections::BTreeSet::from([turn])
            })
            .count(),
        2
    );
}

#[test]
fn direct_fenced_root_delete_is_rejected_but_close_cascade_remains_authorized() {
    let (_tmp, vault) = temp_vault();
    let turn = seed_turn(&vault, 1000);
    let message = EntityId::now();
    let occurred = TimeRange {
        start: 1000,
        end: 1000,
    };
    vault
        .batch()
        .put(
            &message,
            ENTITY_TYPE_MESSAGE,
            occurred,
            1000,
            b"private delete carrier",
        )
        .edge(&message, EdgeKind::PartOf, &turn, 1.0)
        .commit()
        .expect("seed delete carrier");
    vault
        .enter_off_record_session("sess-root-delete", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-root-delete", &turn)
        .expect("tag");

    let batch_error = vault
        .batch()
        .delete(&turn)
        .commit()
        .expect_err("batch delete must reject a direct fenced root");
    assert_eq!(
        batch_error.kind(),
        ErrorKind::OffRecordFencedTurnWriteRejected
    );
    let direct_error = vault
        .delete_entity_with_reason(&turn, DeleteReason::UserHardDelete)
        .expect_err("ordinary hard delete must reject a direct fenced root");
    assert_eq!(
        direct_error.kind(),
        ErrorKind::OffRecordFencedTurnWriteRejected
    );
    assert_eq!(
        [turn, message]
            .into_iter()
            .filter(|id| vault.get_raw(id).expect("raw pre-close row").is_some())
            .count(),
        2
    );
    assert_eq!(
        vault
            .sources_unfiltered(&turn, EdgeKind::PartOf, Some(ENTITY_TYPE_MESSAGE))
            .expect("raw inheritance edge")
            .len(),
        1
    );

    let log = vault
        .off_record_receipt_log("sess-root-delete")
        .expect("close log");
    let outcome = vault
        .close_off_record_session("sess-root-delete", log)
        .expect("close cascade");
    assert_eq!(outcome.turns_deleted, 1);
    assert_eq!(outcome.turns_missing, 0);
    assert_eq!(
        [turn, message]
            .into_iter()
            .filter(|id| vault.get_raw(id).expect("raw post-close row").is_some())
            .count(),
        0
    );
}

#[test]
fn committed_witness_batch_replays_exactly_but_rejects_new_carrier_edge() {
    let (_tmp, vault) = temp_vault();
    let conversation = EntityId::now();
    let turn = EntityId::now();
    let message = EntityId::now();
    let author = EntityId::now();
    let ordinary = EntityId::now();
    let occurred = TimeRange {
        start: 1000,
        end: 1000,
    };
    vault
        .batch()
        .put(
            &conversation,
            ENTITY_TYPE_CONVERSATION,
            occurred,
            1000,
            b"conversation",
        )
        .put(&author, ENTITY_TYPE_PERSON, occurred, 1000, b"author")
        .put(&ordinary, ENTITY_TYPE_PERSON, occurred, 1000, b"ordinary")
        .commit()
        .expect("seed witness endpoints");
    vault
        .enter_off_record_session("sess-witness-retry", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-witness-retry", &turn)
        .expect("tag before witness");
    let witness = crate::facade::WitnessTurn {
        conversation_ref: conversation.to_hex(),
        turn_ref: Some(turn.to_hex()),
        messages: vec![crate::facade::WitnessMessage {
            id: Some(message.to_hex()),
            author: crate::facade::WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: "private retry witness".to_owned(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
        occurred_at: 1000,
    };
    let facade = vault.memory_facade(author, EdgeActorClass::Human);

    facade.witness(&witness).expect("first witness commit");
    facade
        .witness(&witness)
        .expect("byte-identical witness replay");
    assert_eq!(
        vault
            .edges_out_unfiltered(&message)
            .expect("raw replayed witness edges")
            .len(),
        3
    );
    assert_eq!(
        inherited_off_record_fence_carriers(&vault.store)
            .expect("witness sidecars")
            .len(),
        1
    );

    let error = vault
        .put_edge(&message, EdgeKind::Mentions, &ordinary, 0.5)
        .expect_err("a new edge from the inherited carrier must still reject");
    assert_eq!(error.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    assert_eq!(
        vault
            .edges_out_unfiltered(&message)
            .expect("unchanged witness edge set")
            .len(),
        3
    );
}

/// Simulates close-in-flight by stamping the closing flag exactly as
/// close's first transaction does, then interleaves every mutator at
/// the seam. The promote rejection is the load-bearing one: without the
/// flag, close's stale snapshot would hard-delete a just-promoted,
/// user-consented turn.
#[test]
fn off_record_closing_flag_freezes_record_against_mutators() {
    let (_tmp, vault) = temp_vault();
    let fenced = seed_turn(&vault, 1000);
    let late = seed_turn(&vault, 1001);
    vault
        .enter_off_record_session("sess-toctou", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-toctou", &fenced)
        .expect("tag");

    // Stamp the closing flag the way close's txn 1 does.
    vault
        .with_write_txn(|wtxn| {
            let mut record =
                session_record_in_txn(&vault.store, wtxn, "sess-toctou")?.expect("session record");
            record.closing = true;
            vault.store.vault_meta.put(
                wtxn,
                &off_record_session_key("sess-toctou"),
                &encode_off_record_session(&record)?,
            )?;
            Ok(())
        })
        .expect("stamp closing");

    let tag = vault
        .tag_turn_off_record("sess-toctou", &late)
        .expect_err("tag during close");
    assert_eq!(tag.kind(), ErrorKind::OffRecordSessionClosing);
    let promote = vault
        .promote_off_record_turn("sess-toctou", &fenced, TEST_OWNER_REF, &test_owner_actor())
        .expect_err("promote during close");
    assert_eq!(promote.kind(), ErrorKind::OffRecordSessionClosing);
    let note = vault
        .note_off_record_context_receipt("sess-toctou", crate::store::RetrievalRunId::now())
        .expect_err("note during close");
    assert_eq!(note.kind(), ErrorKind::OffRecordSessionClosing);
    let flip = vault
        .set_off_record_session_mode("sess-toctou", OffRecordMode::OnRecord)
        .expect_err("flip during close");
    assert_eq!(flip.kind(), ErrorKind::OffRecordSessionClosing);

    // Close re-enters the closing state idempotently and completes.
    let log = vault
        .off_record_receipt_log("sess-toctou")
        .expect("log during close retry");
    let outcome = vault
        .close_off_record_session("sess-toctou", log)
        .expect("close completes");
    assert_eq!(outcome.turns_deleted, 1);
    assert!(vault.get(&fenced).expect("read fenced").is_none());
    assert!(vault.get(&late).expect("read late").is_some());
}

#[cfg(feature = "sync")]
#[test]
fn off_record_live_fence_rejects_replicated_edge_to_fenced_turn() {
    let (_tmp, vault) = temp_vault();
    let source = seed_turn(&vault, 999);
    let fenced = seed_turn(&vault, 1000);
    vault
        .enter_off_record_session("sess-replicated-edge", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-replicated-edge", &fenced)
        .expect("tag fenced turn");

    let rejected = vault
        .batch()
        .edge_with_value_fields(
            &source,
            EdgeKind::Mentions,
            &fenced,
            crate::batch::EdgeValueFields {
                weight: 1.0,
                created_at: 1001,
                vad: crate::affect::Vad::NEUTRAL,
                provenance: None,
            },
        )
        .commit()
        .expect_err("replicated edge must not cross a live off-record fence");
    assert!(matches!(
        rejected,
        Error::OffRecordFencedTurnWriteRejected { turn_ref } if turn_ref == fenced.to_hex()
    ));
    assert!(
        vault
            .targets(&source, EdgeKind::Mentions, None)
            .expect("read rejected edge")
            .is_empty(),
        "rejected replay must not leave an edge side effect"
    );
}

/// Tag-before-write turn whose entity write lands AFTER close: the
/// sessionless fence marker must reject every entity write door. A
/// fully-missing id stays a strict no-op at close: no tombstone and no
/// receipt are minted for it.
#[test]
fn off_record_close_rejects_late_write_for_missing_turn_without_audit_artifacts() {
    let (_tmp, vault) = temp_vault();
    let written = seed_turn(&vault, 1000);
    let phantom = EntityId::now();
    vault
        .enter_off_record_session("sess-rejoin", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-rejoin", &written)
        .expect("tag written");
    // Tag-before-write: the entity does not exist yet.
    vault
        .tag_turn_off_record("sess-rejoin", &phantom)
        .expect("tag phantom");

    // A headerless delete would address a tombstone to this current/requested
    // at window, not the written fixture's historical window. Keep both
    // probes explicit so this regression verifies the actual no-op surface.
    #[cfg(feature = "sync")]
    let requested_at_window =
        crate::sync::types::WindowKey::from_timestamp(crate::unix_seconds_now());
    let log = vault
        .off_record_receipt_log("sess-rejoin")
        .expect("mint log");
    let outcome = vault
        .close_off_record_session("sess-rejoin", log)
        .expect("close");
    assert_eq!(outcome.turns_deleted, 1);
    assert_eq!(outcome.turns_missing, 1);
    assert_eq!(outcome.fence_rows_retained, 1);
    assert_eq!(
        outcome.redaction_receipt_ids.len(),
        1,
        "only the actually written turn may mint a redaction receipt"
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("redaction receipt index")
            .len(),
        1,
        "the tag-before-write turn must not mint a redaction receipt"
    );

    // Deleted turn's fence row is gone; the missing turn's row remains.
    assert!(!vault.is_turn_off_record_fenced(&written).expect("probe"));
    assert!(vault.is_turn_off_record_fenced(&phantom).expect("probe"));
    let rtxn = vault.store.env.read_txn().expect("read fence marker");
    let retained = vault
        .store
        .vault_meta
        .get(&rtxn, &off_record_fence_key(&phantom))
        .expect("load retained fence")
        .expect("closed fence retained");
    assert!(
        retained.is_empty(),
        "closed fence must not retain the evaporated session ref"
    );
    drop(rtxn);

    // The in-flight write lands late — the shared entity write door rejects
    // it before it can create any entity/index/receipt side effects.
    let late = vault
        .put_entity(
            &phantom,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: 1001,
                end: 1001,
            },
            1001,
            b"late-landing off-record turn",
        )
        .expect_err("late write must be rejected");
    assert_eq!(late.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    assert!(matches!(
        late,
        Error::OffRecordFencedTurnWriteRejected { turn_ref } if turn_ref == phantom.to_hex()
    ));

    #[cfg(feature = "sync")]
    {
        let replay = vault
            .batch()
            .put_replicated(
                &phantom,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: 1001,
                    end: 1001,
                },
                1001,
                b"late-replayed off-record turn",
            )
            .commit()
            .expect_err("replicated late write must hit the same door");
        assert_eq!(replay.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    }
    assert!(vault.get(&phantom).expect("read phantom").is_none());
    assert!(surfaced_turns(&vault).is_empty());
    assert!(dreamer_working_set_turns(&vault).is_empty());

    #[cfg(feature = "sync")]
    {
        for key in [
            crate::sync::types::WindowKey::from_timestamp(1000),
            requested_at_window,
        ] {
            let doc = match crate::sync::window::load_window_from_state(&vault, "test", &key) {
                Ok(doc) => doc,
                // No `d:w:` state is itself the expected no-tombstone proof
                // for an untouched requested-at window.
                Err(Error::WindowNotFound { .. }) => continue,
                Err(error) => panic!("load no-op tombstone window: {error:?}"),
            };
            assert!(
                !crate::sync::loro_support::tombstone_map_contains_id(
                    &doc.get_map("tombstones"),
                    &phantom,
                ),
                "never-written turn must not mint a CRDT tombstone in {key}"
            );
        }
    }
}

/// A retry after PolicyDelete's purge committed but before close removed its
/// fence must recognize the permanent hard-delete marker as a deleted turn,
/// rather than converting it into a closed tag-before-write fence.
#[test]
fn off_record_close_retry_keeps_completed_delete_out_of_missing_counts() {
    let (_tmp, vault) = temp_vault();
    let fenced = seed_turn(&vault, 1000);
    vault
        .enter_off_record_session("sess-close-retry", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-close-retry", &fenced)
        .expect("tag");
    let retry_log = vault
        .off_record_receipt_log("sess-close-retry")
        .expect("receipt log");

    // Reproduce the interruption boundary: close's first transaction froze
    // the session, then PolicyDelete completed, but final fence cleanup did
    // not run before the process stopped.
    vault
        .with_write_txn(|wtxn| {
            let mut record = session_record_in_txn(&vault.store, wtxn, "sess-close-retry")?
                .expect("session record");
            record.closing = true;
            vault.store.vault_meta.put(
                wtxn,
                &off_record_session_key("sess-close-retry"),
                &encode_off_record_session(&record)?,
            )?;
            Ok(())
        })
        .expect("freeze close");
    let first_delete = vault
        .delete_entity_with_reason(&fenced, crate::deletion::DeleteReason::PolicyDelete)
        .expect("PolicyDelete before interruption");
    assert!(first_delete.existed);
    assert!(first_delete.receipt_id.is_some());

    let outcome = vault
        .close_off_record_session("sess-close-retry", retry_log)
        .expect("retry close");
    assert_eq!(outcome.turns_deleted, 1);
    assert_eq!(outcome.turns_missing, 0);
    assert_eq!(outcome.fence_rows_retained, 0);
    assert!(
        !vault
            .is_turn_off_record_fenced(&fenced)
            .expect("fence removed")
    );
    assert!(
        vault
            .off_record_session("sess-close-retry")
            .expect("session")
            .is_none()
    );
}

#[test]
fn off_record_session_ref_bounds_are_enforced_everywhere() {
    let (_tmp, vault) = temp_vault();
    let oversized = "x".repeat(300);
    let turn = seed_turn(&vault, 1000);

    let enter = vault
        .enter_off_record_session(&oversized, OffRecordBackendClass::Local)
        .expect_err("oversized enter");
    assert_eq!(enter.kind(), ErrorKind::InvalidConfig);
    // A ref that cannot pass enter cannot name a session: reads as None.
    assert!(
        vault
            .off_record_session(&oversized)
            .expect("probe")
            .is_none()
    );
    let tag = vault
        .tag_turn_off_record(&oversized, &turn)
        .expect_err("oversized tag");
    assert_eq!(tag.kind(), ErrorKind::InvalidConfig);
    let flip = vault
        .set_off_record_session_mode(&oversized, OffRecordMode::OnRecord)
        .expect_err("oversized flip");
    assert_eq!(flip.kind(), ErrorKind::InvalidConfig);
    let note = vault
        .note_off_record_context_receipt(&oversized, crate::store::RetrievalRunId::now())
        .expect_err("oversized note");
    assert_eq!(note.kind(), ErrorKind::InvalidConfig);
    let promote = vault
        .promote_off_record_turn(&oversized, &turn, TEST_OWNER_REF, &test_owner_actor())
        .expect_err("oversized promote");
    assert_eq!(promote.kind(), ErrorKind::InvalidConfig);
    let log = vault
        .off_record_receipt_log(&oversized)
        .expect_err("oversized log");
    assert_eq!(log.kind(), ErrorKind::InvalidConfig);
    let close = vault
        .close_off_record_session(
            &oversized,
            SessionLocalReceiptLog::off_record(oversized.clone()),
        )
        .expect_err("oversized close");
    assert_eq!(close.kind(), ErrorKind::InvalidConfig);
}

/// A fenced turn must neither seed PPR expansion (pulling its on-record
/// neighbors into results) nor be exposed by context-pack edge lists or
/// hop-1 neighbor hydration.
#[test]
fn off_record_fence_blocks_ppr_expansion_and_context_pack_edges() {
    let (_tmp, vault) = temp_vault();
    // Fenced turn F in the temporal window; its neighbor N far outside
    // the temporal scan radius (only reachable through F's edges).
    // On-record result R in-window with an edge pointing AT F.
    let fenced = seed_turn(&vault, 1000);
    let neighbor = seed_turn(&vault, 100_000_000);
    let on_record = seed_turn(&vault, 1001);
    vault
        .put_edge(&fenced, EdgeKind::Mentions, &neighbor, 0.9)
        .expect("edge F->N");
    vault
        .put_edge(&on_record, EdgeKind::Mentions, &fenced, 0.9)
        .expect("edge R->F");
    vault
        .enter_off_record_session("sess-graph", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-graph", &fenced)
        .expect("tag");

    let expanded: Vec<EntityId> = vault
        .query()
        .search_temporal(900, 1100, 16)
        .expand_ppr(&[], 1)
        .limit(16)
        .run()
        .expect("ppr run")
        .into_iter()
        .map(|scored| scored.id)
        .collect();
    assert!(expanded.contains(&on_record));
    assert!(!expanded.contains(&fenced), "fenced turn surfaced");
    assert!(
        !expanded.contains(&neighbor),
        "fenced turn must not seed expansion toward its neighbors"
    );

    let pack = vault
        .context_pack()
        .search_temporal(900, 1100, 16)
        .include_edges(true)
        .edge_hop(1)
        .run()
        .expect("context pack");
    assert!(pack.results.iter().any(|entity| entity.id == on_record));
    assert!(pack.results.iter().all(|entity| entity.id != fenced));
    assert!(
        pack.neighbors.iter().all(|entity| entity.id != fenced),
        "fenced turn hydrated as a context-pack neighbor"
    );
    for entity in pack.results.iter().chain(pack.neighbors.iter()) {
        if let Some(edges) = &entity.edges {
            assert!(
                edges.iter().all(|edge| edge.target != fenced),
                "edge list exposed the fenced target id"
            );
        }
    }
}
