use super::*;
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::edge::EdgeKind;
use crate::error::{Error, ErrorKind};
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchError,
    OutboundDispatchGate, OutboundDispatchPipeline, OutboundDispatchRequest,
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent,
    OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::registry::{ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_TURN};
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::temporal::TimeRange;

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

fn put_live_overlay_entity(session: &OffRecordSession<'_>, id: &EntityId) -> Result<()> {
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        id.as_bytes(),
        b"live session overlay entity",
    )?;
    segment.commit()
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
        redacted_at: None,
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
    let session = vault
        .off_record_session_vault()
        .enter("sess-enter", OffRecordBackendClass::Local)
        .expect("enter");
    assert_eq!(session.mode().expect("read mode"), OffRecordMode::OffRecord);
    assert_eq!(
        session.backend_class().expect("read backend class"),
        OffRecordBackendClass::Local
    );
    let record = vault
        .off_record_session("sess-enter")
        .expect("read record")
        .expect("live record");
    assert!(record.promoted_turns.is_empty());

    let double_enter = vault
        .enter_off_record_session("sess-enter", OffRecordBackendClass::Local)
        .expect_err("enter is single-shot");
    assert_eq!(
        double_enter.kind(),
        ErrorKind::OffRecordSessionAlreadyExists
    );

    let remote_session = vault
        .off_record_session_vault()
        .enter("sess-enter-remote", OffRecordBackendClass::RemoteProvider)
        .expect("enter remote session");
    assert_eq!(
        remote_session.mode().expect("read remote mode"),
        OffRecordMode::OffRecord
    );
    assert_eq!(
        remote_session
            .backend_class()
            .expect("read remote backend class"),
        OffRecordBackendClass::RemoteProvider
    );
}

#[test]
fn off_record_registry_evaporates_without_base_residue_on_reopen() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), VaultConfig::default())?;
    let base_rows_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.vault_meta.len(&rtxn)?
    };
    let session = vault
        .off_record_session_vault()
        .enter("sess-crash-registry", OffRecordBackendClass::Local)?;
    assert!(vault.off_record_session("sess-crash-registry")?.is_some());
    let base_rows_during = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.vault_meta.len(&rtxn)?
    };
    assert_eq!(
        base_rows_during, base_rows_before,
        "enter must not create a durable session row"
    );
    drop(session);
    drop(vault);

    let reopened = Vault::open(tmp.path(), VaultConfig::default())?;
    assert!(
        reopened
            .off_record_session("sess-crash-registry")?
            .is_none()
    );
    assert!(
        reopened
            .off_record_session_vault()
            .enter("sess-crash-registry", OffRecordBackendClass::Local)
            .is_ok()
    );
    Ok(())
}

#[test]
fn entity_put_guard_rejects_live_overlay_membership() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("sess-overlay-put-guard", OffRecordBackendClass::Local)?;
    put_live_overlay_entity(&session, &id)?;

    let error = vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: 1000,
                end: 1000,
            },
            1000,
            b"must not couple overlay content into base",
        )
        .expect_err("a base entity put must reject a live overlay member");
    assert_eq!(error.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert!(matches!(
        error,
        Error::OffRecordTaintedBaseWrite { entity_ref } if entity_ref == id.to_hex()
    ));
    assert_eq!(
        vault.get_raw(&id)?,
        None,
        "the rejected put must leave no durable entity row"
    );

    session.close()?;
    vault.put_entity(
        &id,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: 1000,
            end: 1000,
        },
        1000,
        b"ordinary base content after membership evaporates",
    )?;
    assert!(
        vault.get_raw(&id)?.is_some(),
        "the door must be keyed to LIVE overlay membership: once the room is \
         gone there is nothing to taint and the id is an ordinary base id"
    );
    Ok(())
}

#[test]
fn mode_flip_seals_overlay_writes_but_keeps_composed_reads() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("sess-mode-route", OffRecordBackendClass::Local)?;
    let overlay = session.overlay();
    let mut wtxn = vault.store.env.write_txn()?;
    let segment = overlay.install_txn_segment()?;
    let view = session.read_view()?;
    view.entities
        .put(&mut wtxn, id.as_bytes(), b"session-row")?;
    drop(view);
    wtxn.commit()?;
    segment.commit()?;

    session.flip_on_record()?;
    let sealed = match overlay.install_txn_segment() {
        Err(error) => error,
        Ok(_) => panic!("mode flip must seal overlay writes"),
    };
    assert_eq!(sealed.kind(), ErrorKind::OffRecordOverlayLeaseClosed);
    let rtxn = vault.store.env.read_txn()?;
    let read_view = session.read_view()?;
    assert_eq!(
        read_view.entities.get(&rtxn, id.as_bytes())?.as_deref(),
        Some(&b"session-row"[..]),
        "mode flip keeps pre-flip overlay rows in the composed read view"
    );
    drop(read_view);
    drop(rtxn);
    assert_eq!(vault.get_raw(&id)?, None, "pre-flip row never reached base");
    session.close()?;
    Ok(())
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

/// Close's base half: it touches base at all only by NOT touching it. Emit
/// receipts drop with the session log, floor receipts survive, and an ordinary
/// base turn written while the room was live is still there afterwards.
///
/// The context-receipt half moved to the SESSION path in ONE-1728 (K8): a
/// retrieval run is session-local by being registered in the session's own
/// overlay keyspace, which only a session-handle run does. This vault-level
/// session has no handle, so its retrieval run is an ordinary base run that
/// close must NOT touch — asserted below. The `context_receipts_deleted == 1`
/// contract is owned by the branch-store oracle's
/// `master_close_deletes_transcript_and_context_receipts_keeps_floor_receipts`,
/// which drives a real session-handle retrieval.
#[test]
fn off_record_close_deletes_transcript_keeps_floor_and_base_receipts() {
    let (_tmp, vault) = temp_vault();
    vault
        .enter_off_record_session("sess-close", OffRecordBackendClass::Local)
        .expect("enter");
    // Commissioned ordinary base writes made DURING the live session. They are
    // not overlay members, so close has no claim on them.
    let commissioned_a = seed_turn(&vault, 1000);
    let commissioned_b = seed_turn(&vault, 1001);

    // A BASE retrieval run taken while a session is live. It is not session
    // content — nothing routed it through the session handle — so its receipt
    // is an ordinary durable row that close must leave alone (K8).
    let telemetry = vault
        .query()
        .search_temporal(900, 1100, 16)
        .filter_types(&[ENTITY_TYPE_TURN])
        .limit(16)
        .run_with_telemetry()
        .expect("retrieval with telemetry");
    let run_id = telemetry.run_id.expect("telemetry run id");
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
    assert_eq!(
        outcome.turns_deleted, 0,
        "this session witnessed nothing through its overlay, so no transcript \
         row evaporated"
    );
    assert_eq!(
        outcome.context_receipts_deleted, 0,
        "this session witnessed nothing through its overlay, so it owns zero \
         session-local retrieval-run receipts"
    );
    assert_eq!(outcome.emit_receipts_deleted, 1);
    assert_eq!(outcome.promoted_turns_kept, 0);

    // Commissioned base writes survive: close performs no PolicyDelete pass,
    // so an ordinary write made while the room was open is an ordinary write.
    assert!(vault.get(&commissioned_a).expect("read a").is_some());
    assert!(vault.get(&commissioned_b).expect("read b").is_some());
    // No redaction-audit receipt is minted, because nothing was deleted.
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("redaction receipt index")
            .is_empty(),
        "close deletes nothing, so it mints no REDACTION_AUDIT receipt"
    );
    // The BASE retrieval run stays: close evaporates the session's own overlay
    // receipts, never an ordinary durable telemetry row.
    assert!(vault.retrieval_run(run_id).expect("run lookup").is_some());
    // Floor receipts remain.
    assert!(!vault.gate_decisions(10).expect("gate decisions").is_empty());
    // Session record is gone; close is not replayable.
    assert!(
        vault
            .off_record_session("sess-close")
            .expect("session lookup")
            .is_none()
    );
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

/// Simulates close-in-flight by stamping the closing flag exactly as
/// close's first transaction does, then interleaves every mutator at
/// the seam. The promote rejection is the load-bearing one: without the
/// flag, close's stale snapshot would hard-delete a just-promoted,
/// user-consented turn.
#[test]
fn off_record_closing_flag_freezes_record_against_mutators() {
    let (_tmp, vault) = temp_vault();
    let commissioned = seed_turn(&vault, 1001);
    // Entered through the session handle so the promote mutator — which lives
    // on the handle, not the vault — is reachable at the same seam.
    let session = vault
        .off_record_session_vault()
        .enter("sess-toctou", OffRecordBackendClass::Local)
        .expect("enter");
    let room_member = EntityId::now();
    put_live_overlay_entity(&session, &room_member).expect("stage a room member");

    // Stamp the in-process closing state exactly as close does.
    let entry = vault
        .store
        .off_record_sessions
        .entry("sess-toctou")
        .expect("registry")
        .expect("session record");
    session_entry_state(&entry)
        .expect("session state")
        .record
        .closing = true;

    // The closing check runs BEFORE the journal is read, so this rejects on the
    // seam rather than on the turn not being journaled — which is the point:
    // the flag, not the closure, is what freezes the record.
    let promote = session
        .promote_turn(&room_member)
        .expect_err("promote during close");
    assert_eq!(promote.kind(), ErrorKind::OffRecordSessionClosing);
    // A promote rejected because the session is closing must NOT have committed
    // a durable promote receipt: a receipt without its replayed rows would
    // claim durable content that does not exist.
    assert!(
        vault
            .off_record_promote_receipt(&room_member)
            .expect("receipt lookup")
            .is_none(),
        "a closing-rejected promote must persist no promote receipt"
    );
    let record_emit = session
        .record_emit_receipt(crate::receipt::outbound_intent_receipt(
            "receipt-toctou",
            "intent-toctou",
            &OutboundIntent::from_trigger(
                OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com"),
                OutboundIntentTrigger::agent_immediate("intent:toctou"),
            ),
            100,
            "delivered_to_channel",
        ))
        .expect_err("emit-receipt record during close");
    assert_eq!(record_emit.kind(), ErrorKind::OffRecordSessionClosing);
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
    assert_eq!(outcome.promoted_turns_kept, 0);
    assert!(
        vault
            .get(&commissioned)
            .expect("read commissioned")
            .is_some(),
        "close touches no base row"
    );
    assert!(
        vault
            .off_record_session("sess-toctou")
            .expect("session lookup")
            .is_none()
    );
}

#[test]
fn off_record_session_ref_bounds_are_enforced_everywhere() {
    let (_tmp, vault) = temp_vault();
    let oversized = "x".repeat(300);
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
    let flip = vault
        .set_off_record_session_mode(&oversized, OffRecordMode::OnRecord)
        .expect_err("oversized flip");
    assert_eq!(flip.kind(), ErrorKind::InvalidConfig);
    // Promote takes no session ref: it hangs off a live session HANDLE, which
    // only `enter` above can mint — so the bound is enforced upstream of it by
    // construction rather than re-checked at the verb.
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

/// ONE-1730: the promote-replay grant exempts ONLY the closure it was minted
/// from, and a rejection INSIDE the promote transaction rolls the whole thing
/// back.
///
/// The grant is minted from the PLAN, so the sharpest probe of its scope is a
/// promote transaction whose op list reaches past that plan's own ids: here a
/// trailing `AuthoredBy` edge naming a second live room's overlay member —
/// the same shape the room's real authorship edge has, which is exactly why
/// that edge is not in the promoted closure. It lands AFTER the shell, turn,
/// message, and summary puts have already staged rows, so zero base delta
/// afterwards is evidence of the single-transaction contract, not of an early
/// bail. The unmodified closure then promotes cleanly, proving a failed
/// promote leaves the journal and overlay rows intact.
#[test]
fn promote_replay_refuses_another_live_rooms_overlay_id_and_rolls_back() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = vault
        .off_record_session_vault()
        .enter("sess-grant-scope", OffRecordBackendClass::Local)?;
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"grant-scope fixture actor",
    )?;
    let receipt = vault
        .memory(actor, EdgeActorClass::Human)
        .witness_into_session(
            &session,
            &crate::memory::WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: None,
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "utterance".to_owned(),
                    content: "grant-scope fixture".to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: 1000,
            },
            Some("grant-scope fixture summary"),
        )
        .unwrap_or_else(|error| panic!("session witness failed: {error:?}"));
    let turn = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .ok_or(Error::InvariantViolation("witness receipt names no turn"))?,
    )?;

    // A SECOND live room takes an id into its overlay.
    let other = vault
        .off_record_session_vault()
        .enter("sess-other-room", OffRecordBackendClass::Local)?;
    let foreign = EntityId::now();
    put_live_overlay_entity(&other, &foreign)?;

    let entities_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.entities.len(&rtxn)?
    };
    let edges_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.edges_out.len(&rtxn)?
    };
    let mut overreaching = session.overlay().snapshot()?.plan_promotion(turn)?;
    overreaching
        .ops
        .push(crate::batch::BatchOp::PublicEdgeWithCreatedAt {
            src: turn,
            kind: EdgeKind::AuthoredBy,
            tgt: foreign,
            weight: 1.0,
            created_at: 1000,
            vad: crate::affect::Vad::NEUTRAL,
        });
    let refusal = vault
        .with_write_txn(|wtxn| {
            FloorWrites::new(&vault.store).promote(
                &vault,
                wtxn,
                "sess-grant-scope",
                &overreaching,
                2000,
            )
        })
        .expect_err("another room's overlay id must taint the replay");
    assert_eq!(refusal.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault.store.entities.len(&rtxn)?,
            entities_before,
            "a rejected promote must leave zero base entity delta"
        );
        assert_eq!(
            vault.store.edges_out.len(&rtxn)?,
            edges_before,
            "a rejected promote must leave zero base edge delta"
        );
    }
    assert!(
        vault.off_record_promote_receipt(&turn)?.is_none(),
        "a rejected promote must persist no receipt"
    );

    // The SAME closure is still promotable through the ordinary path — and
    // the other room stays live, because a closure that stops at its own
    // endpoints has nothing to say about anyone else's ids.
    let outcome = session.promote_turn(&turn)?;
    assert_eq!(
        outcome.replayed.len(),
        4,
        "the rejected promote left the journal closure intact"
    );
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(vault.store.entities.len(&rtxn)? - entities_before, 4);
        // ONE-1767 F2: each promoted turn closure also replays its ChildOf edge.
        assert_eq!(vault.store.edges_out.len(&rtxn)? - edges_before, 4);
    }
    other.close()?;
    session.close()?;
    Ok(())
}

// ─── ONE-1570 Arm B — retrieval-run context receipts follow the transcript ──

/// Seeds base content the room can retrieve, through the production witness
/// door so the text is really BM25-indexed.
fn seed_recallable_base_turn(vault: &Vault, needle: &str) -> EntityId {
    let actor = EntityId::from_bytes([0xA7; 16]).expect("actor id");
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"arm-b person",
        )
        .expect("put actor");
    vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&crate::memory::WitnessTurn {
            conversation_ref: EntityId::from_bytes([0xA8; 16]).expect("conv id").to_hex(),
            turn_ref: None,
            messages: vec![crate::memory::WitnessMessage {
                id: None,
                author: crate::memory::WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: needle.to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: 1500,
        })
        .expect("witness base turn");
    actor
}

/// ARM B ACCEPTANCE (ONE-1570 settle bar).
///
/// Drives the NAMED PUBLIC production entry point of the census-named host —
/// `Memory::recall_in_session` — and proves the whole contract without
/// one manual registration call and without threading a `session_ref` into any
/// internal by hand: the test holds only the public session handle the host
/// takes as an argument.
///
/// The three doors asserted, in order:
///
/// 1. an off-record recall's run registers into the ROOM and the base ledger
///    gains nothing;
/// 2. the row is FINALIZED, exactly once — the room's own reader skips
///    provisional rows, so a run that registered but never finalized is
///    invisible here, which is precisely the break a base-only finalize
///    produced against an overlay-staged provisional;
/// 3. close takes it: the pre-close census counts it as a deleted context
///    receipt and nothing durable survives.
#[test]
fn off_record_recall_registers_its_run_in_the_room_and_close_consumes_it() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = seed_recallable_base_turn(&vault, "armbrecallneedle");
    let facade = vault.memory(actor, EdgeActorClass::Human);

    let base_runs_before = vault.retrieval_runs(64)?.len();
    let session = vault
        .off_record_session_vault()
        .enter("sess-armb", OffRecordBackendClass::Local)?;

    let pack = facade
        .recall_in_session(
            &session,
            "armbrecallneedle",
            crate::memory::Effort::Standard,
            &crate::memory::RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("in-room recall");
    assert!(
        !pack.items.is_empty(),
        "the recall really ran and really retrieved — a zero-output pack would let every \
         assertion below pass vacuously"
    );

    // (1) + (2): the room holds FINALIZED runs; base holds none of them.
    let room_runs = {
        let view = session.read_view()?;
        let rtxn = vault.store.env.read_txn()?;
        view.retrieval_runs_in_txn(&rtxn, 64)?
    };
    assert!(
        !room_runs.is_empty(),
        "an off-record recall registers its retrieval runs in the room"
    );
    // The recall issues TWO retrievals: the PPR seed search (a published
    // `VaultSearch` run) and the context pack itself (registered PROVISIONAL,
    // then finalized). Asserting on the set as a whole would let the seed run
    // alone satisfy it while the pack's provisional row silently never
    // finalized — the exact break a base-only finalize produces against an
    // overlay-staged provisional. So this names the CONTEXT-PACK run.
    let pack_runs: Vec<_> = room_runs
        .iter()
        .filter(|run| run.action == crate::store::RetrievalAction::ContextPack)
        .collect();
    assert_eq!(
        pack_runs.len(),
        1,
        "the context-pack run is registered EXACTLY ONCE in the room: this reader skips \
         provisional rows, so 0 means the provisional never finalized and >1 means the \
         provisional and finalized forms both published"
    );
    assert!(
        !pack_runs[0].result_ids.is_empty(),
        "finalize is what writes result_ids, so a populated row proves the SECOND write \
         reached the SAME row the provisional registration created"
    );
    assert!(
        room_runs
            .iter()
            .any(|run| run.action == crate::store::RetrievalAction::VaultSearch),
        "the PPR seed search is a second retrieval and its run rides the room too, rather \
         than publishing a durable base row naming what the room searched for"
    );
    assert_eq!(
        vault.retrieval_runs(64)?.len(),
        base_runs_before,
        "and the durable base ledger gains NOTHING from a retrieval issued inside the room"
    );

    // (3) close takes them, and counts them while they are still readable.
    let receipt_log = vault.off_record_receipt_log("sess-armb")?;
    let outcome = vault.close_off_record_session("sess-armb", receipt_log)?;
    // `retrieval_runs_in_txn` reads overlay ∪ base, and base is flat across
    // the whole session (asserted above), so every run beyond the pre-session
    // base baseline is an OVERLAY row — which is exactly what the pre-close
    // census counts.
    let overlay_runs = room_runs.len() - base_runs_before;
    assert!(
        overlay_runs >= 2,
        "the recall issued two retrievals — the context pack and the PPR seed search — and \
         both registered in the room"
    );
    assert!(
        outcome.context_receipts_deleted >= overlay_runs,
        "the K8 pre-close census counts every retrieval-run receipt the room held \
         (counted {} for {overlay_runs} overlay runs)",
        outcome.context_receipts_deleted
    );
    assert_eq!(
        vault.retrieval_runs(64)?.len(),
        base_runs_before,
        "nothing durable survives the room"
    );
    Ok(())
}

/// The two negative controls the settle contract names, on ONE fixture so the
/// distinction is visible: a room retrieval is claimed by the room ONLY while
/// the room is off record, and ambient live-session state never claims an
/// ordinary one.
#[test]
fn on_record_and_ordinary_recalls_never_enter_the_rooms_receipt_set() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = seed_recallable_base_turn(&vault, "armbcontrolneedle");
    let facade = vault.memory(actor, EdgeActorClass::Human);
    let session = vault
        .off_record_session_vault()
        .enter("sess-armb-control", OffRecordBackendClass::Local)?;

    // The room's own reader is COMPOSED (overlay ∪ base), so "the room shows
    // no rows" would be the wrong question — a base row is visible through it
    // by design. Room MEMBERSHIP is what the pre-close census counts, so the
    // per-step check is the durable-base one and the membership verdict is the
    // census at the end.
    let landed_in_base = |base_before: usize, expectation: &str| -> Result<()> {
        assert!(
            vault.retrieval_runs(64)?.len() > base_before,
            "{expectation}: the run is an ordinary durable base one"
        );
        Ok(())
    };

    // CONTROL A — an ordinary commissioned recall, taken through the plain
    // public door while the room is live off record. Nothing routed it through
    // the session handle, so the room has no claim on it.
    let before = vault.retrieval_runs(64)?.len();
    facade
        .recall(
            "armbcontrolneedle",
            crate::memory::Effort::Standard,
            &crate::memory::RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("ordinary recall");
    landed_in_base(before, "an ordinary recall beside a live room")?;

    // CONTROL B — the SAME in-room door after a flip back on record. The room
    // is on record, so its retrievals are ordinary ones and their runs belong
    // in the base ledger like any other.
    session.flip_on_record()?;
    let before = vault.retrieval_runs(64)?.len();
    facade
        .recall_in_session(
            &session,
            "armbcontrolneedle",
            crate::memory::Effort::Standard,
            &crate::memory::RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("on-record in-room recall");
    landed_in_base(before, "an on-record room recall")?;

    let receipt_log = vault.off_record_receipt_log("sess-armb-control")?;
    let outcome = vault.close_off_record_session("sess-armb-control", receipt_log)?;
    assert_eq!(
        outcome.context_receipts_deleted, 0,
        "neither control ever became a context receipt of the room"
    );
    Ok(())
}

/// K10 boundary under a MID-ASSEMBLY flip, base direction.
///
/// A retrieval admitted while the room is ON RECORD captures a base-targeted
/// route, and the base arm is the half that publishes DURABLY. If the room
/// flips back off record after the route is captured — safe Rust permits it
/// from another thread, and `rearm` publishes a new mode generation — the
/// registration must refuse rather than land the room's `result_ids` in the
/// base telemetry ledger.
///
/// The flip is staged between capture and registration deliberately: the
/// assembled paths hold their route across the whole run and revalidate at the
/// WRITE, so an entry-time check is exactly the one that cannot see this.
#[test]
fn a_base_routed_room_retrieval_refuses_a_run_the_room_no_longer_authorizes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    seed_recallable_base_turn(&vault, "armbstaleneedle");
    let session = vault
        .off_record_session_vault()
        .enter("sess-armb-stale", OffRecordBackendClass::Local)?;

    session.flip_on_record()?;
    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;

    session.flip_off_record()?;

    let base_runs_before = vault.retrieval_runs(64)?.len();
    let error = vault
        .query()
        .search_text("armbstaleneedle", 10)
        .in_session(&door)
        .run_with_telemetry()
        .expect_err("a run whose room flipped under it must be refused, not published");
    assert_eq!(
        error.kind(),
        ErrorKind::OffRecordOverlayLeaseClosed,
        "the refusal is the stale-route family, naming the mode epoch the room replaced"
    );
    assert_eq!(
        vault.retrieval_runs(64)?.len(),
        base_runs_before,
        "and nothing the room asked about reaches the durable base ledger"
    );
    Ok(())
}

/// The same boundary, overlay direction — and the never-log-and-continue rule.
///
/// A run admitted OFF record stages into the room. A flip to on record SEALS
/// the overlay, so the staged registration cannot land. The retrieval must
/// FAIL: returning a successful pack would hand the caller results whose run
/// row is absent from the session-local set close consumes, which is the one
/// outcome the settle contract forbids outright.
#[test]
fn a_rooms_failed_run_registration_sinks_the_retrieval() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    seed_recallable_base_turn(&vault, "armbsealedneedle");
    let session = vault
        .off_record_session_vault()
        .enter("sess-armb-sealed", OffRecordBackendClass::Local)?;

    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;
    session.flip_on_record()?;

    let base_runs_before = vault.retrieval_runs(64)?.len();
    let error = vault
        .query()
        .search_text("armbsealedneedle", 10)
        .in_session(&door)
        .run_with_telemetry()
        .expect_err("a room's retrieval whose registration cannot land must fail");
    assert_eq!(
        error.kind(),
        ErrorKind::OffRecordOverlayLeaseClosed,
        "the refusal is the stale-route family"
    );
    assert_eq!(
        vault.retrieval_runs(64)?.len(),
        base_runs_before,
        "a refused room registration never falls back to the base ledger"
    );
    Ok(())
}

/// A facade and a session are independent borrows, so nothing in the types
/// stops safe code from pairing a facade on vault A with a room on vault B.
/// That pairing would read A while staging A's run row and `result_ids` into
/// B's overlay, and derive B's room seeds for A's pack. The binding is checked
/// by STORE IDENTITY, the same seam the executor binding uses, before any read
/// or write.
#[test]
fn recall_in_session_refuses_a_room_from_another_vault() -> Result<()> {
    let (_tmp_a, vault_a) = temp_vault();
    let (_tmp_b, vault_b) = temp_vault();
    let actor = seed_recallable_base_turn(&vault_a, "armbcrossvaultneedle");
    let stranger = vault_b
        .off_record_session_vault()
        .enter("sess-armb-cross", OffRecordBackendClass::Local)?;

    let error = vault_a
        .memory(actor, EdgeActorClass::Human)
        .recall_in_session(
            &stranger,
            "armbcrossvaultneedle",
            crate::memory::Effort::Standard,
            &crate::memory::RecallScope::default(),
            10,
            None,
            None,
        )
        .expect_err("a facade must refuse a room that belongs to another vault");
    assert_eq!(error.code, crate::memory::MEMORY_CODE_BAD_REQUEST);

    let stranger_runs = {
        let view = stranger.read_view()?;
        let rtxn = vault_b.store.env.read_txn()?;
        view.retrieval_runs_in_txn(&rtxn, 64)?
    };
    assert!(
        stranger_runs.is_empty(),
        "the refusal lands BEFORE any write: the other vault's room holds none of this \
         retrieval's telemetry"
    );
    Ok(())
}

#[test]
fn post_flip_emit_receipt_routes_on_record_and_survives_close() {
    let (_tmp, vault) = temp_vault();
    let session = vault
        .off_record_session_vault()
        .enter("sess-post-flip", OffRecordBackendClass::Local)
        .expect("enter");
    let r1 = crate::receipt::outbound_intent_receipt(
        "r1",
        "i1",
        &OutboundIntent::from_trigger(
            OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com"),
            OutboundIntentTrigger::agent_immediate("intent:r1"),
        ),
        100,
        "delivered_to_channel",
    );
    let r2 = crate::receipt::outbound_intent_receipt(
        "r2",
        "i2",
        &OutboundIntent::from_trigger(
            OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com"),
            OutboundIntentTrigger::agent_immediate("intent:r2"),
        ),
        100,
        "delivered_to_channel",
    );
    session.record_emit_receipt(r1).expect("record r1");
    session.flip_on_record().expect("flip on record");
    session.record_emit_receipt(r2.clone()).expect("record r2");
    let outcome = session.close().expect("close");
    assert_eq!(outcome.emit_receipts_deleted, 1);
    assert_eq!(outcome.emit_receipts_retained, vec![r2]);
}

#[test]
fn off_record_emit_receipts_still_evaporate_at_close() {
    let (_tmp, vault) = temp_vault();
    let session = vault
        .off_record_session_vault()
        .enter("sess-evaporate", OffRecordBackendClass::Local)
        .expect("enter");
    for id in ["r1", "r2"] {
        session
            .record_emit_receipt(crate::receipt::outbound_intent_receipt(
                id,
                id,
                &OutboundIntent::from_trigger(
                    OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com"),
                    OutboundIntentTrigger::agent_immediate(format!("intent:{id}")),
                ),
                100,
                "delivered_to_channel",
            ))
            .expect("record receipt");
    }
    let outcome = session.close().expect("close");
    assert_eq!(outcome.emit_receipts_deleted, 2);
    assert!(outcome.emit_receipts_retained.is_empty());
}

#[test]
fn flip_back_to_off_record_makes_new_emits_deletable_again() {
    let (_tmp, vault) = temp_vault();
    let session = vault
        .off_record_session_vault()
        .enter("sess-flip-back", OffRecordBackendClass::Local)
        .expect("enter");
    let receipt = |id: &str| {
        crate::receipt::outbound_intent_receipt(
            id,
            id,
            &OutboundIntent::from_trigger(
                OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com"),
                OutboundIntentTrigger::agent_immediate(format!("intent:{id}")),
            ),
            100,
            "delivered_to_channel",
        )
    };
    session.flip_on_record().expect("flip on record");
    let r1 = receipt("r1");
    session.record_emit_receipt(r1.clone()).expect("record r1");
    session.flip_off_record().expect("flip off record");
    session
        .record_emit_receipt(receipt("r2"))
        .expect("record r2");
    let outcome = session.close().expect("close");
    assert_eq!(outcome.emit_receipts_deleted, 1);
    assert_eq!(outcome.emit_receipts_retained, vec![r1]);
}
