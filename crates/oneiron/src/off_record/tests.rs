use super::*;
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::edge::EdgeKind;
use crate::error::{Error, ErrorKind, OffRecordError};
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
    let vault = Vault::open(tmp.path(), telemetry_config()).expect("open vault");
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
    let vault = Vault::open(tmp.path(), telemetry_config())?;
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

    let reopened = Vault::open(tmp.path(), telemetry_config())?;
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
        Error::OffRecord(OffRecordError::OffRecordTaintedBaseWrite { entity_ref }) if entity_ref == id.to_hex()
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
    let owner = crate::test_util::embedded_owner_proof(&vault);
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

    session.flip_on_record_as(&owner)?;
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
    let owner = crate::test_util::embedded_owner_proof(&vault);
    vault
        .enter_off_record_session("sess-talk", OffRecordBackendClass::RemoteProvider)
        .expect("enter");

    let error = OutboundDispatchPipeline
        .dispatch(&vault, talk_only_request("sess-talk"), &mut PanicSink)
        .expect_err("in-mode outbound must be rejected");
    match error {
        OutboundDispatchError::Engine(Error::OffRecord(OffRecordError::OffRecordTalkOnly {
            session_ref,
        })) => {
            assert_eq!(session_ref, "sess-talk");
        }
        other => panic!("expected OffRecordTalkOnly, got {other:?}"),
    }

    // Flipped back on-record the rejection lifts, and the OF-333 floor
    // classifies the egress (gate decision = persistent floor receipt).
    vault
        .off_record_session_vault()
        .bind("sess-talk")
        .expect("bind")
        .flip_on_record_as(&owner)
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
    let owner = crate::test_util::embedded_owner_proof(&vault);
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
        .promote_turn_as(&owner, &room_member)
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
    let flip = session
        .flip_on_record_as(&owner)
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
/// trailing `DerivedFrom` edge naming a second live room's overlay member.
/// It lands AFTER the shell, turn,
/// message, and summary puts have already staged rows, so zero base delta
/// afterwards is evidence of the single-transaction contract, not of an early
/// bail. The unmodified closure then promotes cleanly, proving a failed
/// promote leaves the journal and overlay rows intact.
#[test]
fn promote_replay_refuses_another_live_rooms_overlay_id_and_rolls_back() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let owner = crate::test_util::embedded_owner_proof(&vault);
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
            kind: EdgeKind::DerivedFrom,
            tgt: foreign,
            weight: 1.0,
            created_at: 1000,
            vad: crate::affect::Vad::NEUTRAL,
        });
    // Fail on the FIRST replay op: the builder's copied Put bodies are still
    // queued, so iterator teardown must scrub them without consuming them.
    overreaching.ops.rotate_right(1);
    let initiator = crate::off_record::PromoteInitiator::owner(&vault, &owner).unwrap();
    let early_refusal = crate::session_overlay::hygiene_tests::observe_replay_copy(|| {
        vault.with_write_txn(|wtxn| {
            FloorWrites::new(&vault.store).promote(
                &vault,
                wtxn,
                "sess-grant-scope",
                &overreaching,
                &initiator,
                2000,
            )
        })
    })
    .expect_err("foreign room reference before replay puts must fail");
    assert_eq!(early_refusal.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    overreaching.ops.rotate_left(1);
    let refusal = crate::session_overlay::hygiene_tests::observe_replay_copy(|| {
        vault.with_write_txn(|wtxn| {
            FloorWrites::new(&vault.store).promote(
                &vault,
                wtxn,
                "sess-grant-scope",
                &overreaching,
                &initiator,
                2000,
            )
        })
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
    let outcome = crate::session_overlay::hygiene_tests::observe_replay_copy(|| {
        session.promote_turn_as(&owner, &turn)
    })?;
    assert_eq!(
        outcome.replayed.len(),
        4,
        "the rejected promote left the journal closure intact"
    );
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(vault.store.entities.len(&rtxn)? - entities_before, 4);
        // ONE-1767 F2: each promoted turn closure also replays its ChildOf
        // edge, and ARCH-0052 #d4 its message's AuthoredBy edge.
        assert_eq!(vault.store.edges_out.len(&rtxn)? - edges_before, 5);
    }
    other.close()?;
    session.close()?;
    Ok(())
}

/// ARCH-0052 #d4 (REV-9 item 5): promote keeps each message's `AuthoredBy`
/// edge. When base no longer holds the actor, the edge would dangle, so the
/// promote refuses with a typed error and writes nothing.
#[test]
fn promote_refuses_a_turn_whose_author_left_base() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let owner = crate::test_util::embedded_owner_proof(&vault);
    let session = vault
        .off_record_session_vault()
        .enter("sess-author-gone", OffRecordBackendClass::Local)?;
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"departing author",
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
                    content: "authored in the room".to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: 1000,
            },
            None,
        )
        .unwrap_or_else(|error| panic!("session witness failed: {error:?}"));
    let turn = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .ok_or(Error::InvariantViolation("witness receipt names no turn"))?,
    )?;
    vault.delete_entity_with_reason(&actor, crate::DeleteReason::UserHardDelete)?;
    let entities_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.entities.len(&rtxn)?
    };

    let refusal = session
        .promote_turn_as(&owner, &turn)
        .expect_err("a dangling author edge must not promote");
    assert_eq!(refusal.kind(), ErrorKind::OffRecordPromoteAuthorMissing);
    assert!(vault.off_record_promote_receipt(&turn)?.is_none());
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(vault.store.entities.len(&rtxn)?, entities_before);
    drop(rtxn);
    session.close()?;
    Ok(())
}

/// A PERSON who speaks in a stretch alone with the owner; nobody's owner.
fn solo_speaker(vault: &Vault) -> Result<EntityId> {
    let speaker = EntityId::now();
    vault.put_entity(
        &speaker,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"solo speaker",
    )?;
    Ok(speaker)
}

/// Witnesses `content` into `session` as `speaker` at `at`; its turn.
fn said_alone(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    speaker: EntityId,
    content: &str,
    at: u64,
) -> Result<EntityId> {
    let receipt = vault
        .memory(speaker, EdgeActorClass::Human)
        .witness_into_session(
            session,
            &crate::memory::WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: None,
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "utterance".to_owned(),
                    content: content.to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: at,
            },
            None,
        )
        .unwrap_or_else(|error| panic!("session witness failed: {error:?}"));
    EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .ok_or(Error::InvariantViolation("witness receipt names no turn"))?,
    )
}

fn base_entities(vault: &Vault) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    vault.store.entities.len(&rtxn)
}

/// H203 (security scan, W2-T6): a stretch alone with its owner goes on
/// record, and a turn of it into this vault, only on the owner's proof. The
/// vault door that names a stretch by its ref, which any holder of the string
/// has, refuses the flip, typed; the promoted turn's receipt names who
/// consented. (A session handle has no door without a proof: see the
/// `compile_fail` examples on `OffRecordSession::promote_turn_as`.)
#[test]
fn a_solo_stretch_goes_on_record_and_promotes_only_on_the_owners_proof() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let owner = crate::test_util::embedded_owner_proof(&vault);
    let session = vault
        .off_record_session_vault()
        .enter("sess-solo-consent", OffRecordBackendClass::Local)?;
    let refused = vault
        .set_off_record_session_mode("sess-solo-consent", OffRecordMode::OnRecord)
        .expect_err("a flip by session ref carries no proof");
    assert_eq!(refused.kind(), ErrorKind::OffRecordPromoteUnauthenticated);
    assert_eq!(session.mode()?, OffRecordMode::OffRecord);

    let speaker = solo_speaker(&vault)?;
    let turn = said_alone(
        &vault,
        &session,
        speaker,
        "said alone, off the record",
        1000,
    )?;
    let outcome = session.promote_turn_as(&owner, &turn)?;
    let kept = vault
        .off_record_promote_receipt(&turn)?
        .expect("a promoted turn keeps its receipt");
    assert_eq!(kept.initiator_ref, owner.actor().to_hex());
    assert_eq!(
        kept.initiator_kind,
        crate::off_record::PROMOTE_INITIATOR_OWNER
    );
    assert_eq!(kept.outcome, outcome);

    // The owner's own flip puts the stretch on record.
    session.flip_on_record_as(&owner)?;
    assert_eq!(session.mode()?, OffRecordMode::OnRecord);
    session.close()?;
    Ok(())
}

/// H203 (Sol R1 F1): a live person's proof is not the owner's. Alone with
/// its owner, a stretch's turns land in this vault, so another person's proof
/// neither promotes a turn, nor reads the answer a promoted turn keeps, nor
/// puts the stretch on record, and nothing is written. The owner's own proof
/// still promotes.
#[test]
fn a_solo_stretch_refuses_a_proof_that_is_not_the_owners() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let owner = crate::test_util::embedded_owner_proof(&vault);
    let session = vault
        .off_record_session_vault()
        .enter("sess-solo-stranger", OffRecordBackendClass::Local)?;
    let speaker = solo_speaker(&vault)?;
    let stranger =
        vault.authenticate_owner(speaker, &speaker.to_hex(), true, GateDecisionId::now())?;
    let turn = said_alone(
        &vault,
        &session,
        speaker,
        "said alone, off the record",
        1000,
    )?;
    let entities_before = base_entities(&vault)?;

    let refused = session
        .promote_turn_as(&stranger, &turn)
        .expect_err("a stranger's proof promotes nothing");
    assert_eq!(refused.kind(), ErrorKind::ConsentOwnerNotAuthenticated);
    let refused = session
        .flip_on_record_as(&stranger)
        .expect_err("a stranger's proof puts nothing on record");
    assert_eq!(refused.kind(), ErrorKind::ConsentOwnerNotAuthenticated);
    assert_eq!(session.mode()?, OffRecordMode::OffRecord);
    assert!(vault.off_record_promote_receipt(&turn)?.is_none());
    assert_eq!(base_entities(&vault)?, entities_before);

    let outcome = session.promote_turn_as(&owner, &turn)?;
    let refused = session
        .promote_turn_as(&stranger, &turn)
        .expect_err("a promoted turn's answer is the owner's");
    assert_eq!(refused.kind(), ErrorKind::ConsentOwnerNotAuthenticated);
    assert_eq!(session.promote_turn_as(&owner, &turn)?, outcome);
    session.close()?;
    Ok(())
}

/// H203 (Sol R1 F2): alone, as in a room, a stretch on record saves into this
/// vault only while its owner's proof holds. Once the owner is gone, the next
/// turn stays off record, base takes nothing, and the stretch is off record
/// again.
#[test]
fn a_solo_stretch_on_record_stops_saving_once_its_owners_proof_lapses() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let owner = crate::test_util::embedded_owner_proof(&vault);
    let session = vault
        .off_record_session_vault()
        .enter("sess-solo-lapse", OffRecordBackendClass::Local)?;
    let speaker = solo_speaker(&vault)?;
    session.flip_on_record_as(&owner)?;
    let saved = said_alone(&vault, &session, speaker, "said on record", 1000)?;
    assert!(
        vault.get_raw(&saved)?.is_some(),
        "a turn on record lands in base"
    );

    // A plain delete keeps the PERSON shell; the proof no longer holds.
    assert!(vault.delete_entity(&owner.actor())?);
    let entities_before = base_entities(&vault)?;
    let unsaved = said_alone(
        &vault,
        &session,
        speaker,
        "said once the owner is gone",
        2000,
    )?;
    assert!(
        vault.get_raw(&unsaved)?.is_none(),
        "base took a turn with no saver"
    );
    assert_eq!(base_entities(&vault)?, entities_before);
    assert_eq!(session.mode()?, OffRecordMode::OffRecord);
    session.close()?;
    Ok(())
}

// ─── ONE-1570 Arm B — retrieval-run context receipts follow the transcript ──

/// Seeds base content the room can retrieve, through the production witness
/// door so the text is really BM25-indexed. The vault's owner witnesses it
/// and is returned.
fn seed_recallable_base_turn(vault: &Vault, needle: &str) -> EntityId {
    let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
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

/// ARCH-0052 D3 (REV-9 item 6): a room's PPR cache rows never reach base.
/// The off-record walk runs first; the same walk outside the room then shows
/// the walk does cache, so the first assertion is not vacuous.
#[test]
fn off_record_ppr_walk_leaves_no_cache_row_in_base() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = seed_recallable_base_turn(&vault, "offrecordpprneedle");
    let cache_rows = |vault: &Vault| -> Result<u64> {
        let txn = vault.store.env.read_txn()?;
        vault.store.ppr_cache.len(&txn)
    };
    let before = cache_rows(&vault)?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-ppr-cache", OffRecordBackendClass::Local)?;
    assert_eq!(session.mode()?, OffRecordMode::OffRecord);
    {
        let route = session.write_route()?;
        let telemetry = session.retrieval_telemetry(&route)?;
        let walked = vault
            .query()
            .search_ppr(&[actor], 2)
            .in_session(&telemetry)
            .run_with_pending_vectors()?;
        assert!(!walked.value.is_empty());
    }
    assert_eq!(
        cache_rows(&vault)?,
        before,
        "an off-record walk leaves no PPR cache row in base"
    );
    session.close()?;
    let walked = vault
        .query()
        .search_ppr(&[actor], 2)
        .run_with_pending_vectors()?;
    assert!(!walked.value.is_empty());
    assert!(
        cache_rows(&vault)? > before,
        "a base walk caches its result"
    );
    Ok(())
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
            crate::memory::Effort::Medium,
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
    let owner = crate::test_util::embedded_owner_proof(&vault);
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
            crate::memory::Effort::Medium,
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
    session.flip_on_record_as(&owner)?;
    let before = vault.retrieval_runs(64)?.len();
    facade
        .recall_in_session(
            &session,
            "armbcontrolneedle",
            crate::memory::Effort::Medium,
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
    let owner = crate::test_util::embedded_owner_proof(&vault);
    seed_recallable_base_turn(&vault, "armbstaleneedle");
    let session = vault
        .off_record_session_vault()
        .enter("sess-armb-stale", OffRecordBackendClass::Local)?;

    session.flip_on_record_as(&owner)?;
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
    let owner = crate::test_util::embedded_owner_proof(&vault);
    seed_recallable_base_turn(&vault, "armbsealedneedle");
    let session = vault
        .off_record_session_vault()
        .enter("sess-armb-sealed", OffRecordBackendClass::Local)?;

    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;
    session.flip_on_record_as(&owner)?;

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

/// ARCH-0052 D5 (drift E4): in a room on record, a retrieval's opt-in run
/// row lands in base only while the owner who put the room on record still
/// holds, as every other landing does. Once they left the room, the row is
/// refused in the transaction that would write it, nothing the room asked
/// about reaches the base ledger, and the saving stops.
#[test]
fn a_room_retrieval_publishes_no_run_once_its_saver_left() -> Result<()> {
    use crate::conversation::{ConversationBody, HistoryChoice};

    let (_tmp, vault) = temp_vault();
    seed_recallable_base_turn(&vault, "saverleftneedle");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let by = crate::WriteActor::new(owner, EdgeActorClass::Human);
    let room = EntityId::now();
    vault.create_conversation(room, &ConversationBody::default(), by, 1)?;
    vault.join_member(room, owner, by, 2, HistoryChoice::Share)?;
    let session = vault.off_record_session_vault().enter_in_room(
        "lamp",
        OffRecordBackendClass::Local,
        room,
        owner,
    )?;
    let proof =
        vault.authenticate_owner(owner, "principal:room-owner", true, GateDecisionId::now())?;
    session.flip_on_record_as(&proof)?;
    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;
    vault.leave_member(room, owner, by, 50)?;

    let base_runs_before = vault.retrieval_runs(64)?.len();
    let error = vault
        .query()
        .search_text("saverleftneedle", 10)
        .in_session(&door)
        .run_with_telemetry()
        .expect_err("a room whose saver left publishes no run");
    assert!(
        matches!(
            error,
            Error::OffRecord(OffRecordError::OffRecordSavingStopped { .. })
        ),
        "{error:?}"
    );
    assert_eq!(vault.retrieval_runs(64)?.len(), base_runs_before);
    drop(door);
    assert_eq!(session.mode()?, OffRecordMode::OffRecord);
    Ok(())
}

/// ARCH-0052 D5 (drift E4): a retrieval in a room on record queues embed
/// jobs for the base rows it surfaced only while its saver holds, as every
/// other landing does. Capture is off (the default), so no run row checks
/// the saver first: the enqueue's own transaction refuses.
#[cfg(feature = "sync")]
#[test]
fn a_room_retrieval_queues_no_embed_job_once_its_saver_left() -> Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::conversation::{ConversationBody, HistoryChoice};

    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    // A claim owes its vector from the write that put it.
    let claim = EntityId::now();
    let body = ClaimBody::new(
        "test.status",
        ClaimSubject::Entity(EntityId::from_bytes([0x7C; 16]).expect("subject id")),
        rmpv::Value::from("v"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    vault
        .batch()
        .put(
            &claim,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::claim::encode_claim_body(&body)?,
        )
        .text(&claim, &[("body", "saverleftembedneedle")])
        .commit()?;
    let take_job = || {
        vault.with_write_txn(|wtxn| {
            crate::sync::queue::delete_embed_job_in_txn(&vault.store, wtxn, &claim)
        })
    };
    // Outside any room, the search that surfaces it queues its job.
    let surfaced = vault
        .query()
        .search_text("saverleftembedneedle", 10)
        .run_with_pending_vectors()?;
    assert_eq!(surfaced.pending_vector_ids, vec![claim]);
    assert!(take_job()?);

    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let by = crate::WriteActor::new(owner, EdgeActorClass::Human);
    let room = EntityId::now();
    vault.create_conversation(room, &ConversationBody::default(), by, 1)?;
    vault.join_member(room, owner, by, 2, HistoryChoice::Share)?;
    let session = vault.off_record_session_vault().enter_in_room(
        "lamp",
        OffRecordBackendClass::Local,
        room,
        owner,
    )?;
    let proof =
        vault.authenticate_owner(owner, "principal:room-owner", true, GateDecisionId::now())?;
    session.flip_on_record_as(&proof)?;
    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;
    vault.leave_member(room, owner, by, 50)?;

    let error = vault
        .query()
        .search_text("saverleftembedneedle", 10)
        .in_session(&door)
        .run_with_pending_vectors()
        .expect_err("a room whose saver left queues no embed job");
    assert!(
        matches!(
            error,
            Error::OffRecord(OffRecordError::OffRecordSavingStopped { .. })
        ),
        "{error:?}"
    );
    assert!(
        !take_job()?,
        "the room queued an embed job after its saver left"
    );
    drop(door);
    assert_eq!(session.mode()?, OffRecordMode::OffRecord);
    Ok(())
}

/// The same retrieval reading the room, which holds a message of its own.
/// Base keeps no embed job of a run that read the room's rows, and with
/// capture off no run row lands either. The saver those jobs would have
/// landed under must still hold: the run is refused, and the saving stops.
#[cfg(feature = "sync")]
#[test]
fn a_room_read_that_keeps_its_embed_jobs_out_still_stops_once_its_saver_left() -> Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};

    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    // A claim owes its vector from the write that put it.
    let claim = EntityId::now();
    let body = ClaimBody::new(
        "test.status",
        ClaimSubject::Entity(EntityId::from_bytes([0x7C; 16]).expect("subject id")),
        rmpv::Value::from("v"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    vault
        .batch()
        .put(
            &claim,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::claim::encode_claim_body(&body)?,
        )
        .text(&claim, &[("body", "saverleftroomreadneedle")])
        .commit()?;
    let (room, by, _agent, session) = a_room_on_record_with_an_unsaved_message(&vault)?;
    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;
    vault.leave_member(room, by.entity_ref(), by, 50)?;

    let view = session.read_view()?;
    let error = vault
        .query()
        .search_text("saverleftroomreadneedle", 10)
        .in_session(&door)
        .reading(view.read())
        .run_with_pending_vectors()
        .expect_err("a room whose saver left lands nothing of the run");
    assert!(
        matches!(
            error,
            Error::OffRecord(OffRecordError::OffRecordSavingStopped { .. })
        ),
        "{error:?}"
    );
    drop(view);
    drop(door);
    assert_eq!(session.mode()?, OffRecordMode::OffRecord);
    Ok(())
}

/// A room holding the vault's owner and an agent, with one message nobody
/// saved in its stretch, which the owner has then put on record. Answers the
/// room, the owner and the agent a run acts as.
fn a_room_on_record_with_an_unsaved_message(
    vault: &Vault,
) -> Result<(
    EntityId,
    crate::WriteActor,
    crate::WriteActor,
    OffRecordSession<'_>,
)> {
    use crate::conversation::{ConversationBody, HistoryChoice};

    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let by = crate::WriteActor::new(owner, EdgeActorClass::Human);
    let agent = EntityId::now();
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"room agent",
    )?;
    let room = EntityId::now();
    vault.create_conversation(room, &ConversationBody::default(), by, 1)?;
    vault.join_member(room, owner, by, 2, HistoryChoice::Share)?;
    vault.join_member(room, agent, by, 3, HistoryChoice::Share)?;
    let session = vault.off_record_session_vault().enter_in_room(
        "lamp",
        OffRecordBackendClass::Local,
        room,
        owner,
    )?;
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness_into_session_as_member(
            &session,
            &crate::memory::WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: None,
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "utterance".to_owned(),
                    content: "unsavedlanternneedle".to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: 10,
            },
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("the room hears the message: {error:?}"));
    let proof =
        vault.authenticate_owner(owner, "principal:room-owner", true, GateDecisionId::now())?;
    session.flip_on_record_as(&proof)?;
    Ok((
        room,
        by,
        crate::WriteActor::new(agent, EdgeActorClass::Agent),
        session,
    ))
}

/// A search for the message nobody saved.
fn search_for_the_unsaved_message() -> crate::code_run::SelfCall {
    crate::code_run::SelfCall::MemorySearch(crate::code_run::SelfMemorySearchCall::new(
        "unsavedlanternneedle",
        5,
    ))
}

/// ARCH-0052 D5 (drift E4; Codex burn engine-prs-02): with capture on, a
/// run bound in a room on record searches the room, and the search matches a
/// message nobody saved. Once the saver has left, the run row that would
/// name it is refused in the transaction that would write it, so neither the
/// search nor the close leaves a trace of it in base, and the saving stops.
#[test]
fn a_bound_runs_search_leaves_no_base_trace_once_the_saver_left() -> Result<()> {
    use crate::code_run::{HostSelfDispatcher, SelfDispatcher};

    let (_tmp, vault) = temp_vault();
    let (room, by, agent, session) = a_room_on_record_with_an_unsaved_message(&vault)?;
    let dispatcher = HostSelfDispatcher::for_off_record_session(&session, agent, "lamp-run")?;
    vault.leave_member(room, by.entity_ref(), by, 50)?;

    let base_runs_before = vault.retrieval_runs(64)?.len();
    let error = dispatcher
        .dispatch(search_for_the_unsaved_message())
        .expect_err("a room whose saver left publishes no run");
    assert!(
        matches!(
            error,
            Error::OffRecord(OffRecordError::OffRecordSavingStopped { .. })
        ),
        "{error:?}"
    );
    drop(dispatcher);
    assert_eq!(session.mode()?, OffRecordMode::OffRecord);
    session.close()?;
    assert_eq!(vault.retrieval_runs(64)?.len(), base_runs_before);
    Ok(())
}

/// Astra #1392, P1: the saver was checked against the room's roster now, not
/// against the membership they put the room on record in. A saver who left
/// and joined again, with no new "from here on", revived the old saving: a
/// run bound before they left published its search of an unsaved message in
/// base. Leaving ends the saving for good, so the search is refused and the
/// stretch is back off record.
#[test]
fn a_saver_who_left_and_joined_again_does_not_revive_the_saving() -> Result<()> {
    use crate::code_run::{HostSelfDispatcher, SelfDispatcher};
    use crate::conversation::HistoryChoice;

    let (_tmp, vault) = temp_vault();
    let (room, by, agent, session) = a_room_on_record_with_an_unsaved_message(&vault)?;
    let dispatcher = HostSelfDispatcher::for_off_record_session(&session, agent, "lamp-run")?;
    vault.leave_member(room, by.entity_ref(), by, 50)?;
    vault.join_member(room, by.entity_ref(), by, 55, HistoryChoice::Share)?;

    let base_runs_before = vault.retrieval_runs(64)?.len();
    let error = dispatcher
        .dispatch(search_for_the_unsaved_message())
        .expect_err("saving that stopped publishes no run");
    assert!(
        matches!(
            error,
            Error::OffRecord(OffRecordError::OffRecordSavingStopped { .. })
        ),
        "{error:?}"
    );
    drop(dispatcher);
    assert_eq!(session.mode()?, OffRecordMode::OffRecord);
    session.close()?;
    assert_eq!(vault.retrieval_runs(64)?.len(), base_runs_before);
    Ok(())
}

/// Astra #1392, P1: a run bound in a room on record still forwarded
/// `self.memory.<verb>` through its host's verb door, which runs on the
/// canonical vault and checks neither the run's route nor the room's saver.
/// Once the saver had left, a forwarded recall still published its run in
/// base, past every landing the session checks. A session-bound run now
/// forwards no verb, read or write; the door is never called.
#[test]
fn a_room_bound_run_forwards_no_verb_once_the_saver_left() -> Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::code_run::{
        AGENT_VERB_SESSION_BOUND, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher,
        SelfAgentVerbCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome, SelfDispatcher,
        SelfEffect,
    };
    use crate::conversation::{ConversationBody, HistoryChoice};

    /// A host's verb door reduced to recall, run on the canonical memory
    /// surface under the origin the dispatcher hands it.
    struct RecallDoor {
        vault: Arc<Vault>,
        actor: EntityId,
        calls: AtomicUsize,
    }

    impl RecallDoor {
        fn answer(
            &self,
            call: &SelfAgentVerbCall,
            origin: &crate::memory::HostWriteOrigin,
        ) -> std::result::Result<crate::code_run::AgentVerbAnswer, AgentVerbRefusal> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let refused = |_| AgentVerbRefusal {
                code: "engine_error".to_owned(),
            };
            self.vault
                .memory(self.actor, EdgeActorClass::Human)
                .with_host_origin(origin.clone())
                .recall(
                    call.input["query"].as_str().unwrap_or_default(),
                    crate::memory::Effort::Medium,
                    &crate::memory::RecallScope::default(),
                    10,
                    None,
                    None,
                )
                .map_err(refused)?;
            Ok(crate::code_run::AgentVerbAnswer {
                output: serde_json::json!({"recalled": true}),
                rows: Some(Vec::new()),
            })
        }
    }

    impl AgentVerbDoor for RecallDoor {
        fn call(
            &self,
            call: &SelfAgentVerbCall,
            origin: &crate::memory::HostWriteOrigin,
            _: crate::runtime_hooks::InvocationId,
        ) -> crate::Result<std::result::Result<crate::code_run::AgentVerbAnswer, AgentVerbRefusal>>
        {
            Ok(self.answer(call, origin))
        }

        fn admit_run_call(
            &self,
            _: crate::code_run::RunCall,
        ) -> std::result::Result<Option<crate::claim::ScopedReadActorKey>, AgentVerbRefusal>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
    }

    let (_tmp, vault) = temp_vault();
    let vault = Arc::new(vault);
    let reader = seed_recallable_base_turn(&vault, "forwardedlanternneedle");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let by = crate::WriteActor::new(owner, EdgeActorClass::Human);
    // The run acts as an agent who stays: a run whose own participant left
    // is refused `NotInRoom` before any effect (Codex burn engine-prs-01).
    let agent = EntityId::now();
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"room agent",
    )?;
    let room = EntityId::now();
    vault.create_conversation(room, &ConversationBody::default(), by, 1)?;
    vault.join_member(room, owner, by, 2, HistoryChoice::Share)?;
    vault.join_member(room, agent, by, 3, HistoryChoice::Share)?;
    let session = vault.off_record_session_vault().enter_in_room(
        "lamp-door",
        OffRecordBackendClass::Local,
        room,
        owner,
    )?;
    let proof =
        vault.authenticate_owner(owner, "principal:room-owner", true, GateDecisionId::now())?;
    session.flip_on_record_as(&proof)?;
    let door = Arc::new(RecallDoor {
        vault: Arc::clone(&vault),
        actor: reader,
        calls: AtomicUsize::new(0),
    });
    let dispatcher = HostSelfDispatcher::for_off_record_session(
        &session,
        crate::WriteActor::new(agent, EdgeActorClass::Agent),
        "lamp-door-run",
    )?
    .with_agent_verb_door(door.clone());
    vault.leave_member(room, owner, by, 50)?;

    let base_runs_before = vault.retrieval_runs(64)?.len();
    let answer = dispatcher.dispatch(SelfCall::AgentVerb(SelfAgentVerbCall {
        verb: crate::task_verb::sdk::AgentVerb::Recall,
        input: serde_json::json!({"query": "forwardedlanternneedle"}),
    }))?;
    assert_eq!(
        answer,
        SelfDispatchOutcome::Denied(SelfDeniedResult {
            effect: SelfEffect::AgentVerb,
            outcome: AGENT_VERB_SESSION_BOUND.to_owned(),
            reason_codes: Vec::new(),
        })
    );
    assert_eq!(door.calls.load(Ordering::SeqCst), 0, "the door never runs");
    assert_eq!(vault.retrieval_runs(64)?.len(), base_runs_before);
    drop(dispatcher);
    session.close()?;
    assert_eq!(vault.retrieval_runs(64)?.len(), base_runs_before);
    Ok(())
}

/// Review repro (burn code-mode-door, on merging #1392): a run bound to an
/// off-record session whose host door narrows its search to a reader's lane
/// failed that search as a host fault, since a room's hits include overlay
/// rows no lane can name: the guest got no typed answer and the bridge kept
/// no row for the call. The search is now refused as the run's verb forwards
/// are.
#[test]
fn a_session_bound_run_refuses_a_search_its_door_narrows() -> Result<()> {
    use std::sync::Arc;

    use crate::code_run::{
        AGENT_VERB_DOOR_UNBOUND, AGENT_VERB_SESSION_BOUND, AgentVerbDoor, AgentVerbRefusal,
        HostSelfDispatcher, RunCall, SelfAgentVerbCall, SelfCall, SelfDeniedResult,
        SelfDispatchOutcome, SelfDispatcher, SelfEffect, SelfMemorySearchCall,
    };

    /// A host door that admits a run's search on one reader's lane.
    struct NarrowingDoor;

    impl AgentVerbDoor for NarrowingDoor {
        fn call(
            &self,
            _: &SelfAgentVerbCall,
            _: &crate::memory::HostWriteOrigin,
            _: crate::runtime_hooks::InvocationId,
        ) -> crate::Result<std::result::Result<crate::code_run::AgentVerbAnswer, AgentVerbRefusal>>
        {
            Ok(Err(AgentVerbRefusal {
                code: AGENT_VERB_DOOR_UNBOUND.to_owned(),
            }))
        }

        fn admit_run_call(
            &self,
            _: RunCall,
        ) -> std::result::Result<Option<crate::claim::ScopedReadActorKey>, AgentVerbRefusal>
        {
            Ok(crate::claim::ScopedReadActorKey::new("reader-lane"))
        }
    }

    let (_tmp, vault) = temp_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let by = crate::WriteActor::new(owner, EdgeActorClass::Human);
    let session = vault
        .off_record_session_vault()
        .enter("lane-door", OffRecordBackendClass::Local)?;
    let dispatcher = HostSelfDispatcher::for_off_record_session(&session, by, "lane-door-run")?
        .with_agent_verb_door(Arc::new(NarrowingDoor));
    let answer = dispatcher.dispatch(SelfCall::MemorySearch(SelfMemorySearchCall::new(
        "lantern", 4,
    )))?;
    assert_eq!(
        answer,
        SelfDispatchOutcome::Denied(SelfDeniedResult {
            effect: SelfEffect::MemorySearch,
            outcome: AGENT_VERB_SESSION_BOUND.to_owned(),
            reason_codes: Vec::new(),
        })
    );
    drop(dispatcher);
    session.close()?;
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
            crate::memory::Effort::Medium,
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
    let owner = crate::test_util::embedded_owner_proof(&vault);
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
    session.flip_on_record_as(&owner).expect("flip on record");
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
    let owner = crate::test_util::embedded_owner_proof(&vault);
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
    session.flip_on_record_as(&owner).expect("flip on record");
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

// Inspect stored rows, not internal counters: even an in-place overwrite or a
// row written under an unknown generated id must fail the no-retention law.
type AnonymousRows = Vec<(Vec<u8>, Vec<u8>)>;

fn anonymous_base_rows(vault: &Vault) -> Result<Vec<AnonymousRows>> {
    let txn = vault.store.env.read_txn()?;
    let mut tables = Vec::new();
    for db in [
        &vault.store.entities,
        &vault.store.edges_out,
        &vault.store.edges_in,
        &vault.store.vectors,
        &vault.store.hnsw_neighbors,
        &vault.store.hnsw_meta,
        &vault.store.text_postings,
        &vault.store.text_meta,
        &vault.store.text_forward,
        &vault.store.text_bm25_field_stats,
        &vault.store.text_doc_field_lengths,
        &vault.store.vault_meta,
        &vault.store.ppr_cache,
        &vault.store.ppr_cache_deps,
        &vault.store.type_index,
        &vault.store.temporal_occurred_start,
        &vault.store.temporal_occurred_end,
        &vault.store.temporal_learned,
        &vault.store.temporal_long_intervals,
        &vault.store.phonetic_index,
        &vault.store.phonetic_forward,
        &vault.store.short_ids,
        &vault.store.short_ids_reverse,
        &vault.store.sync_queue,
        &vault.store.attempt_records,
        &vault.store.attempt_ready,
        &vault.store.attempt_dedupe,
    ] {
        let mut rows = Vec::new();
        for row in db.iter(&txn)? {
            let (key, value) = row?;
            rows.push((key.to_vec(), value.to_vec()));
        }
        tables.push(rows);
    }
    let mut sync_rows = Vec::new();
    for row in vault.store.sync_state.iter(&txn)? {
        let (key, value) = row?;
        sync_rows.push((key.as_bytes().to_vec(), value.to_vec()));
    }
    tables.push(sync_rows);
    Ok(tables)
}

#[test]
fn anonymous_witness_read_and_close_retain_no_rows_or_receipts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let owner = crate::test_util::embedded_owner_proof(&vault);
    let actor = seed_recallable_base_turn(&vault, "anonymousbaseneedle");
    let before = anonymous_base_rows(&vault)?;
    let session = vault
        .off_record_session_vault()
        .enter_anonymous("sess-anonymous", OffRecordBackendClass::Local)?;
    assert_eq!(session.mode()?, OffRecordMode::Anonymous);
    let facade = vault.memory(actor, EdgeActorClass::Human);
    let message = EntityId::now();
    let turn = EntityId::now();
    let error = facade
        .witness_into_session(
            &session,
            &crate::memory::WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: Some(turn.to_hex()),
                messages: vec![crate::memory::WitnessMessage {
                    id: Some(message.to_hex()),
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "dialogue".to_owned(),
                    content: "anonymousprivateneedle".to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: 1600,
            },
            Some("anonymous private summary"),
        )
        .expect_err("anonymous cannot promise a materialized witness");
    assert_eq!(error.code, crate::memory::MEMORY_CODE_FORBIDDEN);
    assert!(session.get_raw(&message)?.is_none());
    assert!(session.get_raw(&turn)?.is_none());
    assert!(
        session
            .search_text("anonymousprivateneedle", 10)?
            .is_empty()
    );
    assert!(!session.search_text("anonymousbaseneedle", 10)?.is_empty());

    let route = session.write_route()?;
    let telemetry = session.retrieval_telemetry(&route)?;
    // Exercise the durable-cache and embed-enqueue paths as well as telemetry.
    let retrieved = vault
        .query()
        .search_ppr(&[actor], 2)
        .in_session(&telemetry)
        .run_with_pending_vectors()?;
    assert!(!retrieved.value.is_empty());
    assert!(retrieved.run_id.is_none());
    let pack = facade
        .recall_in_session(
            &session,
            "anonymousbaseneedle",
            crate::memory::Effort::Medium,
            &crate::memory::RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("anonymous read can return base context without retaining it");
    assert!(!pack.items.is_empty());
    assert_eq!(anonymous_base_rows(&vault)?, before);

    // The mode is immutable in both directions, not merely unpromotable.
    for mode in [OffRecordMode::OnRecord, OffRecordMode::OffRecord] {
        assert_eq!(
            vault
                .set_off_record_session_mode(session.session_ref(), mode)
                .expect_err("anonymous cannot switch to retention")
                .kind(),
            ErrorKind::OffRecordTalkOnly
        );
    }
    assert_eq!(
        session
            .promote_turn_as(&owner, &turn)
            .expect_err("cannot promote")
            .kind(),
        ErrorKind::OffRecordTalkOnly
    );
    assert!(vault.off_record_promote_receipt(&turn)?.is_none());
    assert_eq!(
        vault
            .off_record_receipt_log(session.session_ref())
            .expect_err("anonymous has no receipt log")
            .kind(),
        ErrorKind::OffRecordTalkOnly
    );
    let receipt = crate::receipt::outbound_intent_receipt(
        "anonymous-emit",
        "anonymous-intent",
        &talk_only_request(session.session_ref()).intent,
        1600,
        "delivered_to_channel",
    );
    assert_eq!(
        session
            .record_emit_receipt(receipt)
            .expect_err("anonymous cannot retain an emit receipt")
            .kind(),
        ErrorKind::OffRecordTalkOnly
    );
    let anon_rows: crate::side_table::SideTable<String, Vec<u8>, crate::side_table::Raw> =
        crate::side_table::SideTable::new(&crate::side_table::CODE_RUN_RAW_OUTPUT);
    let anon_tally: crate::side_table::SideTable<String, u64, crate::side_table::Raw> =
        crate::side_table::SideTable::new(&crate::side_table::CODE_RUN_HEAL_COUNT);
    let (raw_key, raw_value) = ("anon".to_owned(), b"private".to_vec());
    assert_eq!(
        session
            .side_table_put_routed(&route, &anon_rows, &raw_key, &raw_value)
            .expect_err("no raw output")
            .kind(),
        ErrorKind::OffRecordTalkOnly
    );
    assert_eq!(
        session
            .side_table_compare_and_put_routed(&route, &anon_rows, &raw_key, &raw_value, |_| Ok(()))
            .expect_err("no replay")
            .kind(),
        ErrorKind::OffRecordTalkOnly
    );
    assert_eq!(
        session
            .side_table_compare_and_put_with_counter_routed(
                &route,
                &anon_rows,
                &raw_key,
                &raw_value,
                |_| Ok(()),
                &anon_tally,
                &raw_key,
                |_, _, _| Ok((1, 1)),
            )
            .expect_err("no heal count")
            .kind(),
        ErrorKind::OffRecordTalkOnly
    );
    drop(telemetry);
    let outcome = session.close()?;
    assert_eq!(outcome.turns_deleted, 0);
    assert_eq!(outcome.context_receipts_deleted, 0);
    assert_eq!(outcome.emit_receipts_deleted, 0);
    assert_eq!(outcome.promoted_turns_kept, 0);
    assert!(outcome.emit_receipts_retained.is_empty());
    assert!(vault.off_record_session("sess-anonymous")?.is_none());
    assert_eq!(anonymous_base_rows(&vault)?, before);
    Ok(())
}

#[test]
fn anonymous_telemetry_never_falls_back_to_base_even_for_existing_run_ids() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    seed_recallable_base_turn(&vault, "anonymousledgerneedle");
    let existing = vault
        .query()
        .search_text("anonymousledgerneedle", 10)
        .run_with_telemetry()?
        .run_id
        .expect("canonical run persists");
    let before = vault.retrieval_run(existing)?.expect("base run");
    let session = vault
        .off_record_session_vault()
        .enter_anonymous("sess-anonymous-ledger", OffRecordBackendClass::Local)?;
    let route = session.write_route()?;
    let telemetry = session.retrieval_telemetry(&route)?;
    let mut candidate = before.clone();
    candidate.elapsed_us += 1;
    telemetry.register_run(&candidate, true)?;
    telemetry.finalize_run(crate::store::RetrievalRunFinalize {
        run_id: existing,
        elapsed_us: 999,
        total_in_scope: 0,
        claims_suppressed: 0,
        surfaced_result_ids: &[],
        empty_reason: None,
        pack_config: None,
    })?;
    telemetry.discard_run(existing)?;
    assert_eq!(vault.retrieval_run(existing)?, Some(before));
    candidate.run_id = crate::store::RetrievalRunId::now();
    telemetry.register_run(&candidate, false)?;
    telemetry.register_run(&candidate, true)?;
    assert!(vault.retrieval_run(candidate.run_id)?.is_none());
    {
        let view = session.read_view()?;
        let txn = vault.store.env.read_txn()?;
        assert!(
            view.retrieval_runs_in_txn(&txn, 64)?
                .iter()
                .all(|run| run.run_id != candidate.run_id)
        );
    }
    drop(telemetry);
    let outcome = session.close()?;
    assert_eq!(outcome.context_receipts_deleted, 0);
    Ok(())
}

#[test]
fn anonymous_audited_effects_refuse_before_creating_floor_receipts() -> Result<()> {
    use crate::code_run::{
        HostSelfDispatcher, SelfAskCall, SelfCall, SelfDispatcher, SelfFixtureEffectCall,
        SelfSpeechCall,
    };
    let (_tmp, vault) = temp_vault();
    let actor = seed_recallable_base_turn(&vault, "anonymousauditneedle");
    let before = anonymous_base_rows(&vault)?;
    let gates_before = vault.gate_decisions(64)?;
    let audits_before = vault.entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)?;
    let session = vault.off_record_session_vault().enter_anonymous(
        "sess-anonymous-audit",
        OffRecordBackendClass::RemoteProvider,
    )?;
    let dispatcher = HostSelfDispatcher::for_off_record_session(
        &session,
        crate::WriteActor::new(actor, EdgeActorClass::Human),
        "anonymous-run",
    )?;
    for call in [
        SelfCall::Ask(SelfAskCall::new("private prompt")),
        SelfCall::DestructiveFixture(SelfFixtureEffectCall {
            label: "private deletion".to_owned(),
        }),
        SelfCall::OutboundFixture(SelfFixtureEffectCall {
            label: "private outbound".to_owned(),
        }),
        SelfCall::Speak(SelfSpeechCall::new("private speech")),
    ] {
        assert_eq!(
            dispatcher
                .dispatch(call)
                .expect_err("mandatory retention refuses")
                .kind(),
            ErrorKind::OffRecordTalkOnly
        );
    }
    let error = OutboundDispatchPipeline
        .dispatch(
            &vault,
            talk_only_request(session.session_ref()),
            &mut PanicSink,
        )
        .expect_err("no audited egress in anonymous mode");
    assert!(matches!(
        error,
        OutboundDispatchError::Engine(Error::OffRecord(OffRecordError::OffRecordTalkOnly { .. }))
    ));
    assert_eq!(vault.gate_decisions(64)?, gates_before);
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)?,
        audits_before
    );
    assert_eq!(anonymous_base_rows(&vault)?, before);
    drop(dispatcher);
    session.close()?;
    assert_eq!(anonymous_base_rows(&vault)?, before);

    let ordinary = vault.off_record_session_vault().enter(
        "sess-ordinary-cannot-be-anonymous",
        OffRecordBackendClass::Local,
    )?;
    assert_eq!(
        vault
            .set_off_record_session_mode(ordinary.session_ref(), OffRecordMode::Anonymous)
            .expect_err("cannot relabel an existing session anonymous")
            .kind(),
        ErrorKind::OffRecordTalkOnly
    );
    assert_eq!(ordinary.mode()?, OffRecordMode::OffRecord);
    ordinary.close()?;
    Ok(())
}

fn telemetry_config() -> VaultConfig {
    VaultConfig {
        retrieval_telemetry_capture: true,
        ..VaultConfig::default()
    }
}

// The public self.memory.search route must obey capture policy independently
// of the pipeline and ordinary Vault search registration doors.
fn assert_session_search_capture(capture: bool, on_record: bool) -> Result<()> {
    use crate::code_run::{
        HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfMemorySearchCall,
    };

    let dir = tempfile::tempdir()?;
    let config = VaultConfig {
        retrieval_telemetry_capture: capture,
        ..VaultConfig::default()
    };
    let vault = Vault::open(dir.path(), config)?;
    let id = EntityId::from_bytes([0xB8; 16])?;
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"entity")
        .text(&id, &[("name", "amberlantern")])
        .commit()?;
    let session = vault
        .off_record_session_vault()
        .enter("capture-room", OffRecordBackendClass::Local)?;
    if on_record {
        session.flip_on_record_as(&crate::test_util::embedded_owner_proof(&vault))?;
    }
    let dispatcher = HostSelfDispatcher::for_off_record_session(
        &session,
        crate::WriteActor::new(id, EdgeActorClass::Human),
        "capture-run",
    )?;
    let result = dispatcher.dispatch(SelfCall::MemorySearch(SelfMemorySearchCall::new(
        "amberlantern",
        5,
    )))?;
    let SelfDispatchOutcome::MemorySearch(found) = result else {
        panic!("expected memory search");
    };
    assert!(found.results.iter().any(|row| row.id == id));
    assert_eq!(
        vault.retrieval_runs(10)?.len(),
        usize::from(capture && on_record)
    );
    drop(dispatcher);
    let close = session.close()?;
    assert_eq!(
        close.context_receipts_deleted,
        usize::from(capture && !on_record)
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(
        reopened.retrieval_runs(10)?.len(),
        usize::from(capture && on_record)
    );
    Ok(())
}

#[test]
fn default_on_record_session_search_does_not_persist_telemetry() -> Result<()> {
    assert_session_search_capture(false, true)
}

#[test]
fn default_off_record_session_search_does_not_stage_telemetry() -> Result<()> {
    assert_session_search_capture(false, false)
}

#[test]
fn opted_in_on_record_session_search_persists_telemetry() -> Result<()> {
    assert_session_search_capture(true, true)
}

#[test]
fn opted_in_off_record_session_search_stages_only_in_room() -> Result<()> {
    assert_session_search_capture(true, false)
}
