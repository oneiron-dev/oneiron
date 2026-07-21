use super::*;
use crate::config::VaultConfig;
use crate::edge::EdgeKind;
use crate::error::{Error, ErrorKind};
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchError,
    OutboundDispatchGate, OutboundDispatchPipeline, OutboundDispatchRequest,
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent,
    OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::pipeline::{DreamerWorkingSetBudget, DreamerWorkingSetCursor};
use crate::registry::{ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_TURN};
use crate::store::{GateDecisionId, GateDecisionRecord};
#[cfg(feature = "sync")]
use crate::sync::queue::SyncQueue;
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
    assert!(record.fenced_turns.is_empty());

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

/// Model A durable-backstop-with-recovery, end to end and WITHOUT ONE-1728
/// witness machinery: a crash mid-session leaves an ORPHANED durable fence — a
/// live-session-ref row with no registry entry — over a base turn still on
/// disk. Whole-vault export must REFUSE while the orphan exists, including once
/// the in-process registry is already empty (proving the durable backstop leg,
/// not just the registry leg). The next `Vault::open` must SWEEP the orphan:
/// PolicyDelete the fenced base turn and lift the fence row, after which export
/// is permitted, no live fence residue remains, and the session ref is free.
#[test]
fn off_record_crash_orphaned_fence_is_gated_then_swept_on_reopen() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let session_ref = "sess-crash-durable-backstop";
    let secrets_nulled = crate::batch::export::ExportSecretsNulledManifest::from_redacted(false);

    let fenced = {
        let vault = Vault::open(tmp.path(), VaultConfig::default())?;
        let fenced = seed_turn(&vault, 1_775_000_000);
        assert!(
            vault.get_raw(&fenced)?.is_some(),
            "the base turn must exist before it is fenced"
        );

        vault.enter_off_record_session(session_ref, OffRecordBackendClass::Local)?;
        vault.tag_turn_off_record(session_ref, &fenced)?;

        // The durable fence row is present with a live (non-empty) value.
        {
            let rtxn = vault.store.env.read_txn()?;
            assert_eq!(
                off_record_orphaned_live_fence_session_ref(&vault.store, &rtxn)?.as_deref(),
                Some(session_ref),
                "tag must write a durable live-session-ref fence row"
            );
        }

        // Registry leg: a live session refuses whole-vault export.
        match vault.whole_vault_export_manifest_artifact(secrets_nulled) {
            Err(Error::OffRecordExportRefused {
                session_ref: refused,
            }) => {
                assert_eq!(refused, session_ref);
            }
            other => panic!("live off-record session must refuse export, got {other:?}"),
        }

        // Orphan the fence: drop ONLY the in-process registry entry (no close),
        // exactly the residue a crash leaves — durable fence, no registry.
        let entry = vault
            .store
            .off_record_sessions
            .entry(session_ref)?
            .expect("registry entry is live before the simulated crash");
        vault
            .store
            .off_record_sessions
            .remove_if_same(session_ref, &entry)?;
        assert!(
            vault
                .store
                .off_record_sessions
                .first_session_ref()?
                .is_none(),
            "the registry entry must be gone so only the durable backstop can fire"
        );

        // Durable backstop leg: export still refused with an EMPTY registry.
        match vault.whole_vault_export_manifest_artifact(secrets_nulled) {
            Err(Error::OffRecordExportRefused { .. }) => {}
            other => panic!(
                "an orphaned durable fence must refuse export via the backstop leg, got {other:?}"
            ),
        }

        // Full crash: drop the vault WITHOUT close, leaving the fence orphaned.
        drop(vault);
        fenced
    };

    // Reopen at the same path: the crash-orphan sweep runs inside open().
    let reopened = Vault::open(tmp.path(), VaultConfig::default())?;

    // The sweep PolicyDeleted the orphaned fenced base turn …
    assert!(
        reopened.get_raw(&fenced)?.is_none(),
        "reopen sweep must PolicyDelete the orphaned fenced turn"
    );
    // … and lifted the fence row: zero live (non-empty) fence residue remains.
    {
        let rtxn = reopened.store.env.read_txn()?;
        assert!(
            off_record_orphaned_live_fence_session_ref(&reopened.store, &rtxn)?.is_none(),
            "reopen sweep must leave zero live fence residue"
        );
    }
    // Export is now permitted (both legs clear).
    reopened
        .whole_vault_export_manifest_artifact(secrets_nulled)
        .expect("with the orphan swept, whole-vault export must be permitted");
    // The session ref reads free for reuse.
    assert!(
        reopened.off_record_session(session_ref)?.is_none(),
        "the evaporated session ref must read as free after reopen"
    );
    Ok(())
}

#[test]
fn live_overlay_membership_is_hidden_by_retrieval_fence() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let hidden = seed_turn(&vault, 1000);
    let visible = seed_turn(&vault, 1001);
    let session = vault
        .off_record_session_vault()
        .enter("sess-overlay-retrieval-fence", OffRecordBackendClass::Local)?;
    put_live_overlay_entity(&session, &hidden)?;

    let surfaced = surfaced_turns(&vault);
    assert!(
        !surfaced.contains(&hidden),
        "retrieval must consult live overlay membership before the durable fence backstop"
    );
    assert!(
        surfaced.contains(&visible),
        "an ordinary base turn must remain visible"
    );

    session.close()?;
    assert!(
        surfaced_turns(&vault).contains(&hidden),
        "dropping live overlay membership must release this fence-free base control"
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
    assert_eq!(error.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    assert!(matches!(
        error,
        Error::OffRecordFencedTurnWriteRejected { turn_ref } if turn_ref == id.to_hex()
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
        "the guard must be keyed to live overlay membership"
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

    let receipt = vault
        .promote_off_record_turn("sess-promote", &kept)
        .expect("promote");
    assert_eq!(receipt.turn, *kept.as_bytes());
    assert_eq!(receipt.session_ref, "sess-promote");
    assert_eq!(receipt.initiator, "user");

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
        .promote_off_record_turn("sess-promote", &kept)
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
fn off_record_close_and_promote_are_serialized_by_registry_lock() {
    let (_tmp, vault) = temp_vault();
    let turn = seed_turn(&vault, 1000);
    vault
        .enter_off_record_session("sess-close-promote", OffRecordBackendClass::Local)
        .expect("enter");
    vault
        .tag_turn_off_record("sess-close-promote", &turn)
        .expect("tag");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let (close_result, promote_result) = std::thread::scope(|scope| {
        let close_barrier = barrier.clone();
        let close_vault = &vault;
        let close = scope.spawn(move || {
            close_barrier.wait();
            close_vault.close_off_record_session(
                "sess-close-promote",
                SessionLocalReceiptLog::off_record("sess-close-promote"),
            )
        });
        let promote_barrier = barrier.clone();
        let promote_vault = &vault;
        let promote = scope.spawn(move || {
            promote_barrier.wait();
            promote_vault.promote_off_record_turn("sess-close-promote", &turn)
        });
        barrier.wait();
        (
            close.join().expect("close thread"),
            promote.join().expect("promote thread"),
        )
    });
    let close = close_result.expect("close must complete");
    match promote_result {
        Ok(receipt) => {
            assert_eq!(receipt.turn, *turn.as_bytes());
            assert_eq!(close.turns_deleted, 0);
            assert_eq!(close.promoted_turns_kept, 1);
            assert!(vault.get(&turn).expect("read promoted").is_some());
        }
        Err(error) => {
            assert!(matches!(
                error.kind(),
                ErrorKind::OffRecordSessionClosing | ErrorKind::OffRecordSessionNotFound
            ));
            assert_eq!(close.turns_deleted, 1);
            assert_eq!(close.promoted_turns_kept, 0);
            assert!(vault.get(&turn).expect("read closed").is_none());
            assert!(
                vault
                    .off_record_promote_receipt(&turn)
                    .expect("receipt lookup")
                    .is_none(),
                "a promote that lost the race to close must leave no orphaned receipt"
            );
        }
    }
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

    let tag = vault
        .tag_turn_off_record("sess-toctou", &late)
        .expect_err("tag during close");
    assert_eq!(tag.kind(), ErrorKind::OffRecordSessionClosing);
    let promote = vault
        .promote_off_record_turn("sess-toctou", &fenced)
        .expect_err("promote during close");
    assert_eq!(promote.kind(), ErrorKind::OffRecordSessionClosing);
    // A promote rejected because the session is closing must NOT have committed
    // a durable promote receipt, and must leave the fence intact — otherwise a
    // stale close snapshot could hard-delete a turn whose receipt was already
    // written (finding: promote-commits-after-close).
    assert!(
        vault
            .off_record_promote_receipt(&fenced)
            .expect("receipt lookup")
            .is_none(),
        "a closing-rejected promote must persist no promote receipt"
    );
    assert!(
        vault
            .is_turn_off_record_fenced(&fenced)
            .expect("fence probe"),
        "a closing-rejected promote must leave the fence intact"
    );
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
    let entry = vault
        .store
        .off_record_sessions
        .entry("sess-close-retry")
        .expect("registry")
        .expect("session record");
    session_entry_state(&entry)
        .expect("session state")
        .record
        .closing = true;
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
        .promote_off_record_turn(&oversized, &turn)
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

/// P1 consent-bypass regression. Tag-before-write lets a turn be fenced with no
/// entity row; promoting that body-less turn must NOT open the durable write
/// door. Deleting its fence on promote would let a LATER ordinary `put_entity`
/// for the same id enter the vault UNFENCED — admitting an off-record body that
/// never passed the consent gate. Promote must instead retain a closed-fence
/// marker so the guard stays active for that id, before AND after close.
#[test]
fn promote_without_entity_keeps_guard_active_for_late_write() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session_ref = "sess-promote-bodiless";
    let id = EntityId::now(); // tag-before-write: the entity row never lands.
    vault.enter_off_record_session(session_ref, OffRecordBackendClass::Local)?;
    vault.tag_turn_off_record(session_ref, &id)?;
    assert!(
        vault.get_raw(&id)?.is_none(),
        "the fenced turn has no entity body"
    );

    // Promote the body-less turn. The fence must NOT be lifted into an open
    // durable write door.
    let receipt = vault.promote_off_record_turn(session_ref, &id)?;
    assert_eq!(receipt.turn, *id.as_bytes());

    // A later ordinary put_entity for the promoted-but-never-written id must
    // still be guard-rejected while the session is live.
    let error = vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: 1000,
                end: 1000,
            },
            1000,
            b"late off-record body must not sneak past a lifted fence",
        )
        .expect_err("a promoted body-less turn must keep the write door shut");
    assert_eq!(error.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    assert!(
        vault.get_raw(&id)?.is_none(),
        "the rejected late write leaves no durable entity row"
    );

    // The closed-fence marker survives close, so the door stays shut after the
    // session evaporates.
    let log = vault.off_record_receipt_log(session_ref)?;
    vault.close_off_record_session(session_ref, log)?;
    let error = vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: 1000,
                end: 1000,
            },
            1000,
            b"post-close late body must still be rejected",
        )
        .expect_err("the closed-fence marker keeps the door shut after close");
    assert_eq!(error.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    Ok(())
}

/// A durably-promoted turn's promote receipt outlives its session, but the
/// in-memory `promoted_turns` list does not. A LATER session starting with an
/// empty list must still refuse to re-fence the already-promoted turn — else its
/// close would hard-delete durable content the user consented to keep, orphaning
/// the promote receipt. Tag consults the durable receipt row.
#[test]
fn tag_rejects_re_fencing_a_durably_promoted_turn_in_a_later_session() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = seed_turn(&vault, 1000); // entity exists, so promote lifts the fence.
    vault.enter_off_record_session("sess-1", OffRecordBackendClass::Local)?;
    vault.tag_turn_off_record("sess-1", &id)?;
    vault.promote_off_record_turn("sess-1", &id)?;
    let log = vault.off_record_receipt_log("sess-1")?;
    vault.close_off_record_session("sess-1", log)?;
    assert!(
        vault.off_record_promote_receipt(&id)?.is_some(),
        "the durable promote receipt survives close"
    );

    // Fresh session: empty in-memory promoted_turns cannot catch the id.
    vault.enter_off_record_session("sess-2", OffRecordBackendClass::Local)?;
    let error = vault
        .tag_turn_off_record("sess-2", &id)
        .expect_err("re-fencing a durably-promoted turn must be rejected");
    assert_eq!(error.kind(), ErrorKind::InvariantViolation);
    assert!(
        vault.get(&id).expect("read promoted").is_some(),
        "the durably-promoted turn survives the rejected re-tag"
    );
    Ok(())
}

/// Cross-process sweep-safety regression. The open-time crash-orphan sweep is
/// destructive; it must run ONLY when this process is the sole opener. A live
/// peer process (simulated here by an independent fd holding a SHARED flock on
/// the same open-lock file — flock treats separate `open`s as independent on
/// Linux and macOS) makes the exclusive probe fail, so the sweep is skipped and
/// the peer's live fenced turn is NOT deleted. Once the peer releases the lock,
/// a sole-opener reopen sweeps the orphan as usual.
#[cfg(unix)]
#[test]
fn off_record_crash_sweep_is_skipped_when_a_peer_holds_the_open_lock() -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let tmp = tempfile::tempdir()?;
    let session_ref = "sess-peer-open-lock";
    let fenced = {
        let vault = Vault::open(tmp.path(), VaultConfig::default())?;
        let fenced = seed_turn(&vault, 1_775_000_000);
        vault.enter_off_record_session(session_ref, OffRecordBackendClass::Local)?;
        vault.tag_turn_off_record(session_ref, &fenced)?;
        // Orphan the fence: drop only the registry entry (crash residue).
        let entry = vault
            .store
            .off_record_sessions
            .entry(session_ref)?
            .expect("registry entry live before the simulated crash");
        vault
            .store
            .off_record_sessions
            .remove_if_same(session_ref, &entry)?;
        drop(vault);
        fenced
    };

    // Simulate a live peer process holding the open lock (SHARED) on the same
    // path via an independent fd.
    let canonical = std::fs::canonicalize(tmp.path())?;
    let lock_path = canonical.join("off_record_sweep.lock");
    let peer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    // SAFETY: `peer.as_raw_fd()` is the descriptor of the live, owned `peer`
    // file; `libc::flock` needs only a valid open fd and the result is asserted.
    let peer_lock = unsafe { libc::flock(peer.as_raw_fd(), libc::LOCK_SH) };
    assert_eq!(
        peer_lock, 0,
        "the simulated peer must hold a shared open lock"
    );

    // Reopen while the peer holds the lock: the destructive sweep must be
    // SKIPPED, so the peer's fenced turn and its live fence row survive.
    {
        let reopened = Vault::open(tmp.path(), VaultConfig::default())?;
        assert!(
            reopened.get_raw(&fenced)?.is_some(),
            "the sweep must not delete a live peer's fenced turn"
        );
        let rtxn = reopened.store.env.read_txn()?;
        assert_eq!(
            off_record_orphaned_live_fence_session_ref(&reopened.store, &rtxn)?.as_deref(),
            Some(session_ref),
            "the live fence row must be preserved while a peer holds the lock"
        );
        drop(rtxn);
        drop(reopened);
    }

    // Once the peer releases the lock, a sole-opener reopen sweeps the orphan.
    drop(peer);
    let swept = Vault::open(tmp.path(), VaultConfig::default())?;
    assert!(
        swept.get_raw(&fenced)?.is_none(),
        "with the peer gone, a sole-opener reopen sweeps the orphan"
    );
    Ok(())
}
