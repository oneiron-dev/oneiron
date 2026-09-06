use super::*;
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundTransport, execute_outbound_effect,
};
use crate::outbound_consent::OutboundBindingAuthority;
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, FrozenOutboundCall, IntentLedgerRecord, IntentState,
    OutboundCallRequest, OutboundSendOutcome, insert_pending_in_txn, read_intent_record,
};

#[derive(Default)]
struct FrozenSpy(Vec<Vec<u8>>);

impl OutboundTransport for FrozenSpy {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.0.push(call.payload().to_vec());
        OutboundSendOutcome::Acked
    }
}

fn persist_pending(vault: &Vault, request: OutboundCallRequest) -> IntentLedgerRecord {
    let record = IntentLedgerRecord::pending(
        request,
        true,
        BudgetChargeMarker {
            key_ref: None,
            budget_class: BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: NOW,
        },
    )
    .unwrap();
    let mut txn = vault.store.env.write_txn().unwrap();
    insert_pending_in_txn(vault, &mut txn, &record).unwrap();
    txn.commit().unwrap();
    record
}

fn assert_pending_event(vault: &Vault, event: EntityId, pending: bool) {
    let txn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        lookup::pending_event_in(vault, &txn, event)
            .unwrap()
            .is_some(),
        pending
    );
    assert_eq!(
        ensure_no_pending_effect_in(vault, &txn, event).is_err(),
        pending
    );
}

#[test]
fn malformed_emergency_recovery_bytes_never_reach_transport() {
    for lane in ["calendar", "apology", "pick", "completed"] {
        let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
        let mut sink = spy(&vault, &plan);
        if lane == "completed" {
            execute(&vault, &plan, &mut sink, NOW).unwrap();
        } else if lane == "pick" {
            let item = execute(&vault, &plan, &mut sink, NOW).unwrap();
            sink.fail_channel = Some("calendar");
            assert!(
                counterparty_pick(
                    &vault,
                    &item.actions[1],
                    &calendars(),
                    &consumer(&vault, NOW + 1),
                    &mut sink,
                )
                .is_err()
            );
        } else {
            sink.fail_channel = Some(if lane == "calendar" {
                "calendar"
            } else {
                "email"
            });
            assert!(execute(&vault, &plan, &mut sink, NOW).is_err());
        }
        let pending = emergency_records(&vault)
            .into_iter()
            .find(|record| {
                record.state
                    == if lane == "completed" {
                        IntentState::Done
                    } else {
                        IntentState::Pending
                    }
            })
            .unwrap();
        let authority = OutboundBindingAuthority::for_vault(&vault).unwrap();
        for bytes in [
            b"{not JSON".to_vec(),
            b"{}".to_vec(),
            br#"{"idempotency_key":"ordinary"}"#.to_vec(),
        ] {
            // Keep the trusted attempt identity but reconstruct frozen bytes
            // with a valid ledger hash. The JSON verifier, not ledger decoding,
            // must stop this call at the final transport boundary.
            let corrupt = persist_pending(
                &vault,
                OutboundCallRequest::new(
                    pending.attempt_id,
                    pending.call_seq,
                    &pending.server,
                    &pending.tool,
                    bytes,
                    NOW,
                ),
            );
            let mut transport = FrozenSpy::default();
            assert!(
                execute_outbound_effect(
                    &vault,
                    &authority,
                    OutboundEffectCommand::Resume(corrupt.id),
                    NOW + 2,
                    &mut transport,
                )
                .is_err()
            );
            assert!(transport.0.is_empty());
            assert_eq!(
                read_intent_record(&vault, &corrupt.id).unwrap().unwrap(),
                corrupt
            );
        }
        assert_pending_event(&vault, plan.booking.calendar.event_ref, lane != "completed");
    }
}

#[test]
fn ordinary_non_json_frozen_bytes_are_preserved_on_recovery() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let authority = OutboundBindingAuthority::for_vault(&vault).unwrap();
    for bytes in [
        vec![0xff, 0, 0xfe],
        b"{not JSON".to_vec(),
        br#"{"idempotency_key":"ordinary"}"#.to_vec(),
    ] {
        let record = persist_pending(
            &vault,
            OutboundCallRequest::new(
                crate::attempt_queue::AttemptId::now(),
                0,
                "email",
                "send",
                bytes.clone(),
                NOW,
            ),
        );
        let mut transport = FrozenSpy::default();
        let result = execute_outbound_effect(
            &vault,
            &authority,
            OutboundEffectCommand::Resume(record.id),
            NOW + 1,
            &mut transport,
        )
        .unwrap();
        assert_eq!(result.dispatch.state, Some(IntentState::Done));
        assert_eq!(transport.0, vec![bytes]);
    }
}

#[test]
fn completed_history_is_not_read_by_pending_event_effect_or_request_lookups() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::RequestUpdate);
    let mut sink = spy(&vault, &plan);
    sink.fail_channel = Some("calendar");
    assert!(execute(&vault, &plan, &mut sink, NOW).is_err());
    let item = checkpoint(&vault, &plan).unwrap();
    let pending = emergency_records(&vault).pop().unwrap();
    let before = plan_emergency_reschedule(&vault, &plan.request, &calendars(), NOW).unwrap();
    let history = booking_writer(&vault, |txn| {
        let mut last = None;
        for offset in 1..=2_000 {
            let mut completed = item.clone();
            completed.plan.request.authority.recorded_at += offset;
            completed.calendar_delivered = true;
            completed.apology_delivered = true;
            write_item_in(&vault, txn, &completed)?;
            last = Some(completed);
        }
        // A global scan would fail even before it could skip these unrelated
        // rows. Direct lookups must not deserialize them at all.
        for prefix in [EMERGENCY_ITEM_META_PREFIX, EMERGENCY_PLAN_META_PREFIX] {
            let mut key = prefix.to_vec();
            key.extend_from_slice(b"unrelated-corrupt-history");
            put_meta(&vault, txn, &key, b"not JSON")?;
        }
        Ok(last.unwrap())
    })
    .unwrap();
    assert_pending_event(&vault, item.calendar.event_ref, true);
    let txn = vault.store.env.read_txn().unwrap();
    verify_frozen_effect_in(&vault, &txn, pending.attempt_id, pending.payload()).unwrap();
    assert_eq!(
        read_item_in(
            &vault,
            &txn,
            &item_key(&history.plan.request, history.calendar.event_ref).unwrap(),
        )
        .unwrap(),
        Some(history)
    );
    drop(txn);
    assert_eq!(
        plan_emergency_reschedule(&vault, &plan.request, &calendars(), NOW).unwrap(),
        before
    );
    let complete = execute(&vault, &plan, &mut sink, NOW + 1).unwrap();
    assert!(complete.calendar_delivered && complete.apology_delivered);
    assert_pending_event(&vault, item.calendar.event_ref, false);
}

#[test]
fn checkpoint_indexes_commit_abort_reconnect_and_retry_with_the_item() {
    let (dir, vault, receipt, plan) = executable(EmergencyActionPolicy::RequestUpdate);
    let mut sink = spy(&vault, &plan);
    sink.fail_channel = Some("calendar");
    assert!(execute(&vault, &plan, &mut sink, NOW).is_err());
    let item = checkpoint(&vault, &plan).unwrap();
    let pending = emergency_records(&vault).pop().unwrap();
    drop(sink);
    {
        let mut txn = vault.store.env.write_txn().unwrap();
        let mut completed = item.clone();
        completed.calendar_delivered = true;
        completed.apology_delivered = true;
        write_item_in(&vault, &mut txn, &completed).unwrap();
        assert!(
            lookup::pending_event_in(&vault, &txn, item.calendar.event_ref)
                .unwrap()
                .is_none()
        );
        // Dropping the transaction must restore both checkpoint and index.
    }
    assert_eq!(checkpoint(&vault, &plan), Some(item.clone()));
    assert_pending_event(&vault, item.calendar.event_ref, true);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    assert_pending_event(&vault, item.calendar.event_ref, true);
    let authority = OutboundBindingAuthority::for_vault(&vault).unwrap();
    let mut transport = FrozenSpy::default();
    execute_outbound_effect(
        &vault,
        &authority,
        OutboundEffectCommand::Resume(pending.id),
        NOW + 1,
        &mut transport,
    )
    .unwrap();
    assert_eq!(transport.0, vec![pending.payload().to_vec()]);
    // A crash after ledger ACK but before the lifecycle checkpoint must still
    // fence the revision until the existing execution door records delivery.
    assert_pending_event(&vault, item.calendar.event_ref, true);
    let mut sink = spy(&vault, &plan);
    let completed = execute(&vault, &plan, &mut sink, NOW + 2).unwrap();
    assert_eq!(
        sink.calls.len(),
        1,
        "the calendar ACK is replayed, not resent"
    );
    assert_pending_event(&vault, item.calendar.event_ref, false);
    assert_eq!(checkpoint(&vault, &plan), Some(completed.clone()));
    sink.fail_channel = Some("calendar");
    assert!(
        counterparty_pick(
            &vault,
            &completed.actions[1],
            &calendars(),
            &consumer(&vault, NOW + 3),
            &mut sink,
        )
        .is_err()
    );
    assert_pending_event(&vault, item.calendar.event_ref, true);
    let picked = counterparty_pick(
        &vault,
        &completed.actions[1],
        &calendars(),
        &consumer(&vault, NOW + 4),
        &mut sink,
    )
    .unwrap();
    assert_pending_event(&vault, item.calendar.event_ref, false);
    assert_eq!(picked.sequence, completed.calendar.sequence + 1);
    crate::booking::lifecycle::execute_cancel(
        &vault,
        &CancelSpec {
            token: receipt.cancel_token,
            idempotency_key: None,
        },
        NOW + 5,
    )
    .unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    assert!(verify_frozen_effect_in(&vault, &txn, pending.attempt_id, pending.payload()).is_err());
    assert!(
        read_item_in(
            &vault,
            &txn,
            &item_key(&plan.request, item.calendar.event_ref).unwrap(),
        )
        .unwrap()
        .is_some(),
        "historical checkpoint is retained"
    );
}
