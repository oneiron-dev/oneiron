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
fn damaged_request_plan_rows_refuse_only_the_indexed_event() {
    for (damage, refusal) in [
        ("missing", "indexed emergency plan is missing"),
        ("malformed", "indexed emergency plan is malformed"),
        ("request_binding", "lookup names another instruction"),
        ("event_binding", "lookup names another event"),
        ("target_binding", "lookup names another plan key"),
        ("hash", "content conflicts with the persisted proposal"),
        (
            "noncanonical",
            "content conflicts with the persisted proposal",
        ),
        ("revision", "saved emergency plan is superseded"),
        (
            "checkpoint_decode",
            "indexed emergency checkpoint is malformed",
        ),
        ("checkpoint_binding", "plan conflicts with its checkpoint"),
    ] {
        let (_dir, vault, _, plan) = executable_with_invite(EmergencyActionPolicy::Cancel, false);
        let event = plan.booking.calendar.event_ref;
        let saved = book(&vault, PAGE, NOW + 7_200);
        let before = plan_emergency_reschedule(&vault, &plan.request, &calendars(), NOW).unwrap();
        assert!(
            before.refusals.is_empty(),
            "{damage}: {:?}",
            before.refusals
        );
        let healthy = before
            .plans
            .into_iter()
            .find(|candidate| candidate.booking.calendar.event_ref == saved.calendar.event_ref)
            .unwrap();
        // This booking has no index yet. Both it and the healthy saved plan
        // must survive the damaged row in the same planning call.
        let fresh = book(&vault, PAGE, NOW + 9_000);
        let prefix = lookup::request_plan_prefix(&plan.request).unwrap();
        let mut index_key = prefix.clone();
        index_key.extend_from_slice(event.as_bytes());
        let mut healthy_index_key = prefix;
        healthy_index_key.extend_from_slice(saved.calendar.event_ref.as_bytes());
        let key = {
            let txn = vault.store.env.read_txn().unwrap();
            read_meta_bytes(&vault, &txn, &index_key).unwrap().unwrap()
        };
        let checkpoint_key = item_key(&plan.request, event).unwrap();
        booking_writer(&vault, |txn| {
            match damage {
                "missing" => {
                    assert!(vault.store.vault_meta.delete(txn, &key).unwrap());
                }
                "malformed" => put_meta(&vault, txn, &key, b"{not JSON")?,
                "target_binding" => {
                    let target = read_meta_bytes(&vault, txn, &healthy_index_key)?.unwrap();
                    put_meta(&vault, txn, &index_key, &target)?;
                }
                "checkpoint_decode" => {
                    put_meta(&vault, txn, &checkpoint_key, b"{not JSON")?;
                }
                "checkpoint_binding" => {
                    let checkpoint = EmergencyItem {
                        plan: healthy.clone(),
                        calendar: plan.booking.calendar.clone(),
                        basis: EmergencyLocalBasis::PreStartCancellation,
                        committed_at: NOW,
                        actions: Vec::new(),
                        calendar_delivered: true,
                        apology_delivered: true,
                        picked: None,
                    };
                    put_meta(
                        &vault,
                        txn,
                        &checkpoint_key,
                        &serde_json::to_vec(&checkpoint).unwrap(),
                    )?;
                }
                _ => {
                    let mut damaged = plan.clone();
                    match damage {
                        "request_binding" => damaged.request.authority.recorded_at += 1,
                        "event_binding" => {
                            damaged.booking.calendar.event_ref = saved.calendar.event_ref;
                        }
                        "hash" => damaged.content_hash[0] ^= 1,
                        "noncanonical" => {}
                        "revision" => damaged.booking.calendar.sequence += 1,
                        _ => unreachable!(),
                    }
                    if damage != "hash" {
                        damaged.content_hash = damaged.hash().unwrap();
                    }
                    let mut bytes = serde_json::to_vec(&damaged).unwrap();
                    if damage == "noncanonical" {
                        bytes.push(b' ');
                    }
                    put_meta(&vault, txn, &key, &bytes)?;
                }
            }
            Ok(())
        })
        .unwrap();
        let damaged_rows = {
            let txn = vault.store.env.read_txn().unwrap();
            [index_key.clone(), key.clone(), checkpoint_key.clone()]
                .map(|key| read_meta_bytes(&vault, &txn, &key).unwrap())
        };
        let mut first_batch = None;
        for _ in 0..2 {
            let batch =
                plan_emergency_reschedule(&vault, &plan.request, &calendars(), NOW).unwrap();
            assert_eq!(batch.refusals.len(), 1, "{damage}: {:?}", batch.refusals);
            assert_eq!(batch.refusals[0].0, event, "{damage}");
            assert!(
                batch.refusals[0].1.contains(refusal),
                "{damage}: {:?}",
                batch.refusals
            );
            assert_eq!(
                batch
                    .plans
                    .iter()
                    .map(|candidate| candidate.booking.calendar.event_ref)
                    .collect::<Vec<_>>(),
                vec![saved.calendar.event_ref, fresh.calendar.event_ref],
                "{damage}"
            );
            assert_eq!(batch.plans[0], healthy, "{damage}");
            let txn = vault.store.env.read_txn().unwrap();
            assert_eq!(
                [index_key.clone(), key.clone(), checkpoint_key.clone()]
                    .map(|key| read_meta_bytes(&vault, &txn, &key).unwrap()),
                damaged_rows,
                "{damage}: planning must not repair or retry the refused booking"
            );
            if let Some(first) = &first_batch {
                assert_eq!(
                    &batch, first,
                    "{damage}: retry must preserve the same plans"
                );
            } else {
                first_batch = Some(batch);
            }
        }
        assert!(emergency_records(&vault).is_empty(), "{damage}");
    }
}

#[test]
fn request_plan_event_requires_an_exact_scoped_index_key() {
    let prefix = lookup::request_plan_prefix(&request()).unwrap();
    let mut key = prefix.clone();
    key.extend_from_slice(id(0x61).as_bytes());
    assert_eq!(lookup::request_plan_event(&prefix, &key).unwrap(), id(0x61));
    assert!(lookup::request_plan_event(&prefix, &prefix).is_err());
    assert!(lookup::request_plan_event(b"another request", &key).is_err());
    key.push(0);
    assert!(lookup::request_plan_event(&prefix, &key).is_err());
    let mut sentinel = prefix.clone();
    sentinel.extend_from_slice(&[0; 16]);
    assert!(lookup::request_plan_event(&prefix, &sentinel).is_err());
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
