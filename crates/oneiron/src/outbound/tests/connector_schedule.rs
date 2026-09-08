//! Connector send-task scheduling, executor idempotency, idempotency keys and schedule gates.

use super::*;

#[test]
fn connector_send_schedule_is_additive_and_executor_is_idempotent() -> crate::Result<()> {
    exercise_connector_schedule_and_executor()
}

#[test]
pub(super) fn delivered_send_idempotency_survives_attempt_completion() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState};
    use crate::memory::{BRIDGE_OUTBOUND_ATTEMPT_KIND, OutboundDraftInput};
    use crate::receipt::{ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x4A);
    put_connector_task_actor(&vault, actor, 90)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x4B),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault.register_connector_key(&entity(0x4E), sends_per_day_key(5))?;
    let draft = OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "counterparty:durable-idempotency".to_owned(),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some("durable-idempotency:test".to_owned()),
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:durable-idempotency".to_owned(),
        job_ref: None,
        occurred_at: Some(90),
    };
    let first = vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("first schedule");
    assert!(!first.deduped);
    let unsettled_tasks = vault.connector_send_tasks()?;
    assert_eq!(unsettled_tasks.len(), 1);
    let unsettled = &unsettled_tasks[0];
    let task_ref = unsettled.task_ref;
    // Discriminating: additive absent fields must hydrate as outcome unknown,
    // not as a fabricated successful terminal state.
    assert_eq!(unsettled.attempt_started_node_id, None);
    assert_eq!(unsettled.outcome, None);

    reset_delivered_projection_receipt_observation();
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 91)
            .unwrap(),
        1
    );
    assert_eq!(executor.calls.len(), 1);
    let settled = vault
        .connector_send_task(&task_ref)?
        .expect("settled connector task");
    assert!(settled.attempt_started_node_id.is_some());
    // The Delivered projection is strictly after receipt durability: a crash
    // before the receipt must leave the task outcome unknown, never Delivered.
    assert_eq!(
        (
            settled.outcome,
            send_receipt_exists_for_task(&vault, task_ref)?
        ),
        (Some(ConnectorSendTaskOutcome::Delivered), true)
    );
    assert_eq!(delivered_projection_receipt_observation(), Some(true));
    assert_eq!(
        vault
            .effector_budget_read("email", None)?
            .expect("budget after delivery")
            .rows[0]
            .used,
        1
    );
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .len(),
        1
    );
    assert_eq!(
        vault
            .store
            .get_delivered_send_task_by_idempotency(&actor, "durable-idempotency:test")?,
        Some(task_ref)
    );
    let attempts = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Completed)
            .count(),
        1
    );

    let replay = vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("delivered replay");
    assert!(replay.deduped);
    assert_eq!(replay.outcome, "already_sent");
    assert_eq!(vault.connector_send_tasks()?.len(), 1);
    assert_eq!(
        vault
            .effector_budget_read("email", None)?
            .expect("budget after delivered dedupe")
            .rows[0]
            .used,
        1
    );
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .into_iter()
            .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
            .count(),
        1
    );
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .len(),
        1
    );
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 92)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 1);
    Ok(())
}

#[test]
fn failed_send_receipt_is_audit_only_and_same_task_can_retry() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState, EnqueueAttempt, EnqueueOutcome};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{FIELD_TASK_REF, FIELD_TRANSPORT_DISPATCHED, ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x4C);
    put_connector_task_actor(&vault, actor, 100)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x4D),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let draft = connector_task_draft(
        "failed-receipt-retry:test",
        "session:failed-receipt-retry",
        100,
    );
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule outbound");
    let tasks = vault.connector_send_tasks()?;
    assert_eq!(tasks.len(), 1);
    let task_ref = tasks[0].task_ref;

    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout")
            .with_receipt_field("transport_status", "timeout"),
        ..Default::default()
    };
    reset_failed_projection_receipt_observation();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 101)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 1);
    let failed_task = vault
        .connector_send_task(&task_ref)?
        .expect("failed connector task");
    assert!(failed_task.attempt_started_node_id.is_some());
    assert_eq!(failed_task.outcome, Some(ConnectorSendTaskOutcome::Failed));
    let failed_receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(failed_receipts.len(), 1);
    assert_eq!(failed_receipts[0].outcome, "failed");
    // The Failed projection is strictly after the durable failure receipt: a
    // crash before that record must leave outcome unknown, never Failed.
    assert_eq!(
        (
            failed_task.outcome,
            failed_receipts
                .first()
                .is_some_and(|receipt| receipt.outcome == "failed")
        ),
        (Some(ConnectorSendTaskOutcome::Failed), true)
    );
    assert_eq!(failed_projection_receipt_observation(), Some(true));
    let task_ref_hex = task_ref.to_hex();
    assert_eq!(
        failed_receipts[0]
            .fields
            .get(FIELD_TASK_REF)
            .map(String::as_str),
        Some(task_ref_hex.as_str())
    );
    assert_eq!(
        failed_receipts[0]
            .fields
            .get(FIELD_TRANSPORT_DISPATCHED)
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        failed_receipts[0]
            .fields
            .get("retry_state")
            .map(String::as_str),
        Some("provider_timeout")
    );
    assert_eq!(
        failed_receipts[0]
            .fields
            .get("transport_status")
            .map(String::as_str),
        Some("timeout")
    );
    assert_eq!(
        usize::from(vault.store.get_send_receipt_by_task(&task_ref)?.is_some()),
        1
    );
    assert_eq!(
        usize::from(send_receipt_exists_for_task(&vault, task_ref)?),
        0
    );
    assert_eq!(
        usize::from(
            vault
                .store
                .get_delivered_send_task_by_idempotency(&actor, "failed-receipt-retry:test")?
                .is_some()
        ),
        0
    );

    let retry = AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
        payload: connector_send_attempt_payload(task_ref)?,
        dedupe_key: None,
        run_id: None,
        now: 102,
    })?;
    assert_eq!(usize::from(matches!(retry, EnqueueOutcome::Enqueued(_))), 1);
    executor.outcome = OutboundExecutionOutcome::delivered_to_channel("provider:retry:ok");
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 103)
            .unwrap(),
        1
    );
    assert_eq!(executor.calls.len(), 2);
    let delivered_task = vault
        .connector_send_task(&task_ref)?
        .expect("retried connector task");
    assert!(delivered_task.attempt_started_node_id.is_some());
    assert_eq!(
        delivered_task.outcome,
        Some(ConnectorSendTaskOutcome::Delivered)
    );
    assert_eq!(
        usize::from(send_receipt_exists_for_task(&vault, task_ref)?),
        1
    );
    assert_eq!(
        vault
            .store
            .get_delivered_send_task_by_idempotency(&actor, "failed-receipt-retry:test")?,
        Some(task_ref)
    );
    let delivered_receipts =
        vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(delivered_receipts.len(), 2);
    assert_eq!(delivered_receipts[0].outcome, "delivered_to_channel");
    assert_eq!(delivered_receipts[1], failed_receipts[0]);
    assert_ne!(
        delivered_receipts[0].receipt_id,
        failed_receipts[0].receipt_id
    );
    assert_eq!(
        crate::receipt::delivered_send_receipt_for_task(&vault, task_ref)?,
        Some(delivered_receipts[0].clone())
    );
    assert!(!crate::receipt::persist_send_receipt(
        &vault,
        task_ref,
        delivered_receipts[0].clone(),
        SendReceiptOutcome::Delivered,
        true,
        Some((actor, "failed-receipt-retry:test")),
    )?);
    assert_eq!(
        vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?,
        delivered_receipts
    );
    let attempts = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Failed)
            .count(),
        1
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Completed)
            .count(),
        1
    );
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 104)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 2);
    Ok(())
}

#[test]
fn connector_task_retry_mints_a_fresh_attempt_under_one_task() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x6E);
    put_connector_task_actor(&vault, actor, 200)?;
    vault.register_connector_key(&entity(0x70), sends_per_day_key(5))?;
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "attempt-row-retry:test",
            "session:attempt-row-retry",
            200,
        ))
        .expect("schedule outbound");
    let tasks = vault.connector_send_tasks()?;
    assert_eq!(tasks.len(), 1);
    let task_ref = tasks[0].task_ref;

    let queue = AttemptQueue::new(&vault);
    let scheduled = queue
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(scheduled.len(), 1);
    let first_attempt = scheduled[0].id;

    // With no granting manifest the default gate floors this send to Pending,
    // so the dispatch is Held: retryable, never terminal, and never sent.
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 201)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 0);

    // One TASK, two ATTEMPT rows: the try that ran is terminal history and the
    // next try is a distinct scheduled row linked back to it.
    assert_eq!(vault.connector_send_tasks()?.len(), 1);
    let attempts = queue
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 2);
    let source = attempts
        .iter()
        .find(|attempt| attempt.id == first_attempt)
        .expect("source try stays point-readable");
    assert_eq!(source.state, AttemptState::Failed);
    assert_eq!(source.retry_of, None);
    let retry = attempts
        .iter()
        .find(|attempt| attempt.id != first_attempt)
        .expect("fresh retry row");
    assert_eq!(retry.state, AttemptState::Scheduled);
    assert_eq!(retry.retry_of, Some(first_attempt));
    // ONE-1879: this hold is the GATE's, so the seconds-scale re-arm curve
    // authors the instant — a first try at 201 re-arms one second later.
    assert_eq!(retry.scheduled_at, Some(202));
    assert_eq!(retry.attempt_count, 0);
    assert_eq!(retry.payload, source.payload);
    assert_eq!(retry.task_ref, source.task_ref);

    // The scheduled retry is not claimable before its instant, so the executor
    // loop terminates instead of spinning on the same task.
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 201)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 0);

    // Once its instant has passed the fresh row runs against the now-granting
    // manifest, and the ONE logical send is charged exactly once.
    put_policy_manifest_bytes(
        &vault,
        entity(0x6F),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    executor.outcome = OutboundExecutionOutcome::delivered_to_channel("provider:attempt-row:ok");
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 261)
            .unwrap(),
        1
    );
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(
        vault
            .effector_budget_read("email", None)?
            .expect("budget after the retry")
            .rows[0]
            .used,
        1
    );

    assert_eq!(vault.connector_send_tasks()?.len(), 1);
    assert_eq!(
        vault
            .connector_send_task(&task_ref)?
            .expect("task after delivery")
            .outcome,
        Some(ConnectorSendTaskOutcome::Delivered)
    );
    let final_attempts = queue
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(final_attempts.len(), 2);
    assert_eq!(
        final_attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Completed)
            .count(),
        1
    );
    assert_eq!(
        final_attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Failed)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn logical_send_is_charged_once_across_fresh_retry_attempts() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x4F);
    put_connector_task_actor(&vault, actor, 110)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x50),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault.register_connector_key(&entity(0x51), sends_per_day_key(5))?;
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "charge-once-retry:test",
            "session:charge-once-retry",
            110,
        ))
        .expect("schedule outbound");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let queue = AttemptQueue::new(&vault);
    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("transport_not_started"),
        ..Default::default()
    };

    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 111)
            .unwrap(),
        0
    );
    for now in [112, 114] {
        let retry = queue.enqueue(EnqueueAttempt {
            kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
            payload: connector_send_attempt_payload(task_ref)?,
            dedupe_key: None,
            run_id: None,
            now,
        })?;
        assert!(matches!(retry, EnqueueOutcome::Enqueued(_)));
        if now == 114 {
            executor.outcome =
                OutboundExecutionOutcome::delivered_to_channel("provider:retry:delivered");
        }
        let delivered = vault
            .run_connector_task_executor(&mut executor, now + 1)
            .unwrap();
        assert_eq!(delivered, usize::from(now == 114));
    }

    assert_eq!(executor.calls.len(), 3);
    assert_eq!(
        vault
            .effector_budget_read("email", None)?
            .expect("budget after retries")
            .rows[0]
            .used,
        1
    );
    Ok(())
}

#[test]
fn maybe_delivered_fresh_retry_reuses_provider_idempotency_key() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x52);
    put_connector_task_actor(&vault, actor, 120)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x53),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let mut draft = connector_task_draft(
        "same-provider-key-retry:test",
        "session:same-provider-key-retry",
        120,
    );
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule outbound");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };

    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 121)
            .unwrap(),
        0
    );
    let retry = AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
        payload: connector_send_attempt_payload(task_ref)?,
        dedupe_key: None,
        run_id: None,
        now: 121,
    })?;
    assert!(matches!(retry, EnqueueOutcome::Enqueued(_)));
    executor.outcome = OutboundExecutionOutcome::delivered_to_channel("provider:retry:delivered");
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 121)
            .unwrap(),
        1
    );

    assert_eq!(executor.idempotency_keys.len(), 2);
    assert!(executor.idempotency_keys[0].is_some());
    assert_eq!(executor.idempotency_keys[1], executor.idempotency_keys[0]);
    Ok(())
}

#[test]
fn failed_not_delivered_fresh_retry_replays_existing_intent() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x5A);
    put_connector_task_actor(&vault, actor, 130)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x5B),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "failed-replay-existing-intent:test",
            "session:failed-replay-existing-intent",
            130,
        ))
        .expect("schedule outbound");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("transport_not_started"),
        ..Default::default()
    };

    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 131)
            .unwrap(),
        0
    );
    let failed_records = crate::outbound_intent_ledger::intent_ledger_records(&vault)
        .expect("failed intent ledger read");
    assert_eq!(failed_records.len(), 1);
    assert_eq!(
        failed_records[0].state,
        crate::outbound_intent_ledger::IntentState::Pending
    );
    assert_eq!(
        failed_records[0].recorded_outcome,
        Some(crate::outbound_intent_ledger::RecordedOutboundOutcome::DefiniteNonDelivery)
    );

    let retry = AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
        payload: connector_send_attempt_payload(task_ref)?,
        dedupe_key: None,
        run_id: None,
        now: 132,
    })?;
    assert!(matches!(retry, EnqueueOutcome::Enqueued(_)));
    executor.outcome = OutboundExecutionOutcome::delivered_to_channel("provider:retry:ok");
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 133)
            .unwrap(),
        1
    );

    assert_eq!(executor.idempotency_keys.len(), 2);
    assert_eq!(executor.idempotency_keys[1], executor.idempotency_keys[0]);
    let delivered_records = crate::outbound_intent_ledger::intent_ledger_records(&vault)
        .expect("delivered intent ledger read");
    assert_eq!(delivered_records.len(), 1);
    assert_eq!(delivered_records[0].id, failed_records[0].id);
    assert_eq!(
        delivered_records[0].state,
        crate::outbound_intent_ledger::IntentState::Done
    );
    assert_eq!(
        vault
            .connector_send_task(&task_ref)?
            .expect("retried connector task")
            .outcome,
        Some(ConnectorSendTaskOutcome::Delivered)
    );
    Ok(())
}

#[test]
fn non_idempotent_send_masks_provider_idempotency_key() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x63);
    put_connector_task_actor(&vault, actor, 150)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x64),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "mask-idem-key:test",
            "session:mask-idem-key",
            150,
        ))
        .expect("schedule outbound");
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 151)
            .unwrap(),
        1
    );

    // email/send is NonIdempotentInterrupt: the sink must not be handed the
    // ledger id as a provider idempotency (dedup) token, even though the ledger
    // row still keys the intent internally.
    assert_eq!(executor.idempotency_keys, vec![None]);
    let row = crate::outbound_intent_ledger::intent_ledger_records(&vault)
        .expect("ledger read")
        .into_iter()
        .next()
        .expect("one intent row");
    assert!(
        !row.idempotency_key.is_empty(),
        "the ledger still stores the intent's idempotency key"
    );
    assert!(!row.idempotency_supported, "non-idempotent verb");
    Ok(())
}

#[test]
fn connector_executor_hands_sink_the_stable_scheduled_ref() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x60);
    put_connector_task_actor(&vault, actor, 140)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x61),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "stable-sink-ref:test",
            "session:stable-sink-ref",
            140,
        ))
        .expect("schedule outbound");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 141)
            .unwrap(),
        1
    );

    // Sinks key their per-send plan by `request.intent_ref`, so the executor
    // must hand the sink the stable scheduled task ref — not the private
    // logical-send hash that anchors the ledger/charge identity.
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(
        executor.calls[0].0,
        format!("intent:task:{}", task_ref.to_hex())
    );
    assert!(
        !executor.calls[0].0.starts_with("intent:logical-send:"),
        "the private ledger identity must not leak to the sink"
    );
    Ok(())
}

#[test]
fn replayed_delivery_omits_fabricated_gate_ref() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{FIELD_TASK_REF, ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x65);
    put_connector_task_actor(&vault, actor, 160)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x66),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let mut draft = connector_task_draft("replay-gate-ref:test", "session:replay-gate-ref", 160);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule outbound");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;

    // Attempt 1 comes back maybe-delivered: the idempotent intent stays Pending.
    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 161)
            .unwrap(),
        0
    );

    // A fresh attempt replays the same Pending intent and delivers.
    let retry = AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
        payload: connector_send_attempt_payload(task_ref)?,
        dedupe_key: None,
        run_id: None,
        now: 161,
    })?;
    assert!(matches!(retry, EnqueueOutcome::Enqueued(_)));
    executor.outcome = OutboundExecutionOutcome::delivered_to_channel("provider:replay:delivered");
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 162)
            .unwrap(),
        1
    );

    // The replay carries no gate decision id, so the delivered receipt must omit
    // gate_decision_ref rather than fabricate a non-queryable `intent:` value.
    let receipts = vault.receipts(ReceiptQuery::new(160).with_kind(ReceiptKind::Outbound))?;
    let delivered = receipts
        .iter()
        .find(|receipt| {
            receipt.fields.get(FIELD_TASK_REF).map(String::as_str)
                == Some(task_ref.to_hex().as_str())
        })
        .expect("delivered send receipt");
    assert!(
        !delivered.fields.contains_key("gate_decision_ref"),
        "a replayed send must not fabricate an intent: gate ref"
    );
    Ok(())
}

#[test]
fn send_receipt_point_lookup_skips_gate_and_sink_without_scanning() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{
        ReceiptKind, ReceiptQuery, outbound_intent_receipt, persist_send_receipt,
    };

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x33);
    put_connector_task_actor(&vault, actor, 20)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x34),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "point-receipt:test",
            "session:point-receipt",
            20,
        ))
        .expect("schedule outbound");

    let tasks = vault.connector_send_tasks()?;
    assert_eq!(tasks.len(), 1);
    let task_ref = tasks[0].task_ref;
    let receipt = outbound_intent_receipt(
        "outbound:preexisting",
        "intent:preexisting",
        &tasks[0].intent,
        21,
        "delivered_to_channel",
    );
    assert_eq!(
        usize::from(persist_send_receipt(
            &vault,
            task_ref,
            receipt,
            SendReceiptOutcome::Delivered,
            false,
            Some((actor, "point-receipt:test")),
        )?),
        1
    );
    assert_eq!(
        usize::from(vault.store.get_send_receipt_by_task(&task_ref)?.is_some()),
        1
    );

    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 22)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 0);
    assert_eq!(executor.idempotency_keys.len(), 0);
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .len(),
        1
    );
    let attempts = AttemptQueue::new(&vault).list()?;
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| {
                attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND
                    && attempt.state == AttemptState::Completed
            })
            .count(),
        1
    );
    Ok(())
}

#[test]
fn schedule_denial_is_not_enqueued_and_does_not_block_allowed_task() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{FIELD_TASK_REF, ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let denied_actor = entity(0x35);
    let allowed_actor = entity(0x36);
    put_connector_task_actor(&vault, denied_actor, 30)?;
    put_connector_task_actor(&vault, allowed_actor, 30)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x37),
        &policy_manifest(&denied_actor.to_hex(), "email", &["send"]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x62),
        &policy_manifest(&allowed_actor.to_hex(), "slack", &["send"]),
    )?;
    let denied_key = entity(0x43);
    vault.register_connector_key(
        &denied_key,
        crate::connector_key::ConnectorKeyRecord::active("email", None, Vec::new(), 30),
    )?;
    vault.suspend_connector_key(&denied_key, "test_denial", 30)?;
    let denied = vault
        .memory(denied_actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "batch-denied:test",
            "session:batch-denied",
            30,
        ))
        .expect("schedule denied outbound");
    assert_eq!(denied.outcome, "suppressed");
    let mut allowed_draft = connector_task_draft("batch-allowed:test", "session:batch-allowed", 31);
    allowed_draft.channel = "slack".to_owned();
    vault
        .memory(allowed_actor, EdgeActorClass::Agent)
        .schedule_outbound(&allowed_draft)
        .expect("schedule allowed outbound");

    let tasks = vault.connector_send_tasks()?;
    assert_eq!(tasks.len(), 1);
    let allowed_task = tasks
        .iter()
        .find(|task| task.actor_ref == allowed_actor)
        .expect("allowed task")
        .task_ref;
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 32)
            .unwrap(),
        1
    );
    assert_eq!(executor.calls.len(), 1);

    let attempts = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Leased)
            .count(),
        0
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Completed)
            .count(),
        1
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.fields.get(FIELD_TASK_REF) == Some(&allowed_task.to_hex()))
            .count(),
        1
    );
    Ok(())
}

#[test]
fn off_record_schedule_is_rejected_before_task_or_attempt_persistence() -> crate::Result<()> {
    use crate::attempt_queue::AttemptQueue;
    use crate::memory::{BRIDGE_OUTBOUND_ATTEMPT_KIND, MEMORY_CODE_BAD_REQUEST};
    use crate::off_record::{OffRecordBackendClass, OffRecordMode};
    use crate::receipt::{ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x38);
    put_connector_task_actor(&vault, actor, 40)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x39),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let session_ref = "session:off-record-executor";
    vault.enter_off_record_session(session_ref, OffRecordBackendClass::Local)?;
    let draft = connector_task_draft("off-record:test", session_ref, 40);
    let err = vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect_err("off-record outbound is talk-only");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);

    let tasks = vault.connector_send_tasks()?;
    assert_eq!(tasks.len(), 0);
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .into_iter()
            .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
            .count(),
        0
    );

    vault.set_off_record_session_mode(session_ref, OffRecordMode::OnRecord)?;
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 41)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 0);
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .len(),
        0
    );

    // The rejected schedule left the idempotency key free. Once the same
    // originating session is on-record, the same draft schedules normally.
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule on-record outbound");
    assert_eq!(vault.connector_send_tasks()?.len(), 1);
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .into_iter()
            .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
            .count(),
        1
    );
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 43)
            .unwrap(),
        1
    );
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn preexisting_send_receipt_does_not_debit_budget_again() -> crate::Result<()> {
    use crate::receipt::{outbound_intent_receipt, persist_send_receipt};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x3A);
    put_connector_task_actor(&vault, actor, 50)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x3B),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault.register_connector_key(&entity(0x3C), sends_per_day_key(5))?;
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "budget-replay:test",
            "session:budget-replay",
            50,
        ))
        .expect("schedule outbound");
    let tasks = vault.connector_send_tasks()?;
    assert_eq!(tasks.len(), 1);
    let receipt = outbound_intent_receipt(
        "outbound:budget-replay",
        "intent:budget-replay",
        &tasks[0].intent,
        51,
        "delivered_to_channel",
    );
    assert_eq!(
        usize::from(persist_send_receipt(
            &vault,
            tasks[0].task_ref,
            receipt,
            SendReceiptOutcome::Delivered,
            true,
            Some((actor, "budget-replay:test")),
        )?),
        1
    );
    let before = vault
        .effector_budget_read("email", None)?
        .expect("budget before");
    assert_eq!(before.rows[0].used, 0);

    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 52)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 0);
    let after = vault
        .effector_budget_read("email", None)?
        .expect("budget after");
    assert_eq!(after.rows[0].used, 0);
    Ok(())
}

#[test]
fn schedule_gate_error_leaves_nothing_claimable_and_retry_creates_one() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x3D);
    put_connector_task_actor(&vault, actor, 60)?;
    let malformed = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_QUIET,
        ClaimSubject::Entity(actor),
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from("applies_to"),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (Value::from("window"), Value::from("malformed")),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    put_claim_body(&vault, 0x3E, &malformed)?;
    let draft = connector_task_draft("gate-error-retry:test", "session:gate-error", 60);

    let err = vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect_err("malformed gate claim fails schedule");
    assert_eq!(err.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    assert_eq!(vault.connector_send_tasks()?.len(), 0);
    let attempts = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .count();
    assert_eq!(attempts, 0);
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 61)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 0);

    let replacement = ClaimBody::new(
        "test.non_delivery_window",
        ClaimSubject::Entity(actor),
        Value::from("ok"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    put_claim_body(&vault, 0x3E, &replacement)?;
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("retry schedules");
    assert_eq!(vault.connector_send_tasks()?.len(), 1);
    let attempts = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Queued)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn undecodable_attempt_fails_and_valid_task_in_batch_executes() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState, EnqueueAttempt, EnqueueOutcome};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x3F);
    put_connector_task_actor(&vault, actor, 70)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x40),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let queue = AttemptQueue::new(&vault);
    let invalid = queue.enqueue(EnqueueAttempt {
        kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
        payload: br#"{"legacy":"outbound-draft"}"#.to_vec(),
        dedupe_key: None,
        run_id: None,
        now: 70,
    })?;
    assert_eq!(
        usize::from(matches!(invalid, EnqueueOutcome::Enqueued(_))),
        1
    );
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "valid-after-legacy:test",
            "session:valid-after-legacy",
            71,
        ))
        .expect("schedule valid outbound");

    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 72)
            .unwrap(),
        1
    );
    assert_eq!(executor.calls.len(), 1);
    let attempts = queue
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Failed)
            .count(),
        1
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Completed)
            .count(),
        1
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| attempt.state == AttemptState::Leased)
            .count(),
        0
    );
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn conflicting_connector_actor_id_rejects_schedule_without_task() -> crate::Result<()> {
    use crate::attempt_queue::AttemptQueue;
    use crate::memory::{BRIDGE_OUTBOUND_ATTEMPT_KIND, MEMORY_CODE_INTERNAL};
    use crate::registry::ENTITY_TYPE_MACHINE;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x41);
    put_connector_task_actor(&vault, actor, 80)?;
    let connector_ref = connector_actor_id("email")?;
    let conflicting_body = rmp_serde::to_vec_named(&ConnectorActorBody {
        schema_version: CONNECTOR_ACTOR_SCHEMA_VERSION,
        actor_kind: CONNECTOR_ACTOR_KIND.to_owned(),
        connector_class: "slack".to_owned(),
    })
    .expect("encode conflicting connector actor");
    vault.put_entity(
        &connector_ref,
        ENTITY_TYPE_MACHINE,
        crate::temporal::TimeRange { start: 80, end: 80 },
        80,
        &conflicting_body,
    )?;

    let err = vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "actor-collision:test",
            "session:actor-collision",
            80,
        ))
        .expect_err("connector actor collision");
    assert_eq!(err.code, MEMORY_CODE_INTERNAL);
    assert_eq!(vault.connector_send_tasks()?.len(), 0);
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .into_iter()
            .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
            .count(),
        0
    );
    assert_eq!(
        usize::from(connector_actor_matches(&vault, connector_ref, "email")?),
        0
    );
    Ok(())
}
