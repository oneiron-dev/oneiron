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
        target: "transport:shared-inbox".to_owned(),
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
        .schedule_outbound_for_counterparty(&draft, "counterparty:durable-idempotency")
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
    assert_eq!(unsettled.intent.target, "transport:shared-inbox");
    assert_eq!(
        unsettled.counterparty_ref.as_deref(),
        Some("counterparty:durable-idempotency")
    );

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
    // No separate manual comm event is needed: the projector consumes the
    // durable send receipt. A second pass cannot duplicate the standing head.
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            "counterparty:durable-idempotency",
            "email",
        )
        .expect("comm claim query"),
        0
    );
    crate::comm::run_comm_projector(&vault).expect("project send receipts");
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            "transport:shared-inbox",
            "email",
        )
        .expect("target claim query"),
        0,
        "transport destination is not a PERSON contact",
    );
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            "counterparty:durable-idempotency",
            "email",
        )
        .expect("comm claim query"),
        1
    );
    crate::comm::run_comm_projector(&vault).expect("project send receipts");
    assert_eq!(
        crate::comm::count_total_comm_claim_rows(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            "counterparty:durable-idempotency",
            "email",
        )
        .expect("comm claim query"),
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
        .schedule_outbound_for_counterparty(&draft, &draft.target)
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
    crate::comm::run_comm_projector(&vault).expect("project failed send");
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            &draft.target,
            "email",
        )
        .expect("comm claim query"),
        0
    );
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
    crate::comm::run_comm_projector(&vault).expect("project delivered retry");
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            &draft.target,
            "email",
        )
        .expect("comm claim query"),
        1
    );
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

    fn active_touch_times(vault: &Vault, party: EntityId) -> crate::Result<Vec<u64>> {
        let mut times = Vec::new();
        for id in vault.claims_for_subject(&party)? {
            let Some(body) = vault.get_claim(&id)? else {
                continue;
            };
            if body.predicate != crate::comm::PREDICATE_COMM_LAST_TOUCH {
                continue;
            }
            let claim = crate::comm::CommClaim::from_claim_body(&body)?;
            if claim.lifecycle != crate::claim::ClaimLifecycleStatus::Active
                || claim.valid_to.is_some()
            {
                continue;
            }
            let crate::comm::CommClaimValue::LastTouch {
                party_ref,
                occurred_at,
                ..
            } = claim.value
            else {
                unreachable!("last-touch predicate has a last-touch value")
            };
            assert_eq!(party_ref, party);
            times.push(occurred_at);
        }
        Ok(times)
    }

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x52);
    put_connector_task_actor(&vault, actor, 120)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x53),
        &policy_manifest(&actor.to_hex(), "email_resend", &["send"]),
    )?;
    let mut draft = connector_task_draft(
        "same-provider-key-retry:test",
        "session:same-provider-key-retry",
        120,
    );
    // Preserve provider-native retry and main's counterparty-bound projection.
    draft.channel = "email_resend".to_owned();
    draft.target = "transport:shared-correction-inbox".to_owned();
    let party = "party:correction-recipient";
    crate::comm::record_comm_send_receipt(&vault, party, "email", 100)
        .expect("record older delivered message");
    crate::comm::run_comm_projector(&vault).expect("project older touch");
    let party_ref =
        crate::comm::resolve_or_create_comm_party(&vault, party).expect("resolve prior party");
    assert_eq!(active_touch_times(&vault, party_ref)?, vec![100]);
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound_for_counterparty(&draft, party)
        .expect("schedule bound correction email");
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
    crate::comm::run_comm_projector(&vault).expect("failed retry cannot advance touch");
    assert_eq!(active_touch_times(&vault, party_ref)?, vec![100]);
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

    crate::comm::run_comm_projector(&vault).expect("project delivered correction");
    assert_eq!(active_touch_times(&vault, party_ref)?, vec![121]);
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            &draft.target,
            "email",
        )
        .expect("transport target is not a party"),
        0
    );
    crate::comm::run_comm_projector(&vault).expect("replay delivered correction");
    assert_eq!(active_touch_times(&vault, party_ref)?, vec![121]);
    assert_eq!(
        crate::comm::count_total_comm_claim_rows(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            party,
            "email",
        )
        .expect("touch history"),
        2
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

    // Generic email/send has no provider key: the sink must not be handed the
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
    use crate::memory::{BRIDGE_OUTBOUND_ATTEMPT_KIND, MEMORY_CODE_FORBIDDEN};
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
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);

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

#[test]
fn maybe_delivered_non_idempotent_send_is_ambiguously_terminal() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState, EnqueueAttempt};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0xA7);
    put_connector_task_actor(&vault, actor, 200)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xA8),
        &policy_manifest(&actor.to_hex(), "telegram", &["send"]),
    )?;
    let mut draft = connector_task_draft("ambiguous-send:test", "session:ambiguous", 200);
    draft.channel = "telegram".to_owned();
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
            .run_connector_task_executor(&mut executor, 201)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(executor.idempotency_keys, vec![None]);
    let task = vault.connector_send_task(&task_ref)?.expect("synced task");
    assert!(task.attempt_started_node_id.is_some());
    assert_eq!(task.outcome, Some(ConnectorSendTaskOutcome::Ambiguous));
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "ambiguous");
    assert_eq!(
        receipts[0]
            .fields
            .get("delivery_may_have_occurred")
            .map(String::as_str),
        Some("true")
    );
    assert!(!send_receipt_exists_for_task(&vault, task_ref)?);
    assert_eq!(
        vault
            .store
            .get_delivered_send_task_by_idempotency(&actor, "ambiguous-send:test")?,
        None
    );
    let attempts = AttemptQueue::new(&vault).list()?;
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].state, AttemptState::Failed);
    assert_eq!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("ledger read")[0].state,
        crate::outbound_intent_ledger::IntentState::Abandoned
    );

    assert_ambiguous_on_task_board(&vault, actor, task_ref);

    // A duplicate queue row cannot turn the uncertain outcome into a send permit.
    AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
        payload: connector_send_attempt_payload(task_ref)?,
        dedupe_key: None,
        run_id: None,
        now: 202,
    })?;
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 203)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous)
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
fn maybe_delivered_idempotent_send_audits_ambiguity_until_reconciled() -> crate::Result<()> {
    use crate::receipt::{ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0xA9);
    put_connector_task_actor(&vault, actor, 210)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xAA),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let mut draft = connector_task_draft("ambiguous-replace:test", "session:replace", 210);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 211)
            .unwrap(),
        0
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "ambiguous");
    assert_eq!(vault.connector_send_task(&task_ref)?.unwrap().outcome, None);
    assert!(!send_receipt_exists_for_task(&vault, task_ref)?);
    assert_eq!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("ledger read")[0].state,
        crate::outbound_intent_ledger::IntentState::Pending
    );
    executor.outcome = OutboundExecutionOutcome::delivered_to_channel("provider:replace:ok");
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 271)
            .unwrap(),
        1
    );
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Delivered)
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[1].outcome, "ambiguous");
    assert_eq!(receipts[0].outcome, "delivered_to_channel");
    assert_eq!(executor.idempotency_keys[0], executor.idempotency_keys[1]);
    Ok(())
}

#[test]
fn synced_ambiguous_arrival_between_read_and_attempt_start_cannot_send() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState};
    use crate::outbound::connector_task::project_connector_send_task_outcome;
    use crate::outbound::executor::set_before_attempt_start_hook;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0xAC);
    put_connector_task_actor(&vault, actor, 240)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xAD),
        &policy_manifest(&actor.to_hex(), "telegram", &["send"]),
    )?;
    let mut draft = connector_task_draft("remote-ambiguous:test", "session:remote", 240);
    draft.channel = "telegram".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    // A synced terminal TASK arrives after the executor hydrates its stale
    // snapshot, before the attempt-start transaction. This node has no local
    // receipt or intent that could independently prevent a duplicate send.
    set_before_attempt_start_hook(move |vault| {
        project_connector_send_task_outcome(
            vault,
            task_ref,
            ConnectorSendTaskOutcome::Ambiguous,
            241,
        )
        .expect("import terminal TASK");
    });
    let mut sink = RecordingExecutor::default();
    assert_eq!(
        vault.run_connector_task_executor(&mut sink, 242).unwrap(),
        0
    );
    assert!(sink.calls.is_empty());
    assert!(!send_receipt_exists_for_task(&vault, task_ref)?);
    assert!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault)
            .expect("local intent listing")
            .records
            .is_empty()
    );
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous)
    );
    assert_eq!(
        AttemptQueue::new(&vault).list()?[0].state,
        AttemptState::Completed
    );
    Ok(())
}

#[test]
fn revoked_uncertain_replace_remains_ambiguous_on_synced_task() -> crate::Result<()> {
    use crate::receipt::{ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0xB0);
    let key_ref = entity(0xB1);
    put_connector_task_actor(&vault, actor, 1_280)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xB2),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    vault.register_connector_key(&key_ref, sends_per_day_key(5))?;
    let mut draft = connector_task_draft("revoke-uncertain:test", "session:revoke", 1_280);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };
    assert_eq!(
        vault.run_connector_task_executor(&mut sink, 1_281).unwrap(),
        0
    );
    assert_eq!(vault.connector_send_task(&task_ref)?.unwrap().outcome, None);
    vault.revoke_connector_key(&key_ref, 1_282)?;
    assert_eq!(
        vault.run_connector_task_executor(&mut sink, 1_341).unwrap(),
        0
    );
    assert_eq!(
        sink.calls.len(),
        1,
        "revocation forbids a second transport call"
    );
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous)
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(receipts.len(), 2);
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.outcome == "ambiguous")
    );
    assert_eq!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("ledger")[0].state,
        crate::outbound_intent_ledger::IntentState::Abandoned
    );
    Ok(())
}

fn assert_ambiguous_on_task_board(vault: &Vault, actor: EntityId, task_ref: EntityId) {
    use crate::task_verb::TaskDescription;

    let memory = vault.memory(actor, EdgeActorClass::Agent);
    let TaskDescription::Section(section) = memory.describe(None).expect("ordinary task board")
    else {
        panic!("expected section");
    };
    let row = section
        .rows
        .iter()
        .find(|row| row.id == task_ref.to_hex())
        .expect("TASK row");
    assert_eq!(row.status, crate::context_board::TaskBoardStatus::Failed);
    assert_eq!(
        row.connector_outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous)
    );
    assert!(row.line.contains("failed ambiguous"));
    let TaskDescription::Card { lines } = memory.describe(Some(task_ref)).expect("task detail")
    else {
        panic!("expected card");
    };
    assert_eq!(lines.first(), Some(&row.line));
}

#[cfg(feature = "sync")]
#[test]
fn peer_task_only_projection_shows_ambiguous_without_local_receipt() -> crate::Result<()> {
    use crate::attempt_queue::AttemptQueue;
    use crate::sync::{
        bridge::Materializer,
        schema::create_window_doc,
        types::WindowKey,
        window::{forward_rematerialize, reverse_rematerialize},
    };
    use loro::ExportMode;

    let (_source_tmp, source) = temp_vault();
    let (_peer_tmp, peer) = temp_vault();
    let actor = entity(0xBD);
    put_connector_task_actor(&source, actor, 400)?;
    put_policy_manifest_bytes(
        &source,
        entity(0xBE),
        &policy_manifest(&actor.to_hex(), "telegram", &["send"]),
    )?;
    let mut draft = connector_task_draft("peer-uncertain:test", "session:peer", 400);
    draft.channel = "telegram".to_owned();
    source
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = source.connector_send_tasks()?[0].task_ref;
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };
    source.run_connector_task_executor(&mut sink, 401).unwrap();
    assert_eq!(
        source.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous)
    );

    let window = WindowKey::from_timestamp(400);
    let source_doc = create_window_doc("source", &window);
    reverse_rematerialize(&source, &source_doc, &window)?;
    let update = source_doc
        .export(ExportMode::all_updates())
        .expect("export");
    let peer_doc = create_window_doc("peer", &window);
    peer_doc.import(&update).expect("import");
    forward_rematerialize(&peer, &peer_doc, &Materializer::new(), &window)?;
    assert!(peer.get_raw(&task_ref)?.is_some(), "TASK traveled to peer");
    assert!(AttemptQueue::new(&peer).list()?.is_empty());
    assert!(peer.store.get_send_receipt_by_task(&task_ref)?.is_none());
    assert!(
        crate::outbound_intent_ledger::intent_ledger_records(&peer)
            .expect("peer intent listing")
            .records
            .is_empty()
    );
    let task = peer
        .connector_send_task(&task_ref)?
        .expect("peer connector TASK");
    assert_eq!(task.outcome, Some(ConnectorSendTaskOutcome::Ambiguous));
    assert_ambiguous_on_task_board(&peer, actor, task_ref);
    Ok(())
}

#[test]
fn revocation_after_definite_non_delivery_remains_failed() -> crate::Result<()> {
    use crate::receipt::{ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0xBF);
    let key_ref = entity(0xC0);
    put_connector_task_actor(&vault, actor, 1_300)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xC1),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    vault.register_connector_key(&key_ref, sends_per_day_key(5))?;
    let mut draft = connector_task_draft("revoke-definite:test", "session:definite", 1_300);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("transport_not_started"),
        ..Default::default()
    };
    assert_eq!(
        vault.run_connector_task_executor(&mut sink, 1_301).unwrap(),
        0
    );
    assert_eq!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("ledger")[0]
            .recorded_outcome,
        Some(crate::outbound_intent_ledger::RecordedOutboundOutcome::DefiniteNonDelivery)
    );
    vault.revoke_connector_key(&key_ref, 1_302)?;
    assert_eq!(
        vault.run_connector_task_executor(&mut sink, 1_361).unwrap(),
        0
    );
    assert_eq!(sink.calls.len(), 1);
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Failed)
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().all(|receipt| receipt.outcome == "failed"));
    Ok(())
}

fn next_connector_send_retry_at(vault: &Vault) -> crate::Result<u64> {
    use crate::attempt_queue::{AttemptQueue, AttemptState};
    Ok(AttemptQueue::new(vault)
        .list()?
        .into_iter()
        .filter(|row| row.state == AttemptState::Scheduled)
        .filter_map(|row| row.scheduled_at)
        .max()
        .expect("scheduled connector retry"))
}

#[test]
fn earlier_uncertainty_survives_later_definite_non_delivery_and_revocation() -> crate::Result<()> {
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    let (tmp, vault) = temp_vault();
    let actor = entity(0xC2);
    let key_ref = entity(0xC3);
    put_connector_task_actor(&vault, actor, 1_400)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xC4),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    vault.register_connector_key(&key_ref, sends_per_day_key(5))?;
    let mut draft =
        connector_task_draft("uncertain-then-not-started:test", "session:history", 1_400);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };
    vault.run_connector_task_executor(&mut sink, 1_401).unwrap();
    assert_eq!(sink.calls.len(), 1);
    assert!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("first ledger")[0]
            .delivery_uncertain
    );
    let second_at = next_connector_send_retry_at(&vault)?;
    sink.outcome = OutboundExecutionOutcome::failed("transport_not_started");
    vault
        .run_connector_task_executor(&mut sink, second_at)
        .unwrap();
    assert_eq!(sink.calls.len(), 2);
    let prior = crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("ledger");
    assert_eq!(
        prior[0].recorded_outcome,
        Some(crate::outbound_intent_ledger::RecordedOutboundOutcome::DefiniteNonDelivery)
    );
    assert!(
        prior[0].delivery_uncertain,
        "later non-delivery cannot erase history"
    );
    drop(vault);
    let vault = Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    assert!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("reopened ledger")[0]
            .delivery_uncertain
    );
    vault.revoke_connector_key(&key_ref, second_at + 1)?;
    vault
        .run_connector_task_executor(&mut sink, next_connector_send_retry_at(&vault)?)
        .unwrap();
    assert_eq!(sink.calls.len(), 2, "revocation must not reach transport");
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous)
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].outcome, "ambiguous");
    assert_eq!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("terminal ledger")[0]
            .recorded_outcome,
        Some(
            crate::outbound_intent_ledger::RecordedOutboundOutcome::Abandoned(
                crate::outbound_intent_ledger::IntentEscalationReason::ConnectorRevoked
            )
        )
    );
    assert_ambiguous_on_task_board(&vault, actor, task_ref);
    Ok(())
}

#[test]
fn lost_originating_actor_does_not_erase_prior_uncertain_delivery() -> crate::Result<()> {
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    let (_tmp, vault) = temp_vault();
    let actor = entity(0xC5);
    put_connector_task_actor(&vault, actor, 1_500)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xC6),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let mut draft = connector_task_draft("lost-actor-uncertain:test", "session:actor", 1_500);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };
    vault.run_connector_task_executor(&mut sink, 1_501).unwrap();
    let retry_at = next_connector_send_retry_at(&vault)?;
    vault.delete_entity(&actor)?;
    assert!(
        vault.connector_send_task(&task_ref)?.is_some(),
        "connector assignee remains"
    );
    vault
        .run_connector_task_executor(&mut sink, retry_at)
        .unwrap();
    assert_eq!(
        sink.calls.len(),
        1,
        "invalid actor cannot make a second send"
    );
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous)
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].outcome, "ambiguous");
    Ok(())
}

#[test]
fn lost_originating_actor_before_first_send_is_definite_failure() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0xC7);
    put_connector_task_actor(&vault, actor, 1_600)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xC8),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let mut draft = connector_task_draft("lost-actor-fresh:test", "session:fresh", 1_600);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    vault.delete_entity(&actor)?;
    let mut sink = RecordingExecutor::default();
    vault.run_connector_task_executor(&mut sink, 1_601).unwrap();
    assert!(sink.calls.is_empty());
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Failed)
    );
    Ok(())
}

#[test]
fn semantic_suppression_is_visible_on_synced_task_and_receipt() -> crate::Result<()> {
    use crate::memory::OutboundDraftInput;
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x7a);
    put_connector_task_actor(&vault, actor, 90)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x7b),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let draft = |name: &str| OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "counterparty:cooldown".to_owned(),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some(format!("idem:{name}")),
        dedupe_key: Some("reminder:one".to_owned()),
        trigger: "agent_immediate".to_owned(),
        trigger_ref: format!("session:{name}"),
        job_ref: None,
        occurred_at: Some(90),
    };
    let first = vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft("first"))
        .expect("schedule first");
    let mut sink = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, 91)
            .expect("send first"),
        1
    );
    let second = vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft("second"))
        .expect("schedule second");
    assert_ne!(first.intent_ref, second.intent_ref);
    let second_ref = vault
        .connector_send_tasks()?
        .into_iter()
        .find(|task| task.intent.idempotency_key.as_deref() == Some("idem:second"))
        .expect("second task")
        .task_ref;
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, 92)
            .expect("collapse second"),
        0
    );
    assert_eq!(sink.calls.len(), 1);
    let task = vault
        .connector_send_task(&second_ref)?
        .expect("second task");
    assert_eq!(task.outcome, Some(ConnectorSendTaskOutcome::Failed));
    assert_eq!(task.suppression.as_deref(), Some("dedupe"));
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert!(receipts.iter().any(|r| r.fields.get("intent_ref")
        == Some(&format!("intent:task:{}", second_ref.to_hex()))
        && r.fields.get("suppression").map(String::as_str) == Some("dedupe")));
    Ok(())
}

#[test]
fn failed_scheduled_send_releases_key_after_cooldown_without_reviving_old_task() -> crate::Result<()>
{
    use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x83);
    put_connector_task_actor(&vault, actor, 90)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x84),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let mut first = one_1768_draft("email", "send", "no-wire-first");
    first.dedupe_key = Some("cooldown:no-wire".to_owned());
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&first)
        .expect("schedule first");
    let first_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("transport_not_started"),
        ..Default::default()
    };
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, 131)
            .expect("fail first"),
        0
    );
    assert_eq!(
        vault
            .connector_send_task(&first_ref)?
            .expect("first task")
            .outcome,
        Some(ConnectorSendTaskOutcome::Failed)
    );
    let mut second = one_1768_draft("email", "send", "no-wire-second");
    second.dedupe_key = first.dedupe_key;
    second.occurred_at = Some(87_400);
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&second)
        .expect("schedule after cooldown");
    sink.outcome = OutboundExecutionOutcome::delivered_to_channel("provider:second");
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, 87_401)
            .expect("send new task"),
        1
    );
    let old = AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
        payload: connector_send_attempt_payload(first_ref)?,
        dedupe_key: None,
        run_id: None,
        now: 87_402,
    })?;
    assert!(matches!(old, EnqueueOutcome::Enqueued(_)));
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, 87_403)
            .expect("fence old task"),
        0
    );
    assert_eq!(sink.calls.len(), 2);
    assert_eq!(
        vault
            .connector_send_task(&first_ref)?
            .expect("old task")
            .outcome,
        Some(ConnectorSendTaskOutcome::Failed)
    );
    Ok(())
}

#[test]
fn bound_send_rejects_noncanonical_channel_or_verb_before_unrelated_stop() -> crate::Result<()> {
    let dir = tempfile::tempdir().expect("vault root");
    let vault = Vault::open_unseeded_for_test(dir.path(), crate::VaultConfig::default())?;
    let actor = entity(0xA8);
    put_connector_task_actor(&vault, actor, 100)?;
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let mut draft = connector_task_draft("noncanonical-bound", "session:noncanonical", 100);
    for (channel, verb) in [(" email ", "send"), ("email", " SEND ")] {
        draft.channel = channel.to_owned();
        draft.verb = verb.to_owned();
        assert!(
            outbound_verb_contract(channel, verb).is_ok(),
            "capability lookup accepts this spelling"
        );
        let error = facade
            .schedule_outbound_for_counterparty(&draft, "party:bound")
            .expect_err("noncanonical projector source refused before admission");
        assert_eq!(error.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
        assert!(vault.connector_send_tasks()?.is_empty());
        assert!(
            vault
                .receipts(
                    crate::receipt::ReceiptQuery::new(10)
                        .with_kind(crate::receipt::ReceiptKind::Outbound)
                )?
                .is_empty()
        );
    }
    crate::comm::record_comm_inbound_stop(&vault, "party:unrelated-stop", "email", 110)
        .expect("record independent stop");
    crate::comm::run_comm_projector(&vault).expect("project stop after rejected sends");
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_OPT_OUT,
            "party:unrelated-stop",
            "email",
        )
        .expect("opt-out claim query"),
        1,
    );
    crate::comm::run_comm_projector(&vault).expect("replayed stop projector pass");
    assert_eq!(
        crate::comm::count_total_comm_claim_rows(
            &vault,
            crate::comm::PREDICATE_COMM_OPT_OUT,
            "party:unrelated-stop",
            "email",
        )
        .expect("opt-out history query"),
        1,
    );
    Ok(())
}

#[test]
fn unbound_send_does_not_trust_provider_counterparty_receipt_field() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x4C);
    put_connector_task_actor(&vault, actor, 100)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x4D),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let draft = connector_task_draft("unbound-provider-field", "session:unbound", 100);
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("unbound schedule");
    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::delivered_to_channel("provider:unbound")
            .with_receipt_field("counterparty_ref", "forged-person"),
        ..Default::default()
    };
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 101)
            .unwrap(),
        1
    );
    let receipt = crate::receipt::delivered_send_receipt_for_task(
        &vault,
        vault.connector_send_tasks()?[0].task_ref,
    )?
    .expect("delivered receipt");
    assert_eq!(receipt.fields.get("counterparty_ref"), None);
    crate::comm::run_comm_projector(&vault).expect("project unbound receipt");
    // Neither the transport destination nor a provider-supplied identity
    // becomes a standing counterparty without a frozen TASK binding.
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            "forged-person",
            "email",
        )
        .expect("claim query"),
        0,
    );
    Ok(())
}

#[test]
fn bound_party_stop_before_send_holds_despite_different_transport_target() -> crate::Result<()> {
    use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyOptOutReason};
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    let (_tmp, vault) = temp_vault();
    let actor = entity(0xD1);
    put_connector_task_actor(&vault, actor, 1_700)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xD2),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let mut draft = connector_task_draft("bound-stop:test", "session:bound-stop", 1_700);
    draft.target = "transport:shared-inbox".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound_for_counterparty(&draft, "stop@example.com")
        .expect("schedule bound TASK");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let contact_ref = entity(0xCD);
    let contact =
        CounterpartyContactRecord::user_introduction(entity(0xCC), "stop@example.com", 1_690)?;
    vault.create_counterparty_contact(&contact_ref, &contact)?;
    vault.opt_out_counterparty_contact(
        &contact_ref,
        CounterpartyOptOutReason::Unsubscribe,
        1_701,
    )?;
    let mut sink = RecordingExecutor::default();
    assert_eq!(
        vault.run_connector_task_executor(&mut sink, 1_702).unwrap(),
        0
    );
    assert!(
        sink.calls.is_empty(),
        "a STOP for the frozen party must hold before transport"
    );
    assert_eq!(vault.connector_send_task(&task_ref)?.unwrap().outcome, None);
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert!(receipts.iter().any(
        |receipt| receipt.fields.get("hold_reason").map(String::as_str)
            == Some("gate.pending.counterparty_opt_out")
    ));
    Ok(())
}

#[test]
fn replaced_reservation_cannot_erase_earlier_ambiguous_send() -> crate::Result<()> {
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    let (_tmp, vault) = temp_vault();
    let actor = entity(0xD3);
    put_connector_task_actor(&vault, actor, 1_800)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xD4),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let mut draft = connector_task_draft("reserve-first:test", "session:reserve-first", 1_800);
    draft.verb = "replace".to_owned();
    draft.dedupe_key = Some("reservation:one".to_owned());
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule A");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };
    vault.run_connector_task_executor(&mut sink, 1_801).unwrap();
    let second_at = next_connector_send_retry_at(&vault)?;
    sink.outcome = OutboundExecutionOutcome::failed("transport_not_started");
    vault
        .run_connector_task_executor(&mut sink, second_at)
        .unwrap();
    assert_eq!(sink.calls.len(), 2);
    let third_at = second_at + 86_401;
    let mut other = vault.connector_send_task(&task_ref)?.unwrap().intent;
    other.idempotency_key = Some("reserve-second:test".to_owned());
    let request = OutboundDispatchRequest::new(
        "receipt:reserve-second",
        "intent:reserve-second",
        other,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        third_at,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    vault.clock.set(third_at);
    let mut replacement_sink = RecordingExecutor::default();
    assert_eq!(
        vault
            .dispatch_outbound_intent(request, &mut replacement_sink)
            .expect("reserve replacement B")
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(replacement_sink.calls.len(), 1);
    vault
        .run_connector_task_executor(&mut sink, third_at + 1)
        .unwrap();
    assert_eq!(
        sink.calls.len(),
        2,
        "A's stale reservation cannot send again"
    );
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous)
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert!(receipts.iter().any(|receipt| receipt.fields.get("task_ref")
        == Some(&task_ref.to_hex())
        && receipt.outcome == "ambiguous"));
    assert_ambiguous_on_task_board(&vault, actor, task_ref);
    Ok(())
}

#[test]
fn post_send_crash_then_no_wire_retry_keeps_uncertainty() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, EnqueueAttempt};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    struct CrashAfterPossibleDelivery;
    impl OutboundExecutionSink for CrashAfterPossibleDelivery {
        fn execute(&mut self, _: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
            panic!("crash after provider may have accepted send")
        }
    }
    let (tmp, vault) = temp_vault();
    let actor = entity(0xC9);
    let key_ref = entity(0xCA);
    put_connector_task_actor(&vault, actor, 1_900)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xCB),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    vault.register_connector_key(&key_ref, sends_per_day_key(5))?;
    let mut draft = connector_task_draft("crash-before-outcome:test", "session:crash", 1_900);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = vault.run_connector_task_executor(&mut CrashAfterPossibleDelivery, 1_901);
        }))
        .is_err()
    );
    drop(vault);
    let vault = Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    let before =
        crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("pending ledger");
    assert_eq!(
        before[0].state,
        crate::outbound_intent_ledger::IntentState::Pending
    );
    assert_eq!(before[0].recorded_outcome, None);
    assert!(!before[0].delivery_uncertain);
    AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
        payload: connector_send_attempt_payload(task_ref)?,
        dedupe_key: None,
        run_id: None,
        now: 1_902,
    })?;
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("transport_not_started"),
        ..Default::default()
    };
    vault.run_connector_task_executor(&mut sink, 1_903).unwrap();
    assert_eq!(sink.calls.len(), 1, "retry must not have reached provider");
    let after = crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("retry ledger");
    assert_eq!(
        after[0].recorded_outcome,
        Some(crate::outbound_intent_ledger::RecordedOutboundOutcome::DefiniteNonDelivery)
    );
    assert!(
        after[0].delivery_uncertain,
        "crash-uncertain first attempt survives no-wire retry"
    );
    vault.revoke_connector_key(&key_ref, 1_904)?;
    vault
        .run_connector_task_executor(&mut sink, next_connector_send_retry_at(&vault)?)
        .unwrap();
    assert_eq!(sink.calls.len(), 1);
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous)
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert!(
        receipts
            .iter()
            .any(|receipt| receipt.outcome == "ambiguous")
    );
    Ok(())
}

#[test]
fn ack_before_receipt_then_actor_loss_reconciles_delivered_without_transport() -> crate::Result<()>
{
    use crate::attempt_queue::{AttemptQueue, EnqueueAttempt};
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::outbound::executor::set_before_delivered_receipt_hook;
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    let (tmp, vault) = temp_vault();
    let actor = entity(0xD0);
    let party = "party:reconciled-delivery";
    put_connector_task_actor(&vault, actor, 2_000)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xCE),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    crate::comm::record_comm_send_receipt(&vault, party, "email", 1_900)
        .expect("earlier comm touch");
    crate::comm::run_comm_projector(&vault).expect("project earlier touch");
    let mut draft = connector_task_draft("acked-without-receipt:test", "session:ack", 2_000);
    draft.verb = "replace".to_owned();
    draft.target = "transport:shared-inbox".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound_for_counterparty(&draft, party)
        .expect("schedule bound send");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };
    vault.run_connector_task_executor(&mut sink, 2_001).unwrap();
    let retry_at = next_connector_send_retry_at(&vault)?;
    sink.outcome = OutboundExecutionOutcome::delivered_to_channel("provider:ack");
    set_before_delivered_receipt_hook(|| panic!("cut after ACK before receipt"));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = vault.run_connector_task_executor(&mut sink, retry_at);
        }))
        .is_err()
    );
    assert_eq!(sink.calls.len(), 2);
    assert_eq!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("durable ACK")[0].state,
        crate::outbound_intent_ledger::IntentState::Done
    );
    assert_eq!(vault.connector_send_task(&task_ref)?.unwrap().outcome, None);
    assert!(!send_receipt_exists_for_task(&vault, task_ref)?);
    drop(vault);
    let clock = crate::ports::ManualClock::new(retry_at + 1);
    let vault = Vault::open(
        tmp.path(),
        VaultConfig {
            store_clock: clock.bundle(),
            ..VaultConfig::default()
        },
    )?;
    vault.delete_entity(&actor)?;
    AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
        payload: connector_send_attempt_payload(task_ref)?,
        dedupe_key: None,
        run_id: None,
        now: retry_at + 1,
    })?;
    let mut no_transport = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut no_transport, retry_at + 2)
            .unwrap(),
        0
    );
    assert!(no_transport.calls.is_empty());
    assert_eq!(
        vault.connector_send_task(&task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Delivered)
    );
    let receipt = vault
        .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
        .into_iter()
        .find(|r| {
            r.fields.get("task_ref") == Some(&task_ref.to_hex())
                && r.outcome == "delivered_to_channel"
        })
        .expect("reconciled receipt");
    assert_eq!(
        receipt.fields.get("counterparty_ref").map(String::as_str),
        Some(party)
    );
    assert_eq!(
        vault.store.get_delivered_send_task_by_idempotency(
            &actor,
            draft.idempotency_key.as_deref().expect("key")
        )?,
        Some(task_ref)
    );
    crate::comm::run_comm_projector(&vault).expect("project reconciled delivery");
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            party,
            "email"
        )
        .expect("touch"),
        1
    );
    assert_delivered_on_task_board(&vault, actor, task_ref);
    Ok(())
}

fn assert_delivered_on_task_board(vault: &Vault, actor: EntityId, task_ref: EntityId) {
    use crate::task_verb::TaskDescription;
    let TaskDescription::Section(section) = vault
        .memory(actor, EdgeActorClass::Agent)
        .describe(None)
        .expect("task board")
    else {
        panic!("section");
    };
    let row = section
        .rows
        .iter()
        .find(|row| row.id == task_ref.to_hex())
        .expect("row");
    assert_eq!(row.status, crate::context_board::TaskBoardStatus::Done);
    assert_eq!(
        row.connector_outcome,
        Some(ConnectorSendTaskOutcome::Delivered)
    );
}

#[test]
fn terminal_reconciliation_rejects_foreign_frozen_binding_without_changing_ledger()
-> crate::Result<()> {
    use crate::outbound_intent_ledger::ConnectorIntentBinding;
    let (_tmp, vault) = temp_vault();
    let actor = entity(0xB6);
    put_connector_task_actor(&vault, actor, 2_100)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xB7),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let mut draft = connector_task_draft("same-logical-key:test", "session:original", 2_100);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule original");
    let task = vault.connector_send_tasks()?.remove(0);
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };
    vault.run_connector_task_executor(&mut sink, 2_101).unwrap();
    let original = crate::outbound_intent_ledger::intent_ledger_records(&vault)
        .expect("original ledger")[0]
        .clone();
    let mut forged = task.intent.clone();
    forged.target = "transport:foreign".to_owned();
    let binding = ConnectorIntentBinding {
        intent: &forged,
        actor_ref: actor,
        actor_class: task.actor_class.gate_actor_class(),
        counterparty_ref: task.counterparty_ref.as_deref(),
        originating_session_ref: task.originating_session_ref.as_deref(),
        calendar_invite: task.calendar_invite.as_ref(),
    };
    assert!(binding.verify(&original).is_err());
    assert_eq!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("unchanged ledger")[0],
        original
    );
    assert_eq!(sink.calls.len(), 1);
    Ok(())
}

#[test]
fn terminal_reconciliation_stale_lease_rolls_back_ledger_receipt_and_task() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome};
    use crate::outbound::retry_audit::reconcile_connector_task;
    use crate::outbound_intent_ledger::IntentEscalationReason;
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    let (_tmp, vault) = temp_vault();
    let actor = entity(0xB8);
    put_connector_task_actor(&vault, actor, 2_200)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xB9),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let mut draft = connector_task_draft("settlement-stale:test", "session:stale", 2_200);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task = vault.connector_send_tasks()?.remove(0);
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout").with_possible_delivery(),
        ..Default::default()
    };
    vault.run_connector_task_executor(&mut sink, 2_201).unwrap();
    let at = next_connector_send_retry_at(&vault)?;
    vault.clock.set(at);
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
        crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: super::super::executor::CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
            now: at,
        },
    )?
    else {
        panic!("retry claim");
    };
    let before = crate::outbound_intent_ledger::intent_ledger_records(&vault).expect("ledger");
    let receipts_before = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    let mut stale = attempt.clone();
    stale.attempt_count += 1;
    assert!(
        reconcile_connector_task(
            &vault,
            &stale,
            &task,
            "receipt:stale-reconcile",
            at,
            Some(IntentEscalationReason::BindingInvalid),
            None,
        )
        .is_err()
    );
    assert_eq!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault)
            .expect("ledger")
            .records,
        before.records
    );
    assert_eq!(
        vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?,
        receipts_before
    );
    assert_eq!(
        vault.connector_send_task(&task.task_ref)?.unwrap().outcome,
        None
    );
    assert_eq!(
        queue
            .list()?
            .into_iter()
            .find(|row| row.id == attempt.id)
            .unwrap()
            .state,
        AttemptState::Leased
    );
    assert!(reconcile_connector_task(
        &vault,
        &attempt,
        &task,
        "receipt:valid-reconcile",
        at,
        Some(IntentEscalationReason::BindingInvalid),
        None,
    )?);
    assert_eq!(
        vault.connector_send_task(&task.task_ref)?.unwrap().outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous)
    );
    assert_eq!(
        queue
            .list()?
            .into_iter()
            .find(|row| row.id == attempt.id)
            .unwrap()
            .state,
        AttemptState::Failed
    );
    Ok(())
}
