use super::*;
use rmpv::Value;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    encode_claim_body,
};
use crate::config::VaultConfig;
use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyOptOutReason};
use crate::delivery_window::{
    DELIVERY_WINDOW_SCHEMA_VERSION, DeliveryWindowApnsInterruptionLevel, DeliveryWindowAppliesTo,
    DeliveryWindowContextCondition, PREDICATE_DELIVERY_WINDOW_CHANNEL,
    PREDICATE_DELIVERY_WINDOW_CONTEXT, PREDICATE_DELIVERY_WINDOW_QUIET,
};
use crate::edge::EdgeKind;
use crate::entity_id::ENTITY_ID_LEN;
use crate::linkedin_connector::{
    LINKEDIN_CHANNEL, LinkedInMcpConnectorAdapter, LinkedInMcpSendMessageRequest,
    LinkedInMcpSendTransport, LinkedInMcpVerifiedSendSink, LinkedInSandboxHostConfig,
    LinkedInSandboxHostHarness, LinkedInSeatDispatchState, LinkedInSeatSandboxPolicy,
    LinkedInVerifiedSendPlan, run_linkedin_kill_switch,
};
use crate::llm::{BudgetSignalDeliveryChannel, BudgetThreshold};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_POLICY_MANIFEST};
use crate::store::Store;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn entity(seed: u8) -> EntityId {
    let mut bytes = [seed; ENTITY_ID_LEN];
    bytes[0] = seed.max(1);
    EntityId::from_bytes(bytes).expect("test entity id")
}

fn policy_manifest(actor_ref: &str, channel: &str, verbs: &[&str]) -> Vec<u8> {
    let scoped_grants = verbs
        .iter()
        .map(|verb| {
            Value::Map(vec![
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (
                    Value::from("effector"),
                    Value::from(format!("external:{verb}")),
                ),
                (
                    Value::from("scope"),
                    Value::Map(vec![(Value::from("channel"), Value::from(channel))]),
                ),
            ])
        })
        .collect::<Vec<_>>();
    let entries = vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("outbound-o2-test")),
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
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("agent")),
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (Value::from("scoped_grants"), Value::Array(scoped_grants)),
    ];
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
    out
}

fn put_policy_manifest(vault: &Vault, seed: u8, data: &[u8]) -> crate::Result<()> {
    let id = entity(seed);
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(data);

    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

fn put_claim_body(vault: &Vault, seed: u8, body: &ClaimBody) -> crate::Result<()> {
    let id = entity(seed);
    let data = encode_claim_body(body)?;
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_CLAIM);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&data);

    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })?;

    if let ClaimSubject::Entity(subject) = body.subject {
        vault.put_edge(&id, EdgeKind::ClaimOf, &subject, 1.0)?;
    }
    Ok(())
}

struct RecordingExecutor {
    calls: Vec<(String, String, String)>,
    idempotency_keys: Vec<Option<String>>,
    outcome: OutboundExecutionOutcome,
}

impl Default for RecordingExecutor {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            idempotency_keys: Vec::new(),
            outcome: OutboundExecutionOutcome::delivered_to_channel("provider:message:one"),
        }
    }
}

impl OutboundExecutionSink for RecordingExecutor {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.idempotency_keys
            .push(request.idempotency_key.map(str::to_owned));
        self.calls.push((
            request.intent_ref.to_owned(),
            request.intent.channel.clone(),
            request.verb_contract.kind.clone(),
        ));
        self.outcome.clone()
    }
}

#[test]
fn connector_send_schedule_is_additive_and_executor_is_idempotent() -> crate::Result<()> {
    use crate::attempt_queue::AttemptQueue;
    use crate::facade::{BRIDGE_OUTBOUND_ATTEMPT_KIND, OutboundDraftInput};
    use crate::receipt::{FIELD_TASK_REF, FIELD_TRANSPORT_DISPATCHED, ReceiptKind, ReceiptQuery};
    use crate::registry::ENTITY_TYPE_PERSON;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x31);
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 10, end: 10 },
        10,
        b"connector task actor",
    )?;
    put_policy_manifest(
        &vault,
        0x32,
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;

    vault
        .memory_facade(actor, EdgeActorClass::Agent)
        .schedule_outbound(&OutboundDraftInput {
            verb: "send".to_owned(),
            channel: "email".to_owned(),
            target: "counterparty:test".to_owned(),
            on_behalf_of: None,
            content_ref: Some("content:test".to_owned()),
            idempotency_key: Some("connector-task:test".to_owned()),
            dedupe_key: None,
            trigger: "agent_immediate".to_owned(),
            trigger_ref: "session:test".to_owned(),
            job_ref: None,
            occurred_at: Some(10),
        })
        .expect("schedule outbound");

    let tasks = vault.connector_send_tasks()?;
    assert_eq!(tasks.len(), 1);
    let task_ref = tasks[0].task_ref;
    let task_ref_hex = task_ref.to_hex();
    assert_eq!(tasks[0].task_ref, task_ref);
    assert_eq!(tasks[0].assignee_ref, connector_actor_id("email")?);
    assert_eq!(vault.standalone_outbound_intent_count()?, 0);
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .len(),
        0
    );
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .into_iter()
            .filter(|receipt| {
                receipt
                    .fields
                    .get(FIELD_TRANSPORT_DISPATCHED)
                    .is_some_and(|value| value == "true")
            })
            .count(),
        0
    );
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?
            .len(),
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

    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 11)
            .unwrap(),
        1
    );
    assert_eq!(executor.calls.len(), 1);
    let intent_row = crate::outbound_intent_ledger::intent_ledger_records(&vault)
        .map_err(|_| Error::InvariantViolation("connector execution intent ledger read failed"))?
        .into_iter()
        .next()
        .expect("connector execution journals one intent");
    // email/send is NonIdempotentInterrupt: the sink is not handed the ledger id
    // as a provider idempotency (dedup) token, even though the ledger row still
    // keys the intent internally.
    assert_eq!(executor.idempotency_keys, vec![None]);
    assert!(!intent_row.idempotency_key.is_empty());
    assert_eq!(intent_row.state, crate::IntentState::Done);
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].fields.get(FIELD_TASK_REF).map(String::as_str),
        Some(task_ref_hex.as_str())
    );
    assert_eq!(
        receipts[0]
            .fields
            .get(FIELD_TRANSPORT_DISPATCHED)
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| {
                receipt
                    .fields
                    .get(FIELD_TRANSPORT_DISPATCHED)
                    .is_some_and(|value| value == "true")
            })
            .count(),
        1
    );
    let lineaged_task = receipts[0]
        .fields
        .get(FIELD_TASK_REF)
        .and_then(|task_ref| EntityId::from_hex(task_ref).ok())
        .and_then(|task_ref| vault.connector_send_task(&task_ref).ok().flatten());
    assert_eq!(usize::from(lineaged_task.is_some()), 1);

    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 12)
            .unwrap(),
        0
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
fn delivered_send_idempotency_survives_attempt_completion() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState};
    use crate::facade::{BRIDGE_OUTBOUND_ATTEMPT_KIND, OutboundDraftInput};
    use crate::receipt::{ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x4A);
    put_connector_task_actor(&vault, actor, 90)?;
    put_policy_manifest(
        &vault,
        0x4B,
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
        .memory_facade(actor, EdgeActorClass::Agent)
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
        .memory_facade(actor, EdgeActorClass::Agent)
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
    use crate::facade::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{FIELD_TASK_REF, FIELD_TRANSPORT_DISPATCHED, ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x4C);
    put_connector_task_actor(&vault, actor, 100)?;
    put_policy_manifest(
        &vault,
        0x4D,
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let draft = connector_task_draft(
        "failed-receipt-retry:test",
        "session:failed-receipt-retry",
        100,
    );
    vault
        .memory_facade(actor, EdgeActorClass::Agent)
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
    assert_eq!(delivered_receipts.len(), 1);
    assert_eq!(delivered_receipts[0].outcome, "delivered_to_channel");
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
fn logical_send_is_charged_once_across_fresh_retry_attempts() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
    use crate::facade::BRIDGE_OUTBOUND_ATTEMPT_KIND;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x4F);
    put_connector_task_actor(&vault, actor, 110)?;
    put_policy_manifest(
        &vault,
        0x50,
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault.register_connector_key(&entity(0x51), sends_per_day_key(5))?;
    vault
        .memory_facade(actor, EdgeActorClass::Agent)
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
    use crate::facade::BRIDGE_OUTBOUND_ATTEMPT_KIND;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x52);
    put_connector_task_actor(&vault, actor, 120)?;
    put_policy_manifest(
        &vault,
        0x53,
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let mut draft = connector_task_draft(
        "same-provider-key-retry:test",
        "session:same-provider-key-retry",
        120,
    );
    draft.verb = "replace".to_owned();
    vault
        .memory_facade(actor, EdgeActorClass::Agent)
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
    use crate::facade::BRIDGE_OUTBOUND_ATTEMPT_KIND;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x5A);
    put_connector_task_actor(&vault, actor, 130)?;
    put_policy_manifest(
        &vault,
        0x5B,
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault
        .memory_facade(actor, EdgeActorClass::Agent)
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
    assert_eq!(failed_records[0].state, crate::IntentState::Pending);
    assert_eq!(
        failed_records[0].recorded_outcome,
        Some(crate::RecordedOutboundOutcome::DefiniteNonDelivery)
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
    assert_eq!(delivered_records[0].state, crate::IntentState::Done);
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
    put_policy_manifest(
        &vault,
        0x64,
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault
        .memory_facade(actor, EdgeActorClass::Agent)
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
    put_policy_manifest(
        &vault,
        0x61,
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault
        .memory_facade(actor, EdgeActorClass::Agent)
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
    use crate::facade::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{FIELD_TASK_REF, ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x65);
    put_connector_task_actor(&vault, actor, 160)?;
    put_policy_manifest(
        &vault,
        0x66,
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let mut draft = connector_task_draft("replay-gate-ref:test", "session:replay-gate-ref", 160);
    draft.verb = "replace".to_owned();
    vault
        .memory_facade(actor, EdgeActorClass::Agent)
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

fn connector_task_draft(
    idempotency_key: &str,
    trigger_ref: &str,
    occurred_at: u64,
) -> crate::facade::OutboundDraftInput {
    crate::facade::OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: format!("counterparty:{idempotency_key}"),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some(idempotency_key.to_owned()),
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: trigger_ref.to_owned(),
        job_ref: None,
        occurred_at: Some(occurred_at),
    }
}

fn put_connector_task_actor(vault: &Vault, actor: EntityId, at: u64) -> crate::Result<()> {
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: at, end: at },
        at,
        b"connector task actor",
    )
}

#[test]
fn send_receipt_point_lookup_skips_gate_and_sink_without_scanning() -> crate::Result<()> {
    use crate::attempt_queue::{AttemptQueue, AttemptState};
    use crate::facade::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{
        ReceiptKind, ReceiptQuery, outbound_intent_receipt, persist_send_receipt,
    };

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x33);
    put_connector_task_actor(&vault, actor, 20)?;
    put_policy_manifest(
        &vault,
        0x34,
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault
        .memory_facade(actor, EdgeActorClass::Agent)
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
    use crate::facade::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{FIELD_TASK_REF, ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let denied_actor = entity(0x35);
    let allowed_actor = entity(0x36);
    put_connector_task_actor(&vault, denied_actor, 30)?;
    put_connector_task_actor(&vault, allowed_actor, 30)?;
    put_policy_manifest(
        &vault,
        0x37,
        &policy_manifest(&denied_actor.to_hex(), "email", &["send"]),
    )?;
    put_policy_manifest(
        &vault,
        0x42,
        &policy_manifest(&allowed_actor.to_hex(), "slack", &["send"]),
    )?;
    let denied_key = entity(0x43);
    vault.register_connector_key(
        &denied_key,
        crate::ConnectorKeyRecord::active("email", None, Vec::new(), 30),
    )?;
    vault.suspend_connector_key(&denied_key, "test_denial", 30)?;
    let denied = vault
        .memory_facade(denied_actor, EdgeActorClass::Agent)
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
        .memory_facade(allowed_actor, EdgeActorClass::Agent)
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
    use crate::facade::{BRIDGE_OUTBOUND_ATTEMPT_KIND, FACADE_CODE_BAD_REQUEST};
    use crate::off_record::{OffRecordBackendClass, OffRecordMode};
    use crate::receipt::{ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x38);
    put_connector_task_actor(&vault, actor, 40)?;
    put_policy_manifest(
        &vault,
        0x39,
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let session_ref = "session:off-record-executor";
    vault.enter_off_record_session(session_ref, OffRecordBackendClass::Local)?;
    let draft = connector_task_draft("off-record:test", session_ref, 40);
    let err = vault
        .memory_facade(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect_err("off-record outbound is talk-only");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);

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
        .memory_facade(actor, EdgeActorClass::Agent)
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
    put_policy_manifest(
        &vault,
        0x3B,
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault.register_connector_key(&entity(0x3C), sends_per_day_key(5))?;
    vault
        .memory_facade(actor, EdgeActorClass::Agent)
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
    use crate::facade::BRIDGE_OUTBOUND_ATTEMPT_KIND;

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
        .memory_facade(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect_err("malformed gate claim fails schedule");
    assert_eq!(err.code, crate::facade::FACADE_CODE_BAD_REQUEST);
    assert_eq!(vault.connector_send_tasks()?.len(), 0);
    let attempts = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 0);
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
        .memory_facade(actor, EdgeActorClass::Agent)
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
    use crate::facade::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    use crate::receipt::{ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x3F);
    put_connector_task_actor(&vault, actor, 70)?;
    put_policy_manifest(
        &vault,
        0x40,
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
        .memory_facade(actor, EdgeActorClass::Agent)
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
    use crate::facade::{BRIDGE_OUTBOUND_ATTEMPT_KIND, FACADE_CODE_INTERNAL};
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
        .memory_facade(actor, EdgeActorClass::Agent)
        .schedule_outbound(&connector_task_draft(
            "actor-collision:test",
            "session:actor-collision",
            80,
        ))
        .expect_err("connector actor collision");
    assert_eq!(err.code, FACADE_CODE_INTERNAL);
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

struct ScriptedLinkedInTransport {
    send_calls: Vec<LinkedInMcpSendMessageRequest>,
    get_calls: Vec<String>,
    send_result: std::result::Result<serde_json::Value, String>,
    conversations: std::collections::VecDeque<std::result::Result<serde_json::Value, String>>,
}

impl ScriptedLinkedInTransport {
    fn new(conversations: Vec<serde_json::Value>) -> Self {
        Self {
            send_calls: Vec::new(),
            get_calls: Vec::new(),
            send_result: Ok(serde_json::json!({"status": "ignored"})),
            conversations: conversations.into_iter().map(Ok).collect(),
        }
    }

    fn failing_send(mut self, error_code: &str) -> Self {
        self.send_result = Err(error_code.to_owned());
        self
    }

    fn with_get_error_after_precheck(mut self, error_code: &str) -> Self {
        self.conversations.insert(1, Err(error_code.to_owned()));
        self
    }
}

impl LinkedInMcpSendTransport for ScriptedLinkedInTransport {
    fn send_message(
        &mut self,
        request: &LinkedInMcpSendMessageRequest,
    ) -> std::result::Result<serde_json::Value, String> {
        self.send_calls.push(request.clone());
        self.send_result.clone()
    }

    fn get_conversation(
        &mut self,
        thread_id: &str,
    ) -> std::result::Result<serde_json::Value, String> {
        self.get_calls.push(thread_id.to_owned());
        self.conversations
            .pop_front()
            .unwrap_or_else(|| Err("no_more_recorded_conversations".to_owned()))
    }
}

#[derive(Default)]
struct RecordingLinkedInSandboxHarness {
    destroyed: Vec<String>,
    revoked: Vec<String>,
}

impl LinkedInSandboxHostHarness for RecordingLinkedInSandboxHarness {
    fn destroy_sandbox(&mut self, host: &LinkedInSandboxHostConfig) -> crate::Result<()> {
        self.destroyed.push(host.sandbox_ref.clone());
        Ok(())
    }

    fn revoke_verb_catalog(&mut self, seat_ref: &str) -> crate::Result<()> {
        self.revoked.push(seat_ref.to_owned());
        Ok(())
    }
}

fn linkedin_adapter() -> crate::Result<LinkedInMcpConnectorAdapter> {
    LinkedInMcpConnectorAdapter::new("linkedin:member:yura")?
        .with_session_ref("linkedin:session:yura:tokyo-sandbox")
}

fn linkedin_sandbox_host() -> crate::Result<LinkedInSandboxHostConfig> {
    LinkedInSandboxHostConfig::new(
        "linkedin:seat:yura",
        "sandbox:tokyo:yura",
        "browser-profile:linkedin:yura",
        "vault-secret:linkedin:yura:session-cookie",
    )
}

fn active_linkedin_policy() -> crate::Result<LinkedInSeatSandboxPolicy> {
    Ok(LinkedInSeatSandboxPolicy::active(linkedin_sandbox_host()?)
        .with_state(LinkedInSeatDispatchState::active()))
}

fn linkedin_conversation(thread_id: &str, conversation: &str) -> serde_json::Value {
    serde_json::json!({
        "url": format!("https://www.linkedin.com/messaging/thread/{thread_id}/"),
        "sections": {
            "conversation": conversation
        },
        "references": {
            "conversation": [
                {
                    "kind": "conversation",
                    "url": format!("/messaging/thread/{thread_id}/"),
                    "context": "conversation",
                    "text": "Jane Doe"
                }
            ]
        }
    })
}

fn linkedin_conversation_without_thread_metadata(conversation: &str) -> serde_json::Value {
    serde_json::json!({
        "sections": {
            "conversation": conversation
        }
    })
}

fn dispatch_intent(trigger: OutboundIntentTrigger) -> OutboundIntent {
    OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com")
            .on_behalf_of("owner")
            .content_ref("content:invite-kenji")
            .idempotency_key("idem:invite-kenji")
            .dedupe_key("dedupe:invite-kenji"),
        trigger,
    )
}

fn linkedin_send_intent(trigger: OutboundIntentTrigger) -> OutboundIntent {
    OutboundIntent::from_trigger(
        OutboundIntentDraft::new(
            "agent-alpha",
            "send_dm",
            LINKEDIN_CHANNEL,
            "linkedin:member:jane-doe",
        )
        .on_behalf_of("owner")
        .content_ref("content:linkedin-jane")
        .idempotency_key("lnkd:send:jane:overview")
        .dedupe_key("lnkd:thread:2-jane-doe-abc:overview"),
        trigger,
    )
}

fn allow_linkedin_send(
    vault: &Vault,
    actor: &OutboundDispatchActor,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    put_policy_manifest(
        vault,
        0xE0,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            LINKEDIN_CHANNEL,
            &["send_dm"],
        ),
    )?;
    Ok(())
}

fn linkedin_send_request(
    actor: OutboundDispatchActor,
    receipt_id: &str,
    intent_ref: &str,
) -> OutboundDispatchRequest {
    OutboundDispatchRequest::new(
        receipt_id,
        intent_ref,
        linkedin_send_intent(OutboundIntentTrigger::agent_immediate(
            "session:linkedin-send",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_060,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref("linkedin:member:jane-doe")
}

fn quiet_delivery_window_claim_body(subject_seed: u8) -> ClaimBody {
    let mut claim = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_QUIET,
        ClaimSubject::Entity(entity(subject_seed)),
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from("applies_to"),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (
                Value::from("window"),
                Value::Map(vec![
                    (Value::from("start_minute"), Value::from(22 * 60)),
                    (Value::from("end_minute"), Value::from(8 * 60)),
                ]),
            ),
            (Value::from("tz"), Value::from("user-local")),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    claim.source = Some(ClaimSource::UserStated);
    claim
}

fn quiet_delivery_window_policy() -> DeliveryWindowPolicyClaim {
    let claim = quiet_delivery_window_claim_body(0xE1);
    DeliveryWindowPolicyClaim::from_claim_body(&claim).expect("valid quiet claim")
}

fn calendar_busy_delivery_window_claim_body(subject_seed: u8) -> ClaimBody {
    let mut claim = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_CONTEXT,
        ClaimSubject::Entity(entity(subject_seed)),
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from("applies_to"),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (
                Value::from("when"),
                Value::from(DeliveryWindowContextCondition::CalendarBusy.as_str()),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    claim.source = Some(ClaimSource::UserStated);
    claim
}

fn channel_delivery_window_claim_body(subject_seed: u8, channel: &str, reason: &str) -> ClaimBody {
    let mut claim = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_CHANNEL,
        ClaimSubject::Entity(entity(subject_seed)),
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from("applies_to"),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (Value::from("channel"), Value::from(channel)),
            (
                Value::from("window"),
                Value::Map(vec![
                    (Value::from("start_minute"), Value::from(22 * 60)),
                    (Value::from("end_minute"), Value::from(8 * 60)),
                ]),
            ),
            (Value::from("reason"), Value::from(reason)),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    claim.source = Some(ClaimSource::UserStated);
    claim
}

#[test]
fn every_outbound_verb_declares_the_closed_seven_field_contract() {
    assert_eq!(
        OUTBOUND_VERB_FIELD_CONTRACT,
        [
            "kind",
            "channel_call",
            "params",
            "interruption_class",
            "delivery_semantics",
            "retry_class",
            "capability_vs_permission",
        ]
    );

    for manifest in outbound_capability_manifests() {
        assert_eq!(
            manifest.manifest_version, OUTBOUND_CAPABILITY_MANIFEST_VERSION,
            "{} uses an unexpected manifest version",
            manifest.connector
        );
        assert!(
            !manifest.verbs.is_empty(),
            "{} must expose at least one outbound verb",
            manifest.connector
        );
        for verb in &manifest.verbs {
            let value = serde_json::to_value(verb).expect("serialize outbound verb");
            let object = value.as_object().expect("verb serializes as object");
            let fields = object.keys().map(String::as_str).collect::<Vec<_>>();
            assert_eq!(
                fields, OUTBOUND_VERB_FIELD_CONTRACT,
                "{}.{} drifted from the closed field contract",
                manifest.connector, verb.kind
            );
            assert!(
                verb.capability_vs_permission.capability,
                "{}.{} must describe a capability",
                manifest.connector, verb.kind
            );
        }
    }
}

#[test]
fn outbound_intent_job_ref_is_optional_for_legacy_intents() {
    let intent: OutboundIntent = serde_json::from_str(
        r#"{
                "actor": "agent-alpha",
                "verb": "send",
                "channel": "email",
                "target": "counterparty:kenji",
                "intent_source": "agent_immediate",
                "trigger_ref": "run:planning"
            }"#,
    )
    .expect("legacy intent without job_ref remains valid");

    assert_eq!(intent.job_ref, None);

    let brief_rooted = OutboundIntent {
        job_ref: Some("brief:party".to_owned()),
        ..intent
    };
    let value = serde_json::to_value(&brief_rooted).expect("serialize intent");
    assert_eq!(value["job_ref"], "brief:party");
}

#[test]
fn three_trigger_doors_converge_into_one_intent_shape() {
    let commitment = dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
        "commitment:party-reminder",
    ));
    assert_eq!(commitment.intent_source, "commitment");
    assert_eq!(commitment.trigger_ref, "commitment:party-reminder");

    let gap = dispatch_intent(OutboundIntentTrigger::gap_queue("gap:unresolved-thread"));
    assert_eq!(gap.intent_source, "gap_queue");
    assert_eq!(gap.trigger_ref, "gap:unresolved-thread");

    let immediate = dispatch_intent(
        OutboundIntentTrigger::agent_immediate("session:reply-now").job_ref("brief:party"),
    );
    assert_eq!(immediate.intent_source, "agent_immediate");
    assert_eq!(immediate.job_ref.as_deref(), Some("brief:party"));
    assert_eq!(
        immediate.idempotency_key.as_deref(),
        Some("idem:invite-kenji")
    );
    assert_eq!(immediate.dedupe_key.as_deref(), Some("dedupe:invite-kenji"));
}

#[test]
fn dispatch_pipeline_resolves_gates_executes_and_emits_receipt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x51);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xD0,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let intent = dispatch_intent(
        OutboundIntentTrigger::agent_immediate("session:send-now").job_ref("brief:party"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:invite-kenji",
        "intent:invite-kenji",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref("counterparty:kenji");

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        executor.calls,
        vec![(
            "intent:invite-kenji".to_owned(),
            "email".to_owned(),
            "send".to_owned()
        )]
    );
    assert_eq!(result.gate_outcome, "allow");
    assert_eq!(result.gate_reason_codes, vec!["gate.allow"]);
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_decision_ref")
            .map(String::as_str),
        result.gate_decision_id.as_deref()
    );
    assert!(!result.receipt.fields.contains_key("gate_decision_id"));
    assert_eq!(result.receipt.outcome, "delivered_to_channel");
    assert_eq!(
        result
            .receipt
            .fields
            .get("channel_call")
            .map(String::as_str),
        Some("send_email")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("provider_ref")
            .map(String::as_str),
        Some("provider:message:one")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("idempotency_key")
            .map(String::as_str),
        Some("idem:invite-kenji")
    );
    assert_eq!(
        result.receipt.fields.get("dedupe_key").map(String::as_str),
        Some("dedupe:invite-kenji")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.no_restriction".to_owned())
    );
    Ok(())
}

#[test]
fn verified_dispatch_classifies_a_missing_bound_actor_as_authorization_failure() {
    let (_tmp, vault) = temp_vault();
    let missing_actor = entity(0x52);
    let request = OutboundDispatchRequest::new(
        "outbound:intent:missing-actor",
        "intent:missing-actor",
        dispatch_intent(OutboundIntentTrigger::agent_immediate(
            "session:missing-actor",
        )),
        OutboundDispatchActor::agent(missing_actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_001,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    let mut executor = RecordingExecutor::default();

    let err = OutboundDispatchPipeline
        .dispatch_with_verified_actor(
            &vault,
            request,
            &mut executor,
            missing_actor,
            EdgeActorClass::Agent,
        )
        .expect_err("missing bound actor must fail closed");

    assert!(matches!(err, OutboundDispatchError::InvalidBoundActor));
    assert!(executor.calls.is_empty());
}

#[test]
fn dispatch_pipeline_records_context_receipt_field_set()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x51);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xD0,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let context = ContextReceiptFields {
        persona_compile_stamp: "oneiron.prompt_recompile.v1:deadbeef".to_owned(),
        activated_memory_ids: vec![entity(0x21).to_hex(), entity(0x22).to_hex()],
        board_state_ref: "board:cafe1234".to_owned(),
        substrate_ref: Some(format!("model:{}", entity(0x77).to_hex())),
        model: Some("test-model-v1".to_owned()),
        reasoning_effort: Some("high".to_owned()),
        prompt_input_ref: None,
        disclosure_stamp: None,
    };
    let request = OutboundDispatchRequest::new(
        "outbound:intent:invite-kenji",
        "intent:invite-kenji",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("session:send-now")),
        actor.clone(),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .context_receipt(context.clone());

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        result.receipt.context_receipt_fields().as_ref(),
        Some(&context),
        "what she knew rides the emit receipt"
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("activated_memory_ids")
            .map(String::as_str),
        Some(format!("{},{}", entity(0x21).to_hex(), entity(0x22).to_hex()).as_str())
    );

    // Emits dispatched without an assembled-context stamp stay unstamped.
    let request = OutboundDispatchRequest::new(
        "outbound:intent:invite-yuki",
        "intent:invite-yuki",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("session:send-now")),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_001,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;
    assert_eq!(result.receipt.context_receipt_fields(), None);
    Ok(())
}

#[test]
fn dispatch_pipeline_executes_deliverable_apns_cap()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xA8);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xD8,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "apns",
            &["push"],
        ),
    )?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "push", "apns", "device:kenji")
            .on_behalf_of("owner")
            .content_ref("content:push-kenji")
            .idempotency_key("idem:push-kenji")
            .dedupe_key("dedupe:push-kenji"),
        OutboundIntentTrigger::agent_immediate("session:push-now"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:push-kenji",
        "intent:push-kenji",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_005,
        OutboundDeliveryWindowDecision::DeliverNowWithApnsCap {
            reason: "apns_time_sensitive_ceiling".to_owned(),
            from: "push:critical".to_owned(),
            to: "push:time_sensitive".to_owned(),
        },
    );

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        executor.calls,
        vec![(
            "intent:push-kenji".to_owned(),
            "apns".to_owned(),
            "push".to_owned()
        )]
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("degraded_from")
            .map(String::as_str),
        Some("push:critical")
    );
    assert_eq!(
        result.receipt.fields.get("degraded_to").map(String::as_str),
        Some("push:time_sensitive")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.apns_cap:apns_time_sensitive_ceiling".to_owned())
    );
    Ok(())
}

#[test]
fn dispatch_pipeline_records_typed_failed_execution()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x55);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xD3,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let request = OutboundDispatchRequest::new(
        "outbound:intent:failed-send",
        "intent:failed-send",
        dispatch_intent(OutboundIntentTrigger::agent_immediate(
            "session:failed-send",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_040,
        OutboundDeliveryWindowDecision::DeliverNow,
    );

    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("transport_timeout"),
        ..RecordingExecutor::default()
    };
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(result.receipt.outcome, "failed");
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("transport_timeout")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_receipt_is_delivered_only_after_content_observation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB1));
    vault
        .put_entity(
            &entity(0xB1),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.\nYura\n10:04 AM\nHappy to share more details.",
        ),
    ]);
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?;
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-send", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-send",
            "intent:linkedin-send",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(result.receipt.outcome, "delivered_to_channel");
    assert_eq!(
        sink.transport().send_calls.len(),
        1,
        "fresh send must call send_message once"
    );
    assert_eq!(
        sink.transport().get_calls,
        vec!["2-jane-doe-abc".to_owned(), "2-jane-doe-abc".to_owned()],
        "success is verified by baseline and post-send thread reads"
    );
    let provider_ref = result
        .receipt
        .fields
        .get("provider_ref")
        .expect("verified send writes provider/thread message ref");
    assert!(provider_ref.starts_with("linkedin:thread:2-jane-doe-abc@message:"));
    assert_eq!(
        result.receipt.fields.get("artifact_thread_message_ref"),
        Some(provider_ref),
        "receipt door must target the artifact thread@message"
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_return_trusted")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_result")
            .map(String::as_str),
        Some("ignored"),
        "send_message success return is recorded but not trusted"
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("content_observed")
    );
    Ok(())
}

#[test]
fn linkedin_kill_switch_suppresses_before_mcp_transport()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xC1));
    vault
        .put_entity(
            &entity(0xC1),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let policy = active_linkedin_policy()?;
    let mut harness = RecordingLinkedInSandboxHarness::default();
    let killed = run_linkedin_kill_switch(
        policy,
        &mut harness,
        1_090,
        "consent:owner-disabled-linkedin",
    )?;
    assert_eq!(harness.destroyed, vec!["sandbox:tokyo:yura"]);
    assert_eq!(harness.revoked, vec!["linkedin:seat:yura"]);
    assert!(killed.verb_catalog().is_empty());

    let mut sink = LinkedInMcpVerifiedSendSink::new(
        linkedin_adapter()?,
        ScriptedLinkedInTransport::new(vec![]),
    );
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-kill-switch",
            "intent:linkedin-kill-switch",
        )
        .linkedin_sandbox_policy(killed),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert!(sink.transport().send_calls.is_empty());
    assert!(sink.transport().get_calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_policy_enforced_engine_side")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_engine_policy_reason")
            .map(String::as_str),
        Some("linkedin.kill_switch_engaged")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_sandbox_destroyed")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_verb_catalog_revoked")
            .map(String::as_str),
        Some("true")
    );
    Ok(())
}

#[test]
fn linkedin_daily_dm_cap_holds_before_mcp_transport()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xC2));
    vault
        .put_entity(
            &entity(0xC2),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;
    let policy = active_linkedin_policy()?
        .with_state(LinkedInSeatDispatchState::active().with_dm_sends_today(15));
    let mut sink = LinkedInMcpVerifiedSendSink::new(
        linkedin_adapter()?,
        ScriptedLinkedInTransport::new(vec![]),
    );
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(actor, "outbound:intent:linkedin-cap", "intent:linkedin-cap")
            .linkedin_sandbox_policy(policy),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(sink.transport().send_calls.is_empty());
    assert!(sink.transport().get_calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_engine_policy_reason")
            .map(String::as_str),
        Some("linkedin.daily_dm_cap")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_daily_dm_cap")
            .map(String::as_str),
        Some("15")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_dm_sends_today")
            .map(String::as_str),
        Some("15")
    );
    Ok(())
}

#[test]
fn linkedin_cadence_holds_before_mcp_transport()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xC3));
    vault
        .put_entity(
            &entity(0xC3),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;
    let policy = active_linkedin_policy()?
        .with_state(LinkedInSeatDispatchState::active().with_next_send_not_before(1_500));
    let mut sink = LinkedInMcpVerifiedSendSink::new(
        linkedin_adapter()?,
        ScriptedLinkedInTransport::new(vec![]),
    );
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-cadence",
            "intent:linkedin-cadence",
        )
        .linkedin_sandbox_policy(policy),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(sink.transport().send_calls.is_empty());
    assert!(sink.transport().get_calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_engine_policy_reason")
            .map(String::as_str),
        Some("linkedin.cadence_not_ready")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_next_send_not_before")
            .map(String::as_str),
        Some("1500")
    );
    Ok(())
}

#[test]
fn linkedin_sweeps_are_suppressed_before_mcp_transport()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xC4));
    vault
        .put_entity(
            &entity(0xC4),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;
    let policy =
        active_linkedin_policy()?.with_state(LinkedInSeatDispatchState::active().as_sweep());
    let mut sink = LinkedInMcpVerifiedSendSink::new(
        linkedin_adapter()?,
        ScriptedLinkedInTransport::new(vec![]),
    );
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-sweep",
            "intent:linkedin-sweep",
        )
        .linkedin_sandbox_policy(policy),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert!(sink.transport().send_calls.is_empty());
    assert!(sink.transport().get_calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_engine_policy_reason")
            .map(String::as_str),
        Some("linkedin.no_sweeps")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_sweeps_allowed")
            .map(String::as_str),
        Some("false")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_plan_target_mismatch_fails_before_send()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB7));
    vault
        .put_entity(
            &entity(0xB7),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let plan = LinkedInVerifiedSendPlan::new(
        "linkedin:member:jane-doe",
        "2-jane-doe-abc",
        "Happy to share more details.",
    )?;
    let transport = ScriptedLinkedInTransport::new(vec![linkedin_conversation(
        "2-jane-doe-abc",
        "Yura\n10:04 AM\nHappy to share more details.",
    )]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-target-mismatch", plan)?;
    let result = vault.dispatch_outbound_intent(
        OutboundDispatchRequest::new(
            "outbound:intent:linkedin-target-mismatch",
            "intent:linkedin-target-mismatch",
            linkedin_send_intent(OutboundIntentTrigger::agent_immediate(
                "session:linkedin-send",
            )),
            actor,
            OutboundDispatchGate::allow_when_policy_grants(),
            1_061,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
        .counterparty_ref("linkedin:member:mallory"),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(result.receipt.outcome, "failed");
    assert!(sink.transport().send_calls.is_empty());
    assert!(sink.transport().get_calls.is_empty());
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("linkedin_verified_send_target_mismatch")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_called")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("target_mismatch")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_verifies_metadata_light_conversation_with_requested_thread()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB8));
    vault
        .put_entity(
            &entity(0xB8),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?;
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation_without_thread_metadata(
            "Jane Doe\n10:01 AM\nThanks for reaching out.\nYura\n10:04 AM\nHappy to share more details.",
        ),
    ]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-metadata-light", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-metadata-light",
            "intent:linkedin-metadata-light",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.transport().send_calls.len(), 1);
    assert_eq!(
        sink.transport().get_calls,
        vec!["2-jane-doe-abc".to_owned(), "2-jane-doe-abc".to_owned()]
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("content_observed")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_send_failure_fails_without_verification()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB4));
    vault
        .put_entity(
            &entity(0xB4),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let transport = ScriptedLinkedInTransport::new(vec![linkedin_conversation(
        "2-jane-doe-abc",
        "Jane Doe\n10:01 AM\nThanks for reaching out.",
    )])
    .failing_send("upstream_send_message_flaked");
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?;
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-send-failed", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-send-failed",
            "intent:linkedin-send-failed",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(result.receipt.outcome, "failed");
    assert!(!result.receipt.fields.contains_key("provider_ref"));
    assert_eq!(sink.transport().send_calls.len(), 1);
    assert_eq!(
        sink.transport().get_calls,
        vec!["2-jane-doe-abc".to_owned()]
    );
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("verify_after_send_send_message_failed")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_result")
            .map(String::as_str),
        Some("failed")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_tool_error")
            .map(String::as_str),
        Some("upstream_send_message_flaked")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("send_message_failed")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_observed_absent_produces_failed_receipt_without_phantom_success()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB2));
    vault
        .put_entity(
            &entity(0xB2),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let plan = LinkedInVerifiedSendPlan::new(
        "linkedin:member:jane-doe",
        "2-jane-doe-abc",
        "Happy to share more details.",
    )?
    .with_max_observation_attempts(2)?;
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
    ]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-absent", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-absent",
            "intent:linkedin-absent",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(result.receipt.outcome, "failed");
    assert!(!result.receipt.fields.contains_key("provider_ref"));
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("verify_after_send_observed_absent")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("observed_absent")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("verification_attempts")
            .map(String::as_str),
        Some("2")
    );
    assert_eq!(sink.transport().send_calls.len(), 1);
    Ok(())
}

#[test]
fn linkedin_send_dm_does_not_verify_older_matching_transcript_line()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB5));
    vault
        .put_entity(
            &entity(0xB5),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?
            .with_max_observation_attempts(1)?;
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Yura\n10:04 AM\nHappy to share more details.\nJane Doe\n10:05 AM\nSounds good.",
        ),
    ]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-older-match", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-older-match",
            "intent:linkedin-older-match",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert!(!result.receipt.fields.contains_key("provider_ref"));
    assert_eq!(sink.transport().send_calls.len(), 1);
    assert_eq!(sink.transport().get_calls.len(), 2);
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("verify_after_send_observed_stale")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("observed_stale")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_requires_new_post_send_occurrence()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB9));
    vault
        .put_entity(
            &entity(0xB9),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?
            .with_max_observation_attempts(1)?;
    let existing_thread = linkedin_conversation(
        "2-jane-doe-abc",
        "Jane Doe\n10:01 AM\nThanks for reaching out.\nYura\n10:04 AM\nHappy to share more details.",
    );
    let transport = ScriptedLinkedInTransport::new(vec![existing_thread.clone(), existing_thread]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-noop-send", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-noop-send",
            "intent:linkedin-noop-send",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(sink.transport().send_calls.len(), 1);
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("verify_after_send_observed_stale")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("observed_stale")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("pre_send_match_count")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("post_send_match_count")
            .map(String::as_str),
        Some("1")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_successful_absent_read_clears_prior_get_error()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB6));
    vault
        .put_entity(
            &entity(0xB6),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let plan = LinkedInVerifiedSendPlan::new(
        "linkedin:member:jane-doe",
        "2-jane-doe-abc",
        "Happy to share more details.",
    )?
    .with_max_observation_attempts(2)?;
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
    ])
    .with_get_error_after_precheck("temporary_get_failure");
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-transient-error", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-transient-error",
            "intent:linkedin-transient-error",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(sink.transport().get_calls.len(), 3);
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("verify_after_send_observed_absent")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("observed_absent")
    );
    assert!(
        !result
            .receipt
            .fields
            .contains_key("verify_get_conversation_error"),
        "a later successful absent read should classify the final attempt"
    );
    Ok(())
}

#[test]
fn linkedin_retry_guard_observes_existing_message_without_duplicate_send()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB3));
    vault
        .put_entity(
            &entity(0xB3),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?
            .retry_guarded();
    let transport = ScriptedLinkedInTransport::new(vec![linkedin_conversation(
        "2-jane-doe-abc",
        "Jane Doe\n10:01 AM\nThanks for reaching out.\nYura\n10:04 AM\nHappy to share more details.",
    )]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-retry", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-retry",
            "intent:linkedin-retry",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert!(sink.transport().send_calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("duplicate_send_guard")
            .map(String::as_str),
        Some("observed_existing")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_called")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("content_observed")
    );
    Ok(())
}

#[test]
fn dispatch_pipeline_holds_gate_pending_without_executing()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x52);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xD1,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let gate = OutboundDispatchGate {
        has_opted_in: true,
        has_permission: false,
        policy_risk: OutboundDispatchPolicyRisk::Normal,
    };
    let request = OutboundDispatchRequest::new(
        "outbound:intent:held",
        "intent:held",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("session:held")),
        actor,
        gate,
        1_010,
        OutboundDeliveryWindowDecision::DeliverNow,
    );

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(result.gate_outcome, "pending");
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"gate.pending.external_effect_authority".to_owned())
    );
    assert_eq!(
        result.receipt.fields.get("hold_reason").map(String::as_str),
        Some("gate.pending.external_effect_authority")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_reason_codes")
            .map(String::as_str),
        Some("gate.pending.external_effect_authority")
    );
    assert_eq!(result.receipt.outcome, "held");
    Ok(())
}

#[test]
fn dispatch_pipeline_preserves_gate_hold_reason_when_window_also_holds()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xA7);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xD7,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let gate = OutboundDispatchGate {
        has_opted_in: true,
        has_permission: false,
        policy_risk: OutboundDispatchPolicyRisk::Normal,
    };
    let request = OutboundDispatchRequest::new(
        "outbound:intent:gate-and-window-held",
        "intent:gate-and-window-held",
        dispatch_intent(OutboundIntentTrigger::agent_immediate(
            "session:gate-window-held",
        )),
        actor,
        gate,
        1_015,
        OutboundDeliveryWindowDecision::Hold {
            reason: "quiet_window".to_owned(),
            retry_at: Some(2_100),
        },
    );

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(result.gate_outcome, "pending");
    assert_eq!(
        result.receipt.fields.get("hold_reason").map(String::as_str),
        Some("gate.pending.external_effect_authority")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("quiet_window")
    );
    assert_eq!(
        result.receipt.fields.get("retry_at").map(String::as_str),
        Some("2100")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.hold:quiet_window".to_owned())
    );
    Ok(())
}

#[test]
fn dispatch_pipeline_suppresses_gate_denied_without_executing()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xD6);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xD4,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let identity_ref = entity(0xB6);
    let contact_id = entity(0xB7);
    let contact =
        CounterpartyContactRecord::user_introduction(identity_ref, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &contact)?;
    vault.opt_out_counterparty_contact(&contact_id, CounterpartyOptOutReason::Unsubscribe, 20)?;

    let request = OutboundDispatchRequest::new(
        "outbound:intent:suppressed",
        "intent:suppressed",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("session:suppressed")),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_045,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .channel_identity_ref(identity_ref)
    .counterparty_ref("kenji@example.com");

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert!(executor.calls.is_empty());
    assert_eq!(result.gate_outcome, "deny");
    assert_eq!(result.receipt.outcome, "suppressed");
    assert_eq!(
        result.receipt.fields.get("suppression").map(String::as_str),
        Some("counterparty_opt_out")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("suppression_reason")
            .map(String::as_str),
        Some("counterparty_opt_out_unsubscribe")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"gate.deny.counterparty_opt_out".to_owned())
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"counterparty_opt_out_unsubscribe".to_owned())
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_receipt_reasons")
            .map(String::as_str),
        Some("counterparty_opt_out_unsubscribe,counterparty_first_touch_user_introduction")
    );
    Ok(())
}

#[test]
fn dispatch_pipeline_rejects_unsupported_verbs_before_execution() {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x53);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "edit", "line", "line:user:kenji"),
        OutboundIntentTrigger::agent_immediate("session:edit"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:line-edit",
        "intent:line-edit",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_020,
        OutboundDeliveryWindowDecision::DeliverNow,
    );

    let mut executor = RecordingExecutor::default();
    let error = vault
        .dispatch_outbound_intent(request, &mut executor)
        .expect_err("line edit should fail capability resolution");

    assert!(executor.calls.is_empty());
    match error {
        OutboundDispatchError::UnsupportedCapability(error) => {
            assert_eq!(error.connector(), "line");
            assert_eq!(error.verb(), Some("edit"));
        }
        OutboundDispatchError::InvalidBoundActor => {
            panic!("unexpected facade-bound actor validation")
        }
        OutboundDispatchError::Engine(error) => panic!("unexpected engine error: {error}"),
        OutboundDispatchError::Chokepoint(error) => {
            panic!("unexpected chokepoint error: {error}")
        }
    }
}

#[test]
fn dispatch_pipeline_window_hold_skips_execution_after_gate_allow()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x54);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xD2,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let request = OutboundDispatchRequest::new(
        "outbound:intent:window-held",
        "intent:window-held",
        dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
            "commitment:morning",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_030,
        OutboundDeliveryWindowDecision::Hold {
            reason: "quiet_window".to_owned(),
            retry_at: Some(2_000),
        },
    );

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(result.gate_outcome, "allow");
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("hold")
    );
    assert_eq!(
        result.receipt.fields.get("retry_at").map(String::as_str),
        Some("2000")
    );
    assert_eq!(
        result.receipt.fields.get("hold_reason").map(String::as_str),
        Some("quiet_window")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.hold:quiet_window".to_owned())
    );
    Ok(())
}

#[test]
fn dispatch_door_defers_call_inside_stored_quiet_hours()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB1);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xE2,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(&vault, 0xE3, &quiet_delivery_window_claim_body(0xB1))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15551234567"),
        OutboundIntentTrigger::commitment_timer_wake("commitment:quiet-call"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:quiet-call",
        "intent:quiet-call",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(result.gate_outcome, "allow");
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("hold")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("quiet_window")
    );
    assert_eq!(
        result.receipt.fields.get("retry_at").map(String::as_str),
        Some("115200")
    );
    assert_ne!(result.receipt.outcome, "suppressed");
    Ok(())
}

#[test]
fn dispatch_door_allows_chat_send_inside_stored_quiet_hours()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB2);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xE5,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "slack",
            &["send"],
        ),
    )?;
    put_claim_body(&vault, 0xE6, &quiet_delivery_window_claim_body(0xB2))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "send", "slack", "slack:channel:C123"),
        OutboundIntentTrigger::agent_immediate("session:chat-leave"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:chat-leave",
        "intent:chat-leave",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        executor.calls,
        vec![(
            "intent:chat-leave".to_owned(),
            "slack".to_owned(),
            "send".to_owned()
        )]
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.no_restriction".to_owned())
    );
    Ok(())
}

#[test]
fn dispatch_door_defers_interruption_when_calendar_busy_is_active()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB3);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xE8,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(
        &vault,
        0xE9,
        &calendar_busy_delivery_window_claim_body(0xB3),
    )?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15557654321"),
        OutboundIntentTrigger::agent_immediate("session:calendar-busy-call"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:calendar-busy-call",
        "intent:calendar-busy-call",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        12 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .active_delivery_context(DeliveryWindowContextCondition::CalendarBusy);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("context_window")
    );
    assert_eq!(result.receipt.fields.get("retry_at"), None);
    assert_ne!(result.receipt.outcome, "suppressed");
    Ok(())
}

#[test]
fn dispatch_door_ignores_delivery_window_claims_for_other_subjects()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB4);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xEC,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(&vault, 0xED, &quiet_delivery_window_claim_body(0xC4))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15550001111"),
        OutboundIntentTrigger::commitment_timer_wake("commitment:other-subject-call"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:other-subject-call",
        "intent:other-subject-call",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    Ok(())
}

#[test]
fn dispatch_door_uses_supplied_local_minute_for_user_local_quiet_hours()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB5);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xEE,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(&vault, 0xEF, &quiet_delivery_window_claim_body(0xB5))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15550002222"),
        OutboundIntentTrigger::commitment_timer_wake("commitment:local-minute-call"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:local-minute-call",
        "intent:local-minute-call",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        12 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("quiet_window")
    );
    assert_eq!(
        result.receipt.fields.get("retry_at").map(String::as_str),
        Some("75600")
    );
    Ok(())
}

#[test]
fn dispatch_door_holds_interrupt_when_local_minute_missing_for_time_window()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB6);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xF0,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(&vault, 0xF1, &quiet_delivery_window_claim_body(0xB6))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15550003333"),
        OutboundIntentTrigger::commitment_timer_wake("commitment:missing-local-minute"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:missing-local-minute",
        "intent:missing-local-minute",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    );

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("local_minute_unavailable")
    );
    assert_eq!(result.receipt.fields.get("retry_at"), None);
    Ok(())
}

#[test]
fn dispatch_door_preserves_connector_channel_for_channel_window_claim()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB7);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xF2,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(
        &vault,
        0xF3,
        &channel_delivery_window_claim_body(0xB7, "voice", "voice_window"),
    )?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15550004444"),
        OutboundIntentTrigger::commitment_timer_wake("commitment:voice-window"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:voice-window",
        "intent:voice-window",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("voice_window")
    );
    assert!(executor.calls.is_empty());
    Ok(())
}

#[test]
fn dispatch_door_enforces_manifest_interrupt_for_email_send()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB8);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xF4,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;
    put_claim_body(&vault, 0xF5, &quiet_delivery_window_claim_body(0xB8))?;

    let request = OutboundDispatchRequest::new(
        "outbound:intent:quiet-email",
        "intent:quiet-email",
        dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
            "commitment:quiet-email",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("quiet_window")
    );
    Ok(())
}

#[test]
fn dispatch_door_preserves_passive_apns_window_context()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB9);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xF6,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "apns",
            &["push"],
        ),
    )?;
    put_claim_body(&vault, 0xF7, &quiet_delivery_window_claim_body(0xB9))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "push", "apns", "device:kenji"),
        OutboundIntentTrigger::agent_immediate("session:passive-push"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:passive-push",
        "intent:passive-push",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60)
    .delivery_window_apns_interruption_level(DeliveryWindowApnsInterruptionLevel::Passive);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    Ok(())
}

#[test]
fn dispatch_door_preserves_request_degrade_target_for_stored_quiet_policy()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xBA);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xF8,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;
    put_claim_body(&vault, 0xF9, &quiet_delivery_window_claim_body(0xBA))?;

    let context = DeliveryWindowEvaluationContext::new(
        23 * 60 * 60,
        23 * 60,
        DeliveryWindowVerbClass::Interrupt,
    )?
    .channel("email")
    .interrupt_surface("email:send")
    .degrade_to("chat:passive");
    let policy = quiet_delivery_window_policy();
    let request = OutboundDispatchRequest::new(
        "outbound:intent:quiet-email-degrade",
        "intent:quiet-email-degrade",
        dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
            "commitment:quiet-email-degrade",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_policy(&context, &[policy]);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Degraded);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result.receipt.fields.get("degraded_to").map(String::as_str),
        Some("chat:passive")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("degrade")
    );
    Ok(())
}

#[test]
fn most_restrictive_delivery_window_decision_merges_same_rank_holds() {
    let current = OutboundDeliveryWindowDecision::Hold {
        reason: "current".to_owned(),
        retry_at: Some(100),
    };
    let later = OutboundDeliveryWindowDecision::Hold {
        reason: "later".to_owned(),
        retry_at: Some(200),
    };
    assert_eq!(
        most_restrictive_delivery_window_decision(current.clone(), later.clone()),
        later
    );

    let indefinite = OutboundDeliveryWindowDecision::Hold {
        reason: "indefinite".to_owned(),
        retry_at: None,
    };
    assert_eq!(
        most_restrictive_delivery_window_decision(current, indefinite.clone()),
        indefinite
    );
}

#[test]
fn dispatch_request_evaluates_delivery_window_policy_before_execution()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x55);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest(
        &vault,
        0xD3,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let context =
        DeliveryWindowEvaluationContext::new(1_030, 23 * 60, DeliveryWindowVerbClass::Interrupt)?
            .interrupt_surface("email:send")
            .degrade_to("chat:passive");
    let policy = quiet_delivery_window_policy();
    let request = OutboundDispatchRequest::new(
        "outbound:intent:window-degraded",
        "intent:window-degraded",
        dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
            "commitment:quiet",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_030,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_policy(&context, &[policy]);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Degraded);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("degrade")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("degraded_from")
            .map(String::as_str),
        Some("email:send")
    );
    assert_eq!(
        result.receipt.fields.get("degraded_to").map(String::as_str),
        Some("chat:passive")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.degrade:quiet_window".to_owned())
    );
    Ok(())
}

#[test]
fn unsupported_connector_verb_is_typed_and_actionable() {
    let error = outbound_verb_contract("line", "edit").expect_err("line edit unsupported");

    assert_eq!(error.connector(), "line");
    assert_eq!(error.verb(), Some("edit"));
    assert!(error.connector_known());
    assert!(
        error.supported_verbs().contains(&"send".to_owned()),
        "known connector errors should include supported verbs"
    );
    assert!(
        error
            .recovery_suggestions()
            .iter()
            .any(|suggestion| suggestion.contains("/v1/core/outbound/capabilities/line")),
        "unsupported errors must tell clients how to recover"
    );

    let error = outbound_verb_contract("unknown-connector", "send")
        .expect_err("unknown connector unsupported");
    assert!(!error.connector_known());
    assert!(error.supported_verbs().is_empty());
    assert!(
        error.supported_connectors().contains(&"slack".to_owned()),
        "unknown connector errors should include registered connectors"
    );
}

#[test]
fn connector_only_discovery_errors_do_not_fabricate_a_verb() {
    let error = unsupported_outbound_connector("unknown-connector");

    assert_eq!(error.connector(), "unknown_connector");
    assert_eq!(error.verb(), None);
    assert!(!error.connector_known());
    assert!(error.supported_verbs().is_empty());
    assert!(
        error
            .recovery_suggestions()
            .iter()
            .any(|suggestion| suggestion.contains("/v1/core/outbound/capabilities")),
        "connector-only unsupported errors should advertise the manifest index"
    );
}

#[test]
fn connector_specific_verbs_live_as_manifest_data() {
    let line_narrowcast =
        outbound_verb_contract("line", "narrowcast").expect("line narrowcast manifest");
    assert_eq!(line_narrowcast.kind, "narrowcast");
    assert_eq!(
        line_narrowcast.capability_vs_permission.permission,
        OutboundPermissionState::ProviderReview
    );

    let mfb_invite = outbound_verb_contract("imessage-mfb", "invite").expect("mfb invite manifest");
    assert_eq!(mfb_invite.kind, "invite");
    assert!(
        !COMMON_OUTBOUND_VERB_KINDS.contains(&mfb_invite.kind.as_str()),
        "connector-specific verbs should not expand the common vocabulary"
    );

    let linkedin_dm =
        outbound_verb_contract("linkedin", "send-dm").expect("linkedin send_dm manifest");
    assert_eq!(linkedin_dm.kind, "send_dm");
    assert_eq!(linkedin_dm.channel_call, "send_message");
    assert!(
        !COMMON_OUTBOUND_VERB_KINDS.contains(&linkedin_dm.kind.as_str()),
        "LinkedIn-specific DM verbs should stay manifest data"
    );

    let linkedin_connect = outbound_verb_contract("linkedin", "connect_request")
        .expect("linkedin connect_request manifest");
    assert_eq!(linkedin_connect.kind, "connect_request");
    assert_eq!(linkedin_connect.channel_call, "connect_with_person");
}

#[test]
fn line_reply_and_push_manifests_separate_quota_semantics() {
    let line_reply = outbound_verb_contract("line", "reply").expect("line reply manifest");
    assert_eq!(line_reply.channel_call, "reply_message");
    assert_eq!(
        line_reply.capability_vs_permission.permission,
        OutboundPermissionState::Allowed
    );
    assert_eq!(line_reply.params["quota"]["quota_debit"], false);
    assert_eq!(line_reply.params["quota"]["metered"], false);
    assert_eq!(line_reply.params["quota"]["plan_tier"], "all");
    assert!(line_reply.params.get("replyToken").is_none());
    assert_eq!(
        line_reply.params["reply_token_ref"],
        "payload_ref host-local reply token handle"
    );

    let line_push = outbound_verb_contract("line", "push").expect("line push manifest");
    assert_eq!(line_push.channel_call, "push_message");
    assert_eq!(
        line_push.capability_vs_permission.permission,
        OutboundPermissionState::Conditional
    );
    assert_eq!(line_push.params["quota"]["quota_debit"], true);
    assert_eq!(line_push.params["quota"]["metered"], true);
    assert_eq!(
        line_push.params["quota"]["free_monthly_allowance"],
        crate::channel_identity_provider::DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE
    );
    assert_eq!(
        line_push.params["quota"]["overage_policy"],
        "requires_metered_plan"
    );

    let legacy_send = outbound_verb_contract("line", "send").expect("legacy line send");
    assert_eq!(legacy_send.channel_call, "reply_message | push_message");
    assert_eq!(
        legacy_send.capability_vs_permission.permission,
        OutboundPermissionState::Conditional
    );
    assert_eq!(legacy_send.params["mode"], "reply | push");
    assert_eq!(
        legacy_send.params["reply"]["reply_token_ref"],
        "payload_ref host-local reply token handle"
    );
    assert_eq!(
        legacy_send.params["reply"]["quota"],
        line_reply.params["quota"]
    );
    assert_eq!(
        legacy_send.params["push"]["quota"],
        line_push.params["quota"]
    );
    assert_eq!(legacy_send.params["reply"]["quota"]["quota_debit"], false);
    assert_eq!(legacy_send.params["push"]["quota"]["quota_debit"], true);
    assert_eq!(legacy_send.params["push"]["quota"]["metered"], true);
    assert_eq!(
        legacy_send.params["push"]["quota"]["free_monthly_allowance"],
        crate::channel_identity_provider::DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE
    );
    assert_eq!(
        legacy_send.params["push"]["quota"]["overage_policy"],
        "requires_metered_plan"
    );

    let legacy_send_media =
        outbound_verb_contract("line", "send_media").expect("legacy line send_media");
    assert_eq!(
        legacy_send_media.capability_vs_permission.permission,
        OutboundPermissionState::Conditional
    );
    assert_eq!(legacy_send_media.params["mode"], "reply | push");
    assert_eq!(
        legacy_send_media.params["reply"]["reply_token_ref"],
        "payload_ref host-local reply token handle"
    );
    assert_eq!(
        legacy_send_media.params["reply"]["quota"],
        line_reply.params["quota"]
    );
    assert_eq!(
        legacy_send_media.params["push"]["quota"],
        line_push.params["quota"]
    );
    assert_eq!(
        legacy_send_media.params["reply"]["quota"]["quota_debit"],
        false
    );
    assert_eq!(
        legacy_send_media.params["push"]["quota"]["quota_debit"],
        true
    );
    assert_eq!(legacy_send_media.params["push"]["quota"]["metered"], true);
    assert_eq!(
        legacy_send_media.params["push"]["quota"]["overage_policy"],
        "requires_metered_plan"
    );
}

#[test]
fn manifests_emit_concrete_schema_on_demand_links() {
    let slack = outbound_capability_manifest("slack").expect("slack manifest");

    assert_eq!(
        slack.schema_on_demand,
        "/v1/core/outbound/capabilities/slack"
    );
}

// --- GOV-01 connector-key effector budgets (ONE-1416) ------------------------

fn email_send_dispatch_request(actor: OutboundDispatchActor, seq: u32) -> OutboundDispatchRequest {
    OutboundDispatchRequest::new(
        format!("outbound:intent:budget-{seq}"),
        format!("intent:budget-{seq}"),
        dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:budget-{seq}"
        ))),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000 + u64::from(seq),
        OutboundDeliveryWindowDecision::DeliverNow,
    )
}

#[test]
fn dispatch_with_no_key_and_empty_budget_key_are_equivalent()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let dispatch_once = |with_key: bool| -> std::result::Result<
        OutboundDispatchResult,
        Box<dyn std::error::Error>,
    > {
        let (_tmp, vault) = temp_vault();
        let agent = entity(0xA1);
        let actor = OutboundDispatchActor::agent(agent);
        put_policy_manifest(
            &vault,
            0xD0,
            &policy_manifest(
                actor.actor_ref.as_deref().expect("actor ref"),
                "email",
                &["send"],
            ),
        )?;
        if with_key {
            vault.register_connector_key(
                &entity(0xB9),
                crate::ConnectorKeyRecord::active("email", None, Vec::new(), 1_000),
            )?;
        }
        let mut executor = RecordingExecutor::default();
        Ok(vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 0), &mut executor)?)
    };

    let without_key = dispatch_once(false)?;
    let with_empty_key = dispatch_once(true)?;
    assert_eq!(without_key.outcome, with_empty_key.outcome);
    assert_eq!(without_key.gate_outcome, with_empty_key.gate_outcome);
    assert_eq!(
        without_key.gate_reason_codes,
        with_empty_key.gate_reason_codes
    );
    assert_eq!(
        without_key.receipt.policy_trace,
        with_empty_key.receipt.policy_trace
    );
    // Receipts are field-identical modulo the per-run gate decision id and
    // (since GOV-02) the honest connector-key stamps a governing key adds:
    // an empty-budget key records `connector_key_ref` + `budget_debit: "0"`
    // but no `budget` field (no matched rows) and changes nothing else.
    let strip = |result: &OutboundDispatchResult| {
        let mut fields = result.receipt.fields.clone();
        fields.remove("gate_decision_ref");
        fields.remove("connector_key_ref");
        fields.remove("budget_debit");
        fields
    };
    assert_eq!(strip(&without_key), strip(&with_empty_key));
    assert!(!without_key.receipt.fields.contains_key("connector_key_ref"));
    assert!(!without_key.receipt.fields.contains_key("budget_debit"));
    assert!(without_key.effector_budget.is_none());
    assert!(without_key.budget_ladder_events.is_empty());
    assert_eq!(
        with_empty_key
            .receipt
            .fields
            .get("budget_debit")
            .map(String::as_str),
        Some("0")
    );
    assert!(!with_empty_key.receipt.fields.contains_key("budget"));
    Ok(())
}

#[test]
fn dispatch_sends_budget_exhausts_suspends_and_walls_until_resume()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xA1);
    let actor = OutboundDispatchActor::agent(agent);
    put_policy_manifest(
        &vault,
        0xD0,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;
    let key_id = entity(0xB7);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active(
            "email",
            None,
            vec![crate::EffectorBudget::sends(
                2,
                crate::EffectorBudgetWindow::Calendar {
                    period: crate::CalendarPeriod::Day,
                    tz: None,
                },
                crate::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;

    let mut executor = RecordingExecutor::default();
    // AC6: sends 1-2 deliver.
    for seq in 1..=2 {
        let result = vault.dispatch_outbound_intent(
            email_send_dispatch_request(actor.clone(), seq),
            &mut executor,
        )?;
        assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    }
    // Send 3: suppressed, exhausted, and the key flips Suspended.
    let result = vault
        .dispatch_outbound_intent(email_send_dispatch_request(actor.clone(), 3), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.gate_reason_codes,
        vec!["gate.deny.effector_budget_exhausted"]
    );
    let record = vault.get_connector_key(&key_id)?.expect("key");
    assert_eq!(record.status, crate::ConnectorKeyStatus::Suspended);
    assert_eq!(
        record.suspended_reason.as_deref(),
        Some("budget_exhausted:row:0")
    );

    // AC7: the suspension is a real ceiling — the 4th dispatch hits the
    // status wall (NOT the exhausted code), proving suspension outlives the
    // exhausting call and would outlive a window rollover.
    let result = vault
        .dispatch_outbound_intent(email_send_dispatch_request(actor.clone(), 4), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.gate_reason_codes,
        vec!["gate.deny.connector_key_suspended"]
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_receipt_reasons")
            .map(String::as_str),
        Some("connector_key_suspended")
    );

    // After an owner resume, budgets evaluate again — and, same window,
    // re-deny with the exhausted code (the reason-code difference across the
    // three phases is the AC).
    vault.resume_connector_key(&key_id, 2_000)?;
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 5), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.gate_reason_codes,
        vec!["gate.deny.effector_budget_exhausted"]
    );
    // Only the first two sends reached the connector.
    assert_eq!(executor.calls.len(), 2);
    Ok(())
}

#[test]
fn parked_and_seat_suppressed_dispatches_never_debit_budgets()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let sends_budget = || {
        vec![crate::EffectorBudget::sends(
            5,
            crate::EffectorBudgetWindow::Calendar {
                period: crate::CalendarPeriod::Day,
                tz: None,
            },
            crate::EffectorBudgetOnExhaust::Suspend,
        )]
    };
    let usage_row_absent = |vault: &Vault, key_id: &EntityId| -> crate::Result<bool> {
        let usage_key = crate::connector_key::connector_key_usage_row_key(key_id, 0);
        let rtxn = vault.store.env.read_txn()?;
        Ok(vault.store.vault_meta.get(&rtxn, &usage_key)?.is_none())
    };

    // A window-Held dispatch passes the gate but never becomes an effect —
    // it must not consume or exhaust the key's budget.
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xA1));
    put_policy_manifest(
        &vault,
        0xD0,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;
    let key_id = entity(0xB8);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active("email", None, sends_budget(), 1_000),
    )?;

    let held_request = OutboundDispatchRequest::new(
        "outbound:intent:held",
        "intent:held",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("session:held")),
        actor.clone(),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::Hold {
            reason: "quiet_hours".to_owned(),
            retry_at: None,
        },
    );
    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(held_request, &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(result.gate_outcome, "allow");
    assert!(
        usage_row_absent(&vault, &key_id)?,
        "held dispatch left usage unchanged"
    );
    assert!(executor.calls.is_empty());

    // The same intent debits when it re-enters and actually delivers.
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 1), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert!(
        !usage_row_absent(&vault, &key_id)?,
        "delivered dispatch debits"
    );

    // A seat-policy-suppressed dispatch (kill switch engaged) also passes
    // the gate but never becomes an effect: no debit.
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB1);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;
    let key_id = entity(0xB9);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active(LINKEDIN_CHANNEL, None, sends_budget(), 1_000),
    )?;
    let killed = active_linkedin_policy()?.mark_killed(1_050, "command:kill-switch")?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(actor, "outbound:intent:killed", "intent:killed")
            .linkedin_sandbox_policy(killed),
        &mut executor,
    )?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.gate_outcome, "allow",
        "the seat policy suppressed, not the gate"
    );
    assert!(
        usage_row_absent(&vault, &key_id)?,
        "seat-suppressed dispatch left usage unchanged"
    );
    Ok(())
}

// --- GOV-02 budget legibility + graceful wrap (ONE-1418) ---------------------

fn sends_per_day_key(limit: u64) -> crate::ConnectorKeyRecord {
    crate::ConnectorKeyRecord::active(
        "email",
        None,
        vec![crate::EffectorBudget::sends(
            limit,
            crate::EffectorBudgetWindow::Calendar {
                period: crate::CalendarPeriod::Day,
                tz: None,
            },
            crate::EffectorBudgetOnExhaust::Suspend,
        )],
        1_000,
    )
}

fn budget_vault_with_key(
    limit: u64,
) -> std::result::Result<
    (tempfile::TempDir, Vault, OutboundDispatchActor),
    Box<dyn std::error::Error>,
> {
    let (tmp, vault) = temp_vault();
    let agent = entity(0xA1);
    let actor = OutboundDispatchActor::agent(agent);
    put_policy_manifest(
        &vault,
        0xD0,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;
    vault.register_connector_key(&entity(0xB7), sends_per_day_key(limit))?;
    Ok((tmp, vault, actor))
}

#[test]
fn dispatch_budget_injection_echoes_meter_and_receipt_fields()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = budget_vault_with_key(100)?;
    let mut executor = RecordingExecutor::default();
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 1), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);

    let read = result.effector_budget.as_ref().expect("budget echo");
    assert_eq!(read.connector, "email");
    assert_eq!(read.status, crate::ConnectorKeyStatus::Active);
    assert_eq!(read.rows.len(), 1);
    assert_eq!(read.rows[0].used, 1);
    assert_eq!(read.rows[0].remaining, 99);
    assert_eq!(read.rows[0].percent_used, 1);

    let key_ref = format!("ckey:{}", entity(0xB7).to_hex());
    assert_eq!(
        result
            .receipt
            .fields
            .get("connector_key_ref")
            .map(String::as_str),
        Some(key_ref.as_str())
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("budget_debit")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        result.receipt.fields.get("budget").map(String::as_str),
        Some("99")
    );

    // AC4c echo property: the dispatch-borne budget equals a fresh meter
    // read at the same instant.
    let fresh = vault
        .effector_budget_read("email", None)?
        .expect("governing key read");
    assert_eq!(read, &fresh);
    Ok(())
}

#[test]
fn ladder_fires_once_per_threshold_across_separate_dispatches()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = budget_vault_with_key(10)?;
    let mut executor = RecordingExecutor::default();
    let mut events_by_send = Vec::new();
    for seq in 1..=9 {
        let result = vault.dispatch_outbound_intent(
            email_send_dispatch_request(actor.clone(), seq),
            &mut executor,
        )?;
        assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        events_by_send.push(result.budget_ladder_events);
    }

    for (index, events) in events_by_send.iter().enumerate() {
        let send = index + 1;
        match send {
            5 => {
                // Crossing 50% fires the silent tick (no steering); a
                // single-row cross emits ONE event tagged with its row.
                assert_eq!(events.len(), 1, "send 5 fires Silent50");
                assert_eq!(events[0].threshold, BudgetThreshold::Silent50);
                assert!(events[0].steering.is_none());
                assert_eq!(events[0].row_index, Some(0));
            }
            8 => {
                // Crossing 80% fires the wrap-up notice.
                assert_eq!(events.len(), 1, "send 8 fires Plan80");
                assert_eq!(events[0].threshold, BudgetThreshold::Plan80);
                let steering = events[0].steering.as_ref().expect("plan steering");
                assert_eq!(steering.template_id, "effector_budget.plan.80");
                assert_eq!(
                    steering.channel,
                    BudgetSignalDeliveryChannel::SteeringQueueNextTurn
                );
                assert_eq!(
                    steering.message,
                    crate::EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE
                );
                assert_eq!(events[0].row_index, Some(0));
            }
            // Single-fire is persisted in the usage row: re-crossings on
            // separate dispatch calls (9th send, 90%) fire nothing new.
            _ => assert!(events.is_empty(), "send {send} fires nothing"),
        }
    }
    Ok(())
}

#[test]
fn graceful_wrap_window_is_bounded_then_hard_cut_suspends()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let limit: u64 = 100;
    let wrap = limit - (95 * limit).div_ceil(100);
    assert_eq!(wrap, 5, "the bounded graceful-wrap window");

    let (_tmp, vault, actor) = budget_vault_with_key(limit)?;
    let mut executor = RecordingExecutor::default();
    for seq in 1..=100 {
        let result = vault.dispatch_outbound_intent(
            email_send_dispatch_request(actor.clone(), seq),
            &mut executor,
        )?;
        assert_eq!(
            result.outcome,
            OutboundDispatchOutcome::DeliveredToChannel,
            "send {seq} still admits"
        );
        let thresholds: Vec<_> = result
            .budget_ladder_events
            .iter()
            .map(|event| event.threshold)
            .collect();
        match seq {
            50 => assert_eq!(thresholds, vec![BudgetThreshold::Silent50]),
            80 => assert_eq!(thresholds, vec![BudgetThreshold::Plan80]),
            95 => {
                // 95% fires LAND: the finalize signal ahead of the hard cut.
                assert_eq!(thresholds, vec![BudgetThreshold::Land95]);
                let steering = result.budget_ladder_events[0]
                    .steering
                    .as_ref()
                    .expect("land steering");
                assert_eq!(steering.template_id, "effector_budget.land.95");
                assert_eq!(
                    steering.message,
                    crate::EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE
                );
            }
            _ => assert!(thresholds.is_empty(), "send {seq} fires nothing"),
        }
        // A3 conformance: every steering signal rides the ONE channel.
        for event in &result.budget_ladder_events {
            if let Some(steering) = event.steering.as_ref() {
                assert_eq!(
                    steering.channel,
                    BudgetSignalDeliveryChannel::SteeringQueueNextTurn
                );
            }
        }
    }

    // The 101st unit is the hard cut: refused AND the key flips Suspended.
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 101), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.gate_reason_codes,
        vec!["gate.deny.effector_budget_exhausted"]
    );
    assert!(result.budget_ladder_events.is_empty());
    let echoed = result.effector_budget.expect("exhaustion still echoes");
    assert_eq!(echoed.status, crate::ConnectorKeyStatus::Suspended);
    assert_eq!(echoed.rows[0].remaining, 0);
    assert_eq!(
        result
            .receipt
            .fields
            .get("budget_debit")
            .map(String::as_str),
        Some("0")
    );
    assert_eq!(
        result.receipt.fields.get("budget").map(String::as_str),
        Some("0")
    );
    Ok(())
}

// --- GOV-10 charter drift at the dispatch surface (ONE-1417) ------------------

#[test]
fn dispatch_holds_on_charter_drift_until_restamped()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = budget_vault_with_key(5)?;
    let key_id = entity(0xB7);
    let pending = vault.propose_connector_charter(&key_id, "never delete on email", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;

    // Hand-corrupt the stored charter text under the stale stamp.
    let mut record = vault.get_connector_key(&key_id)?.expect("record");
    record.charter.as_mut().expect("charter").text = "never delete on email (edited)".to_owned();
    vault.with_write_txn(|wtxn| {
        crate::connector_key::rewrite_connector_key_in_txn(&vault.store, wtxn, &key_id, &record)
    })?;

    // Drift degrades the send to proposed-only: Held, receipted, no debit.
    let mut executor = RecordingExecutor::default();
    let result = vault
        .dispatch_outbound_intent(email_send_dispatch_request(actor.clone(), 1), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(result.gate_reason_codes, vec!["gate.pending.charter_drift"]);
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_receipt_reasons")
            .map(String::as_str),
        Some("charter_drift")
    );
    assert!(result.effector_budget.is_none(), "drift skips all debits");
    assert!(executor.calls.is_empty());
    let read = vault
        .effector_budget_read("email", None)?
        .expect("governing key");
    assert_eq!(read.rows[0].used, 0);

    // A fresh propose/approve re-stamps and restores enforcement.
    let restamp = vault.propose_connector_charter(&key_id, "never delete on email", 1_010)?;
    vault.approve_connector_charter(&key_id, restamp.compiled_hash, "owner", 1_011)?;
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 2), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    Ok(())
}
