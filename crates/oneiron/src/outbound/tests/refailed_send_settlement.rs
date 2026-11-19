//! A connector send that fails again keeps one settlement instant on every
//! peer: the synced outcome's instant follows the newest failed attempt.

use super::*;
use crate::attempt_queue::{
    AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases, EnqueueAttempt,
    EnqueueOutcome,
};
use crate::context_board::TaskBoardStatus;
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::memory::{BRIDGE_OUTBOUND_ATTEMPT_KIND, OutboundDraftInput};
use crate::outbound::executor::CONNECTOR_TASK_EXECUTOR_LEASE_OWNER;
use crate::outbound::retry_audit::{
    TerminalSendSettlement, persist_terminal_send_receipt_and_fail,
};
use crate::ports::EntityStoreRead;
use crate::receipt::{SendReceiptOutcome, outbound_intent_receipt};

fn scheduled_connector_send() -> (tempfile::TempDir, TimedVault, EntityId, EntityId, u64) {
    let (tmp, vault) = temp_vault();
    let now = 1_800_000_000;
    vault.clock.set(now);
    let owner = crate::test_util::embedded_owner_proof(&vault);
    let actor = entity(0xC4);
    put_connector_task_actor(&vault, actor, now).expect("a live sending agent");
    vault
        .grant_agent_principal(&owner, &actor.to_hex(), AgentCeiling::Auto)
        .expect("the owner gives the agent the full-access ceiling");
    vault
        .mint_standing_outbound_grant(
            &owner,
            entity(0xD4),
            &GrantMintIntent {
                principal_ref: actor.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "create".to_owned(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: "send".to_owned(),
                },
            },
        )
        .expect("the owner grants the sends");
    let sender = vault.memory(actor, EdgeActorClass::Agent);
    sender
        .schedule_outbound(&OutboundDraftInput {
            verb: "send".to_owned(),
            channel: "discord".to_owned(),
            target: "owen@example.com".to_owned(),
            on_behalf_of: None,
            content_ref: None,
            idempotency_key: Some("refailed-send-settlement:1".to_owned()),
            dedupe_key: None,
            trigger: "agent_immediate".to_owned(),
            trigger_ref: "session:refailed-send-settlement".to_owned(),
            job_ref: None,
            occurred_at: None,
            mention: None,
        })
        .expect("the agent schedules one connector send");
    let tasks = vault.connector_send_tasks().expect("connector TASKs");
    assert_eq!(tasks.len(), 1, "one connector send was scheduled");
    let task_ref = tasks[0].task_ref;
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);
    let attempts: Vec<_> = queue
        .list()
        .expect("read attempts")
        .into_iter()
        .filter(|attempt| attempt.task_ref.as_deref() == Some(task_hex.as_str()))
        .collect();
    assert_eq!(attempts.len(), 1, "one realizing attempt, with no failure");
    assert_eq!(attempts[0].state, AttemptState::Queued);
    (tmp, vault, actor, task_ref, now)
}

#[test]
fn a_send_that_fails_again_moves_its_synced_settlement() {
    let (_tmp, vault, actor, task_ref, now) = scheduled_connector_send();
    let sender = vault.memory(actor, EdgeActorClass::Agent);
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);

    // The failure takes the store's recorded instant: the clock reads the
    // drain's instant, as it does in production.
    let t1 = now + 10;
    vault.clock.set(t1);
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout"),
        ..Default::default()
    };
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, t1)
            .expect("the executor fails the first attempt"),
        0,
        "a failed send delivers nothing"
    );
    assert_eq!(sink.calls.len(), 1, "the executor attempted the send once");
    let task = vault
        .connector_send_task(&task_ref)
        .expect("read the failed TASK")
        .expect("the TASK stands");
    assert_eq!(
        task.outcome,
        Some(ConnectorSendTaskOutcome::Failed),
        "the first failure settles the TASK Failed"
    );
    assert_eq!(
        task.outcome_at,
        Some(t1),
        "the synced settlement is the first failure's instant"
    );
    let attempts: Vec<_> = queue
        .list()
        .expect("read attempts after first failure")
        .into_iter()
        .filter(|attempt| attempt.task_ref.as_deref() == Some(task_hex.as_str()))
        .collect();
    assert_eq!(
        attempts.len(),
        1,
        "one realizing attempt after first failure"
    );
    assert_eq!(
        attempts[0].state,
        AttemptState::Failed,
        "the first attempt failed"
    );
    assert_eq!(
        attempts[0].settled_at, task.outcome_at,
        "the synced settlement is the failed attempt's own instant"
    );

    let t2 = t1 + 10;
    vault.clock.set(t2);
    let receipt = sender
        .tasks_update(task_ref)
        .expect("the sender acknowledges the failure");
    assert!(receipt.acked, "the failure is dismissed: {receipt:?}");
    assert!(
        sender
            .describe_rows()
            .expect("the sender reads after acknowledgement")
            .intents
            .iter()
            .all(|row| row.id != task_hex),
        "the failed TASK is no longer listed"
    );

    // The same TASK is retried with a second attempt, as
    // connector_schedule.rs `failed_send_receipt_is_audit_only_and_same_task_can_retry`
    // does.
    let retry = queue
        .enqueue(EnqueueAttempt {
            kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
            payload: connector_send_attempt_payload(task_ref).expect("second attempt payload"),
            dedupe_key: None,
            run_id: None,
            now: t2,
        })
        .expect("queue the second attempt");
    assert!(
        matches!(retry, EnqueueOutcome::Enqueued(_)),
        "the second attempt is queued"
    );

    let t3 = t1 + 100;
    vault.clock.set(t3);
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, t3)
            .expect("the executor fails the second attempt"),
        0,
        "a refailed send delivers nothing"
    );
    assert_eq!(
        sink.calls.len(),
        2,
        "the executor attempted the second send once"
    );
    let task = vault
        .connector_send_task(&task_ref)
        .expect("read the refailed TASK")
        .expect("the TASK stands");
    assert_eq!(
        task.outcome,
        Some(ConnectorSendTaskOutcome::Failed),
        "the second failure keeps the TASK Failed"
    );
    assert_eq!(
        task.outcome_at,
        Some(t3),
        "the synced settlement follows the newest failed attempt"
    );
    let rows = sender
        .describe_rows()
        .expect("the sender reads after the second failure");
    let row = rows
        .intents
        .iter()
        .find(|row| row.id == task_hex)
        .expect("the refailed TASK is listed again after acknowledgement");
    assert_eq!(row.status, TaskBoardStatus::Failed);

    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, t3 + 5)
            .expect("the executor passes with no attempt left"),
        0,
        "a pass with no attempt delivers nothing"
    );
    assert_eq!(sink.calls.len(), 2, "a pass with no attempt sends nothing");
    assert_eq!(
        vault
            .connector_send_task(&task_ref)
            .expect("read the TASK after the empty pass")
            .expect("the TASK stands")
            .outcome_at,
        Some(t3),
        "a pass that fails no attempt keeps the stamp"
    );
}

#[test]
fn a_failure_stamps_its_task_at_the_failed_attempts_instant() {
    let (_tmp, vault, _actor, task_ref, now) = scheduled_connector_send();
    let queue = AttemptQueue::new(&vault);
    let drain = now + 10;
    vault.clock.set(drain);
    let ClaimOutcome::Claimed(attempt) = queue
        .claim_kind(
            BRIDGE_OUTBOUND_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                now: drain,
            },
        )
        .expect("claim the scheduled send")
    else {
        panic!("the scheduled send must be claimable");
    };
    let task = vault
        .connector_send_task(&task_ref)
        .expect("read the scheduled TASK")
        .expect("the TASK stands");
    let failed_at = drain + 2;
    vault.clock.set(failed_at);
    let receipt = outbound_intent_receipt(
        "outbound:failure-recorded-instant",
        "intent:failure-recorded-instant",
        &task.intent,
        drain,
        "failed",
    );
    assert!(
        persist_terminal_send_receipt_and_fail(
            &vault,
            TerminalSendSettlement {
                attempt: &attempt,
                task_ref,
                receipt,
                receipt_outcome: SendReceiptOutcome::Failed,
                transport_dispatched: true,
                task_outcome: ConnectorSendTaskOutcome::Failed,
                reason: "provider_timeout",
                now: drain,
            },
        )
        .expect("settle the failed send at the store's recorded instant")
    );
    let failed = queue
        .get(attempt.id)
        .expect("read the failed attempt")
        .expect("the attempt stands");
    assert_eq!(failed.state, AttemptState::Failed);
    assert_eq!(failed.settled_at, Some(failed_at));
    let task = vault
        .connector_send_task(&task_ref)
        .expect("read the failed TASK")
        .expect("the TASK stands");
    assert_eq!(task.outcome, Some(ConnectorSendTaskOutcome::Failed));
    assert_eq!(
        task.outcome_at,
        Some(failed_at),
        "the TASK takes the failed attempt's recorded instant, not the drain's sampled now"
    );
}

#[test]
fn a_stale_drain_never_restamps_a_newer_failure() {
    let (_tmp, vault, _actor, task_ref, now) = scheduled_connector_send();
    let queue = AttemptQueue::new(&vault);
    let t1 = now + 10;
    vault.clock.set(t1);
    let ClaimOutcome::Claimed(attempt) = queue
        .claim_kind(
            BRIDGE_OUTBOUND_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                now: t1,
            },
        )
        .expect("the first drain claims the scheduled send")
    else {
        panic!("the scheduled send must be claimable");
    };
    let stale = attempt.clone();
    let lease_timeout_secs = 60;
    let expired_at = t1 + lease_timeout_secs + 1;
    vault.clock.set(expired_at);
    queue
        .cleanup_leases(CleanupAttemptLeases {
            now: expired_at,
            lease_timeout_secs,
        })
        .expect("cleanup requeues the expired lease");
    let requeued = queue
        .get(stale.id)
        .expect("read the requeued attempt")
        .expect("the same attempt stands");
    assert_eq!(requeued.id, stale.id);
    assert_eq!(requeued.state, AttemptState::Queued);
    assert_eq!(requeued.attempt_count, stale.attempt_count);

    let t4 = t1 + 100;
    vault.clock.set(t4);
    let ClaimOutcome::Claimed(current) = queue
        .claim_kind(
            BRIDGE_OUTBOUND_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                now: t4,
            },
        )
        .expect("a newer drain claims the requeued send")
    else {
        panic!("the requeued send must be claimable");
    };
    assert_eq!(current.id, stale.id);
    assert_eq!(current.attempt_count, stale.attempt_count + 1);
    let task = vault
        .connector_send_task(&task_ref)
        .expect("read the scheduled TASK")
        .expect("the TASK stands");
    let receipt = outbound_intent_receipt(
        "outbound:newer-drain-failure",
        "intent:newer-drain-failure",
        &task.intent,
        t4,
        "failed",
    );
    assert!(
        persist_terminal_send_receipt_and_fail(
            &vault,
            TerminalSendSettlement {
                attempt: &current,
                task_ref,
                receipt,
                receipt_outcome: SendReceiptOutcome::Failed,
                transport_dispatched: true,
                task_outcome: ConnectorSendTaskOutcome::Failed,
                reason: "provider_timeout",
                now: t4,
            },
        )
        .expect("the newer drain fails the send")
    );
    assert_eq!(
        vault
            .connector_send_task(&task_ref)
            .expect("read the newer failure")
            .expect("the TASK stands")
            .outcome_at,
        Some(t4)
    );
    let receipt = outbound_intent_receipt(
        "outbound:stale-drain-failure",
        "intent:stale-drain-failure",
        &task.intent,
        t1,
        "failed",
    );
    // The clock stays at t4 while the first drain resumes with its old claim and now.
    assert!(
        persist_terminal_send_receipt_and_fail(
            &vault,
            TerminalSendSettlement {
                attempt: &stale,
                task_ref,
                receipt,
                receipt_outcome: SendReceiptOutcome::Failed,
                transport_dispatched: true,
                task_outcome: ConnectorSendTaskOutcome::Failed,
                reason: "provider_timeout",
                now: t1,
            },
        )
        .expect("a stale drain's already-failed settlement must return Ok")
    );
    assert_eq!(
        vault
            .connector_send_task(&task_ref)
            .expect("read the TASK after the stale drain resumes")
            .expect("the TASK stands")
            .outcome_at,
        Some(t4),
        "the stale drain must not restamp the newer failure"
    );
    let failed = queue
        .get(stale.id)
        .expect("read the failed attempt after the stale drain")
        .expect("the attempt stands");
    assert_eq!(failed.state, AttemptState::Failed);
    assert_eq!(failed.settled_at, Some(t4));
    let latest = vault
        .store
        .get_send_receipt_by_task(&task_ref)
        .expect("read the TASK's latest send receipt")
        .expect("the TASK holds a latest send receipt");
    let (latest, latest_outcome) =
        crate::Vault::decode_archived_send_receipt_for_restore(&task_ref, &latest)
            .expect("the latest send receipt decodes");
    assert_eq!(
        latest.receipt_id, "outbound:newer-drain-failure",
        "the stale drain's receipt must not replace the newer failure's as the TASK's latest"
    );
    assert_eq!(latest_outcome, SendReceiptOutcome::Failed);
    let (trail, undecodable) =
        crate::receipt::durable_send_receipts(&vault).expect("read the send receipt audit trail");
    assert!(undecodable.is_empty());
    for receipt_id in [
        "outbound:newer-drain-failure",
        "outbound:stale-drain-failure",
    ] {
        assert!(
            trail.iter().any(|receipt| receipt.receipt_id == receipt_id),
            "the audit trail keeps {receipt_id}"
        );
    }
}

#[test]
fn an_ack_refuses_a_refailure_synced_after_its_read() {
    let (_tmp, vault, actor, task_ref, now) = scheduled_connector_send();
    let sender = vault.memory(actor, EdgeActorClass::Agent);
    let task_hex = task_ref.to_hex();
    let t1 = now + 10;
    vault.clock.set(t1);
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_timeout"),
        ..Default::default()
    };
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, t1)
            .expect("the executor fails the scheduled send"),
        0
    );
    let task = vault
        .connector_send_task(&task_ref)
        .expect("read the failed TASK")
        .expect("the TASK stands");
    assert_eq!(task.outcome, Some(ConnectorSendTaskOutcome::Failed));
    assert_eq!(task.outcome_at, Some(t1));
    let rows = sender.describe_rows().expect("read the sender's board");
    let row = rows
        .intents
        .iter()
        .find(|row| row.id == task_hex)
        .expect("the failed TASK is listed before acknowledgement");
    assert_eq!(row.status, TaskBoardStatus::Failed);

    let t2 = t1 + 10;
    vault.clock.set(t2);
    let peer_settled_at = t1 + 5;
    crate::task_verb::set_before_ack_writer_hook(move |vault: &Vault| {
        // Same replicated TASK rewrite as owner_declined_resend_ack.rs:244-278.
        let raw = {
            let rtxn = vault.store.env.read_txn().expect("read snapshot");
            vault
                .store
                .port_entity_record(&rtxn, &task_ref)
                .expect("read the stored TASK row")
                .expect("the TASK row stands")
        };
        let Value::Map(mut fields) =
            rmpv::decode::read_value(&mut raw.body.as_slice()).expect("decode the TASK body")
        else {
            panic!("the connector TASK body must be a named map");
        };
        let (_, outcome_at) = fields
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("outcome_at"))
            .expect("the settled TASK has an outcome_at field");
        *outcome_at = Value::from(peer_settled_at);
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &Value::Map(fields))
            .expect("encode the peer TASK body");
        vault
            .batch()
            .put_replicated(
                &task_ref,
                raw.entity_type,
                raw.occurred,
                raw.learned_at,
                None,
                &body,
            )
            .commit()
            .expect("sync a refailure between the acknowledgement's read and writer");
    });
    let result = sender.tasks_update(task_ref);
    assert!(
        matches!(
            &result,
            Err(error) if error.code == crate::memory::MEMORY_CODE_INVALID_STATE
        ),
        "an acknowledgement must refuse an unseen refailure with INVALID_STATE: {result:?}"
    );
    assert_eq!(
        vault
            .connector_send_task(&task_ref)
            .expect("read the synced refailure")
            .expect("the TASK stands")
            .outcome_at,
        Some(peer_settled_at)
    );
    let rows = sender
        .describe_rows()
        .expect("read the board after the refused acknowledgement");
    let row = rows
        .intents
        .iter()
        .find(|row| row.id == task_hex)
        .expect("the unseen refailure stays listed");
    assert_eq!(row.status, TaskBoardStatus::Failed);
    assert!(
        !crate::context_board::task_is_acked(&vault, task_ref)
            .expect("the refused acknowledgement wrote no ack fact")
    );

    let receipt = sender
        .tasks_update(task_ref)
        .expect("an unarmed acknowledgement re-reads the synced refailure");
    assert!(receipt.acked, "the re-read acknowledgement converges");
    assert!(
        sender
            .describe_rows()
            .expect("read the board after the re-read acknowledgement")
            .intents
            .iter()
            .all(|row| row.id != task_hex),
        "the acknowledged refailure is no longer listed"
    );
}
