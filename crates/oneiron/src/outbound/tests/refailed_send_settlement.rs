//! A connector send that fails again keeps one settlement instant on every
//! peer: the synced outcome's instant follows the newest failed attempt.

use super::*;
use crate::attempt_queue::{AttemptQueue, AttemptState, EnqueueAttempt, EnqueueOutcome};
use crate::context_board::TaskBoardStatus;
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::memory::{BRIDGE_OUTBOUND_ATTEMPT_KIND, OutboundDraftInput};

#[test]
fn a_send_that_fails_again_moves_its_synced_settlement() {
    let (_tmp, vault) = temp_vault();
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
