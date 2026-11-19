//! An owner's no-resend answer settles the sender's failure acknowledgement,
//! before and after the executor drains the still-live attempt.

use super::*;
use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::context_board::TaskBoardStatus;
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::memory::OutboundDraftInput;

#[test]
fn an_owner_declined_resend_is_dismissed_by_its_senders_ack() {
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
            idempotency_key: Some("owner-declined-resend-ack:1".to_owned()),
            dedupe_key: None,
            trigger: "agent_immediate".to_owned(),
            trigger_ref: "session:owner-declined-resend-ack".to_owned(),
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
    let task = vault
        .connector_send_task(&task_ref)
        .expect("read the TASK")
        .expect("the TASK stands");

    let t1 = now + 1;
    vault.clock.set(t1);
    super::super::uncertain_send::hold_uncertain_send(&vault, &task, t1)
        .expect("hold the uncertain send for its owner's answer");
    assert!(
        vault
            .connector_send_task(&task_ref)
            .expect("read the held TASK")
            .expect("the TASK stands")
            .uncertain_send
            .is_some()
    );

    let t2 = t1 + 5;
    vault.clock.set(t2);
    assert_eq!(
        vault
            .answer_uncertain_send(&owner, task_ref, false)
            .expect("the owner declines resend"),
        UncertainSendAnswerOutcome::Declined
    );
    assert_eq!(
        vault
            .connector_send_task(&task_ref)
            .expect("read the declined TASK")
            .expect("the TASK stands")
            .outcome,
        Some(ConnectorSendTaskOutcome::OwnerDeclinedResend)
    );
    let rows = sender.describe_rows().expect("the sender reads its board");
    let row = rows
        .intents
        .iter()
        .find(|row| row.id == task_hex)
        .expect("the declined TASK is listed before acknowledgement");
    assert_eq!(row.status, TaskBoardStatus::Failed);

    vault.clock.set(t2 + 1);
    let receipt = sender
        .tasks_update(task_ref)
        .expect("the sender acknowledges before executor cleanup");
    assert!(receipt.acked, "the declined send is dismissed: {receipt:?}");
    assert!(
        sender
            .describe_rows()
            .expect("the sender reads after acknowledgement")
            .intents
            .iter()
            .all(|row| row.id != task_hex),
        "the declined TASK is no longer listed"
    );

    let t3 = t2 + 10;
    let mut sink = RecordingExecutor::default();
    vault
        .run_connector_task_executor(&mut sink, t3)
        .expect("the executor drains the owner-declined attempt");
    assert!(sink.calls.is_empty(), "the executor sends nothing");
    assert_eq!(
        queue
            .get(attempts[0].id)
            .expect("read the drained attempt")
            .expect("the attempt stands")
            .state,
        AttemptState::Completed,
        "the executor completed the attempt after acknowledgement"
    );
    assert!(
        sender
            .describe_rows()
            .expect("the sender reads after executor cleanup")
            .intents
            .iter()
            .all(|row| row.id != task_hex),
        "later executor cleanup never reopens the dismissed TASK"
    );
    assert!(crate::context_board::task_is_acked(&vault, task_ref).expect("ack state"));
}
