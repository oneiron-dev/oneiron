//! Generated SDK calls preserve handles and durable C9 wait results.
use oneiron::task_verb::sdk::{TaskAnswerRequest, TaskWaitRequest};
use oneiron::task_verb::{TaskAskSpec, TaskWaitOutcome};
use oneiron_remote::{OneironClient, OpenOptions};
use std::collections::BTreeSet;
#[test]
fn generated_sdk_ask_answer_and_wait_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let client = OneironClient::open(Some(dir.path()), &OpenOptions::default()).unwrap();
    let actor = client.actor_ref().unwrap();
    let spec = TaskAskSpec {
        question: serde_json::json!({"text":"Proceed?"}),
        holders: BTreeSet::from([actor.clone()]),
        idempotency_key: "sdk-one".into(),
        outcome_binding: None,
    };
    let receipt = client.tasks_ask(&spec).unwrap();
    assert_eq!(client.tasks_ask(&spec).unwrap().handle, receipt.handle);
    let wait = TaskWaitRequest {
        handle: receipt.handle.clone(),
        step_key: "step-one".into(),
    };
    assert!(matches!(
        client.tasks_wait(&wait).unwrap(),
        TaskWaitOutcome::Pending { .. }
    ));
    let answer = client
        .tasks_answer(&TaskAnswerRequest {
            handle: receipt.handle,
            result_ref: actor,
        })
        .unwrap();
    assert_eq!(
        client.tasks_wait(&wait).unwrap(),
        TaskWaitOutcome::Ready(answer.clone())
    );
    assert_eq!(
        client.tasks_wait(&wait).unwrap(),
        TaskWaitOutcome::AlreadyResumed(answer)
    );
    assert!(
        client
            .agent_verb("not.a.verb", serde_json::json!({}))
            .is_err()
    );
}
