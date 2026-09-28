//! Generated SDK calls preserve handles and durable C9 wait results.
use oneiron::task_verb::sdk::{TaskAnswerRequest, TaskAskRequest, TaskAskShort, TaskWaitRequest};
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskSpec, TaskAskTarget, TaskAskWait, TaskAssignee,
};
use oneiron_remote::{OneironClient, OpenOptions};
#[test]
fn generated_sdk_ask_answer_and_wait_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let question = oneiron::EntityId::now();
    {
        let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap();
        vault
            .put_entity(
                &question,
                oneiron::registry::ENTITY_TYPE_TURN,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                &[0xc0],
            )
            .unwrap();
    }
    let client = OneironClient::open(Some(dir.path()), &OpenOptions::default()).unwrap();
    let actor = client.actor_ref().unwrap();
    let spec = TaskAskSpec {
        intent_key: "sdk-one".into(),
        ..oneiron::task_verb::TaskAskSpec::shorthand(
            Some(TaskAskTarget::Responder(TaskAssignee::Human {
                actor_ref: oneiron::EntityId::from_hex(&actor).unwrap(),
            })),
            oneiron::task_verb::TaskAskQuestion {
                reference: ConsultPayloadRef::Turn(question),
                revision: 1,
                options: Default::default(),
                context_refs: Vec::new(),
                label: None,
                outcome_binding: None,
                ladder_answer: None,
                class_key: None,
                commitment: false,
            },
            Some(u64::MAX),
            oneiron::task_verb::TaskAskDefault::AskMe,
        )
    };
    let rich = TaskAskRequest::Rich(Box::new(spec));
    let receipt = client.tasks_ask(&rich).unwrap();
    assert_eq!(client.tasks_ask(&rich).unwrap().handle, receipt.handle);
    let wait = TaskWaitRequest {
        handle: receipt.handle,
        step_key: "step-one".into(),
    };
    assert!(matches!(
        client.tasks_wait(&wait).unwrap(),
        TaskAskWait::Pending { .. }
    ));
    let answer = client
        .tasks_answer(&TaskAnswerRequest {
            handle: receipt.handle,
            word: oneiron::task_verb::TaskAskWord::new(
                oneiron::EntityId::from_hex(&actor).unwrap(),
            ),
        })
        .unwrap();
    let expected = client.tasks_wait(&wait).unwrap();
    let TaskAskWait::Ready(result) = &expected else {
        panic!("settled wait")
    };
    assert_eq!(
        result.decision,
        oneiron::task_verb::TaskAskDecision::First(answer)
    );
    assert!(result.coverage.met);
    assert_eq!(client.tasks_wait(&wait).unwrap(), expected);

    // The same generated Rust client also admits the four-field short shape
    // without a second verb or a caller-supplied retry key.
    let short = TaskAskRequest::Short(Box::new(TaskAskShort {
        who: Some(TaskAskTarget::Responder(TaskAssignee::Human {
            actor_ref: oneiron::EntityId::from_hex(&actor).unwrap(),
        })),
        what: oneiron::task_verb::TaskAskQuestion::new(ConsultPayloadRef::Turn(question)),
        until: Some(u64::MAX),
        default: oneiron::task_verb::TaskAskDefault::Hold,
    }));
    let short_receipt = client.tasks_ask(&short).unwrap();
    assert_ne!(short_receipt.handle, receipt.handle);
    assert_eq!(
        client.tasks_ask(&short).unwrap().handle,
        short_receipt.handle
    );
    let short_wait = TaskWaitRequest {
        handle: short_receipt.handle,
        step_key: "step-short".into(),
    };
    assert!(matches!(
        client.tasks_wait(&short_wait).unwrap(),
        TaskAskWait::Pending { .. }
    ));
    let short_answer = client
        .tasks_answer(&TaskAnswerRequest {
            handle: short_receipt.handle,
            word: oneiron::task_verb::TaskAskWord::new(
                oneiron::EntityId::from_hex(&actor).unwrap(),
            ),
        })
        .unwrap();
    let TaskAskWait::Ready(short_result) = client.tasks_wait(&short_wait).unwrap() else {
        panic!("short ask settled");
    };
    assert_eq!(
        short_result.decision,
        oneiron::task_verb::TaskAskDecision::First(short_answer)
    );
    assert!(short_result.coverage.met);
    assert!(
        client
            .agent_verb("not.a.verb", serde_json::json!({}))
            .is_err()
    );
}

/// ARCH-0067's 2026-09-22 amendment renamed the four task rows, with no alias.
#[test]
fn retired_task_verb_names_are_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let client = OneironClient::open(Some(dir.path()), &OpenOptions::default()).unwrap();
    for name in ["tasks.check", "tasks.expand", "tasks.ack", "tasks.cancel"] {
        let refusal = client
            .agent_verb(name, serde_json::json!({}))
            .expect_err(name);
        assert_eq!(
            refusal.code,
            oneiron::memory::MEMORY_CODE_BAD_REQUEST,
            "{name}"
        );
        assert_eq!(refusal.message, "unknown SDK agent verb", "{name}");
    }
}
