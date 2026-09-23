use super::*;
use crate::task_verb::{
    ConsultPayloadRef, ConsultResultInput, ConsultResultKind, TaskAskSpec, TaskAskTarget,
    TaskAskWait, TaskAssignee,
};

fn turn(vault: &Vault) -> ConsultPayloadRef {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_TURN,
            occurred(DELEGATE_NOW),
            DELEGATE_NOW,
            &[0x80],
        )
        .unwrap();
    ConsultPayloadRef::Turn(id)
}

#[test]
fn ask_returns_before_idle_and_multiple_steps_resume_from_one_answer_after_restart() -> Result<()> {
    let (dir, vault) = open_delegation_vault();
    let mut one = step_fixture(&vault, 10)?;
    // This pinned first-party actor is the policy's actual Auto principal.
    let owner = EntityId::from_bytes([0xE1; 16])?;
    vault.put_entity(
        &owner,
        ENTITY_TYPE_PERSON,
        occurred(DELEGATE_NOW),
        DELEGATE_NOW,
        b"owner",
    )?;
    one.actor = WriteActor::new(owner, EdgeActorClass::Agent);
    let mut two = step_fixture(&vault, 10)?;
    two.actor = one.actor;
    let other = step_fixture(&vault, 10)?;
    let peer = EntityId::now();
    vault.put_entity(
        &peer,
        ENTITY_TYPE_PERSON,
        occurred(DELEGATE_NOW),
        DELEGATE_NOW,
        b"peer",
    )?;
    let question = turn(&vault);
    let memory = vault.memory(one.actor.entity_ref(), one.actor.actor_class());
    let ask = memory
        .tasks_ask(&TaskAskSpec {
            intent_key: "idle-only".to_owned(),
            ..crate::task_verb::TaskAskSpec::shorthand(
                Some(TaskAskTarget::Responder(TaskAssignee::Peer {
                    actor_ref: peer,
                })),
                crate::task_verb::TaskAskQuestion {
                    reference: question,
                    revision: 1,
                    options: Default::default(),
                    context_refs: vec![],
                    label: None,
                    outcome_binding: None,
                },
                Some(crate::unix_seconds_now() + 3600),
                crate::task_verb::TaskAskDefault::AskMe,
            )
        })
        .expect("ask queued");
    let runner = DreamerRunnerStore::new(&vault);
    assert_eq!(runner.parked_attempt(one.attempt_id)?, None);
    assert_eq!(runner.parked_attempt(two.attempt_id)?, None);
    assert!(ask.hold.is_some());
    let now = crate::unix_seconds_now() * 1000;
    let one_ctx = ctx(&vault, &one, now);
    let two_ctx = ctx(&vault, &two, now);
    let a = crate::llm::park_peer_result_step(&one_ctx, ask.handle.group_ref, [1; 32])?;
    let b = crate::llm::park_peer_result_step(&two_ctx, ask.handle.group_ref, [2; 32])?;
    assert_ne!(a.trap_claim_id, b.trap_claim_id);
    assert_eq!(
        crate::llm::park_peer_result_step(&one_ctx, ask.handle.group_ref, [1; 32])?,
        a
    );
    assert_eq!(runner.parked_attempt(other.attempt_id)?, None);
    assert!(consume_trap_signal(&vault, &runner, &a, now + 1).is_err());
    let result = turn(&vault);
    vault
        .memory(peer, EdgeActorClass::Human)
        .land_consult_result(
            ask.task_refs[0],
            &ConsultResultInput {
                kind: ConsultResultKind::Answer {
                    result_ref: result.entity_ref(),
                    evidence_refs: vec![result],
                },
                completed_at: now / 1000,
            },
        )
        .expect("answer lands");
    assert!(matches!(
        memory.tasks_wait(ask.handle, None).unwrap(),
        TaskAskWait::Ready(_)
    ));
    // A crash here leaves two durable signals and owner-checked parks, not a
    // lost callback. Startup maintenance consumes both without parking the run.
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    assert_eq!(crate::llm::resume_peer_result_steps(&vault, now + 2)?, 2);
    let runner = DreamerRunnerStore::new(&vault);
    assert_eq!(runner.parked_attempt(one.attempt_id)?, None);
    assert_eq!(runner.parked_attempt(two.attempt_id)?, None);
    assert_eq!(runner.parked_attempt(other.attempt_id)?, None);
    assert_eq!(crate::llm::resume_peer_result_steps(&vault, now + 3)?, 0);
    Ok(())
}
