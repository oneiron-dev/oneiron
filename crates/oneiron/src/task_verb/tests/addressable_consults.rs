use super::support::*;
use super::*;

#[test]
fn child_consult_answers_abstains_and_refuses_dangling_actor() {
    let (_dir, vault) = open_vault();
    let owner = own_agent(&vault);
    let child = consult_peer(&vault, 0xE2);
    let question = consult_turn(&vault, 0x7A);
    let answer = consult_turn(&vault, 0x7B);
    let facade = vault.memory(owner, EdgeActorClass::Agent);
    let spec = consult_spec(question, child, CONSULT_DEADLINE)
        .with_assignee(TaskAssignee::Child { actor_ref: child });
    let created = facade.tasks_create(&spec).unwrap();
    assert_eq!(created.route.unwrap().lane(), TaskRouteLane::ChildActor);
    let task = created.task_ref.unwrap();
    assert_eq!(
        task_verb_body(&vault, task).unwrap().unwrap().assignee,
        spec.assignee
    );
    assert!(
        facade
            .land_consult_result(task, &answer_input(answer.entity_ref(), question))
            .is_err()
    );
    let child_facade = vault.memory(child, EdgeActorClass::Agent);
    child_facade
        .land_consult_result(task, &answer_input(answer.entity_ref(), question))
        .unwrap();
    let abstention = facade.tasks_create(&spec).unwrap().task_ref.unwrap();
    let result = child_facade
        .land_consult_result(
            abstention,
            &ConsultResultInput {
                kind: ConsultResultKind::Abstain {
                    result_ref: answer.entity_ref(),
                    reason_ref: question,
                },
                completed_at: CONSULT_NOW + 10,
            },
        )
        .unwrap();
    assert!(matches!(
        result.terminal.summary,
        Some(ConsultResultSummary::Abstained { .. })
    ));
    let before = task_entity_census(&vault);
    assert!(
        facade
            .tasks_create(&spec.with_assignee(TaskAssignee::Child {
                actor_ref: EntityId::now()
            }))
            .is_err()
    );
    assert_eq!(task_entity_census(&vault), before);
}

#[test]
fn dreamer_consult_has_a_deadline_answer_and_expiry() {
    let (_dir, vault) = open_vault();
    let owner = own_agent(&vault);
    grant_outbound(&vault, owner, 0xD1);
    let question = consult_turn(&vault, 0x7A);
    let answer = consult_turn(&vault, 0x7B);
    let facade = vault.memory(owner, EdgeActorClass::Agent);
    let spec = consult_spec(question, owner, CONSULT_DEADLINE).with_assignee(TaskAssignee::Dreamer);
    let created = facade.tasks_create(&spec).unwrap();
    assert_eq!(created.route.unwrap().lane(), TaskRouteLane::Dreamer);
    let answered = created.task_ref.unwrap();
    let expired = facade.tasks_create(&spec).unwrap().task_ref.unwrap();
    facade
        .land_consult_result(answered, &answer_input(answer.entity_ref(), question))
        .unwrap();
    let sweep = facade
        .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
        .unwrap();
    assert_eq!(sweep.expired_task_refs, vec![expired]);
    assert_eq!(
        task_verb_body(&vault, answered)
            .unwrap()
            .unwrap()
            .terminal()
            .unwrap()
            .disposition,
        TaskTerminalDisposition::Completed
    );
    assert_eq!(
        task_verb_body(&vault, expired)
            .unwrap()
            .unwrap()
            .terminal()
            .unwrap()
            .disposition,
        TaskTerminalDisposition::Expired
    );
}
