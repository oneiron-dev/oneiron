use super::support::*;
use super::*;

#[test]
fn child_consult_answers_abstains_and_refuses_dangling_actor() {
    let (_dir, vault) = open_consult_vault();
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
                measured_spend: None,
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

/// A consult addressed to a running child is its inbox input, which no
/// attempt leases: the child's own run lands it whatever TASK that run
/// leased. Any other run lands a consult only on the TASK it leased.
#[test]
fn child_consult_lands_from_the_child_run_and_elsewhere_only_from_its_lease() {
    let (_dir, vault) = open_consult_vault();
    let owner = own_agent(&vault);
    let child = consult_peer(&vault, 0xE2);
    let question = consult_turn(&vault, 0x7A);
    let spec = consult_spec(question, child, CONSULT_DEADLINE)
        .with_assignee(TaskAssignee::Child { actor_ref: child });
    let task = vault
        .memory(owner, EdgeActorClass::Agent)
        .tasks_create(&spec)
        .unwrap()
        .task_ref
        .unwrap();
    let lands = |leased: Option<EntityId>, actor: EntityId| {
        crate::task_verb::run_rows::consult_result::lands_from_run(&vault, task, leased, actor)
            .unwrap()
    };
    let other_task = EntityId::now();
    assert!(lands(Some(other_task), child));
    assert!(!lands(Some(other_task), owner));
    assert!(!lands(None, owner));
    assert!(lands(Some(task), owner));
}
