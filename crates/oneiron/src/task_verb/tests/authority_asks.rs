use super::support::*;
use super::*;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};

fn grant_scope(vault: &Vault, owner: EntityId, delegate: EntityId, class: &str) -> String {
    let auth = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    let bound = GrantBound::action(
        ActorBound::new(delegate.to_hex()).unwrap(),
        ActionClass::new(class).unwrap(),
        ActionEnvelope::new(["project:alpha".to_owned()]).unwrap(),
    )
    .unwrap();
    let reference = bound.digest().to_hex();
    vault.create_standing_grant(&auth, bound).unwrap();
    reference
}

fn scope_spec(vault: &Vault, key: &str) -> ScopeTaskAskSpec {
    ScopeTaskAskSpec {
        intent_key: key.to_owned(),
        target: TaskAskTarget::Authority(AskAuthorityScope {
            class: ActionClass::new("review").unwrap(),
            envelope: ActionEnvelope::new(["project:alpha".to_owned()]).unwrap(),
        }),
        question_ref: consult_turn(vault, 0x81),
        context_refs: vec![],
        deadline_at: unix_seconds_now() + 3600,
        label: None,
    }
}

#[test]
fn ask_resolves_live_holders_delegate_first_and_retries_one_intent() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let delegate_a = consult_peer(&vault, 0x91);
    let delegate_b = consult_peer(&vault, 0x92);
    let owner_a = consult_peer(&vault, 0x93);
    let owner_b = consult_peer(&vault, 0x94);
    grant_scope(&vault, owner_a, delegate_a, "review");
    let revoked = grant_scope(&vault, owner_b, delegate_b, "review");
    // Another class is not another holder of this authority.
    grant_scope(&vault, owner_b, delegate_b, "unrelated");
    let memory = vault.memory(asker, EdgeActorClass::Agent);
    let input = scope_spec(&vault, "fanout");
    let receipt = memory.tasks_ask(&input).unwrap();
    let actors: Vec<_> = receipt
        .task_refs
        .iter()
        .map(|id| {
            task_verb_body(&vault, *id)
                .unwrap()
                .unwrap()
                .assignee
                .unwrap()
                .entity_ref()
                .unwrap()
        })
        .collect();
    assert_eq!(actors, vec![delegate_a, delegate_b, owner_a, owner_b]);
    assert_eq!(receipt.hold, Some(TaskAskHoldReason::NoLiveRoute));
    let replay = memory.tasks_ask(&input).unwrap();
    assert_eq!(replay.handle, receipt.handle);
    assert!(replay.idempotent_replay);
    let mut changed = input.clone();
    changed.label = Some("different".to_owned());
    assert!(memory.tasks_ask(&changed).is_err());
    let auth = vault
        .authenticate_owner(
            owner_b,
            &owner_b.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    vault.revoke_consent_grant(&auth, &revoked).unwrap();
    let mut next = input;
    next.intent_key = "after-revoke".to_owned();
    assert_eq!(memory.tasks_ask(&next).unwrap().task_refs.len(), 2);
}

#[test]
fn abstention_is_not_winner_late_answers_keep_evidence_and_forged_siblings_do_not_settle() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let delegate = consult_peer(&vault, 0x95);
    let owner = consult_peer(&vault, 0x96);
    grant_scope(&vault, owner, delegate, "review");
    let memory = vault.memory(asker, EdgeActorClass::Agent);
    let input = scope_spec(&vault, "first-answer");
    let receipt = memory.tasks_ask(&input).unwrap();
    let result_a = consult_turn(&vault, 0x82);
    let result_b = consult_turn(&vault, 0x83);
    // A caller can choose a correlation id, but that never adds a member.
    let forged = memory
        .tasks_create(
            &TaskCreateSpec::new(Value::Nil, None, None, Some(unix_seconds_now()))
                .with_kind(TaskKind::Consult)
                .with_consult(ConsultPayload::question(
                    input.question_ref,
                    vec![],
                    receipt.handle.group_ref,
                ))
                .with_assignee(TaskAssignee::Peer {
                    actor_ref: delegate,
                })
                .with_ttl(TaskTtl::at(input.deadline_at)),
        )
        .unwrap()
        .task_ref
        .unwrap();
    vault
        .memory(delegate, EdgeActorClass::Human)
        .land_consult_result(forged, &answer_input(result_a.entity_ref(), result_a))
        .unwrap();
    assert!(matches!(
        memory.tasks_wait(receipt.handle).unwrap(),
        TaskAskWait::Park(_)
    ));
    vault
        .memory(delegate, EdgeActorClass::Human)
        .land_consult_result(
            receipt.task_refs[0],
            &ConsultResultInput {
                kind: ConsultResultKind::Abstain {
                    result_ref: result_a.entity_ref(),
                    reason_ref: result_a,
                },
                completed_at: unix_seconds_now(),
            },
        )
        .unwrap();
    assert!(matches!(
        memory.tasks_wait(receipt.handle).unwrap(),
        TaskAskWait::Park(_)
    ));
    vault
        .memory(owner, EdgeActorClass::Human)
        .land_consult_result(
            receipt.task_refs[1],
            &answer_input(result_b.entity_ref(), result_b),
        )
        .unwrap();
    let expected = TaskAskStatus::Answered(ScopeTaskAskAnswer {
        task_ref: receipt.task_refs[1],
        actor_ref: owner,
        result_ref: result_b.entity_ref(),
    });
    for actor in [asker, delegate, owner] {
        assert_eq!(
            vault
                .memory(
                    actor,
                    if actor == asker {
                        EdgeActorClass::Agent
                    } else {
                        EdgeActorClass::Human
                    }
                )
                .tasks_ask_status(receipt.handle)
                .unwrap(),
            expected
        );
    }
    for task in &receipt.task_refs {
        assert_eq!(
            memory.tasks_ask_status_for_task(*task).unwrap(),
            Some(expected.clone())
        );
    }
    assert!(matches!(
        task_verb_body(&vault, receipt.task_refs[0])
            .unwrap()
            .unwrap()
            .terminal()
            .unwrap()
            .summary,
        Some(ConsultResultSummary::Abstained { .. })
    ));
}

#[test]
fn first_landed_answer_wins_over_backdated_later_answer_and_survives_reopen() {
    let (dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let delegate = consult_peer(&vault, 0x97);
    let owner = consult_peer(&vault, 0x98);
    grant_scope(&vault, owner, delegate, "review");
    let input = scope_spec(&vault, "race");
    let receipt = vault
        .memory(asker, EdgeActorClass::Agent)
        .tasks_ask(&input)
        .unwrap();
    let a = consult_turn(&vault, 0x84);
    let b = consult_turn(&vault, 0x85);
    let mut first = answer_input(a.entity_ref(), a);
    first.completed_at = unix_seconds_now() + 2;
    vault
        .memory(owner, EdgeActorClass::Human)
        .land_consult_result(receipt.task_refs[1], &first)
        .unwrap();
    let mut late = answer_input(b.entity_ref(), b);
    late.completed_at = first.completed_at - 1;
    vault
        .memory(delegate, EdgeActorClass::Human)
        .land_consult_result(receipt.task_refs[0], &late)
        .unwrap();
    let winner = TaskAskStatus::Answered(ScopeTaskAskAnswer {
        task_ref: receipt.task_refs[1],
        actor_ref: owner,
        result_ref: a.entity_ref(),
    });
    assert_eq!(
        vault
            .memory(asker, EdgeActorClass::Agent)
            .tasks_ask_status(receipt.handle)
            .unwrap(),
        winner
    );
    assert_eq!(
        task_verb_body(&vault, receipt.task_refs[0])
            .unwrap()
            .unwrap()
            .terminal()
            .unwrap()
            .result_ref,
        Some(b.entity_ref())
    );
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    assert_eq!(
        vault
            .memory(asker, EdgeActorClass::Agent)
            .tasks_ask_status(receipt.handle)
            .unwrap(),
        winner
    );
    // Raw callers cannot forge or replace the protected membership.
    assert!(
        vault
            .put_entity(
                &receipt.handle.group_ref,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                1,
                &crate::task_verb::wire_encode::canonical_bytes(&Value::Map(vec![(
                    Value::from("role"),
                    Value::from(6)
                )]))
            )
            .is_err()
    );
}

#[test]
fn ask_winner_and_membership_survive_replicated_rows_in_either_order() {
    let (_dir, source) = open_vault();
    let asker = own_agent(&source);
    let delegate = consult_peer(&source, 0xB1);
    let owner = consult_peer(&source, 0xB2);
    grant_scope(&source, owner, delegate, "review");
    let input = scope_spec(&source, "replicated");
    let receipt = source
        .memory(asker, EdgeActorClass::Agent)
        .tasks_ask(&input)
        .unwrap();
    let result = consult_turn(&source, 0x86);
    source
        .memory(owner, EdgeActorClass::Human)
        .land_consult_result(
            receipt.task_refs[1],
            &answer_input(result.entity_ref(), result),
        )
        .unwrap();
    let ids = source
        .entities_by_type_page(ENTITY_TYPE_TASK, None, 256)
        .unwrap();
    let rows: Vec<_> = ids
        .into_iter()
        .map(|id| (id, source.get_raw(&id).unwrap().unwrap()))
        .collect();
    for reverse in [false, true] {
        let (_dir, target) = open_vault();
        own_agent(&target);
        consult_peer(&target, 0xB1);
        consult_peer(&target, 0xB2);
        consult_turn(&target, 0x81);
        consult_turn(&target, 0x86);
        let mut ordered = rows.clone();
        if reverse {
            ordered.reverse();
        }
        for (id, raw) in ordered {
            target
                .batch()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_TASK,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                )
                .commit()
                .unwrap();
        }
        assert_eq!(
            target
                .memory(asker, EdgeActorClass::Agent)
                .tasks_ask_status(receipt.handle)
                .unwrap(),
            TaskAskStatus::Answered(ScopeTaskAskAnswer {
                task_ref: receipt.task_refs[1],
                actor_ref: owner,
                result_ref: result.entity_ref()
            })
        );
    }
}
