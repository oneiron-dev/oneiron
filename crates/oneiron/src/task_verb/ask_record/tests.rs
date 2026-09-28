use super::*;
use crate::task_verb::{
    TaskAskDefault, TaskAskOptionId, TaskAskQuestion, TaskAskSpec, TaskAskTarget, TaskAssignee,
};

#[test]
fn stored_invalid_option_is_a_store_error_not_caller_input()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let actor = vault.ensure_embedded_owner_actor()?;
    let question = EntityId::now();
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))?;
    vault.put_entity(
        &question,
        crate::registry::ENTITY_TYPE_TURN,
        crate::TimeRange { start: 1, end: 1 },
        1,
        &body,
    )?;
    let mut what = TaskAskQuestion::new(super::super::ConsultPayloadRef::Turn(question));
    what.options = [(TaskAskOptionId::new("yes")?, "yes".into())].into();
    let spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::Responder(TaskAssignee::Human {
            actor_ref: actor,
        })),
        what,
        Some(u64::MAX),
        TaskAskDefault::AskMe,
    );
    let memory = vault.memory(actor, crate::EdgeActorClass::Human);
    let handle = memory.tasks_ask(&spec)?.handle;
    let rtxn = vault.store.env.read_txn()?;
    let group = read_group(&vault, &rtxn, handle.group_ref)?.expect("ask group");
    let task = entity(&group.members[0].task)?;
    drop(rtxn);
    let word = TaskAskWord {
        result_ref: question,
        option: Some(TaskAskOptionId::new("not-an-option")?),
        inform_for: None,
        companion_for: None,
        confirmation: None,
        provenance_refs: Default::default(),
    };
    let source = TaskAskSource::Human;
    let word_ref = answer_id(handle.group_ref, task, actor, source, &word)?;
    let encoded = value(
        ANSWER,
        &AskAnswerFact {
            group: handle.group_ref,
            task,
            actor,
            source,
            word,
            order: 1,
            delegation_grant_ref: None,
            at: 1,
        },
    )?;
    vault
        .batch()
        .put_replicated(
            &word_ref,
            ENTITY_TYPE_TASK,
            crate::TimeRange { start: 1, end: 1 },
            1,
            &encoded,
        )
        .edge(&word_ref, crate::EdgeKind::About, &handle.group_ref, 1.0)
        .commit()?;
    let error = memory
        .tasks_ask_evidence(handle)
        .expect_err("stored invalid option");
    assert_eq!(error.code, crate::memory::MEMORY_CODE_INTERNAL);
    Ok(())
}

#[test]
fn answer_header_mismatch_is_refused_on_birth_and_identical_body_reput()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let actor = vault.ensure_embedded_owner_actor()?;
    let question = EntityId::now();
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))?;
    vault.put_entity(
        &question,
        crate::registry::ENTITY_TYPE_TURN,
        crate::TimeRange { start: 1, end: 1 },
        1,
        &body,
    )?;
    let spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::Responder(TaskAssignee::Human {
            actor_ref: actor,
        })),
        TaskAskQuestion::new(super::super::ConsultPayloadRef::Turn(question)),
        Some(u64::MAX),
        TaskAskDefault::Hold,
    );
    let memory = vault.memory(actor, crate::EdgeActorClass::Human);
    let handle = memory.tasks_ask(&spec)?.handle;
    let txn = vault.store.env.read_txn()?;
    let group = read_group(&vault, &txn, handle.group_ref)?.expect("group");
    let task = entity(&group.members[0].task)?;
    drop(txn);
    let word = TaskAskWord::new(question);
    let id = answer_id(handle.group_ref, task, actor, TaskAskSource::Human, &word)?;
    let encoded = value(
        ANSWER,
        &AskAnswerFact {
            group: handle.group_ref,
            task,
            actor,
            source: TaskAskSource::Human,
            word,
            order: 1,
            delegation_grant_ref: None,
            at: 42,
        },
    )?;
    let wrong = crate::TimeRange { start: 43, end: 43 };
    assert!(
        vault
            .batch()
            .put_replicated(&id, ENTITY_TYPE_TASK, wrong, 43, &encoded)
            .commit()
            .is_err(),
        "a new answer cannot disagree with its header"
    );
    assert!(vault.get_raw(&id)?.is_none());
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_TASK,
            crate::TimeRange { start: 42, end: 42 },
            42,
            &encoded,
        )
        .edge(&id, crate::EdgeKind::About, &handle.group_ref, 1.0)
        .commit()?;
    let before = memory.tasks_ask_evidence(handle)?;
    assert_eq!(before.len(), 1);
    let raw = vault.get_raw(&id)?.expect("stored answer");
    assert!(
        vault
            .batch()
            .put_replicated(&id, ENTITY_TYPE_TASK, wrong, 43, &encoded)
            .commit()
            .is_err(),
        "identical body cannot rewrite answer timestamps"
    );
    assert_eq!(vault.get_raw(&id)?.expect("unchanged answer"), raw);
    assert_eq!(memory.tasks_ask_evidence(handle)?, before);
    assert_eq!(memory.tasks_ask_peek(handle)?[0].at, 42);
    Ok(())
}
