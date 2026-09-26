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
