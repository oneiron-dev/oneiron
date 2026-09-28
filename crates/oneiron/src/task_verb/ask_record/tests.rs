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
            link_proof: None,
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
            link_proof: None,
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

#[test]
fn forged_foreign_word_and_voided_digest_cannot_cross_batch_door()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let friend = EntityId::from_bytes([0x86; 16])?;
    super::super::tests::support::put_person(&vault, friend);
    let reference = super::super::tests::support::consult_turn(&vault, 0x87);
    let mut what = TaskAskQuestion::new(reference);
    what.options
        .insert(TaskAskOptionId::new("yes")?, "Yes".into());
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People([friend].into())),
        what,
        Some(u64::MAX),
        TaskAskDefault::Hold,
    );
    spec.intent_key = "forge-foreign".into();
    let memory = vault.memory(owner, crate::EdgeActorClass::Human);
    let ask = memory.tasks_ask(&spec)?.handle;
    let link = memory.tasks_ask_option_link(ask, friend)?;
    vault.void_ask_option_link(&link.token)?;
    let txn = vault.store.env.read_txn()?;
    let group = read_group(&vault, &txn, ask.group_ref)?.expect("group");
    let task = entity(&group.members[0].task)?;
    drop(txn);
    let word = TaskAskWord {
        result_ref: friend,
        option: Some(TaskAskOptionId::new("yes")?),
        inform_for: None,
        companion_for: None,
        confirmation: None,
        provenance_refs: Default::default(),
    };
    let id = answer_id(
        ask.group_ref,
        task,
        friend,
        TaskAskSource::ForeignStated,
        &word,
    )?;
    let forged = AskAnswerFact {
        group: ask.group_ref,
        task,
        actor: friend,
        source: TaskAskSource::ForeignStated,
        word,
        link_proof: None,
        order: 1,
        delegation_grant_ref: None,
        at: 42,
    };
    let stage = |fact: &AskAnswerFact| -> crate::Result<()> {
        vault
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_TASK,
                crate::TimeRange { start: 42, end: 42 },
                42,
                &value(ANSWER, fact)?,
            )
            .edge(&id, crate::EdgeKind::About, &ask.group_ref, 1.0)
            .commit()
    };
    assert!(
        stage(&forged).is_err(),
        "a correct public hash is not a bearer proof"
    );
    let mut forged = forged;
    forged.link_proof = Some(super::link_proof::LinkProof {
        token_digest: *blake3::hash(link.token.as_bytes()).as_bytes(),
        revision: group.effective.what.revision,
        signature: vec![0; 64],
    });
    assert!(
        stage(&forged).is_err(),
        "a voided link digest is not a signature"
    );
    assert!(vault.get_raw(&id)?.is_none());
    assert!(memory.tasks_ask_evidence(ask)?.is_empty());
    assert!(matches!(
        memory.tasks_ask_status(ask)?,
        super::super::TaskAskStatus::Pending { .. }
    ));
    Ok(())
}

#[test]
fn non_person_foreign_word_is_refused_before_it_poisoned_an_ask()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let machine = EntityId::from_bytes([0x88; 16])?;
    vault.put_entity(
        &machine,
        crate::registry::ENTITY_TYPE_MACHINE,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"machine",
    )?;
    let reference = super::super::tests::support::consult_turn(&vault, 0x89);
    let mut what = TaskAskQuestion::new(reference);
    what.options
        .insert(TaskAskOptionId::new("yes")?, "Yes".into());
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People([machine].into())),
        what,
        Some(u64::MAX),
        TaskAskDefault::Hold,
    );
    spec.intent_key = "non-person-foreign".into();
    let memory = vault.memory(owner, crate::EdgeActorClass::Human);
    let ask = memory.tasks_ask(&spec)?.handle;
    let txn = vault.store.env.read_txn()?;
    let group = read_group(&vault, &txn, ask.group_ref)?.expect("group");
    let task = entity(&group.members[0].task)?;
    drop(txn);
    let word = TaskAskWord {
        result_ref: machine,
        option: Some(TaskAskOptionId::new("yes")?),
        inform_for: None,
        companion_for: None,
        confirmation: None,
        provenance_refs: Default::default(),
    };
    let id = answer_id(
        ask.group_ref,
        task,
        machine,
        TaskAskSource::ForeignStated,
        &word,
    )?;
    let forged = AskAnswerFact {
        group: ask.group_ref,
        task,
        actor: machine,
        source: TaskAskSource::ForeignStated,
        word,
        link_proof: Some(super::link_proof::LinkProof {
            token_digest: [7; 32],
            revision: 1,
            signature: vec![0; 64],
        }),
        order: 1,
        delegation_grant_ref: None,
        at: 42,
    };
    assert!(
        vault
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_TASK,
                crate::TimeRange { start: 42, end: 42 },
                42,
                &value(ANSWER, &forged)?
            )
            .commit()
            .is_err()
    );
    assert!(vault.get_raw(&id)?.is_none());
    assert!(memory.tasks_ask_evidence(ask)?.is_empty());
    Ok(())
}
