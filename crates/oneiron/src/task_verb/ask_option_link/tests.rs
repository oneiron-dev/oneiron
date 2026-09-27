use super::*;
use crate::task_verb::{
    TaskAskDecision, TaskAskEffectAuthorization, TaskAskPersonKind, TaskAskQuestion, TaskAskSource,
    TaskAskSpec, TaskAskStatus, TaskAskTarget, TaskAskWait,
};
use crate::{EdgeActorClass, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn two_friends_get_distinct_generic_links_and_void_is_final() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let friends = [
        EntityId::from_bytes([0x43; 16])?,
        EntityId::from_bytes([0x44; 16])?,
    ];
    for friend in friends {
        super::super::tests::support::put_person(&vault, friend);
    }
    let mut question =
        TaskAskQuestion::new(super::super::tests::support::consult_turn(&vault, 0x45));
    question.options = [
        (TaskAskOptionId::new("a")?, "Same display".to_string()),
        (TaskAskOptionId::new("b")?, "Same display".to_string()),
    ]
    .into();
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People(friends.into())),
        question,
        Some(u64::MAX),
        Default::default(),
    );
    spec.intent_key = "generic-non-slot-link".to_string();
    spec.decide = None;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let ask = memory.tasks_ask(&spec)?.handle;
    let first = memory.tasks_ask_option_link(ask, friends[0])?;
    let second = memory.tasks_ask_option_link(ask, friends[1])?;
    assert_ne!(first.token, second.token);
    let view = vault.ask_option_link_view(&first.token)?;
    assert_eq!(view.intended_recipient, friends[0]);
    assert_eq!(view.revision, 1);
    assert_eq!(view.options, spec.what.options);
    assert_eq!(
        vault
            .ask_option_link_view(&second.token)?
            .intended_recipient,
        friends[1]
    );
    assert!(
        vault
            .answer_ask_option_link(&first.token, &TaskAskOptionId::new("fake")?)
            .is_err()
    );
    let answer = vault.answer_ask_option_link(&first.token, &TaskAskOptionId::new("b")?)?;
    assert_eq!(answer.actor_ref, friends[0]);
    assert!(
        vault
            .answer_ask_option_link(&first.token, &TaskAskOptionId::new("a")?)
            .is_err()
    );
    let evidence = memory.tasks_ask_evidence(ask)?;
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].source, TaskAskSource::ForeignStated);
    assert_eq!(evidence[0].answer, answer);
    assert_eq!(evidence[0].word.option.as_ref().unwrap().as_str(), "b");
    assert_eq!(evidence[0].person_ref, friends[0]);
    let attributed = memory.tasks_ask_peek(ask)?;
    assert_eq!(attributed.len(), 1);
    assert_eq!(attributed[0].kind, TaskAskPersonKind::Word);
    assert_eq!(attributed[0].who, friends[0]);
    assert_eq!(attributed[0].source, Some(friends[0]));
    assert!(matches!(
        memory.tasks_ask_status(ask)?,
        TaskAskStatus::Pending { .. }
    ));
    let TaskAskWait::Pending { trap_ref } = memory.tasks_wait(ask, Some("void-step"))? else {
        panic!("unanswered friend keeps ask pending");
    };
    vault.void_ask_option_link(&second.token)?;
    assert!(vault.ask_option_link_view(&second.token).is_err());
    assert!(
        vault
            .answer_ask_option_link(&second.token, &TaskAskOptionId::new("a")?)
            .is_err()
    );
    assert_eq!(memory.tasks_ask_option_link_voids(ask)?, vec![friends[1]]);
    let mut head = EntityId::from_hex(&trap_ref)?;
    while let Some(edge) = vault
        .edges_in(&head)?
        .into_iter()
        .find(|edge| edge.kind == crate::EdgeKind::Supersedes)
    {
        head = edge.target;
    }
    let trap = vault.get_claim(&head)?.expect("wait signal fact");
    let signal_state = trap
        .value
        .as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| key.as_str() == Some("state"))
        .and_then(|(_, value)| value.as_str());
    assert_eq!(signal_state, Some("sent"));
    assert_eq!(memory.tasks_ask_evidence(ask)?.len(), 1);
    assert!(
        !matches!(memory.tasks_ask_status(ask)?, TaskAskStatus::Settled(result) if result.decision == TaskAskDecision::First(answer))
    );
    Ok(())
}

#[test]
fn reissued_link_revokes_previous_token_without_affecting_other_friend() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let friend = EntityId::from_bytes([0x52; 16])?;
    super::super::tests::support::put_person(&vault, friend);
    let mut question =
        TaskAskQuestion::new(super::super::tests::support::consult_turn(&vault, 0x53));
    question
        .options
        .insert(TaskAskOptionId::new("yes")?, "Yes".into());
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People([friend].into())),
        question,
        Some(u64::MAX),
        Default::default(),
    );
    spec.intent_key = "reissue".into();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let ask = memory.tasks_ask(&spec)?.handle;
    let old = memory.tasks_ask_option_link(ask, friend)?;
    let new = memory.tasks_ask_option_link(ask, friend)?;
    assert!(vault.ask_option_link_view(&old.token).is_err());
    assert!(
        vault
            .answer_ask_option_link(&old.token, &TaskAskOptionId::new("yes")?)
            .is_err()
    );
    assert_eq!(
        vault.ask_option_link_view(&new.token)?.intended_recipient,
        friend
    );
    let answer = vault.answer_ask_option_link(&new.token, &TaskAskOptionId::new("yes")?)?;
    let TaskAskStatus::Settled(result) = memory.tasks_ask_status(ask)? else {
        panic!("one-person first answer must settle");
    };
    assert_eq!(result.decision, TaskAskDecision::First(answer));
    assert_eq!(
        result.effect_authorization,
        TaskAskEffectAuthorization::NotEvaluatedByAsk
    );
    assert_eq!(result.evidence[0].source, TaskAskSource::ForeignStated);
    Ok(())
}
