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
    assert!(super::super::task_is_terminal(&vault, answer.task_ref)?);

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
    assert_eq!(
        serde_json::to_value(&*result)?["evidence"][0]["source"],
        "foreign_stated"
    );
    Ok(())
}

#[test]
fn unused_friend_link_lands_late_word_without_changing_first_answer() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let friends = [
        EntityId::from_bytes([0x61; 16])?,
        EntityId::from_bytes([0x62; 16])?,
    ];
    for friend in friends {
        super::super::tests::support::put_person(&vault, friend);
    }
    let mut question =
        TaskAskQuestion::new(super::super::tests::support::consult_turn(&vault, 0x63));
    question.options = [
        (TaskAskOptionId::new("yes")?, "Yes".into()),
        (TaskAskOptionId::new("no")?, "No".into()),
    ]
    .into();
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People(friends.into())),
        question,
        Some(u64::MAX),
        Default::default(),
    );
    spec.intent_key = "late-link".into();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let ask = memory.tasks_ask(&spec)?.handle;
    let links = [
        memory.tasks_ask_option_link(ask, friends[0])?,
        memory.tasks_ask_option_link(ask, friends[1])?,
    ];
    let first = vault.answer_ask_option_link(&links[0].token, &TaskAskOptionId::new("yes")?)?;
    let TaskAskStatus::Settled(original) = memory.tasks_ask_status(ask)? else {
        panic!("first answer settles")
    };
    assert_eq!(original.decision, TaskAskDecision::First(first));
    assert_eq!(
        vault
            .ask_option_link_view(&links[1].token)?
            .intended_recipient,
        friends[1]
    );
    let late = vault.answer_ask_option_link(&links[1].token, &TaskAskOptionId::new("no")?)?;
    assert!(super::super::task_is_terminal(&vault, late.task_ref)?);
    let TaskAskStatus::Settled(after) = memory.tasks_ask_status(ask)? else {
        panic!("immutable settlement")
    };
    assert_eq!(after, original);
    let evidence = memory.tasks_ask_evidence(ask)?;
    assert_eq!(evidence.len(), 2);
    assert!(evidence.iter().any(
        |row| row.answer == late && row.reason == crate::task_verb::TaskAskEvidenceReason::Late
    ));
    Ok(())
}

#[test]
fn governed_link_requires_explicit_disclosed_source_before_consuming_token() -> TestResult {
    use crate::task_verb::{
        TaskAskClass, TaskAskDecide, TaskAskDefault, TaskAskElectorate, TaskAskNeed,
    };
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let friend = EntityId::from_bytes([0x71; 16])?;
    super::super::tests::support::put_person(&vault, friend);
    let reference = super::super::tests::support::consult_turn(&vault, 0x72);
    let mut question = TaskAskQuestion::new(reference);
    let yes = TaskAskOptionId::new("yes")?;
    question.options.insert(yes.clone(), "Yes".into());
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People([friend].into())),
        question,
        Some(u64::MAX),
        TaskAskDefault::Hold,
    );
    spec.intent_key = "governed-link".into();
    spec.class = Some(TaskAskClass {
        key: "source-required".into(),
        version: 1,
        governance: false,
        deadline_seconds: 1000,
        allowed_recipients: [friend].into(),
        required_people: [friend].into(),
        minimum_responses: 1,
        required_sources: [reference].into(),
        decision: Some(TaskAskDecide::First),
        disclosure: [(friend, [reference].into())].into(),
        fallback: [TaskAskDefault::Hold].into(),
        remind: vec![],
        guest_fact_limit: None,
        soft_confirm_surface: None,
    });
    spec.need = TaskAskNeed {
        count: 1,
        of: TaskAskElectorate::Any,
    };
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let ask = memory.tasks_ask(&spec)?.handle;
    let link = memory.tasks_ask_option_link(ask, friend)?;
    assert_eq!(
        vault.ask_option_link_view(&link.token)?.disclosed_sources,
        [reference].into()
    );
    assert!(vault.answer_ask_option_link(&link.token, &yes).is_err());
    assert!(memory.tasks_ask_evidence(ask)?.is_empty());
    let answer =
        vault.answer_ask_option_link_with_sources(&link.token, &yes, &[reference].into())?;
    let TaskAskStatus::Settled(result) = memory.tasks_ask_status(ask)? else {
        panic!("counted answer")
    };
    assert_eq!(result.decision, TaskAskDecision::First(answer));
    assert!(result.coverage.met);
    assert_eq!(result.evidence[0].word.provenance_refs, [reference].into());
    Ok(())
}

#[test]
fn settlement_replay_without_issuer_proof_is_refused_for_unissued_and_voided_links() -> TestResult {
    use crate::task_verb::{
        TaskAskAnswer, TaskAskCoverage, TaskAskEvidence, TaskAskEvidenceReason, TaskAskResult,
        TaskAskSettlement, TaskAskSettlementReason, TaskAskWord,
    };
    use std::collections::BTreeSet;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let friends = [
        EntityId::from_bytes([0x61; 16])?,
        EntityId::from_bytes([0x62; 16])?,
        EntityId::from_bytes([0x63; 16])?,
    ];
    for friend in friends {
        super::super::tests::support::put_person(&vault, friend);
    }
    let mut question =
        TaskAskQuestion::new(super::super::tests::support::consult_turn(&vault, 0x64));
    question.options = [(TaskAskOptionId::new("yes")?, "Yes".to_string())].into();
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People(friends.into())),
        question,
        Some(u64::MAX),
        Default::default(),
    );
    spec.intent_key = "hostile-settlement-replay".to_string();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let ask = memory.tasks_ask(&spec)?.handle;
    let issued = memory.tasks_ask_option_link(ask, friends[0])?;
    let voided = memory.tasks_ask_option_link(ask, friends[1])?;
    vault.void_ask_option_link(&voided.token)?;
    // friends[2] never receives a link at all.
    let group = {
        let txn = vault.store.env.read_txn()?;
        super::super::ask_record::read_group(&vault, &txn, ask.group_ref)?.expect("ask group")
    };
    let reference = crate::EntityId::derive(crate::entity_id::derived_domains::TASK_ASK_SETTLEMENT, &[ask.group_ref.as_bytes(), b"receipt"])?;
    let electorate: BTreeSet<_> = friends.into();
    for friend in [friends[1], friends[2]] {
        let answer = TaskAskAnswer {
            task_ref: super::super::ask_record::member_id(ask.group_ref, friend)?,
            actor_ref: friend,
            result_ref: friend,
            word_ref: EntityId::from_bytes([0x65; 16])?,
        };
        let mut word = TaskAskWord::new(friend);
        word.option = Some(TaskAskOptionId::new("yes")?);
        let forged = TaskAskResult {
            effect_authorization: TaskAskEffectAuthorization::NotEvaluatedByAsk,
            coverage: TaskAskCoverage {
                met: true,
                required: 1,
                responded: [friend].into(),
                unknown: electorate
                    .iter()
                    .copied()
                    .filter(|person| *person != friend)
                    .collect(),
                unmet_people: BTreeSet::new(),
            },
            decision: TaskAskDecision::First(answer),
            fallback: None,
            evidence: vec![TaskAskEvidence {
                answer,
                word,
                source: TaskAskSource::ForeignStated,
                person_ref: friend,
                order: 1,
                reason: TaskAskEvidenceReason::Counted,
                ladder_changed: None,
                soft_confirm: false,
                delegation_grant_ref: None,
            }],
            settlement: TaskAskSettlement {
                group_ref: ask.group_ref,
                reference,
                revision: group.effective.what.revision,
                at: group.created_at + 1,
                cutoff_order: 1,
                reason: TaskAskSettlementReason::FirstWord,
                requested: group.requested.clone(),
                effective: group.effective.clone(),
                base_policy_version: group.base_policy_version,
                electorate: electorate.clone(),
                question_digest: group.question_digest,
                unmet_sources: BTreeSet::new(),
                outcome_answer_ref: None,
                policy_surface: group.policy_surface,
                link_result_proof: None,
            },
        };
        // The reducer transcript is self-consistent; only the missing issuer
        // proof separates it from a genuine receipt.
        super::super::ask_settlement::validate_result(reference, &forged)?;
        let mut stolen = forged.clone();
        stolen.settlement.link_result_proof = Some(vec![0; 64]);
        for hostile in [forged, stolen] {
            let now = vault.store.clock.now_recorded_at();
            let refused = vault.with_write_txn(|txn| {
                super::super::ask_record::put(
                    &vault,
                    txn,
                    reference,
                    "tasks.ask_settlement",
                    &hostile,
                    now,
                )
            });
            assert_eq!(
                refused.expect_err("unsigned link receipt").kind(),
                crate::error::ErrorKind::InvalidTaskBody
            );
        }
    }
    assert!(vault.get_raw(&reference)?.is_none());
    assert!(matches!(
        memory.tasks_ask_status(ask)?,
        TaskAskStatus::Pending { .. }
    ));

    let answer = vault.answer_ask_option_link(&issued.token, &TaskAskOptionId::new("yes")?)?;
    let TaskAskStatus::Settled(result) = memory.tasks_ask_status(ask)? else {
        panic!("the issued link settles the ask");
    };
    assert_eq!(result.decision, TaskAskDecision::First(answer));
    assert!(result.settlement.link_result_proof.is_some());
    super::super::ask_record::verify_link_settlement(&group, &result)?;
    let mut altered = (*result).clone();
    altered.settlement.at += 1;
    assert!(super::super::ask_record::verify_link_settlement(&group, &altered).is_err());
    Ok(())
}
