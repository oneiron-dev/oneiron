use super::*;
use crate::edge::EdgeActorClass;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionRung,
};
use crate::{EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn definition(unit: EntityId, text: &str) -> QuestionDefinition {
    QuestionDefinition {
        question: DecisionQuestion {
            id: EntityId::now(),
            version: 1,
            text: text.into(),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        adapter: "graph".into(),
        units: vec![unit],
        recipe: "unit".into(),
        profile: "local".into(),
        dial: DecisionDial {
            first: DecisionRung::Rule,
            ceiling: DecisionRung::Human,
            band: DecisionBand::default(),
        },
        refresh: RefreshPolicy {
            on_arrival: false,
            every_seconds: Some(60),
        },
        delivery: "nightly".into(),
        learning: false,
        binding: None,
    }
}

fn input(unit: EntityId) -> StandingAnswer {
    StandingAnswer {
        unit,
        answer: DecisionAnswer::Noul(true),
        probability: Some(0.9),
        evidence: vec![unit],
        providers: vec![],
    }
}

#[test]
fn standing_backfill_keeps_receipts_by_immutable_version_after_edit_and_pause() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let principal = EntityId::now();
    let stranger = EntityId::now();
    let unit = EntityId::now();
    for id in [principal, stranger, unit] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"fixture",
        )?;
    }
    let actor = WriteActor::new(principal, EdgeActorClass::Human);
    let first = create_question(&vault, principal, definition(unit, "Old wording?"), 10)?;
    let id = first.definition.question.id;
    let v1 = backfill_standing_answer(&vault, principal, id, 1, actor, input(unit), 11)?;
    assert_eq!(v1.decision.receipt.question_version, 1);
    assert_eq!(v1.decision.receipt.question, id);
    assert_eq!(v1.decision.receipt.principal, principal);
    let second = edit_question(
        &vault,
        principal,
        id,
        1,
        definition(unit, "New wording?"),
        12,
    )?;
    assert_eq!(second.definition.question.version, 2);
    assert_eq!(
        read_question(&vault, principal, id, Some(1))?,
        Some(first.clone())
    );
    pause_question(&vault, principal, id, true)?;
    assert!(matches!(
        backfill_standing_answer(&vault, principal, id, 1, actor, input(unit), 13),
        Err(Error::ConcurrentWrite(_))
    ));
    let v2 = backfill_standing_answer(&vault, principal, id, 2, actor, input(unit), 14)?;
    assert_ne!(v1.claim, v2.claim);
    assert_eq!(v2.decision.receipt.question_version, 2);
    assert_eq!(
        backfill_standing_answer(&vault, principal, id, 2, actor, input(unit), 15)?.claim,
        v2.claim
    );
    for (answer, version) in [(&v1, 1), (&v2, 2)] {
        let claim = vault.get_claim(&answer.claim)?.expect("kept answer claim");
        assert_eq!(claim.predicate, "judgment.answer");
        let encoded = super::store::encode(answer)?;
        let receipt: AnswerRecord = super::store::decode(&encoded)?;
        assert_eq!(receipt.decision.receipt.question_version, version);
        assert_eq!(
            claim.value,
            rmpv::decode::read_value(&mut encoded.as_slice())?
        );
    }
    assert!(read_question(&vault, stranger, id, None)?.is_none());
    assert!(matches!(
        backfill_standing_answer(&vault, stranger, id, 2, actor, input(unit), 16),
        Err(Error::EntityNotFound)
    ));
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(
        read_question(&reopened, principal, id, Some(1))?,
        Some(first)
    );
    assert!(reopened.get_claim(&v2.claim)?.is_some());
    Ok(())
}

#[test]
fn standing_backfill_rejects_out_of_scope_and_invalid_answers_without_writing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let unit = EntityId::now();
    let other = EntityId::now();
    for id in [owner, unit, other] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"fixture",
        )?;
    }
    let id = create_question(&vault, owner, definition(unit, "Question?"), 1)?
        .definition
        .question
        .id;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let mut bad = input(other);
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, bad.clone(), 2).is_err());
    bad.unit = unit;
    bad.answer = DecisionAnswer::Choice("invalid".into());
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, bad, 2).is_err());
    let mut bad = input(unit);
    bad.probability = Some(f64::NAN);
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, bad, 2).is_err());
    let answer = backfill_standing_answer(&vault, owner, id, 1, actor, input(unit), 3)?;
    assert_eq!(vault.claims_for_subject(&unit)?.len(), 1);
    assert_eq!(answer.answered_at, 3);
    vault.put_entity(
        &unit,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 4, end: 4 },
        4,
        b"updated fixture",
    )?;
    let refreshed = backfill_standing_answer(&vault, owner, id, 1, actor, input(unit), 5)?;
    assert_ne!(refreshed.claim, answer.claim);
    assert_eq!(refreshed.decision.receipt.question_version, 1);
    assert_eq!(vault.claims_for_subject(&unit)?.len(), 2);
    assert_eq!(
        backfill_standing_answer(&vault, owner, id, 1, actor, input(unit), 6)?.claim,
        refreshed.claim
    );
    Ok(())
}
