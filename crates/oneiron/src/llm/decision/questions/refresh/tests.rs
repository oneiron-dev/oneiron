use super::super::{create_question, edit_question, pause_question};
use super::*;
use crate::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionRung, ProviderPin,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<(tempfile::TempDir, Vault, EntityId, EntityId, WriteActor)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let unit = EntityId::now();
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    for id in [owner, unit] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"source",
        )?;
    }
    Ok((dir, vault, owner, unit, actor))
}

fn definition(unit: EntityId) -> QuestionDefinition {
    QuestionDefinition {
        question: DecisionQuestion {
            id: EntityId::now(),
            version: 1,
            text: "fixture question".into(),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        adapter: "graph".into(),
        units: vec![unit],
        recipe: "unit".into(),
        profile: "fixture".into(),
        dial: DecisionDial {
            first: DecisionRung::Rule,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        refresh: RefreshPolicy {
            on_arrival: true,
            every_seconds: Some(10),
        },
        delivery: "now".into(),
        learning: false,
        binding: None,
    }
}

fn propose(_: &QuestionRecord, _: EntityId, _: &[u8]) -> AnswerProposal {
    AnswerProposal {
        answer: DecisionAnswer::Noul(true),
        probability: Some(0.8),
        providers: vec![ProviderPin {
            rung: DecisionRung::Rule,
            model: "fixture".into(),
            version: "one".into(),
        }],
    }
}

#[test]
fn arrival_schedule_manual_version_and_pause() -> TestResult {
    let (_dir, vault, owner, unit, actor) = fixture()?;
    let record = create_question(&vault, owner, definition(unit), 2)?;
    let id = record.definition.question.id;
    assert!(refresh_due_questions(&vault, actor, 3, |r, u, s| Ok(propose(r, u, s)))?.is_empty());
    vault.put_entity(
        &unit,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 4, end: 4 },
        4,
        b"arrival",
    )?;
    let first = refresh_due_questions(&vault, actor, 4, |r, u, s| Ok(propose(r, u, s)))?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].decision.receipt.question_version, 1);
    assert_eq!(
        first[0].frontier,
        *blake3::hash(
            &vault
                .store
                .entities
                .get(&vault.store.env.read_txn()?, unit.as_bytes())?
                .unwrap()
        )
        .as_bytes()
    );
    assert!(vault.get_claim(&first[0].claim)?.is_some());
    assert!(refresh_due_questions(&vault, actor, 4, |r, u, s| Ok(propose(r, u, s)))?.is_empty());
    let scheduled = refresh_due_questions(&vault, actor, 12, |r, u, s| Ok(propose(r, u, s)))?;
    assert_eq!(scheduled.len(), 1);
    assert_ne!(first[0].claim, scheduled[0].claim);
    assert!(refresh_due_questions(&vault, actor, 12, |r, u, s| Ok(propose(r, u, s)))?.is_empty());
    let mut changed = definition(unit);
    changed.question.text = "changed".into();
    edit_question(&vault, owner, id, 1, changed, 13)?;
    let next = refresh_question(
        &vault,
        actor,
        owner,
        id,
        RefreshTrigger::Manual,
        13,
        |r, u, s| Ok(propose(r, u, s)),
    )?;
    assert_eq!(next[0].decision.receipt.question_version, 2);
    assert_eq!(answer_records(&vault, owner, id)?.len(), 3);
    pause_question(&vault, owner, id, true)?;
    vault.put_entity(
        &unit,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 14, end: 14 },
        14,
        b"pause",
    )?;
    assert!(refresh_due_questions(&vault, actor, 30, |r, u, s| Ok(propose(r, u, s)))?.is_empty());
    assert!(
        refresh_question(
            &vault,
            actor,
            owner,
            id,
            RefreshTrigger::Manual,
            30,
            |r, u, s| Ok(propose(r, u, s))
        )?
        .is_empty()
    );
    pause_question(&vault, owner, id, false)?;
    assert_eq!(
        refresh_due_questions(&vault, actor, 30, |r, u, s| Ok(propose(r, u, s)))?.len(),
        1
    );
    assert_eq!(answer_records(&vault, owner, id)?.len(), 4);
    Ok(())
}

#[test]
fn concurrent_version_pause_and_source_changes_do_not_land() -> TestResult {
    let (_dir, vault, owner, unit, actor) = fixture()?;
    let record = create_question(&vault, owner, definition(unit), 2)?;
    let id = record.definition.question.id;
    let err = refresh_question(
        &vault,
        actor,
        owner,
        id,
        RefreshTrigger::Manual,
        3,
        |r, u, source| {
            pause_question(&vault, owner, id, true)?;
            Ok(propose(r, u, source))
        },
    );
    assert!(matches!(err, Err(Error::ConcurrentWrite(_))));
    assert!(answer_records(&vault, owner, id)?.is_empty());
    pause_question(&vault, owner, id, false)?;
    let err = refresh_question(
        &vault,
        actor,
        owner,
        id,
        RefreshTrigger::Manual,
        3,
        |r, u, source| {
            vault.put_entity(
                &unit,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 3, end: 3 },
                3,
                b"changed",
            )?;
            Ok(propose(r, u, source))
        },
    );
    assert!(matches!(err, Err(Error::ConcurrentWrite(_))));
    assert!(answer_records(&vault, owner, id)?.is_empty());
    let err = refresh_question(
        &vault,
        actor,
        owner,
        id,
        RefreshTrigger::Manual,
        4,
        |r, u, source| {
            let mut changed = definition(unit);
            changed.question.text = "new version".into();
            edit_question(&vault, owner, id, 1, changed, 4)?;
            Ok(propose(r, u, source))
        },
    );
    assert!(matches!(err, Err(Error::ConcurrentWrite(_))));
    assert!(answer_records(&vault, owner, id)?.is_empty());
    assert!(answer_records(&vault, EntityId::now(), id).is_err());
    Ok(())
}

#[test]
fn removing_arrival_retire_queued_work_without_reanswering() -> TestResult {
    let (_dir, vault, owner, unit, actor) = fixture()?;
    let record = create_question(&vault, owner, definition(unit), 2)?;
    let id = record.definition.question.id;
    vault.put_entity(
        &unit,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 3, end: 3 },
        3,
        b"arrival",
    )?;
    let mut changed = definition(unit);
    changed.refresh.on_arrival = false;
    changed.refresh.every_seconds = None;
    edit_question(&vault, owner, id, 1, changed, 4)?;
    assert!(refresh_due_questions(&vault, actor, 5, |r, u, s| Ok(propose(r, u, s)))?.is_empty());
    assert!(
        vault
            .store
            .vault_meta
            .get(
                &vault.store.env.read_txn()?,
                &arrival::pending_key(id, unit)
            )?
            .is_none()
    );
    vault.put_entity(
        &unit,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 6, end: 6 },
        6,
        b"later",
    )?;
    assert!(refresh_due_questions(&vault, actor, 6, |r, u, s| Ok(propose(r, u, s)))?.is_empty());
    assert!(answer_records(&vault, owner, id)?.is_empty());
    Ok(())
}

#[test]
fn scheduled_refresh_consumes_same_unit_arrival_once() -> TestResult {
    let (_dir, vault, owner, unit, actor) = fixture()?;
    let record = create_question(&vault, owner, definition(unit), 2)?;
    let id = record.definition.question.id;
    vault.put_entity(
        &unit,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 12, end: 12 },
        12,
        b"both",
    )?;
    let answers = refresh_due_questions(&vault, actor, 12, |r, u, s| Ok(propose(r, u, s)))?;
    assert_eq!(answers.len(), 1);
    assert_eq!(answer_records(&vault, owner, id)?, answers);
    assert!(refresh_due_questions(&vault, actor, 12, |r, u, s| Ok(propose(r, u, s)))?.is_empty());
    Ok(())
}
