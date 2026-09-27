use super::super::{create_question, edit_question, pause_question};
use super::*;
use crate::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionRung, ProviderPin,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

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
    crate::test_util::authorize_readers(&vault, &[owner.to_hex().as_str()]);
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
    assert!(
        refresh_due_questions(&vault, actor, 3, |r, u, s| Ok(propose(r, u, s)))?
            .answers
            .is_empty()
    );
    vault.put_entity(
        &unit,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 4, end: 4 },
        4,
        b"arrival",
    )?;
    let first = refresh_due_questions(&vault, actor, 4, |r, u, s| Ok(propose(r, u, s)))?.answers;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].decision.receipt.question_version, 1);
    assert_eq!(
        first[0].frontier,
        *blake3::hash(&vault.get_raw(&unit)?.expect("source")).as_bytes()
    );
    assert!(vault.get_claim(&first[0].claim)?.is_some());
    assert!(
        refresh_due_questions(&vault, actor, 4, |r, u, s| Ok(propose(r, u, s)))?
            .answers
            .is_empty()
    );
    let scheduled =
        refresh_due_questions(&vault, actor, 12, |r, u, s| Ok(propose(r, u, s)))?.answers;
    assert_eq!(scheduled.len(), 1);
    assert_ne!(first[0].claim, scheduled[0].claim);
    assert!(
        refresh_due_questions(&vault, actor, 12, |r, u, s| Ok(propose(r, u, s)))?
            .answers
            .is_empty()
    );
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
    assert!(
        refresh_due_questions(&vault, actor, 30, |r, u, s| Ok(propose(r, u, s)))?
            .answers
            .is_empty()
    );
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
        refresh_due_questions(&vault, actor, 30, |r, u, s| Ok(propose(r, u, s)))?
            .answers
            .len(),
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
    assert!(
        refresh_due_questions(&vault, actor, 5, |r, u, s| Ok(propose(r, u, s)))?
            .answers
            .is_empty()
    );
    vault.put_entity(
        &unit,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 6, end: 6 },
        6,
        b"later",
    )?;
    assert!(
        refresh_due_questions(&vault, actor, 6, |r, u, s| Ok(propose(r, u, s)))?
            .answers
            .is_empty()
    );
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
    let answers = refresh_due_questions(&vault, actor, 12, |r, u, s| Ok(propose(r, u, s)))?.answers;
    assert_eq!(answers.len(), 1);
    assert_eq!(answer_records(&vault, owner, id)?, answers);
    assert!(
        refresh_due_questions(&vault, actor, 12, |r, u, s| Ok(propose(r, u, s)))?
            .answers
            .is_empty()
    );
    Ok(())
}

fn private_note_fixture() -> TestResult<(tempfile::TempDir, Vault, EntityId, EntityId, EntityId)> {
    use crate::note::{NoteKind, NoteScope, NoteWriteEnvelope};
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let owner = EntityId::now();
    let other = EntityId::now();
    for id in [owner, other] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    crate::test_util::authorize_readers(
        &vault,
        &[owner.to_hex().as_str(), other.to_hex().as_str()],
    );
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::parse("diary").expect("shipped diary kind"),
            scope: NoteScope::ActorPrivate { owner_ref: owner },
            source_revision_ref: [7; 16],
            markdown: "birth secret".into(),
            mask: None,
        })?;
    let note = EntityId::from_hex(&receipt.id_hex)?;
    Ok((dir, vault, owner, other, note))
}

#[test]
fn private_note_never_reaches_foreign_provider_or_claim() -> TestResult {
    let (_dir, vault, owner, other, note) = private_note_fixture()?;
    let other_actor = WriteActor::new(other, EdgeActorClass::Human);
    let denied = create_question(&vault, other, definition(note), 3)?;
    let denied_id = denied.definition.question.id;
    let mut called = false;
    let answers = refresh_question(
        &vault,
        other_actor,
        other,
        denied_id,
        RefreshTrigger::Manual,
        4,
        |_, _, _| {
            called = true;
            Ok(propose(&denied, note, &[]))
        },
    )?;
    assert!(!called);
    assert!(answers.is_empty());
    assert!(answer_records(&vault, other, denied_id)?.is_empty());

    let allowed = create_question(&vault, owner, definition(note), 3)?;
    let allowed_id = allowed.definition.question.id;
    let mut called = false;
    let answers = refresh_question(
        &vault,
        WriteActor::new(owner, EdgeActorClass::Human),
        owner,
        allowed_id,
        RefreshTrigger::Manual,
        4,
        |r, u, body| {
            called = true;
            assert_eq!(
                crate::note::decode_note_body(body)?.markdown,
                "birth secret"
            );
            Ok(propose(r, u, body))
        },
    )?;
    assert!(called);
    assert_eq!(answers.len(), 1);
    assert!(vault.get_claim(&answers[0].claim)?.is_some());
    Ok(())
}

#[test]
fn note_refresh_reads_live_edits_and_refuses_provider_time_change() -> TestResult {
    use crate::note::{NoteEdit, NoteEditOutcome};
    let (_dir, vault, owner, _other, note) = private_note_fixture()?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let record = create_question(&vault, owner, definition(note), 3)?;
    let question = record.definition.question.id;
    let birth = vault.get_raw(&note)?.expect("birth row");
    let apply = |text: &str| -> TestResult {
        let base = vault.note_document(note)?.frontier;
        let result = vault.memory(owner, EdgeActorClass::Human).apply_note_ops(
            note,
            &base,
            &[NoteEdit {
                start: 0,
                delete: 0,
                insert: text.into(),
            }],
        )?;
        assert!(matches!(result, NoteEditOutcome::Applied(_)));
        Ok(())
    };
    apply("live ")?;
    assert_eq!(vault.get_raw(&note)?.unwrap(), birth);
    let first = refresh_question(
        &vault,
        actor,
        owner,
        question,
        RefreshTrigger::Manual,
        5,
        |r, u, body| {
            assert_eq!(
                crate::note::decode_note_body(body)?.markdown,
                "live birth secret"
            );
            Ok(propose(r, u, body))
        },
    )?;
    assert_eq!(first.len(), 1);
    let stale = refresh_question(
        &vault,
        actor,
        owner,
        question,
        RefreshTrigger::Manual,
        6,
        |r, u, body| {
            apply("new ").map_err(|e| Error::InvalidConfig(e.to_string()))?;
            Ok(propose(r, u, body))
        },
    );
    assert!(matches!(stale, Err(Error::ConcurrentWrite(_))));
    assert_eq!(vault.get_raw(&note)?.unwrap(), birth);
    assert_eq!(answer_records(&vault, owner, question)?.len(), 1);
    Ok(())
}

#[test]
fn concurrent_arrival_cannot_settle_twice() -> TestResult {
    let (_dir, vault, owner, unit, actor) = fixture()?;
    let record = create_question(&vault, owner, definition(unit), 2)?;
    let id = record.definition.question.id;
    vault.put_entity(
        &unit,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 3, end: 3 },
        3,
        b"arrived",
    )?;
    let mut nested = Vec::new();
    let outer = refresh_question(
        &vault,
        actor,
        owner,
        id,
        RefreshTrigger::Arrival(unit),
        4,
        |r, u, body| {
            nested = refresh_question(
                &vault,
                actor,
                owner,
                id,
                RefreshTrigger::Arrival(unit),
                4,
                |inner, inner_unit, source| Ok(propose(inner, inner_unit, source)),
            )?;
            Ok(propose(r, u, body))
        },
    );
    assert!(matches!(outer, Err(Error::ConcurrentWrite(_))));
    assert_eq!(nested.len(), 1);
    assert_eq!(answer_records(&vault, owner, id)?, nested);
    Ok(())
}

#[test]
fn failing_question_does_not_starve_other_due_work() -> TestResult {
    let (_dir, vault, owner, unit, actor) = fixture()?;
    let first = create_question(&vault, owner, definition(unit), 2)?
        .definition
        .question
        .id;
    let second = create_question(&vault, owner, definition(unit), 2)?
        .definition
        .question
        .id;
    for at in [12, 22] {
        let batch = refresh_due_questions(&vault, actor, at, |r, u, body| {
            if r.definition.question.id == first {
                Err(Error::InvalidConfig("fixture answerer unavailable".into()))
            } else {
                Ok(propose(r, u, body))
            }
        })?;
        assert_eq!(batch.failures.len(), 1);
        assert_eq!(batch.failures[0].question, first);
        assert!(matches!(batch.failures[0].error, Error::InvalidConfig(_)));
        assert_eq!(batch.answers.len(), 1);
        assert_eq!(batch.answers[0].decision.receipt.question, second);
    }
    assert!(answer_records(&vault, owner, first)?.is_empty());
    assert_eq!(answer_records(&vault, owner, second)?.len(), 2);
    Ok(())
}

#[test]
fn relationship_message_requires_principal_grant_before_provider_and_at_settle() -> TestResult {
    use crate::access_grant::{
        AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    };
    use crate::claim::ScopedReadActorKey;
    use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let principal = EntityId::now();
    let space = EntityId::now();
    let message = EntityId::now();
    for id in [owner, principal] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            occurred_at: 1,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: "relationship source".into(),
                metadata: Some(serde_json::json!({"rel": space.to_hex()})),
                is_visible: true,
                order: 0,
            }],
        })?;
    crate::test_util::authorize_readers(
        &vault,
        &[owner.to_hex().as_str(), principal.to_hex().as_str()],
    );
    let scoped = vault.scoped_read(
        ScopedReadActorKey::with_actor_class(principal.to_hex(), "human")
            .expect("reader")
            .require_access_grants(Some(principal)),
    );
    assert!(scoped.get(&message)?.value.is_none());
    let record = create_question(&vault, principal, definition(message), 2)?;
    let question = record.definition.question.id;
    let actor = WriteActor::new(principal, EdgeActorClass::Human);
    let mut called = 0;
    let without = refresh_question(
        &vault,
        actor,
        principal,
        question,
        RefreshTrigger::Manual,
        3,
        |r, u, body| {
            called += 1;
            Ok(propose(r, u, body))
        },
    )?;
    assert_eq!(called, 0);
    assert!(without.is_empty());
    assert!(answer_records(&vault, principal, question)?.is_empty());

    let grant_id = EntityId::now();
    let grant = AccessGrant {
        principal_ref: principal,
        scope: AccessGrantScope::Messages { space_ref: space },
        capability: AccessGrantCapability::MessagesRead,
        status: AccessGrantStatus::Active,
        created_at: 1,
        revoked_at: None,
        expires_at: Some(u64::MAX),
        authority_scope: crate::federation::scope_codec::read_preset(),
    };
    vault.create_access_grant(&grant_id, &grant)?;
    assert!(scoped.get(&message)?.value.is_some());
    let allowed = refresh_question(
        &vault,
        actor,
        principal,
        question,
        RefreshTrigger::Manual,
        4,
        |r, u, body| {
            called += 1;
            Ok(propose(r, u, body))
        },
    )?;
    assert_eq!(called, 1);
    assert_eq!(allowed.len(), 1);
    assert!(vault.get_claim(&allowed[0].claim)?.is_some());

    let stale = refresh_question(
        &vault,
        actor,
        principal,
        question,
        RefreshTrigger::Manual,
        5,
        |r, u, body| {
            called += 1;
            vault.revoke_access_grant(&grant_id, 5)?;
            Ok(propose(r, u, body))
        },
    );
    assert!(matches!(stale, Err(Error::ConcurrentWrite(_))));
    assert_eq!(called, 2);
    assert!(scoped.get(&message)?.value.is_none());
    assert_eq!(answer_records(&vault, principal, question)?, allowed);
    Ok(())
}
