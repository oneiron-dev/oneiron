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
        activation: QuestionActivation::Standing,
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
        source_frontier: [0; 32],
    }
}

fn prepared(
    vault: &Vault,
    owner: EntityId,
    question: EntityId,
    version: u32,
    actor: WriteActor,
    unit: EntityId,
) -> crate::Result<StandingAnswer> {
    let mut answer = input(unit);
    answer.source_frontier = standing_source_frontier(
        vault,
        owner,
        question,
        version,
        actor,
        unit,
        &answer.evidence,
    )?;
    Ok(answer)
}

fn grant(vault: &Vault, owner: EntityId) -> crate::Result<()> {
    grant_with_bands(vault, owner, None)
}

fn grant_with_bands(vault: &Vault, owner: EntityId, bands: Option<u8>) -> crate::Result<()> {
    let bytes = crate::gate::default_policy_manifest();
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("fixture policy"))?;
    let mut scope = crate::federation::scope_codec::read_preset();
    if let Some(band) = bands {
        scope.bands = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([band]));
    }
    manifest["scoped_grants"] = serde_json::json!([{
        "actor_ref": owner.to_hex(),
        "effector": "core:read",
        "scope": scope,
        "receipt_required": false,
    }]);
    for predicate in ["review.source", "judgment.answer"] {
        manifest["rules"]
            .as_array_mut()
            .expect("rules")
            .push(serde_json::json!({
                "prefix": predicate, "exact": true,
                "axes": {"criticality":"normal", "sensitivity":"normal"}
            }));
    }
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &rmp_serde::to_vec_named(&manifest).map_err(|_| Error::CorruptedIndex("fixture policy"))?,
    )
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
    grant(&vault, principal)?;
    let actor = WriteActor::new(principal, EdgeActorClass::Human);
    let first = create_question(&vault, principal, definition(unit, "Old wording?"), 10)?;
    let id = first.definition.question.id;
    let v1 = backfill_standing_answer(
        &vault,
        principal,
        id,
        1,
        actor,
        prepared(&vault, principal, id, 1, actor, unit)?,
        11,
    )?;
    assert_eq!(v1.decision.receipt.question_version, 1);
    assert_eq!(v1.decision.receipt.question, id);
    assert_eq!(v1.decision.receipt.principal, principal);
    let mut one_off = definition(unit, "One off?");
    one_off.activation = QuestionActivation::OneOff;
    assert!(edit_question(&vault, principal, id, 1, one_off, 12).is_err());
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
    let v2 = backfill_standing_answer(
        &vault,
        principal,
        id,
        2,
        actor,
        prepared(&vault, principal, id, 2, actor, unit)?,
        14,
    )?;
    assert_ne!(v1.claim, v2.claim);
    assert_eq!(v2.decision.receipt.question_version, 2);
    assert_eq!(
        backfill_standing_answer(
            &vault,
            principal,
            id,
            2,
            actor,
            prepared(&vault, principal, id, 2, actor, unit)?,
            15
        )?
        .claim,
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
    grant(&vault, owner)?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let mut bad = prepared(&vault, owner, id, 1, actor, unit)?;
    bad.unit = other;
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, bad.clone(), 2).is_err());
    bad.unit = unit;
    bad.answer = DecisionAnswer::Choice("invalid".into());
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, bad, 2).is_err());
    let mut bad = prepared(&vault, owner, id, 1, actor, unit)?;
    bad.probability = Some(f64::NAN);
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, bad, 2).is_err());
    let answer = backfill_standing_answer(
        &vault,
        owner,
        id,
        1,
        actor,
        prepared(&vault, owner, id, 1, actor, unit)?,
        3,
    )?;
    assert_eq!(vault.claims_for_subject(&unit)?.len(), 1);
    assert_eq!(answer.answered_at, 3);
    vault.put_entity(
        &unit,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 4, end: 4 },
        4,
        b"updated fixture",
    )?;
    let refreshed = backfill_standing_answer(
        &vault,
        owner,
        id,
        1,
        actor,
        prepared(&vault, owner, id, 1, actor, unit)?,
        5,
    )?;
    assert_ne!(refreshed.claim, answer.claim);
    assert_eq!(refreshed.decision.receipt.question_version, 1);
    assert_eq!(vault.claims_for_subject(&unit)?.len(), 2);
    assert_eq!(
        backfill_standing_answer(
            &vault,
            owner,
            id,
            1,
            actor,
            prepared(&vault, owner, id, 1, actor, unit)?,
            6
        )?
        .claim,
        refreshed.claim
    );
    Ok(())
}

#[test]
fn live_note_edits_advance_the_source_pin_and_old_provider_work_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    person(&vault, owner)?;
    grant(&vault, owner)?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let unit = vault.create_note("opinion/take", "unfinished", actor)?;
    let id = create_question(&vault, owner, definition(unit, "Complete?"), 10)?
        .definition
        .question
        .id;
    let mut old = prepared(&vault, owner, id, 1, actor, unit)?;
    old.answer = DecisionAnswer::Noul(false);
    let first = backfill_standing_answer(&vault, owner, id, 1, actor, old.clone(), 11)?;
    let birth = vault.get_raw(&unit)?.expect("birth");
    let doc = vault.note_document(unit)?;
    vault.memory(owner, EdgeActorClass::Human).apply_note_ops(
        unit,
        &doc.frontier,
        &[crate::note::NoteEdit {
            start: 0,
            delete: 10,
            insert: "completed".into(),
        }],
    )?;
    assert_eq!(vault.get_raw(&unit)?.expect("birth"), birth);
    assert_eq!(vault.note_document(unit)?.markdown, "completed");
    assert!(matches!(
        backfill_standing_answer(&vault, owner, id, 1, actor, old, 12),
        Err(Error::ConcurrentWrite(_))
    ));
    let second = backfill_standing_answer(
        &vault,
        owner,
        id,
        1,
        actor,
        prepared(&vault, owner, id, 1, actor, unit)?,
        13,
    )?;
    assert_ne!(first.claim, second.claim);
    assert_ne!(first.frontier, second.frontier);
    Ok(())
}

fn person(vault: &Vault, id: EntityId) -> crate::Result<()> {
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )
}

#[test]
fn private_diary_and_foreign_scope_are_not_admitted() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let author = EntityId::now();
    person(&vault, owner)?;
    person(&vault, author)?;
    grant(&vault, owner)?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let diary = vault.create_note(
        "diary",
        "private",
        WriteActor::new(author, EdgeActorClass::Human),
    )?;
    let id = create_question(&vault, owner, definition(diary, "Private?"), 10)?
        .definition
        .question
        .id;
    assert!(standing_source_frontier(&vault, owner, id, 1, actor, diary, &[diary]).is_err());
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, input(diary), 11).is_err());
    let own = vault.create_note("opinion/take", "visible before floor", actor)?;
    let own_question = create_question(&vault, owner, definition(own, "Allowed?"), 12)?
        .definition
        .question
        .id;
    assert!(standing_source_frontier(&vault, owner, own_question, 1, actor, own, &[own]).is_ok());
    grant_with_bands(&vault, owner, Some(crate::registry::ENTITY_TYPE_PERSON))?;
    assert!(standing_source_frontier(&vault, owner, own_question, 1, actor, own, &[own]).is_err());
    assert!(
        backfill_standing_answer(&vault, owner, own_question, 1, actor, input(own), 13).is_err()
    );
    Ok(())
}

#[test]
fn removed_evidence_and_landed_claim_cannot_be_replayed_from_cache() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let unit = EntityId::now();
    let evidence = EntityId::now();
    for id in [owner, unit] {
        person(&vault, id)?;
    }
    grant(&vault, owner)?;
    let mut fact = crate::claim::ClaimBody::new(
        "review.source",
        crate::claim::ClaimSubject::Entity(unit),
        rmpv::Value::from("evidence"),
        1.0,
        crate::claim::ClaimApprovalStatus::Approved,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    fact.source = Some(crate::claim::ClaimSource::Imported);
    vault.put_claim(&evidence, &fact, TimeRange { start: 1, end: 1 }, 1)?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let id = create_question(&vault, owner, definition(unit, "Answer?"), 10)?
        .definition
        .question
        .id;
    let mut answer = input(unit);
    answer.evidence.push(evidence);
    answer.source_frontier =
        standing_source_frontier(&vault, owner, id, 1, actor, unit, &answer.evidence)?;
    let stored = backfill_standing_answer(&vault, owner, id, 1, actor, answer.clone(), 11)?;
    assert_eq!(
        vault.get_claim(&stored.claim)?.expect("landed").scope_facet,
        crate::claim::substrate_facet_id(unit),
    );
    let incompatible = EntityId::now();
    person(&vault, incompatible)?;
    let mut conflicting = input(unit);
    conflicting.evidence.push(incompatible);
    conflicting.source_frontier =
        standing_source_frontier(&vault, owner, id, 1, actor, unit, &conflicting.evidence)?;
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, conflicting, 11).is_err());
    assert_eq!(
        backfill_standing_answer(&vault, owner, id, 1, actor, answer.clone(), 12)?.claim,
        stored.claim
    );
    vault.delete_entity(&evidence)?;
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, answer.clone(), 13).is_err());
    let mut replacement = input(unit);
    replacement.source_frontier = answer.source_frontier;
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, replacement, 14).is_err());
    Ok(())
}

#[test]
fn graph_backfill_rejects_artifact_and_one_off_records() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let unit = EntityId::now();
    person(&vault, owner)?;
    person(&vault, unit)?;
    grant(&vault, owner)?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let mut def = definition(unit, "Question?");
    def.adapter = "artifact".into();
    let artifact = create_question(&vault, owner, def, 10)?
        .definition
        .question
        .id;
    assert!(standing_source_frontier(&vault, owner, artifact, 1, actor, unit, &[unit]).is_err());
    assert!(backfill_standing_answer(&vault, owner, artifact, 1, actor, input(unit), 11).is_err());
    let mut one_off = definition(unit, "One off?");
    one_off.activation = QuestionActivation::OneOff;
    assert!(create_question(&vault, owner, one_off, 10).is_err());
    Ok(())
}

#[test]
fn real_secret_custody_cannot_be_supplemental_evidence() -> TestResult {
    use crate::secret_custody::{
        CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor, SecretCustodyRecord,
        SecretCustodyStatus,
    };
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let unit = EntityId::now();
    for id in [owner, unit] {
        person(&vault, id)?;
    }
    grant(&vault, owner)?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let secret = vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: "standing-fixture-key".into(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: b"fixture secret".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1_700_000_000,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![],
        manifest_ref: "secrets.toml".into(),
        declared_paths: vec![".secrets/api.key".into()],
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })?;
    let id = create_question(&vault, owner, definition(unit, "Classify?"), 10)?
        .definition
        .question
        .id;
    let mut answer = prepared(&vault, owner, id, 1, actor, unit)?;
    answer.evidence.push(secret);
    assert!(standing_source_frontier(&vault, owner, id, 1, actor, unit, &answer.evidence).is_err());
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, answer, 11).is_err());
    Ok(())
}

#[test]
fn deleted_landed_claim_is_not_returned_from_cache() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let unit = EntityId::now();
    for id in [owner, unit] {
        person(&vault, id)?;
    }
    grant(&vault, owner)?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let id = create_question(&vault, owner, definition(unit, "Question?"), 10)?
        .definition
        .question
        .id;
    let answer = prepared(&vault, owner, id, 1, actor, unit)?;
    let first = backfill_standing_answer(&vault, owner, id, 1, actor, answer.clone(), 11)?;
    vault.delete_entity(&first.claim)?;
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, answer, 12).is_err());
    Ok(())
}

#[test]
fn supplemental_claim_evidence_taint_scope_and_revisions_are_preserved() -> TestResult {
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    };
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    person(&vault, owner)?;
    grant(&vault, owner)?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let unit = EntityId::now();
    let evidence = EntityId::now();
    let source = |kind| {
        let mut body = ClaimBody::new(
            "review.source",
            ClaimSubject::Entity(owner),
            rmpv::Value::from("fact"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(kind);
        body
    };
    vault.put_claim(
        &unit,
        &source(ClaimSource::UserStated),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let mut imported = source(ClaimSource::Imported);
    imported.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("private"),
        rmpv::Value::Boolean(true),
    )]));
    vault.put_claim(&evidence, &imported, TimeRange { start: 1, end: 1 }, 1)?;
    let id = create_question(&vault, owner, definition(unit, "Fact?"), 10)?
        .definition
        .question
        .id;
    let mut answer = input(unit);
    answer.evidence.push(evidence);
    answer.source_frontier =
        standing_source_frontier(&vault, owner, id, 1, actor, unit, &answer.evidence)?;
    let first = backfill_standing_answer(&vault, owner, id, 1, actor, answer.clone(), 11)?;
    let landed = vault.get_claim(&first.claim)?.expect("landed");
    assert_eq!(landed.source, Some(ClaimSource::Imported));
    assert_eq!(
        crate::claim::claim_evidence_taint(&landed),
        Some(ClaimSource::Imported)
    );
    assert_eq!(landed.scope_project, imported.scope_project);
    assert_eq!(landed.scope_facet, imported.scope_facet);
    let scope = landed.scope.expect("scope");
    assert!(
        scope
            .as_map()
            .expect("map")
            .iter()
            .any(|(key, value)| key.as_str() == Some("private") && value.as_bool() == Some(true))
    );
    let refs = landed.evidence.expect("evidence").to_string();
    assert!(refs.contains(&unit.to_hex()) && refs.contains(&evidence.to_hex()));
    vault.put_claim(&evidence, &imported, TimeRange { start: 2, end: 2 }, 2)?;
    assert!(backfill_standing_answer(&vault, owner, id, 1, actor, answer, 12).is_err());
    Ok(())
}
