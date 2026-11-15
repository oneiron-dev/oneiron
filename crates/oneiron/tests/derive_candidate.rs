//! The Candidate derive item (untangle 6.9e e2g.2): the batch's new wire
//! item lands one extraction candidate that replaces nothing, through
//! native's own promotion writer with derive provenance.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test derive_candidate`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "extraction_verdict/support.rs"]
mod support;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{batches_of, claim_lifecycle, refusal_receipt, source_version};
use oneiron::test_doors::derive_conflict;
use oneiron::test_doors::derive_verbs::{define_agent, grant_derive_rows, revert_as_owner};
use oneiron::test_doors::extraction_inputs::{
    append_extraction_turn_words, enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_routing::native_routes;
use oneiron::test_doors::open_candidate::build_native_candidate;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{AttemptId, EdgeActorClass, EntityId, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use std::sync::Arc;
use support::{
    QUEUE_NOW, bind_extraction, extraction_attempt_hex, extraction_attempt_with_turns,
    extraction_candidate, open_extraction_verdict_vault, page_turns_with_versions,
    read_bound_extraction_page,
};

/// A fixture or assertion error, without hiding its source.
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The refusal of a Candidate item outside a queued extraction attempt, as
/// the stager spells it. Written as a literal: the tests name no new
/// constant.
const NEEDS_EXTRACTION_ATTEMPT: &str = "gate.deny.derive.candidate_needs_extraction_attempt";
/// The refusal of a Candidate item whose actor is not the attempt's
/// Dreamer.
const NOT_ATTEMPT_DREAMER: &str = "gate.deny.derive.candidate_not_attempt_dreamer";
/// The refusal of a Candidate item whose operand is refused.
const OPERAND_REFUSED: &str = "gate.deny.derive.candidate_operand_refused";
/// The refusal of a Candidate item that restates a head.
const RESTATES_HEAD: &str = "gate.deny.derive.candidate_restates_head";
/// The refusal of a Candidate item that contests a head.
const CONTESTS_HEAD: &str = "gate.deny.derive.candidate_contests_head";
/// The refusal of a Candidate item whose claim already stands.
const DUPLICATE: &str = "gate.deny.derive.candidate_duplicate";

/// The predicate the extraction fixture asserts.
const FOOD: &str = "preference.food";

/// Writes `body` as a row of `entity_type`; its id.
fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> TestResult<EntityId> {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault.put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)?;
    Ok(id)
}

/// A vault with one agent the owner's policy lets derive, a person and a TURN.
struct AgentFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    agent: EntityId,
    person: EntityId,
    turn: EntityId,
}

/// Opens [`AgentFixture`] with the agent `name`.
fn agent_fixture(name: &str) -> TestResult<AgentFixture> {
    let dir = tempfile::tempdir()?;
    let vault = open_dreamer_vault(dir.path(), "reader")?;
    let agent = define_agent(&vault, name)?;
    grant_derive_rows(&vault, &[agent])?;
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone")?;
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))?;
    let turn = put(&vault, ENTITY_TYPE_TURN, &body)?;
    Ok(AgentFixture {
        _dir: dir,
        vault,
        agent,
        person,
        turn,
    })
}

/// The version of the fixture's TURN as its agent reads it now, as JSON.
fn turn_version(fixture: &AgentFixture) -> TestResult<Value> {
    let version = source_version(
        &fixture.vault,
        fixture.agent,
        EdgeActorClass::Agent,
        fixture.turn,
    )?
    .ok_or("the agent reads the TURN")?;
    Ok(serde_json::to_value(version)?)
}

/// One candidate operand over `subject` citing `turn` at `version`.
fn candidate(subject: &str, turn: &str, version: Value) -> Value {
    json!({
        "subject": subject,
        "predicate": "profile.drink",
        "value": "an oat milk flat white",
        "evidence": [{"turn": turn, "version": version}],
    })
}

/// One Candidate wire item with one member over `subject`, `turn` and `version`.
fn candidate_item(local: &str, subject: &str, turn: &str, version: Value) -> Value {
    json!({
        "kind": "candidate",
        "spec": {
            "local": local,
            "member": {
                "candidate": candidate(subject, turn, version),
                "confidence": 0.9,
            },
        },
    })
}

/// A well-formed Candidate batch decodes and commits outside an attempt as
/// refused, while each malformed form (an unknown field, a confidence
/// outside `[0, 1]`, a hint the normaliser refuses) is refused whole: the
/// door errs and records no batch.
#[test]
fn a_candidate_item_decodes_and_a_malformed_one_aborts_its_batch() -> TestResult<()> {
    let fixture = agent_fixture("owen")?;
    let version = turn_version(&fixture)?;
    let request = json!({
        "items": [candidate_item(
            "first",
            &fixture.person.to_hex(),
            &fixture.turn.to_hex(),
            version,
        )],
        "sources": [],
    });
    let answer = derive_conflict::commit(
        &fixture.vault,
        fixture.agent,
        EdgeActorClass::Agent,
        "run-candidate-t1",
        None,
        request,
    )
    .expect("a well-formed Candidate batch decodes and commits");
    let item = &answer["items"][0];
    assert_eq!(item["local"], "first");
    assert_eq!(item["kind"], "candidate");
    assert_eq!(item["landed"], false, "{answer}");
    assert_eq!(item["rows"], json!([]));
    assert!(
        item["receipt"].is_string(),
        "a refused item keeps its receipt: {answer}"
    );
    assert_eq!(
        item["reasons"],
        json!([NEEDS_EXTRACTION_ATTEMPT]),
        "{answer}"
    );
    assert_eq!(
        batches_of(&fixture.vault, fixture.agent)?.len(),
        1,
        "the well-formed batch is recorded"
    );

    let version = turn_version(&fixture)?;
    let unknown = json!({
        "items": [{
            "kind": "candidate",
            "spec": {
                "local": "first",
                "member": {
                    "candidate": candidate(
                        &fixture.person.to_hex(),
                        &fixture.turn.to_hex(),
                        version.clone(),
                    ),
                    "confidence": 0.9,
                },
                "bogus": 1,
            },
        }],
        "sources": [],
    });
    let confident = json!({
        "items": [{
            "kind": "candidate",
            "spec": {
                "local": "first",
                "member": {
                    "candidate": candidate(
                        &fixture.person.to_hex(),
                        &fixture.turn.to_hex(),
                        version.clone(),
                    ),
                    "confidence": 1.5,
                },
            },
        }],
        "sources": [],
    });
    let hinted = json!({
        "items": [{
            "kind": "candidate",
            "spec": {
                "local": "first",
                "member": {
                    "candidate": candidate(
                        &fixture.person.to_hex(),
                        &fixture.turn.to_hex(),
                        version,
                    ),
                    "confidence": 0.9,
                    "prospective_queries": ["q".repeat(257)],
                },
            },
        }],
        "sources": [],
    });
    for (what, request) in [
        ("a Candidate batch with an unknown field", unknown),
        ("a Candidate batch with confidence 1.5", confident),
        ("a Candidate batch with a 257-byte hint", hinted),
    ] {
        let refusal = derive_conflict::commit(
            &fixture.vault,
            fixture.agent,
            EdgeActorClass::Agent,
            "run-candidate-t1",
            None,
            request,
        )
        .err()
        .ok_or_else(|| format!("{what} is not refused whole"))?;
        assert_eq!(refusal.code, MEMORY_CODE_BAD_REQUEST, "{refusal:?}");
        assert_eq!(
            batches_of(&fixture.vault, fixture.agent)?.len(),
            1,
            "{what} records no batch"
        );
    }
    Ok(())
}

/// Lands one user-stated food preference about `subject` and returns its id.
fn land_head(vault: &Vault, subject: EntityId, value: &str) -> TestResult<EntityId> {
    let head = EntityId::now();
    let mut body = ClaimBody::new(
        FOOD,
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    let at = TimeRange {
        start: now,
        end: now,
    };
    vault.put_claim(&head, &body, at, now)?;
    Ok(head)
}

/// One extraction attempt over witnessed turns: the vault, the attempt, the
/// served turns with their versions, and the subject.
type AttemptSetup = (Arc<Vault>, AttemptId, Vec<(String, Value)>, EntityId);

/// The one-turn attempt: green tea.
fn single_attempt(dir: &tempfile::TempDir) -> TestResult<AttemptSetup> {
    let words = ["owen chooses green tea"];
    extraction_attempt_with_turns(dir, "owen", &words)
}

/// One candidate operand over `subject` with `value` citing `turn`.
fn operand_for(subject: &str, value: Value, turn: &(String, Value)) -> Value {
    extraction_candidate(subject, FOOD, value, &turn.0, turn.1.clone())
}

/// One candidate member: `candidate` with `confidence` and `hints`.
fn member(candidate: Value, confidence: f64, hints: Vec<Value>) -> Value {
    json!({"candidate": candidate, "confidence": confidence, "prospective_queries": hints})
}

/// One Candidate wire item over `member`.
fn candidate_spec(local: &str, member: Value) -> Value {
    json!({"kind": "candidate", "spec": {"local": local, "member": member}})
}

/// Commits `request` as the Dreamer in `attempt`.
fn commit_dreamer(vault: &Vault, attempt: Option<AttemptId>, request: Value) -> TestResult<Value> {
    let actor = dreamer(vault)?;
    let class = EdgeActorClass::System;
    derive_conflict::commit(vault, actor, class, "run", attempt, request).map_err(Into::into)
}

/// The map entry `key` of `value`, when it is a map holding one.
fn map_at<'v>(value: &'v RmpValue, key: &str) -> Option<&'v RmpValue> {
    let RmpValue::Map(rows) = value else {
        return None;
    };
    rows.iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, found)| found)
}

/// `value`'s encoded bytes as lowercase hex.
fn hex_of(value: &RmpValue) -> TestResult<String> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| "the value encodes")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// One candidate lands as native prepares it, with derive provenance.
#[test]
fn a_candidate_lands_as_native_prepares_it() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = single_attempt(&dir)?;
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    // The build-only door first, at the commit's own clock unit: the vault's
    // recorded seconds as milliseconds, as step e stamps them. No compared
    // field carries time (the id hashes identity axes only; the body, scope
    // and evidence are timeless), so the door's clock need not equal the
    // commit's second.
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let hex = extraction_attempt_hex(attempt_id);
    let door = build_native_candidate(&vault, &hex, now_ms, &operand)?;
    let green = member(operand.clone(), 0.0, vec![]);
    let request = json!({"items": [candidate_spec("first", green)], "sources": []});
    let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["kind"], "candidate");
    assert_eq!(door["claim"], item["rows"][0]);
    assert_eq!(item["approval"], json!("auto"));
    let claim = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let stored = vault.get_claim(&claim)?.ok_or("the stored claim")?;
    assert_eq!(door["predicate"].as_str().ok_or("p")?, stored.predicate);
    let ClaimSubject::Entity(stored_subject) = stored.subject else {
        return Err("the claim names an entity subject".into());
    };
    assert_eq!(
        door["subject"].as_str().ok_or("s")?,
        stored_subject.to_hex()
    );
    assert_eq!(
        door["value_hex"].as_str().ok_or("v")?,
        hex_of(&stored.value)?
    );
    let stored_scope = stored.scope.as_ref().ok_or("scope")?;
    assert_eq!(
        door["scope_hex"].as_str().ok_or("sc")?,
        hex_of(stored_scope)?
    );
    assert_eq!(
        door["source"].as_str().ok_or("src")?,
        stored.source.ok_or("source")?.as_str()
    );
    assert_eq!(
        door["confidence"].as_f64().ok_or("c")?,
        f64::from(stored.confidence)
    );
    assert_eq!(
        door["world"].as_str(),
        stored.world.map(|world| world.to_hex()).as_deref()
    );
    let stored_rel: Option<Vec<String>> = stored
        .rel
        .as_ref()
        .map(|rel| rel.iter().map(EntityId::to_hex).collect());
    assert_eq!(
        door["relationship"],
        stored_rel.map_or(json!(null), |rel| json!(rel))
    );
    assert_eq!(
        door["facet"].as_str().ok_or("f")?,
        stored.scope_facet.to_hex()
    );
    assert_eq!(
        door["project"].as_str().ok_or("pr")?,
        stored.scope_project.to_hex()
    );
    let stored_evidence = stored.evidence.as_ref().ok_or("e")?;
    let candidate_evidence = map_at(stored_evidence, "candidate_evidence").ok_or("ce")?;
    assert_eq!(
        door["candidate_evidence_hex"].as_str().ok_or("ee")?,
        hex_of(candidate_evidence)?
    );
    assert_eq!(
        door["approval"].as_str().ok_or("a")?,
        stored.approval.as_str()
    );
    let provenance = map_at(stored_evidence, "provenance").ok_or("p")?;
    let at = |key: &str| map_at(provenance, key).and_then(RmpValue::as_str);
    assert_eq!(at("surface"), Some("vault.derive"));
    assert_eq!(at("batch"), answer["batch"].as_str());
    assert_eq!(at("item"), Some("first"));
    assert_eq!(at("run"), Some("run"));
    assert!(map_at(provenance, "job_id").is_none());
    assert!(map_at(provenance, "decisions").is_none());
    Ok(())
}

/// A candidate keeps its confidence under the same id law: neither the
/// confidence nor the hints enter the claim id. The hints are not asserted:
/// a signed promotion keeps none (`dreamer_promotion/writer.rs`, the
/// `signed` rule: its queries join the birth text), an unsigned one keeps
/// them as lexical rows beside the body, and a claim read shows neither.
#[test]
fn a_candidate_keeps_its_confidence() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = single_attempt(&dir)?;
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let hex = extraction_attempt_hex(attempt_id);
    let door = build_native_candidate(&vault, &hex, now_ms, &operand)?;
    let sure = member(operand, 0.7, vec![json!("  green tea  ")]);
    let request = json!({"items": [candidate_spec("first", sure)], "sources": []});
    let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    assert_eq!(door["claim"], answer["items"][0]["rows"][0]);
    let claim = EntityId::from_hex(answer["items"][0]["rows"][0].as_str().ok_or("the row")?)?;
    let stored = vault.get_claim(&claim)?.ok_or("the stored claim")?;
    assert_eq!(stored.confidence, 0.7);
    Ok(())
}

/// A candidate that meets a stored head lands nothing, restating or
/// contesting; native routes the same operands to an attachment and to a
/// judge set. The head is user-stated and the candidate cites one TURN, so
/// it does not qualify as observed beside the head.
#[test]
fn a_candidate_that_meets_a_head_lands_nothing() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let words = ["owen chooses black coffee"];
    let (vault, attempt_id, turns, subject) = extraction_attempt_with_turns(&dir, "owen", &words)?;
    assert_eq!(turns.len(), 1);
    let head = land_head(&vault, subject, "green tea")?;
    let hex = extraction_attempt_hex(attempt_id);
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);

    let same = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let routes = native_routes(&vault, &hex, now_ms, std::slice::from_ref(&same))?;
    assert_eq!(routes["choices"][0]["kind"], json!("attach"));
    let spec = candidate_spec("first", member(same, 0.0, vec![]));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], false, "{answer}");
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([RESTATES_HEAD]));

    let other = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let routes = native_routes(&vault, &hex, now_ms, std::slice::from_ref(&other))?;
    assert_eq!(routes["judge_sets"].as_array().ok_or("judge")?.len(), 1);
    let spec = candidate_spec("second", member(other, 0.0, vec![]));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], false, "{answer}");
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([CONTESTS_HEAD]));

    let stored = vault.get_claim(&head)?.ok_or("the head still stands")?;
    assert_eq!(stored.value, RmpValue::from("green tea"));
    Ok(())
}

/// A second landing of the same candidate is refused; one claim stands.
#[test]
fn a_second_landing_of_the_same_candidate_is_refused() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = single_attempt(&dir)?;
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let spec = candidate_spec("first", member(operand, 0.0, vec![]));
    let attempt = Some(attempt_id);
    let first = commit_dreamer(
        &vault,
        attempt,
        json!({"items": [spec.clone()], "sources": []}),
    )?;
    assert_eq!(first["items"][0]["landed"], true, "{first}");
    let second = commit_dreamer(&vault, attempt, json!({"items": [spec], "sources": []}))?;
    assert_eq!(second["items"][0]["landed"], false, "{second}");
    assert_eq!(second["items"][0]["reasons"], json!([DUPLICATE]));
    let claim = EntityId::from_hex(first["items"][0]["rows"][0].as_str().ok_or("the row")?)?;
    assert!(vault.get_claim(&claim)?.is_some());
    Ok(())
}

/// The committer's revert takes the claim back.
#[test]
fn the_committer_s_revert_takes_the_claim_back() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = single_attempt(&dir)?;
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let spec = candidate_spec("first", member(operand, 0.0, vec![]));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    let claim = EntityId::from_hex(answer["items"][0]["rows"][0].as_str().ok_or("the row")?)?;
    let reverted = revert_as_owner(&vault, batch)?;
    assert_eq!(reverted["reverted"], json!(["first"]));
    assert_eq!(reverted["left"], json!([]));
    assert_ne!(
        claim_lifecycle(&vault, claim)?,
        Some("active".to_owned()),
        "the claim no longer stands"
    );
    Ok(())
}

/// A candidate cites only what the attempt serves: an unserved TURN and a
/// stale TURN version are each refused alone, with the token alone on the
/// receipt.
#[test]
fn a_candidate_cites_only_what_the_attempt_serves() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let first = witness_extraction_turns(&vault, &["owen chooses green tea"])?;
    let second = witness_extraction_turns(&vault, &["owen chooses black coffee"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &first.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    // The owner's read gives the other conversation's TURN a current
    // version, so only the attempt's own partition can refuse it.
    let owner = vault.ensure_embedded_owner_actor()?;
    let elsewhere = source_version(&vault, owner, EdgeActorClass::Human, second.turns[0])?
        .ok_or("the owner reads the other conversation's turn")?;
    let turn = (second.turns[0].to_hex(), serde_json::to_value(elsewhere)?);
    let away = operand_for(&subject.to_hex(), json!("black coffee"), &turn);
    let spec = candidate_spec("away", member(away, 0.0, vec![]));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], false);
    assert_eq!(answer["items"][0]["reasons"], json!([OPERAND_REFUSED]));
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    assert_eq!(
        refusal_receipt(&vault, batch, "away")?,
        Some(vec![OPERAND_REFUSED.to_owned()])
    );
    let moved = "owen now wants oolong";
    append_extraction_turn_words(&vault, first.conversation, first.turns[0], moved)?;
    let stale = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let spec = candidate_spec("stale", member(stale, 0.0, vec![]));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], false);
    assert_eq!(answer["items"][0]["reasons"], json!([OPERAND_REFUSED]));
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    assert_eq!(
        refusal_receipt(&vault, batch, "stale")?,
        Some(vec![OPERAND_REFUSED.to_owned()])
    );
    Ok(())
}

/// Only the attempt's Dreamer lands a candidate: an agent is refused.
#[test]
fn only_the_attempt_s_dreamer_lands_a_candidate() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = single_attempt(&dir)?;
    let agent = define_agent(&vault, "yuki")?;
    grant_derive_rows(&vault, &[agent])?;
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let spec = candidate_spec("first", member(operand, 0.0, vec![]));
    let request = json!({"items": [spec], "sources": []});
    let answer = derive_conflict::commit(
        &vault,
        agent,
        EdgeActorClass::Agent,
        "run-candidate-p8",
        Some(attempt_id),
        request,
    )?;
    assert_eq!(answer["items"][0]["landed"], false);
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([NOT_ATTEMPT_DREAMER]));
    Ok(())
}

/// A candidate restating an unlisted head of the Dreamer's own lands
/// nothing. The second attempt's passage does not name the subject, so its
/// listing holds none of the subject's heads; the claim the first attempt
/// landed is such a head, and native's unlisted restatement rule meets it.
/// Native writes nothing for the same operand either.
#[test]
fn a_candidate_restating_an_unlisted_own_head_lands_nothing() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let first = witness_extraction_turns(&vault, &["owen chooses green tea"])?;
    let second = witness_extraction_turns(&vault, &["the same drink again today"])?;
    let (first_id, first_admitted) =
        enqueue_admitted_extraction_attempt(&vault, &first.turns, QUEUE_NOW)?;
    let (second_id, second_admitted) =
        enqueue_admitted_extraction_attempt(&vault, &second.turns, QUEUE_NOW)?;
    let first_binding = bind_extraction(&vault, &first_admitted)?;
    let first_page = read_bound_extraction_page(&first_binding, &extraction_attempt_hex(first_id))?;
    let first_turns = page_turns_with_versions(&first_page);
    assert_eq!(first_turns.len(), 1);
    let second_binding = bind_extraction(&vault, &second_admitted)?;
    let second_hex = extraction_attempt_hex(second_id);
    let second_page = read_bound_extraction_page(&second_binding, &second_hex)?;
    let second_turns = page_turns_with_versions(&second_page);
    assert_eq!(second_turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &first_turns[0]);
    let spec = candidate_spec("first", member(operand, 0.0, vec![]));
    let landed = commit_dreamer(
        &vault,
        Some(first_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(landed["items"][0]["landed"], true, "{landed}");
    let again = operand_for(&subject.to_hex(), json!("green tea"), &second_turns[0]);
    let spec = candidate_spec("again", member(again.clone(), 0.0, vec![]));
    let answer = commit_dreamer(
        &vault,
        Some(second_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], false, "{answer}");
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([RESTATES_HEAD]));
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let routes = native_routes(&vault, &second_hex, now_ms, std::slice::from_ref(&again))?;
    assert_eq!(routes["judge_sets"], json!([]), "{routes}");
    assert_eq!(
        routes["choices"][0]["kind"],
        json!("already_represented"),
        "{routes}"
    );
    Ok(())
}
