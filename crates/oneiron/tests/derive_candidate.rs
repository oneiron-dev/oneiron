//! The Candidate derive item (untangle 6.9e e2g.2): the batch's new wire
//! item lands one extraction candidate that replaces nothing, through
//! native's own promotion writer with derive provenance.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test derive_candidate`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "extraction_verdict/support.rs"]
#[allow(dead_code)]
mod support;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, ConfidenceBand,
    VerdictBasis,
};
use oneiron::dreamer_consolidation::decode_consolidation_evidence;
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::provenance::{
    PREDICATE_EDGE_PROVENANCE, SupersessionStatus, decode_edge_provenance_body,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    batches_of, claim_lifecycle, derive_item_receipts, reader_claim_rows, refusal_receipt,
    source_version, supports,
};
use oneiron::test_doors::derive_conflict;
use oneiron::test_doors::derive_verbs::{define_agent, grant_derive_rows, revert_as_owner};
use oneiron::test_doors::extraction_inputs::{
    append_extraction_turn_words, enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_outputs::recorded_outputs;
use oneiron::test_doors::extraction_routing::native_routes;
use oneiron::test_doors::open_candidate::build_native_candidate;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{AttemptId, EdgeActorClass, EdgeKind, EntityId, Vault, WriteActor};
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
/// The refusal of a Candidate item whose landing is refused.
const LANDING_REFUSED: &str = "gate.deny.derive.candidate_landing_refused";
/// The refusal of an item naming a batch-local row that is unavailable: a
/// refused item's, or an attached candidate's, which created support rather
/// than a named claim.
const DEPENDENCY_REFUSED: &str = "gate.deny.derive.dependency_refused";
/// The allowance an attached candidate's receipt names: support now stands on
/// the head, and no new claim does.
const CANDIDATE_ATTACHED: &str = "gate.allow.derive.candidate_attached";

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

/// A candidate equal to a stored head attaches its evidence to the head: the
/// item lands with the support record and no approval, the head's bytes stay
/// as they are, and the cited TURN supports the head. An unequal candidate
/// still contests. Native routes the same operands to an attachment and to a
/// judge set. The head is user-stated and the candidate cites one TURN, so
/// it does not qualify as observed beside the head. If the stager landed a
/// claim instead, the route's own id would read back; if it refused, the
/// item would not land.
#[test]
fn a_candidate_equal_to_a_head_attaches_its_evidence() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let words = ["owen chooses black coffee"];
    let (vault, attempt_id, turns, subject) = extraction_attempt_with_turns(&dir, "owen", &words)?;
    assert_eq!(turns.len(), 1);
    let head = land_head(&vault, subject, "green tea")?;
    let hex = extraction_attempt_hex(attempt_id);
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let turn = EntityId::from_hex(&turns[0].0)?;
    let before = vault.get(&head)?.ok_or("the head's bytes")?;
    let dreamer_id = dreamer(&vault)?;
    let before_rows = reader_claim_rows(&vault, dreamer_id, EdgeActorClass::System)?;
    assert!(before_rows.contains(&head), "the head stands before the attach");

    let same = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let routes = native_routes(&vault, &hex, now_ms, std::slice::from_ref(&same))?;
    assert_eq!(routes["choices"][0]["kind"], json!("attach"));
    assert_eq!(
        routes["candidates"][0]["claim"].as_str(),
        routes["choices"][0]["claim"].as_str(),
        "the route names one own id"
    );
    let own = EntityId::from_hex(
        routes["choices"][0]["claim"].as_str().ok_or("the route's own id")?,
    )?;
    assert_ne!(own, head, "the own id is not the head");
    let spec = candidate_spec("first", member(same, 0.0, vec![]));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["kind"], "candidate");
    assert_eq!(item["rows"].as_array().ok_or("rows")?.len(), 1, "{answer}");
    assert!(
        item.get("approval").is_none(),
        "an attachment lands no claim, so no approval: {answer}"
    );
    assert!(item["receipt"].is_string(), "{answer}");
    let support = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    assert_ne!(support, head, "the row is the support record, not the head");
    let record = vault.get_claim(&support)?.ok_or("the support record")?;
    assert_eq!(record.predicate, PREDICATE_EDGE_PROVENANCE);
    assert_eq!(record.approval, ClaimApprovalStatus::Auto);
    assert_eq!(
        vault.get(&head)?.ok_or("the head still stands")?,
        before,
        "the head's bytes stay as they are"
    );
    assert!(supports(&vault, turn, head)?, "the TURN supports the head");
    assert_eq!(
        vault.sources(&head, EdgeKind::Supports, None)?,
        vec![turn],
        "the public edge read shows the TURN behind the head"
    );
    let after_rows = reader_claim_rows(&vault, dreamer_id, EdgeActorClass::System)?;
    assert_eq!(
        after_rows.len(),
        before_rows.len() + 1,
        "exactly one row is new"
    );
    assert!(
        after_rows.contains(&head) && after_rows.contains(&support),
        "the new row is the support record"
    );
    assert_ne!(support, own, "the row is support, not the candidate's own id");
    assert!(
        vault.get_claim(&own)?.is_none(),
        "no claim stands at the candidate's own id"
    );
    assert!(
        recorded_outputs(&vault, attempt_id)?.is_empty(),
        "a stamp door records no attempt outputs"
    );
    let receipts = derive_item_receipts(&vault, &head)?;
    assert!(
        receipts
            .iter()
            .any(|receipt| receipt.outcome == "approved"
                && receipt.reasons == vec![CANDIDATE_ATTACHED.to_owned()]),
        "the allowance receipt names the head: {receipts:?}"
    );

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

/// The committer's revert takes an attachment back: the batch's own Dreamer
/// reverts, not the owner, and the support is gone while the head stands
/// with its earlier evidence, which here is none. If the candidate arm
/// missed attachments, the support would still stand and the item would be
/// left, not reverted.
#[test]
fn the_committer_s_revert_takes_an_attachment_back() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let words = ["owen chooses black coffee"];
    let (vault, attempt_id, turns, subject) = extraction_attempt_with_turns(&dir, "owen", &words)?;
    assert_eq!(turns.len(), 1);
    let head = land_head(&vault, subject, "green tea")?;
    let turn = EntityId::from_hex(&turns[0].0)?;
    let before = vault.get(&head)?.ok_or("the head's bytes")?;
    assert!(vault.sources(&head, EdgeKind::Supports, None)?.is_empty());
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let spec = candidate_spec("first", member(operand, 0.0, vec![]));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    let support = EntityId::from_hex(answer["items"][0]["rows"][0].as_str().ok_or("the row")?)?;
    assert!(supports(&vault, turn, head)?);
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    // The committer reverts as itself: it is the batch's actor, and its
    // subjectless Derive verdict passes exactly as the commit's own
    // subjectful one did (same grant, same landing rows, no target to
    // reach), so no owner proof is needed.
    let dreamer_id = dreamer(&vault)?;
    let reverted = vault.derive_revert(
        WriteActor::new(dreamer_id, EdgeActorClass::System),
        None,
        batch,
    )?;
    assert_eq!(reverted.batch, batch);
    assert_eq!(reverted.reverted, vec!["first".to_owned()]);
    assert!(reverted.left.is_empty());
    assert!(!supports(&vault, turn, head)?, "the support is retracted");
    assert!(vault.sources(&head, EdgeKind::Supports, None)?.is_empty());
    assert_eq!(
        vault.get(&head)?.ok_or("the head still stands")?,
        before
    );
    assert_eq!(claim_lifecycle(&vault, head)?, Some("active".to_owned()));
    assert_ne!(
        claim_lifecycle(&vault, support)?,
        Some("active".to_owned()),
        "the support record no longer stands"
    );
    Ok(())
}

/// A later item naming an attached candidate is refused: the candidate created
/// support, not a named claim, so the name is unavailable. Person is the only
/// extraction-facet kind that names a batch-local row. If a support id were
/// registered, Person would reach its stager instead of DEPENDENCY_REFUSED;
/// resolving an unregistered name would abort the commit instead of answering.
#[test]
fn a_later_item_naming_an_attached_candidate_is_refused() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let words = ["owen chooses black coffee"];
    let (vault, attempt_id, turns, subject) = extraction_attempt_with_turns(&dir, "owen", &words)?;
    assert_eq!(turns.len(), 1);
    let head = land_head(&vault, subject, "green tea")?;
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let first = candidate_spec("first", member(operand, 0.0, vec![]));
    let second = json!({
        "kind": "person",
        "spec": {"local": "owen", "name": "Owen", "evidence": [{"local": "first"}]},
    });
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [first, second], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    assert_eq!(answer["items"][1]["landed"], false, "{answer}");
    assert_eq!(answer["items"][1]["rows"], json!([]));
    assert_eq!(
        answer["items"][1]["reasons"],
        json!([DEPENDENCY_REFUSED]),
        "{answer}"
    );
    let stored = vault.get_claim(&head)?.ok_or("the head still stands")?;
    assert_eq!(stored.value, RmpValue::from("green tea"));
    Ok(())
}

/// An attachment matches native's support record, every field but the record's
/// own id, clocks and stored provenance, against native's code by reading: no
/// test door runs native's own attach (its shell stays private and its sealed
/// write cannot be built outside its module), so no parity door of about 60
/// lines exists, and this test pins the shared body's fields instead
/// (`dreamer_promotion/scoped.rs`, `provenance/writes.rs`). Any field
/// mismatch fails: both paths call the shared attach body, so a difference
/// means the derive call site passes something native does not.
#[test]
fn an_attachment_matches_native_s_support_record() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let words = ["owen chooses black coffee"];
    let (vault, attempt_id, turns, subject) = extraction_attempt_with_turns(&dir, "owen", &words)?;
    assert_eq!(turns.len(), 1);
    let head = land_head(&vault, subject, "green tea")?;
    let turn = EntityId::from_hex(&turns[0].0)?;
    let dreamer_id = dreamer(&vault)?;
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let spec = candidate_spec("first", member(operand, 0.0, vec![]));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    let support = EntityId::from_hex(answer["items"][0]["rows"][0].as_str().ok_or("the row")?)?;
    let record = vault.get_claim(&support)?.ok_or("the support record")?;
    let head_body = vault.get_claim(&head)?.ok_or("the head")?;
    // The wrapper: predicate, subject, confidence with its band and basis,
    // approval, lifecycle, then every other field the writer sets or leaves
    // (`provenance/writes.rs`).
    assert_eq!(record.predicate, PREDICATE_EDGE_PROVENANCE);
    assert_eq!(
        record.subject,
        ClaimSubject::Edge {
            source: turn,
            kind: EdgeKind::Supports,
            target: head,
        }
    );
    assert_eq!(record.confidence, 1.0f32);
    assert_eq!(record.confidence_band, ConfidenceBand::Certain);
    assert_eq!(record.confidence_basis, VerdictBasis::DeterministicFallback);
    assert_eq!(record.approval, ClaimApprovalStatus::Auto);
    assert_eq!(record.lifecycle, ClaimLifecycleStatus::Active);
    assert!(record.salience.is_none());
    assert!(record.evidence.is_none(), "the wrapper's evid stays empty");
    assert!(record.valid_from.is_none());
    assert!(record.valid_to.is_none());
    // The meet of the Dreamer's Generated floor with the user-stated TURN.
    assert_eq!(record.source, Some(ClaimSource::Generated));
    assert!(record.world.is_none());
    assert!(record.rel.is_none(), "the relationship key is all");
    assert!(record.session_tag.is_none());
    assert!(!record.stale);
    // The witness TURN carries no FacetOf edge, so the writer takes the
    // vault default facet; the row lands in the project its ends share.
    assert_eq!(record.scope_facet, vault.default_facet()?);
    assert_eq!(record.scope_project, head_body.scope_project);
    // The typed value: all ten record fields (`provenance/codec.rs`).
    let body = decode_edge_provenance_body(&record.value)?;
    assert_eq!(body.actor_entity_ref, dreamer_id);
    assert_eq!(body.confidence, 1.0f32);
    assert_eq!(body.supersession_status, SupersessionStatus::Confirmed);
    assert_eq!(body.actor_class, Some(EdgeActorClass::System));
    assert!(body.source_revision_ref.is_some(), "the source revision is pinned");
    assert!(body.body_snapshot_ref.is_some(), "the head bytes are pinned");
    assert!(body.valid_from.is_none());
    assert!(body.valid_to.is_none());
    assert!(body.substrate_ref.is_none());
    assert!(body.reasoning_effort.is_none());
    // The scope: exactly taint and derived evidence.
    let scope = record.scope.as_ref().ok_or("the support's scope")?;
    let RmpValue::Map(entries) = scope else {
        return Err("the support's scope is a map".into());
    };
    assert_eq!(entries.len(), 2);
    assert_eq!(
        map_at(scope, "evidence_taint").and_then(RmpValue::as_str),
        Some("generated")
    );
    // The derived evidence: the envelope decoded, then its locators in full.
    // The attach carries no conflict answers, so no answers key rides along.
    let derived = map_at(scope, "derived_evidence").ok_or("the derived evidence")?;
    assert!(map_at(derived, "answers_open_conflict").is_none());
    let envelope = decode_consolidation_evidence(derived)?.ok_or("the evidence envelope")?;
    assert_eq!(envelope.refs, vec![turn]);
    assert!(envelope.chain.is_empty());
    assert_eq!(envelope.source_meet, ClaimSource::Generated);
    let RmpValue::Map(fields) = derived else {
        return Err("the derived evidence is a map".into());
    };
    assert_eq!(fields.len(), 4, "refs, chain, source_meet, locators");
    let locators = map_at(derived, "locators").ok_or("the locators")?;
    let RmpValue::Array(locators) = locators else {
        return Err("the locators are an array".into());
    };
    assert_eq!(locators.len(), 1);
    let row = &locators[0];
    let RmpValue::Map(row_fields) = row else {
        return Err("the locator is a map".into());
    };
    assert_eq!(row_fields.len(), 4, "source, hash, range, messages");
    let source_id = map_at(row, "source_id")
        .and_then(RmpValue::as_slice)
        .ok_or("the locator source")?;
    assert_eq!(source_id, turn.as_bytes().as_slice());
    let hash = map_at(row, "content_hash")
        .and_then(RmpValue::as_slice)
        .ok_or("the content hash")?;
    assert_eq!(hash.len(), 32);
    assert!(map_at(row, "claim_id").is_none(), "a TURN locator names no claim");
    let range = map_at(row, "byte_range").ok_or("the byte range")?;
    let RmpValue::Array(range) = range else {
        return Err("the byte range is an array".into());
    };
    assert_eq!(range.len(), 2);
    assert_eq!(range[0].as_u64(), Some(0), "a whole-text range starts at zero");
    assert!(range[1].as_u64().is_some_and(|end| end > 0));
    let spans = map_at(row, "messages").ok_or("the message spans")?;
    let RmpValue::Array(spans) = spans else {
        return Err("the message spans are an array".into());
    };
    assert!(!spans.is_empty(), "the range covers message bytes");
    for span in spans {
        let RmpValue::Map(span_fields) = span else {
            return Err("a message span is a map".into());
        };
        assert_eq!(span_fields.len(), 3, "message, span, revision");
        let message = map_at(span, "message")
            .and_then(RmpValue::as_slice)
            .ok_or("the span message")?;
        assert_eq!(message.len(), 16);
        let bounds = map_at(span, "span").ok_or("the span bounds")?;
        let RmpValue::Array(bounds) = bounds else {
            return Err("the span bounds are an array".into());
        };
        assert_eq!(bounds.len(), 2);
        let (Some(from), Some(to)) = (bounds[0].as_u64(), bounds[1].as_u64()) else {
            return Err("the span bounds are integers".into());
        };
        assert!(from <= to);
        let revision = map_at(span, "revision")
            .and_then(RmpValue::as_slice)
            .ok_or("the span revision")?;
        assert_eq!(revision.len(), 32);
        assert!(map_at(span, "frontier").is_none(), "no document frontier");
        assert!(map_at(span, "attribution").is_none(), "a native child names no speaker");
    }
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

/// A candidate under a blank run lands nothing, as native's promotion
/// refuses a blank run: it would hide the write from every reader that
/// groups by the Dreamer's run. The queue admits a run that is only
/// whitespace, and a stamp carries its attempt's run as recorded.
#[test]
fn a_candidate_under_a_blank_run_lands_nothing() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = single_attempt(&dir)?;
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let spec = candidate_spec("first", member(operand, 0.9, vec![]));
    let request = json!({"items": [spec], "sources": []});
    let answer = derive_conflict::commit(
        &vault,
        dreamer(&vault)?,
        EdgeActorClass::System,
        "  ",
        Some(attempt_id),
        request,
    )?;
    assert_eq!(answer["items"][0]["landed"], false, "{answer}");
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([LANDING_REFUSED]));
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
