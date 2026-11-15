//! The Conflict derive item (untangle 6.9e e2h.3 PR-B): the batch's new
//! wire item opens the set a bound Resolution read of `ai.verdict` names.
//! PR-A built the wire form, the batch arm, the shape checks and the
//! stager's first rule; PR-B stages the set, lands the one canonical marker
//! with derive provenance, and reverts it unless an answer stands.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test derive_conflict`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "extraction_verdict/support.rs"]
mod support;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_consolidation::OpenConflict;
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{batches_of, refusal_receipt, source_version};
use oneiron::test_doors::derive_conflict;
use oneiron::test_doors::derive_verbs::{
    define_agent, grant_derive_rows, lease_run, revert_as_owner,
};
use oneiron::test_doors::extraction_inputs::{
    append_extraction_turn_words, enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::open_conflict_marker::build_native_open_conflict;
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

/// The refusal of a Conflict item outside a queued extraction attempt, as the
/// stager spells it. Written as a literal: the tests name no new constant.
const NEEDS_EXTRACTION_ATTEMPT: &str = "gate.deny.derive.conflict_needs_extraction_attempt";

/// The refusal of an item naming a refused item of its batch, as the commit
/// spells it.
const DEPENDENCY_REFUSED: &str = "gate.deny.derive.dependency_refused";

/// The refusal of operands that are not one servable native conflict.
const OPERANDS_REFUSED: &str = "gate.deny.derive.conflict_operands_refused";

/// The refusal of heads that differ from the rebuilt set's prior heads.
const HEADS_DIFFER: &str = "gate.deny.derive.conflict_heads_differ";

/// The refusal of a set that already stands opened.
const DUPLICATE: &str = "gate.deny.derive.conflict_duplicate";

/// Why a revert left an item standing: its inverse refused.
const INVERSE_REFUSED: &str = "derive.revert.inverse_refused";

/// The predicate the extraction fixture contests.
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

/// One Conflict wire item with one member over `subject`, `turn` and `version`.
fn conflict_item(local: &str, subject: &str, turn: &str, version: Value) -> Value {
    json!({
        "kind": "conflict",
        "spec": {
            "local": local,
            "members": [{
                "candidate": candidate(subject, turn, version),
                "confidence": 0.9,
            }],
        },
    })
}

/// A well-formed Conflict batch decodes and commits, while each malformed
/// form (no member, a confidence outside `[0, 1]`, a hint the normaliser
/// refuses) is refused whole: the door errs and records no batch.
#[test]
fn a_conflict_item_decodes_and_a_malformed_one_aborts_its_batch() -> TestResult<()> {
    let fixture = agent_fixture("owen")?;
    let version = turn_version(&fixture)?;
    let request = json!({
        "items": [conflict_item(
            "open",
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
        "run-conflict-t1",
        None,
        request,
    )
    .expect("a well-formed Conflict batch decodes and commits");
    let item = &answer["items"][0];
    assert_eq!(item["local"], "open");
    assert_eq!(item["kind"], "conflict");
    assert_eq!(item["landed"], false, "PR-A stages no conflict: {answer}");
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
    let memberless = json!({
        "items": [{"kind": "conflict", "spec": {"local": "open", "members": []}}],
        "sources": [],
    });
    let confident = json!({
        "items": [{
            "kind": "conflict",
            "spec": {
                "local": "open",
                "members": [{
                    "candidate": candidate(
                        &fixture.person.to_hex(),
                        &fixture.turn.to_hex(),
                        version.clone(),
                    ),
                    "confidence": 1.5,
                }],
            },
        }],
        "sources": [],
    });
    let hinted = json!({
        "items": [{
            "kind": "conflict",
            "spec": {
                "local": "open",
                "members": [{
                    "candidate": candidate(
                        &fixture.person.to_hex(),
                        &fixture.turn.to_hex(),
                        version,
                    ),
                    "confidence": 0.9,
                    "prospective_queries": ["q".repeat(257)],
                }],
            },
        }],
        "sources": [],
    });
    for (what, request) in [
        ("a memberless Conflict batch", memberless),
        ("a Conflict batch with confidence 1.5", confident),
        ("a Conflict batch with a 257-byte hint", hinted),
    ] {
        let refusal = derive_conflict::commit(
            &fixture.vault,
            fixture.agent,
            EdgeActorClass::Agent,
            "run-conflict-t1",
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

/// Through an agent run's own verb door a Conflict item is refused, a Settle
/// item naming it is refused for the dependency, and an ordinary Claim lands.
#[test]
fn an_agent_run_opens_no_conflict() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_dreamer_vault(dir.path(), "reader")?;
    let agent = define_agent(&vault, "owen")?;
    let other = define_agent(&vault, "yuki")?;
    grant_derive_rows(&vault, &[agent, other])?;
    let run = lease_run(&vault, agent)?;
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone")?;
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))?;
    let turn = put(&vault, ENTITY_TYPE_TURN, &body)?;
    let version = source_version(&vault, agent, EdgeActorClass::Agent, turn)?
        .ok_or("the agent reads the TURN")?;
    let request = json!({
        "items": [
            conflict_item(
                "open",
                &person.to_hex(),
                &turn.to_hex(),
                serde_json::to_value(&version)?,
            ),
            {
                "kind": "settle",
                "spec": {
                    "local": "close",
                    "marker": {"local": "open"},
                    "settlement": "dismiss",
                },
            },
            {
                "kind": "claim",
                "spec": {
                    "local": "drink",
                    "predicate": "profile.drink",
                    "subject": {"stored": person},
                    "value": "an oat milk flat white",
                    "confidence": 0.9,
                    "evidence": [{"stored": turn}],
                },
            },
        ],
        "sources": [version],
    });
    let answer = run
        .commit(&vault, request)
        .expect("a Conflict batch decodes and commits on a live run");
    let items = answer["items"]
        .as_array()
        .ok_or("the commit answers its items")?;
    assert_eq!(items.len(), 3, "{answer}");
    assert_eq!(items[0]["local"], "open");
    assert_eq!(items[0]["kind"], "conflict");
    assert_eq!(items[0]["landed"], false, "{answer}");
    assert_eq!(items[0]["rows"], json!([]));
    assert_eq!(
        items[0]["reasons"],
        json!([NEEDS_EXTRACTION_ATTEMPT]),
        "{answer}"
    );
    assert_eq!(items[1]["local"], "close");
    assert_eq!(items[1]["landed"], false, "{answer}");
    assert_eq!(items[1]["reasons"], json!([DEPENDENCY_REFUSED]), "{answer}");
    assert_eq!(items[2]["local"], "drink");
    assert_eq!(
        items[2]["landed"], true,
        "the ordinary claim lands: {answer}"
    );
    assert_eq!(
        items[2]["rows"]
            .as_array()
            .ok_or("a landed claim names its row")?
            .len(),
        1
    );
    let batch = EntityId::from_hex(
        answer["batch"]
            .as_str()
            .ok_or("the commit answers its batch")?,
    )?;
    assert_eq!(
        refusal_receipt(&vault, batch, "open")?,
        Some(vec![NEEDS_EXTRACTION_ATTEMPT.to_owned()]),
        "the Conflict refusal keeps its receipt"
    );
    Ok(())
}

/// Outside an attempt a Conflict item is refused and lands nothing.
#[test]
fn a_commit_outside_an_attempt_opens_no_conflict() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_dreamer_vault(dir.path(), "reader")?;
    let steward = dreamer(&vault)?;
    let subject = EntityId::now();
    let turn = EntityId::now();
    let version = json!({
        "entity": turn.to_hex(),
        "entity_type": ENTITY_TYPE_TURN,
        "learned_at": 1,
        "revision": format!("blake3:{}", "0".repeat(64)),
    });
    let request = json!({
        "items": [conflict_item("open", &subject.to_hex(), &turn.to_hex(), version)],
        "sources": [],
    });
    let answer = derive_conflict::commit(
        &vault,
        steward,
        EdgeActorClass::System,
        "run-conflict-t3",
        None,
        request,
    )
    .expect("a Conflict batch outside an attempt decodes and commits");
    let item = &answer["items"][0];
    assert_eq!(item["local"], "open");
    assert_eq!(item["kind"], "conflict");
    assert_eq!(item["landed"], false, "{answer}");
    assert_eq!(item["rows"], json!([]));
    assert_eq!(
        item["reasons"],
        json!([NEEDS_EXTRACTION_ATTEMPT]),
        "{answer}"
    );
    assert!(
        item["receipt"].is_string(),
        "a refused item keeps its receipt: {answer}"
    );
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

/// The two-turn sibling attempt: green tea against black coffee.
fn sibling_attempt(dir: &tempfile::TempDir) -> TestResult<AttemptSetup> {
    let words = ["owen chooses green tea", "owen chooses black coffee"];
    extraction_attempt_with_turns(dir, "owen", &words)
}

/// One candidate operand over `subject` with `value` citing `turn`.
fn operand_for(subject: &str, value: Value, turn: &(String, Value)) -> Value {
    extraction_candidate(subject, FOOD, value, &turn.0, turn.1.clone())
}

/// One conflict member: `candidate` with `confidence` and `hints`.
fn member(candidate: Value, confidence: f64, hints: Vec<Value>) -> Value {
    json!({"candidate": candidate, "confidence": confidence, "prospective_queries": hints})
}

/// The green-tea/black-coffee sibling pair over `subject` and `turns`.
fn sibling_pair(subject: &EntityId, turns: &[(String, Value)]) -> Vec<Value> {
    let hex = subject.to_hex();
    let green = operand_for(&hex, json!("green tea"), &turns[0]);
    let black = operand_for(&hex, json!("black coffee"), &turns[1]);
    vec![member(green, 0.0, vec![]), member(black, 0.0, vec![])]
}

/// One Conflict wire item over `members` against `heads`.
fn conflict_spec(local: &str, members: Vec<Value>, heads: Vec<Value>) -> Value {
    json!({"kind": "conflict", "spec": {"local": local, "members": members, "heads": heads}})
}

/// One Settle wire item answering `marker` with `settlement`.
fn settle_spec(local: &str, marker: Value, settlement: &str) -> Value {
    json!({"kind": "settle", "spec": {"local": local, "marker": marker, "settlement": settlement}})
}

/// The version of `entity` as the Dreamer reads it now, as JSON.
fn served_version(vault: &Vault, entity: EntityId) -> TestResult<Value> {
    let actor = dreamer(vault)?;
    let version = source_version(vault, actor, EdgeActorClass::System, entity)?.ok_or("unread")?;
    Ok(serde_json::to_value(version)?)
}

/// Commits `request` as the Dreamer in `attempt`.
fn commit_dreamer(vault: &Vault, attempt: Option<AttemptId>, request: Value) -> TestResult<Value> {
    let actor = dreamer(vault)?;
    let class = EdgeActorClass::System;
    derive_conflict::commit(vault, actor, class, "run", attempt, request).map_err(Into::into)
}

/// The marker `ops` would natively park at `batch`'s clock.
fn built_for(
    vault: &Vault,
    batch: EntityId,
    attempt: AttemptId,
    ops: &[Value],
) -> TestResult<Value> {
    let record = vault.derive_batch(batch)?.ok_or("the batch")?;
    let now_ms = record.committed_at.saturating_mul(1_000);
    let hex = extraction_attempt_hex(attempt);
    Ok(build_native_open_conflict(vault, &hex, now_ms, ops)?)
}

/// The Dreamer's open conflicts about `subject`.
fn open_for(vault: &Vault, subject: EntityId) -> TestResult<Vec<OpenConflict>> {
    let memory = vault.memory(dreamer(vault)?, EdgeActorClass::System);
    Ok(memory.open_conflicts(None, Some(subject), usize::MAX)?)
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

/// Two sibling candidates open native's marker, with derive provenance.
#[test]
fn two_sibling_candidates_open_native_s_marker() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = sibling_attempt(&dir)?;
    assert_eq!(turns.len(), 2);
    let members = sibling_pair(&subject, &turns);
    let operands: Vec<Value> = members
        .iter()
        .map(|member| member["candidate"].clone())
        .collect();
    let request = json!({"items": [conflict_spec("open", members, vec![])], "sources": []});
    let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true);
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    let built = built_for(&vault, batch, attempt_id, &operands)?;
    assert_eq!(built["marker"], item["rows"][0]);
    let marker = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let open = open_for(&vault, subject)?;
    assert_eq!(open.len(), 1);
    let conflict = &open[0];
    assert_eq!(conflict.marker, marker);
    assert_eq!(
        built["predicate"].as_str().ok_or("p")?,
        conflict.body.predicate.as_str()
    );
    let ClaimSubject::Entity(stored) = conflict.body.subject else {
        return Err("the marker names an entity subject".into());
    };
    assert_eq!(built["subject"].as_str().ok_or("s")?, stored.to_hex());
    assert_eq!(
        built["value_hex"].as_str().ok_or("v")?,
        hex_of(&conflict.body.value)?
    );
    let stored_evidence = conflict.body.evidence.as_ref().ok_or("e")?;
    let candidate_evidence = map_at(stored_evidence, "candidate_evidence").ok_or("ce")?;
    assert_eq!(
        built["evidence_hex"].as_str().ok_or("ee")?,
        hex_of(candidate_evidence)?
    );
    let provenance = map_at(stored_evidence, "provenance").ok_or("p")?;
    let at = |key: &str| map_at(provenance, key).and_then(RmpValue::as_str);
    assert_eq!(at("surface"), Some("vault.derive"));
    assert_eq!(at("batch"), answer["batch"].as_str());
    assert_eq!(at("item"), Some("open"));
    assert_eq!(at("run"), Some("run"));
    assert_ne!(at("run"), Some(extraction_attempt_hex(attempt_id).as_str()));
    assert!(map_at(provenance, "decisions").is_none());
    Ok(())
}

/// One candidate against an unequal stored head lands naming that head.
#[test]
fn a_candidate_against_a_stored_head_names_that_head() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let words = ["owen chooses black coffee"];
    let (vault, attempt_id, turns, subject) = extraction_attempt_with_turns(&dir, "owen", &words)?;
    assert_eq!(turns.len(), 1);
    let head = land_head(&vault, subject, "green tea")?;
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = conflict_spec("open", vec![black.clone()], vec![pin]);
    let request = json!({"items": [spec], "sources": []});
    let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
    assert_eq!(answer["items"][0]["landed"], true);
    let marker = EntityId::from_hex(answer["items"][0]["rows"][0].as_str().ok_or("the row")?)?;
    let open = open_for(&vault, subject)?;
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].marker, marker);
    assert_eq!(open[0].members, vec![head]);
    let yuki = EntityId::now();
    seed_named_person(&vault, &yuki, "yuki", vault.now_recorded_at())?;
    let other = land_head(&vault, yuki, "oolong tea")?;
    let other_pin = json!({"claim": other.to_hex(), "version": served_version(&vault, other)?});
    for (what, heads) in [("no head", vec![]), ("another claim", vec![other_pin])] {
        let spec = conflict_spec("open", vec![black.clone()], heads);
        let request = json!({"items": [spec], "sources": []});
        let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
        assert_eq!(answer["items"][0]["landed"], false, "{what}");
        assert_eq!(answer["items"][0]["rows"], json!([]));
        assert_eq!(
            answer["items"][0]["reasons"],
            json!([HEADS_DIFFER]),
            "{what}"
        );
    }
    Ok(())
}

/// Two candidates with equal values are not one conflict: refused, nothing lands.
#[test]
fn operands_that_are_not_one_conflict_open_nothing() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let words = ["owen chooses green tea", "owen chooses green tea again"];
    let (vault, attempt_id, turns, subject) = extraction_attempt_with_turns(&dir, "owen", &words)?;
    let green = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let again = operand_for(&subject.to_hex(), json!("green tea"), &turns[1]);
    let spec = conflict_spec(
        "open",
        vec![member(green, 0.0, vec![]), member(again, 0.0, vec![])],
        vec![],
    );
    let request = json!({"items": [spec], "sources": []});
    let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
    assert_eq!(answer["items"][0]["landed"], false);
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([OPERANDS_REFUSED]));
    assert!(open_for(&vault, subject)?.is_empty());
    Ok(())
}

/// A second opening of the same set is refused as a duplicate; one marker stands.
#[test]
fn a_second_opening_of_the_same_set_is_refused() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = sibling_attempt(&dir)?;
    let attempt = Some(attempt_id);
    let spec = conflict_spec("open", sibling_pair(&subject, &turns), vec![]);
    let first = commit_dreamer(
        &vault,
        attempt,
        json!({"items": [spec.clone()], "sources": []}),
    )?;
    assert_eq!(first["items"][0]["landed"], true);
    let second = commit_dreamer(&vault, attempt, json!({"items": [spec], "sources": []}))?;
    assert_eq!(second["items"][0]["landed"], false);
    assert_eq!(second["items"][0]["reasons"], json!([DUPLICATE]));
    let open = open_for(&vault, subject)?;
    assert_eq!(open.len(), 1);
    let row = first["items"][0]["rows"][0].as_str().ok_or("the row")?;
    assert_eq!(open[0].marker.to_hex(), row);
    Ok(())
}

/// A member keeps its confidence and hints under the same marker id law.
#[test]
fn a_member_keeps_its_confidence_and_hints() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = sibling_attempt(&dir)?;
    let green = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let black = operand_for(&subject.to_hex(), json!("black coffee"), &turns[1]);
    let sure = member(green.clone(), 0.7, vec![json!("  green tea  ")]);
    let unsure = member(black.clone(), 0.0, vec![]);
    let spec = conflict_spec("open", vec![sure, unsure], vec![]);
    let request = json!({"items": [spec], "sources": []});
    let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
    assert_eq!(answer["items"][0]["landed"], true);
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    let operands = vec![green, black];
    let built = built_for(&vault, batch, attempt_id, &operands)?;
    assert_eq!(built["marker"], answer["items"][0]["rows"][0]);
    let open = open_for(&vault, subject)?;
    assert_eq!(open[0].alternatives.len(), 2);
    let first = &open[0].alternatives[0];
    assert_eq!(
        first.id.to_hex(),
        built["members"][0].as_str().ok_or("the member")?
    );
    assert_eq!(first.confidence, 0.7);
    let RmpValue::Array(alternatives) = map_at(&open[0].body.value, "alternatives").ok_or("a")?
    else {
        return Err("the alternatives ride as an array".into());
    };
    let stored = alternatives.first().ok_or("the first alternative")?;
    let RmpValue::Array(hints) = map_at(stored, "hints").ok_or("h")? else {
        return Err("the hints ride as an array".into());
    };
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].as_str(), Some("green tea"));
    Ok(())
}

/// A Conflict item with a Settle item of the same batch: both land answered.
#[test]
fn a_settle_item_of_the_same_batch_answers_the_new_marker() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = sibling_attempt(&dir)?;
    let pair = sibling_pair(&subject, &turns);
    let open_spec = conflict_spec("open", pair, vec![]);
    let close = settle_spec("close", json!({"local": "open"}), "hold_both");
    let request = json!({"items": [open_spec, close], "sources": []});
    let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
    assert_eq!(answer["items"][0]["landed"], true);
    assert_eq!(answer["items"][1]["landed"], true);
    assert!(open_for(&vault, subject)?.is_empty());
    Ok(())
}

/// The opener's revert takes the marker back, unless a standing answer names it.
#[test]
fn the_opener_s_revert_takes_the_marker_back_unless_an_answer_stands() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = sibling_attempt(&dir)?;
    let spec = conflict_spec("open", sibling_pair(&subject, &turns), vec![]);
    let request = json!({"items": [spec], "sources": []});
    let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    let reverted = revert_as_owner(&vault, batch)?;
    assert_eq!(reverted["reverted"], json!(["open"]));
    assert_eq!(reverted["left"], json!([]));
    assert!(open_for(&vault, subject)?.is_empty());

    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = sibling_attempt(&dir)?;
    let spec = conflict_spec("open", sibling_pair(&subject, &turns), vec![]);
    let request = json!({"items": [spec], "sources": []});
    let first = commit_dreamer(&vault, Some(attempt_id), request)?;
    let marker = first["items"][0]["rows"][0]
        .as_str()
        .ok_or("the marker")?
        .to_owned();
    let close = settle_spec("close", json!({"stored": marker}), "hold_both");
    let request = json!({"items": [close], "sources": []});
    let second = commit_dreamer(&vault, Some(attempt_id), request)?;
    assert_eq!(second["items"][0]["landed"], true);
    let batch = EntityId::from_hex(first["batch"].as_str().ok_or("the batch")?)?;
    let reverted = revert_as_owner(&vault, batch)?;
    assert_eq!(reverted["reverted"], json!([]));
    assert_eq!(reverted["left"][0]["local"], "open");
    assert_eq!(reverted["left"][0]["reason"], INVERSE_REFUSED);
    assert!(open_for(&vault, subject)?.is_empty());
    Ok(())
}

/// A member citing an unserved TURN, or a stale TURN version, is refused alone.
#[test]
fn a_member_cites_only_what_the_attempt_serves() -> TestResult<()> {
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
    let spec = conflict_spec("open", vec![member(away, 0.0, vec![])], vec![]);
    let request = json!({"items": [spec], "sources": []});
    let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
    assert_eq!(answer["items"][0]["landed"], false);
    assert_eq!(answer["items"][0]["reasons"], json!([OPERANDS_REFUSED]));
    let moved = "owen now wants oolong";
    append_extraction_turn_words(&vault, first.conversation, first.turns[0], moved)?;
    let stale = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let spec = conflict_spec("open", vec![member(stale, 0.0, vec![])], vec![]);
    let request = json!({"items": [spec], "sources": []});
    let answer = commit_dreamer(&vault, Some(attempt_id), request)?;
    assert_eq!(answer["items"][0]["landed"], false);
    assert_eq!(answer["items"][0]["reasons"], json!([OPERANDS_REFUSED]));
    assert!(open_for(&vault, subject)?.is_empty());
    Ok(())
}

/// An agent that is not the attempt's reader opens nothing: the stager's own
/// read check refuses past the attempt rule.
#[test]
fn an_actor_that_is_not_the_attempt_s_reader_opens_nothing() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = sibling_attempt(&dir)?;
    let agent = define_agent(&vault, "yuki")?;
    grant_derive_rows(&vault, &[agent])?;
    let spec = conflict_spec("open", sibling_pair(&subject, &turns), vec![]);
    let request = json!({"items": [spec], "sources": []});
    let answer = derive_conflict::commit(
        &vault,
        agent,
        EdgeActorClass::Agent,
        "run-conflict-p9",
        Some(attempt_id),
        request,
    )?;
    assert_eq!(answer["items"][0]["landed"], false);
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([OPERANDS_REFUSED]));
    assert!(open_for(&vault, subject)?.is_empty());
    Ok(())
}
