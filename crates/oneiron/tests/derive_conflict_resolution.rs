//! The ConflictResolution derive item (untangle 6.9e e2g.3): the Conflict
//! item's set shape with the job's decision for that set. The engine rebuilds
//! the set exactly as the Conflict item does and then does what native's
//! conflict loop does for that decision, inside the batch's write transaction.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test derive_conflict_resolution`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "extraction_verdict/support.rs"]
mod support;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_consolidation::OpenConflict;
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{batches_of, claim_lifecycle, refusal_receipt, source_version};
use oneiron::test_doors::derive_conflict;
use oneiron::test_doors::derive_conflict_resolution::{build_native_merge, build_native_skip};
use oneiron::test_doors::derive_verbs::{define_agent, grant_derive_rows, revert_as_owner};
use oneiron::test_doors::extraction_routing::native_routes;
use oneiron::test_doors::extraction_single_valued::seed_extraction_single_valued_predicates;
use oneiron::test_doors::steward::dreamer;
use oneiron::{AttemptId, EdgeActorClass, EntityId, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use std::sync::Arc;
use support::{extraction_attempt_hex, extraction_attempt_with_turns, extraction_candidate};

/// A fixture or assertion error, without hiding its source.
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The refusal of a resolution item outside a queued extraction attempt, as
/// the stager spells it. Written as a literal: the tests name no new
/// constant.
const NEEDS_EXTRACTION_ATTEMPT: &str =
    "gate.deny.derive.conflict_resolution_needs_extraction_attempt";
/// The refusal of a resolution item whose actor is not the attempt's
/// Dreamer.
const NOT_ATTEMPT_DREAMER: &str = "gate.deny.derive.conflict_resolution_not_attempt_dreamer";
/// The refusal of operands that are not one servable native conflict.
const OPERANDS_REFUSED: &str = "gate.deny.derive.conflict_resolution_operands_refused";
/// The refusal of heads that differ from the rebuilt set's prior heads.
const HEADS_DIFFER: &str = "gate.deny.derive.conflict_resolution_heads_differ";
/// The refusal of a skip native's own no-verdict rule does not allow.
const SKIP_NOT_ALLOWED: &str = "gate.deny.derive.conflict_resolution_skip_not_allowed";
/// The refusal of a merge the engine cannot build.
const MERGE_REFUSED: &str = "gate.deny.derive.conflict_resolution_merge_refused";
/// The refusal of a resolution whose claim is already stored.
const DUPLICATE: &str = "gate.deny.derive.conflict_resolution_duplicate";

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

/// Lands one food preference about `subject` with `source` and returns its
/// id: the raw claim shape the routing parity fixture lands its head with.
fn land_sourced_head(
    vault: &Vault,
    subject: EntityId,
    value: &str,
    source: ClaimSource,
) -> TestResult<EntityId> {
    let head = EntityId::now();
    let mut body = ClaimBody::new(
        FOOD,
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(source);
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    let at = TimeRange {
        start: now,
        end: now,
    };
    vault.put_claim(&head, &body, at, now)?;
    Ok(head)
}

/// Lands one user-stated food preference about `subject` and returns its id.
/// A replacement of it waits for the owner.
fn land_head(vault: &Vault, subject: EntityId, value: &str) -> TestResult<EntityId> {
    land_sourced_head(vault, subject, value, ClaimSource::UserStated)
}

/// Lands one Generated food preference about `subject` and returns its id.
/// A replacement of it is granted with no owner.
fn land_generated_head(vault: &Vault, subject: EntityId, value: &str) -> TestResult<EntityId> {
    land_sourced_head(vault, subject, value, ClaimSource::Generated)
}

/// One extraction attempt over witnessed turns: the vault, the attempt, the
/// served turns with their versions, and the subject.
type AttemptSetup = (Arc<Vault>, AttemptId, Vec<(String, Value)>, EntityId);

/// The one-turn attempt: green tea.
fn single_attempt(dir: &tempfile::TempDir) -> TestResult<AttemptSetup> {
    let words = ["owen chooses green tea"];
    extraction_attempt_with_turns(dir, "owen", &words)
}

/// The two-turn sibling attempt: green tea against black coffee.
fn sibling_attempt(dir: &tempfile::TempDir) -> TestResult<AttemptSetup> {
    let words = ["owen chooses green tea", "owen chooses black coffee"];
    extraction_attempt_with_turns(dir, "owen", &words)
}

/// The one-turn black-coffee attempt over a stored green-tea head: the
/// attempt setup with the head. The head is Generated when `generated`, else
/// user-stated.
fn black_against_green(
    dir: &tempfile::TempDir,
    generated: bool,
) -> TestResult<(AttemptSetup, EntityId)> {
    let words = ["owen chooses black coffee"];
    let setup = extraction_attempt_with_turns(dir, "owen", &words)?;
    let head = if generated {
        land_generated_head(&setup.0, setup.3, "green tea")?
    } else {
        land_head(&setup.0, setup.3, "green tea")?
    };
    Ok((setup, head))
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

/// One skip resolution over `members` against `heads`.
fn skip_spec(local: &str, members: Vec<Value>, heads: Vec<Value>) -> Value {
    json!({"kind": "conflict_resolution", "spec": {"local": local, "members": members, "heads": heads, "outcome": "skip"}})
}

/// One merge resolution over `members` against `heads`, keeping `kept` with `value`.
fn merge_spec(
    local: &str,
    members: Vec<Value>,
    heads: Vec<Value>,
    kept: usize,
    value: Value,
) -> Value {
    json!({"kind": "conflict_resolution", "spec": {"local": local, "members": members, "heads": heads, "outcome": "merge", "kept": kept, "value": value}})
}

/// One accumulate resolution over `members` against `heads`.
fn accumulate_spec(local: &str, members: Vec<Value>, heads: Vec<Value>) -> Value {
    json!({"kind": "conflict_resolution", "spec": {"local": local, "members": members, "heads": heads, "outcome": "accumulate"}})
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

/// A well-formed resolution batch decodes and commits outside an attempt as
/// refused, while each malformed form (an unknown field, an unknown outcome,
/// a merge with no value, a skip with a value, a kept past the members) is
/// refused whole: the door errs and records no batch.
#[test]
fn a_conflict_resolution_item_decodes_and_a_malformed_one_aborts_its_batch() -> TestResult<()> {
    let fixture = agent_fixture("owen")?;
    // The agent with derive rows commits, as the Conflict and Candidate wire
    // tests do: outside an attempt the item is refused before any actor rule.
    let resolver = fixture.agent;
    let version = turn_version(&fixture)?;
    let one = member(
        candidate(&fixture.person.to_hex(), &fixture.turn.to_hex(), version),
        0.9,
        vec![],
    );
    let request = json!({"items": [skip_spec("first", vec![one], vec![])], "sources": []});
    let answer = derive_conflict::commit(
        &fixture.vault,
        resolver,
        EdgeActorClass::Agent,
        "run-resolution-t1",
        None,
        request,
    )
    .expect("a well-formed resolution batch decodes and commits");
    let item = &answer["items"][0];
    assert_eq!(item["local"], "first");
    assert_eq!(item["kind"], "conflict_resolution");
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
        batches_of(&fixture.vault, resolver)?.len(),
        1,
        "the well-formed batch is recorded"
    );

    let version = turn_version(&fixture)?;
    let one = || {
        member(
            candidate(
                &fixture.person.to_hex(),
                &fixture.turn.to_hex(),
                version.clone(),
            ),
            0.9,
            vec![],
        )
    };
    let unknown = json!({
        "items": [{
            "kind": "conflict_resolution",
            "spec": {
                "local": "first",
                "members": [one()],
                "outcome": "skip",
                "bogus": 1,
            },
        }],
        "sources": [],
    });
    let blended = json!({
        "items": [{
            "kind": "conflict_resolution",
            "spec": {
                "local": "first",
                "members": [one()],
                "outcome": "blend",
            },
        }],
        "sources": [],
    });
    let valueless = json!({
        "items": [{
            "kind": "conflict_resolution",
            "spec": {
                "local": "first",
                "members": [one()],
                "outcome": "merge",
                "kept": 0,
            },
        }],
        "sources": [],
    });
    let valued_skip = json!({
        "items": [{
            "kind": "conflict_resolution",
            "spec": {
                "local": "first",
                "members": [one()],
                "outcome": "skip",
                "value": "an oat milk flat white",
            },
        }],
        "sources": [],
    });
    let kept_past = json!({
        "items": [{
            "kind": "conflict_resolution",
            "spec": {
                "local": "first",
                "members": [one()],
                "outcome": "merge",
                "kept": 5,
                "value": "an oat milk flat white",
            },
        }],
        "sources": [],
    });
    for (what, request) in [
        ("a resolution batch with an unknown field", unknown),
        ("a resolution batch with an unknown outcome", blended),
        ("a merge with no value", valueless),
        ("a skip with a value", valued_skip),
        ("a kept past the members", kept_past),
    ] {
        let refusal = derive_conflict::commit(
            &fixture.vault,
            resolver,
            EdgeActorClass::Agent,
            "run-resolution-t1",
            None,
            request,
        )
        .err()
        .ok_or_else(|| format!("{what} is not refused whole"))?;
        assert_eq!(refusal.code, MEMORY_CODE_BAD_REQUEST, "{refusal:?}");
        assert_eq!(
            batches_of(&fixture.vault, resolver)?.len(),
            1,
            "{what} records no batch"
        );
    }
    Ok(())
}

/// A merge replaces a Generated head as native builds it, with derive provenance.
#[test]
fn a_merge_replaces_a_generated_head_as_native_builds_it() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, true)?;
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let hex = extraction_attempt_hex(attempt_id);
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let routes = native_routes(&vault, &hex, now_ms, std::slice::from_ref(&operand))?;
    assert_eq!(
        routes["judge_sets"].as_array().ok_or("judge")?.len(),
        1,
        "{routes}"
    );
    let merged = json!("oolong tea");
    let door = build_native_merge(
        &vault,
        &hex,
        now_ms,
        std::slice::from_ref(&operand),
        0,
        &merged,
    )?;
    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = merge_spec("resolve", vec![black], vec![pin], 0, merged);
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["approval"], json!("auto"), "{answer}");
    assert_eq!(
        item["rows"].as_array().ok_or("the rows")?.len(),
        1,
        "{answer}"
    );
    assert_eq!(door["claim"], item["rows"][0]);
    assert_eq!(door["supersedes"], json!(head.to_hex()));
    let claim = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    assert!(
        vault
            .edges_out(&claim)?
            .iter()
            .any(|edge| { edge.kind == oneiron::EdgeKind::Supersedes && edge.target == head }),
        "the stored replacement names native's replaced head"
    );
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
    assert_eq!(stored.confidence, 0.5);
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
    // No approval compare: the door prepares but never grants, while the
    // stager grants the replacement Auto in the same transaction.
    let provenance = map_at(stored_evidence, "provenance").ok_or("p")?;
    let at = |key: &str| map_at(provenance, key).and_then(RmpValue::as_str);
    assert_eq!(at("surface"), Some("vault.derive"));
    assert_eq!(at("batch"), answer["batch"].as_str());
    assert_eq!(at("item"), Some("resolve"));
    assert_eq!(at("run"), Some("run"));
    assert!(map_at(provenance, "job_id").is_none());
    assert!(map_at(provenance, "decisions").is_none());
    assert_eq!(
        claim_lifecycle(&vault, head)?,
        Some("superseded".to_owned()),
        "the head is superseded"
    );
    Ok(())
}

/// A merge over a UserStated head lands Proposed and waits for the owner:
/// the head still stands and the staged supersession names it.
#[test]
fn a_merge_over_a_user_stated_head_is_held_for_the_owner() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, false)?;
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = merge_spec("resolve", vec![black], vec![pin], 0, json!("oolong tea"));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["approval"], json!("proposed"), "{answer}");
    assert_eq!(
        item["rows"].as_array().ok_or("the rows")?.len(),
        1,
        "{answer}"
    );
    let replacement = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    assert_eq!(
        claim_lifecycle(&vault, head)?,
        Some("active".to_owned()),
        "the head still stands"
    );
    let stored = vault.get_claim(&head)?.ok_or("the head still stands")?;
    assert_eq!(stored.value, RmpValue::from("green tea"));
    assert_eq!(vault.pending_claim_supersession(&replacement)?, Some(head));
    Ok(())
}

/// A skip replaces the head by the single-value rule, keeping the member's
/// confidence and matching native's skip build.
#[test]
fn a_skip_replaces_the_head_by_the_single_value_rule() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, true)?;
    seed_extraction_single_valued_predicates(&vault, &[FOOD])?;
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let hex = extraction_attempt_hex(attempt_id);
    // The build-only door first, at the commit's own clock unit: the vault's
    // recorded seconds as milliseconds. No compared field carries time, so
    // the door's clock need not equal the commit's second.
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let door = build_native_skip(&vault, &hex, now_ms, std::slice::from_ref(&operand), 0.7)?;
    let black = member(operand, 0.7, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = skip_spec("resolve", vec![black], vec![pin]);
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["approval"], json!("auto"), "{answer}");
    assert_eq!(
        item["rows"].as_array().ok_or("the rows")?.len(),
        1,
        "{answer}"
    );
    assert_eq!(door["claim"], item["rows"][0]);
    assert_eq!(door["supersedes"], json!(head.to_hex()));
    let claim = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    assert!(
        vault
            .edges_out(&claim)?
            .iter()
            .any(|edge| { edge.kind == oneiron::EdgeKind::Supersedes && edge.target == head }),
        "the stored replacement names native's replaced head"
    );
    let stored = vault.get_claim(&claim)?.ok_or("the stored claim")?;
    assert_eq!(
        stored.confidence, 0.7,
        "the claim keeps the member's confidence"
    );
    assert_eq!(
        door["confidence"].as_f64().ok_or("c")?,
        f64::from(stored.confidence),
        "native builds the same confidence"
    );
    // Every other field matches native's build. Approval is excluded: the
    // door prepares but never grants.
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
    let provenance = map_at(stored_evidence, "provenance").ok_or("p")?;
    let at = |key: &str| map_at(provenance, key).and_then(RmpValue::as_str);
    assert_eq!(at("surface"), Some("vault.derive"));
    assert_eq!(at("batch"), answer["batch"].as_str());
    assert_eq!(at("item"), Some("resolve"));
    assert_eq!(at("run"), Some("run"));
    assert!(map_at(provenance, "job_id").is_none());
    assert!(map_at(provenance, "decisions").is_none());
    assert_eq!(
        claim_lifecycle(&vault, head)?,
        Some("superseded".to_owned()),
        "the head is superseded"
    );
    Ok(())
}

/// A skip native would judge is refused: without the single-valued seed over
/// a Generated head, and with the seed over a UserStated head. Nothing lands.
#[test]
fn a_skip_native_would_judge_is_refused() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, true)?;
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = skip_spec("resolve", vec![black], vec![pin]);
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], false, "no seed: {answer}");
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([SKIP_NOT_ALLOWED]));
    assert_eq!(
        claim_lifecycle(&vault, head)?,
        Some("active".to_owned()),
        "the head still stands"
    );

    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, false)?;
    seed_extraction_single_valued_predicates(&vault, &[FOOD])?;
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = skip_spec("resolve", vec![black], vec![pin]);
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], false, "stated head: {answer}");
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([SKIP_NOT_ALLOWED]));
    assert_eq!(
        claim_lifecycle(&vault, head)?,
        Some("active".to_owned()),
        "the head still stands"
    );
    Ok(())
}

/// A bound correction skips the verdict: a candidate correcting its listed
/// head replaces it with no seed and no judge.
#[test]
fn a_bound_correction_skips_the_verdict() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, true)?;
    assert_eq!(turns.len(), 1);
    let mut operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    operand["corrects"] = json!(head.to_hex());
    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = skip_spec("resolve", vec![black], vec![pin]);
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["approval"], json!("auto"), "{answer}");
    assert_eq!(
        claim_lifecycle(&vault, head)?,
        Some("superseded".to_owned()),
        "the corrected head is superseded"
    );
    Ok(())
}

/// Two sibling candidates accumulate as two rows in set order, both Auto.
#[test]
fn an_accumulate_lands_every_member() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = sibling_attempt(&dir)?;
    assert_eq!(turns.len(), 2);
    let spec = accumulate_spec("resolve", sibling_pair(&subject, &turns), vec![]);
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["approval"], json!("auto"), "{answer}");
    let rows = item["rows"].as_array().ok_or("the rows")?;
    assert_eq!(rows.len(), 2, "{answer}");
    let first = EntityId::from_hex(rows[0].as_str().ok_or("the first row")?)?;
    let second = EntityId::from_hex(rows[1].as_str().ok_or("the second row")?)?;
    let first_body = vault.get_claim(&first)?.ok_or("the first claim")?;
    let second_body = vault.get_claim(&second)?.ok_or("the second claim")?;
    assert_eq!(first_body.value, RmpValue::from("green tea"), "set order");
    assert_eq!(
        second_body.value,
        RmpValue::from("black coffee"),
        "set order"
    );
    assert_eq!(first_body.approval, ClaimApprovalStatus::Auto);
    assert_eq!(second_body.approval, ClaimApprovalStatus::Auto);
    Ok(())
}

/// A merge of two sibling candidates with no head lands one claim, as native
/// builds it from the kept member and the whole set, and replaces nothing.
#[test]
fn a_merge_of_two_siblings_lands_one_claim_as_native_builds_it() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = sibling_attempt(&dir)?;
    assert_eq!(turns.len(), 2);
    let pair = sibling_pair(&subject, &turns);
    let operands: Vec<Value> = pair
        .iter()
        .map(|member| member["candidate"].clone())
        .collect();
    let hex = extraction_attempt_hex(attempt_id);
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let merged = json!("oolong tea");
    let door = build_native_merge(&vault, &hex, now_ms, &operands, 1, &merged)?;
    assert_eq!(door["supersedes"], json!(null), "{door}");
    let spec = merge_spec("resolve", pair, vec![], 1, merged);
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["approval"], json!("auto"), "{answer}");
    assert_eq!(
        item["rows"].as_array().ok_or("the rows")?.len(),
        1,
        "{answer}"
    );
    assert_eq!(door["claim"], item["rows"][0]);
    let claim = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let stored = vault.get_claim(&claim)?.ok_or("the stored claim")?;
    assert_eq!(stored.value, RmpValue::from("oolong tea"));
    assert_eq!(stored.predicate, FOOD);
    assert_eq!(stored.confidence, 0.5);
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert!(
        !vault
            .edges_out(&claim)?
            .iter()
            .any(|edge| edge.kind == oneiron::EdgeKind::Supersedes),
        "a merge with no head replaces nothing"
    );
    let stored_evidence = stored.evidence.as_ref().ok_or("the evidence")?;
    let candidate_evidence =
        map_at(stored_evidence, "candidate_evidence").ok_or("the candidate evidence")?;
    assert_eq!(
        door["candidate_evidence_hex"]
            .as_str()
            .ok_or("the door's evidence")?,
        hex_of(candidate_evidence)?,
        "the merged claim cites both members' evidence as native's does"
    );
    Ok(())
}

/// A resolution that does not fit its set is refused: heads that leave out
/// the rebuilt set's head differ, a head pin at a version the head no longer
/// has refuses the operands, and a kept member outside the selected set
/// refuses the merge. Nothing lands.
#[test]
fn a_resolution_that_does_not_fit_its_set_is_refused() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, true)?;
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand.clone(), 0.0, vec![]);
    let spec = merge_spec("resolve", vec![black], vec![], 0, json!("oolong tea"));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], false, "no head: {answer}");
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([HEADS_DIFFER]));
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    assert_eq!(
        refusal_receipt(&vault, batch, "resolve")?,
        Some(vec![HEADS_DIFFER.to_owned()])
    );

    let black = member(operand, 0.0, vec![]);
    let mut stale = served_version(&vault, head)?;
    stale["revision"] = json!(format!("blake3:{}", "0".repeat(64)));
    let pin = json!({"claim": head.to_hex(), "version": stale});
    let spec = merge_spec("resolve", vec![black], vec![pin], 0, json!("oolong tea"));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], false, "stale pin: {answer}");
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([OPERANDS_REFUSED]));
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    assert_eq!(
        refusal_receipt(&vault, batch, "resolve")?,
        Some(vec![OPERANDS_REFUSED.to_owned()])
    );
    assert_eq!(
        claim_lifecycle(&vault, head)?,
        Some("active".to_owned()),
        "the head still stands"
    );

    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = sibling_attempt(&dir)?;
    let head = land_generated_head(&vault, subject, "green tea")?;
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = merge_spec(
        "resolve",
        sibling_pair(&subject, &turns),
        vec![pin],
        0,
        json!("oolong tea"),
    );
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(
        answer["items"][0]["landed"], false,
        "kept outside the set: {answer}"
    );
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([MERGE_REFUSED]));
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    assert_eq!(
        refusal_receipt(&vault, batch, "resolve")?,
        Some(vec![MERGE_REFUSED.to_owned()])
    );
    Ok(())
}

/// Only the attempt's Dreamer resolves a conflict: an agent is refused.
#[test]
fn only_the_attempt_s_dreamer_resolves_a_conflict() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, attempt_id, turns, subject) = single_attempt(&dir)?;
    let agent = define_agent(&vault, "yuki")?;
    grant_derive_rows(&vault, &[agent])?;
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let spec = accumulate_spec("resolve", vec![member(operand, 0.0, vec![])], vec![]);
    let request = json!({"items": [spec], "sources": []});
    let answer = derive_conflict::commit(
        &vault,
        agent,
        EdgeActorClass::Agent,
        "run-resolution-p9",
        Some(attempt_id),
        request,
    )?;
    assert_eq!(answer["items"][0]["landed"], false);
    assert_eq!(answer["items"][0]["rows"], json!([]));
    assert_eq!(answer["items"][0]["reasons"], json!([NOT_ATTEMPT_DREAMER]));
    Ok(())
}

/// A second resolution of the same set is refused, by the first check that
/// meets what the first one wrote. While the replacement waits for the owner
/// its head is unchanged, the set rebuilds the same and the stored claim is
/// a duplicate. Once the replacement is granted, the pinned head has moved
/// and the operands are refused. One row stands either way.
#[test]
fn a_second_resolution_of_the_same_set_is_refused() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, false)?;
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = merge_spec("resolve", vec![black], vec![pin], 0, json!("oolong tea"));
    let attempt = Some(attempt_id);
    let first = commit_dreamer(
        &vault,
        attempt,
        json!({"items": [spec.clone()], "sources": []}),
    )?;
    assert_eq!(first["items"][0]["landed"], true, "{first}");
    assert_eq!(first["items"][0]["approval"], json!("proposed"), "{first}");
    let second = commit_dreamer(&vault, attempt, json!({"items": [spec], "sources": []}))?;
    assert_eq!(second["items"][0]["landed"], false, "held: {second}");
    assert_eq!(second["items"][0]["rows"], json!([]));
    assert_eq!(second["items"][0]["reasons"], json!([DUPLICATE]));
    let row = first["items"][0]["rows"][0].as_str().ok_or("the row")?;
    let claim = EntityId::from_hex(row)?;
    assert!(vault.get_claim(&claim)?.is_some());
    assert_eq!(vault.pending_claim_supersession(&claim)?, Some(head));

    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, true)?;
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = merge_spec("resolve", vec![black], vec![pin], 0, json!("oolong tea"));
    let attempt = Some(attempt_id);
    let first = commit_dreamer(
        &vault,
        attempt,
        json!({"items": [spec.clone()], "sources": []}),
    )?;
    assert_eq!(first["items"][0]["landed"], true, "{first}");
    assert_eq!(first["items"][0]["approval"], json!("auto"), "{first}");
    let second = commit_dreamer(&vault, attempt, json!({"items": [spec], "sources": []}))?;
    assert_eq!(second["items"][0]["landed"], false, "granted: {second}");
    assert_eq!(second["items"][0]["rows"], json!([]));
    assert_eq!(second["items"][0]["reasons"], json!([OPERANDS_REFUSED]));
    let row = first["items"][0]["rows"][0].as_str().ok_or("the row")?;
    let claim = EntityId::from_hex(row)?;
    assert_eq!(
        claim_lifecycle(&vault, claim)?,
        Some("active".to_owned()),
        "the first replacement stands"
    );
    Ok(())
}

/// The committer's revert takes a resolution back: a granted replacement no
/// longer stands and its head stands again, and a held replacement no longer
/// stands with no staged supersession left.
///
/// The granted half replaces an observed head: the revert's restore reopens
/// an observed raw claim, and not a generated one (FIX row
/// DERIVE-REVERT-GENERATED-CLAIM), as the derive revert tests land theirs.
#[test]
fn the_committer_s_revert_takes_a_resolution_back() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let words = ["owen chooses black coffee"];
    let (vault, attempt_id, turns, subject) = extraction_attempt_with_turns(&dir, "owen", &words)?;
    let head = land_sourced_head(&vault, subject, "green tea", ClaimSource::Observed)?;
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = merge_spec("resolve", vec![black], vec![pin], 0, json!("oolong tea"));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    assert_eq!(answer["items"][0]["approval"], json!("auto"), "{answer}");
    assert_eq!(
        claim_lifecycle(&vault, head)?,
        Some("superseded".to_owned()),
        "the granted replacement closed the head"
    );
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    let replacement = EntityId::from_hex(answer["items"][0]["rows"][0].as_str().ok_or("the row")?)?;
    let reverted = revert_as_owner(&vault, batch)?;
    assert_eq!(reverted["reverted"], json!(["resolve"]));
    assert_eq!(reverted["left"], json!([]));
    assert_ne!(
        claim_lifecycle(&vault, replacement)?,
        Some("active".to_owned()),
        "the replacement no longer stands"
    );
    assert_eq!(
        claim_lifecycle(&vault, head)?,
        Some("active".to_owned()),
        "the head stands again"
    );
    let stored = vault.get_claim(&head)?.ok_or("the head stands again")?;
    assert_eq!(stored.value, RmpValue::from("green tea"));

    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, false)?;
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = merge_spec("resolve", vec![black], vec![pin], 0, json!("oolong tea"));
    let answer = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [spec], "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    let replacement = EntityId::from_hex(answer["items"][0]["rows"][0].as_str().ok_or("the row")?)?;
    assert_eq!(vault.pending_claim_supersession(&replacement)?, Some(head));
    let reverted = revert_as_owner(&vault, batch)?;
    assert_eq!(reverted["reverted"], json!(["resolve"]));
    assert_eq!(reverted["left"], json!([]));
    assert_ne!(
        claim_lifecycle(&vault, replacement)?,
        Some("active".to_owned()),
        "the replacement no longer stands"
    );
    assert_eq!(vault.pending_claim_supersession(&replacement)?, None);
    Ok(())
}

/// A granted replacement closes the open conflict that named its head: the
/// marker a Conflict item opened in a first batch is answered by the merge
/// of a second.
#[test]
fn a_granted_replacement_closes_the_open_conflict_that_named_its_head() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let ((vault, attempt_id, turns, subject), head) = black_against_green(&dir, true)?;
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand.clone(), 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let open = conflict_spec("open", vec![black], vec![pin]);
    let first = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [open], "sources": []}),
    )?;
    assert_eq!(first["items"][0]["landed"], true, "{first}");
    let marker = EntityId::from_hex(first["items"][0]["rows"][0].as_str().ok_or("the marker")?)?;
    let open = open_for(&vault, subject)?;
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].marker, marker);

    let black = member(operand, 0.0, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let resolve = merge_spec("resolve", vec![black], vec![pin], 0, json!("oolong tea"));
    let second = commit_dreamer(
        &vault,
        Some(attempt_id),
        json!({"items": [resolve], "sources": []}),
    )?;
    assert_eq!(second["items"][0]["landed"], true, "{second}");
    assert_eq!(second["items"][0]["approval"], json!("auto"), "{second}");
    let replacement = EntityId::from_hex(second["items"][0]["rows"][0].as_str().ok_or("the row")?)?;
    assert!(
        open_for(&vault, subject)?.is_empty(),
        "the marker is closed"
    );

    let mut answered = false;
    for id in vault.claims_for_subject(&subject)? {
        let Some(body) = vault.get_claim(&id)? else {
            continue;
        };
        if body.predicate != "core.conflict.resolved"
            || body.lifecycle != ClaimLifecycleStatus::Active
            || !matches!(
                body.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
        {
            continue;
        }
        let Some(named) = map_at(&body.value, "open_marker").and_then(|value| match value {
            RmpValue::Binary(bytes) => <[u8; 16]>::try_from(bytes.as_slice())
                .ok()
                .and_then(|raw| EntityId::from_bytes(raw).ok()),
            _ => None,
        }) else {
            continue;
        };
        if named != marker {
            continue;
        }
        let Some(resolution) = map_at(&body.value, "resolution") else {
            continue;
        };
        let Some(superseded) = map_at(resolution, "superseded_by").and_then(|value| match value {
            RmpValue::Binary(bytes) => <[u8; 16]>::try_from(bytes.as_slice())
                .ok()
                .and_then(|raw| EntityId::from_bytes(raw).ok()),
            _ => None,
        }) else {
            continue;
        };
        if superseded == replacement {
            answered = true;
        }
    }
    assert!(
        answered,
        "a standing conflict.resolved names the marker and the replacement"
    );
    Ok(())
}
