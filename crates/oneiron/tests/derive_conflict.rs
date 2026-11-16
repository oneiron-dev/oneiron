//! The Conflict derive item (untangle 6.9e e2h.3 PR-A): the batch's new
//! wire item opens the set a bound Resolution read of `ai.verdict` names.
//! PR-A builds the wire form, the batch arm, the shape checks and the
//! stager's first rule (a Conflict item stages only inside a queued
//! extraction attempt) and refuses every Conflict item, so none lands a row.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test derive_conflict`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "extraction_verdict/support.rs"]
mod support;

use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{batches_of, refusal_receipt, source_version};
use oneiron::test_doors::derive_conflict;
use oneiron::test_doors::derive_verbs::{define_agent, grant_derive_rows, lease_run};
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};
use std::sync::Arc;
use support::{
    QUEUE_NOW, bind_extraction, extraction_attempt_hex, extraction_candidate,
    open_extraction_verdict_vault, page_turns_with_versions, read_bound_extraction_page,
};

/// A fixture or assertion error, without hiding its source.
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The refusal of a Conflict item outside a queued extraction attempt, as the
/// stager spells it. Written as a literal: the tests name no new constant.
const NEEDS_EXTRACTION_ATTEMPT: &str = "gate.deny.derive.conflict_needs_extraction_attempt";

/// The refusal of an item naming a refused item of its batch, as the commit
/// spells it.
const DEPENDENCY_REFUSED: &str = "gate.deny.derive.dependency_refused";

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

/// Opens the extraction fixture vault with the Dreamer's Steward grant
/// standing and a selection that holds no candidate back.
fn open_vault(dir: &tempfile::TempDir) -> TestResult<Arc<Vault>> {
    let vault = Arc::new(open_extraction_verdict_vault(dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    Ok(vault)
}

/// In a queued extraction attempt a Conflict item reaches the stager: it is
/// refused, lands no row, and its reasons are not the
/// needs-extraction-attempt token. PR-B replaces this test with the landing.
#[test]
fn a_conflict_item_in_an_extraction_attempt_reaches_the_stager() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(&dir)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(
        &vault,
        &["owen chooses green tea", "owen chooses black coffee"],
    )?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt = extraction_attempt_hex(attempt_id);
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &attempt)?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2, "the page serves both witnessed turns");
    let members = json!([
        {
            "candidate": extraction_candidate(
                &subject.to_hex(),
                FOOD,
                json!("green tea"),
                &turns[0].0,
                turns[0].1.clone(),
            ),
            "confidence": 0.9,
        },
        {
            "candidate": extraction_candidate(
                &subject.to_hex(),
                FOOD,
                json!("black coffee"),
                &turns[1].0,
                turns[1].1.clone(),
            ),
            "confidence": 0.8,
        },
    ]);
    let request = json!({
        "items": [{
            "kind": "conflict",
            "spec": {"local": "open", "members": members},
        }],
        "sources": [],
    });
    let answer = derive_conflict::commit(
        &vault,
        dreamer(&vault)?,
        EdgeActorClass::System,
        "run-conflict-t4",
        Some(attempt_id),
        request,
    )
    .expect("a Conflict item in an extraction attempt reaches the stager");
    let item = &answer["items"][0];
    assert_eq!(item["local"], "open");
    assert_eq!(item["kind"], "conflict");
    assert_eq!(item["landed"], false, "PR-A stages no conflict: {answer}");
    assert_eq!(item["rows"], json!([]));
    assert!(
        item["receipt"].is_string(),
        "a refused item keeps its receipt: {answer}"
    );
    let reasons = item["reasons"]
        .as_array()
        .ok_or("a refused item names its reasons")?;
    assert_eq!(reasons.len(), 1, "{answer}");
    assert!(
        !reasons
            .iter()
            .any(|reason| reason.as_str() == Some(NEEDS_EXTRACTION_ATTEMPT)),
        "the stager saw the queued extraction branch: {answer}"
    );
    Ok(())
}
