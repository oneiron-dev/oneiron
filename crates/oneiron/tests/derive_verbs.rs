//! The derivation verbs (untangle 6.7d): `vault.derive.commit` lands a batch
//! as the caller's attached live run, and `vault.derive.revert` takes one
//! back for two callers: the agent that committed it, through its own run,
//! and the vault's owner, for any batch. A third agent is refused. The wire
//! carries no actor: the engine stamps the run's.
//!
//! The verbs' typed host entries run on a leased run, as the served door
//! runs them; by name, off a host, both verbs answer that they need one.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_verbs`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_LEASE_REQUIRED};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{batches_of, claim_lifecycle, source_version};
use oneiron::test_doors::derive_verbs::{
    LiveRun, define_agent, grant_derive_rows, lease_run, revert_as_owner,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

const READER: &str = "reader";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    agent: EntityId,
    run: LiveRun,
    other_run: LiveRun,
    person: EntityId,
    turn: EntityId,
}

/// A vault with two agents the owner's policy lets derive, each on a leased
/// run of its own, a person and a TURN.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let agent = define_agent(&vault, "oneiron.agent.derive-verbs").expect("an agent");
    let other = define_agent(&vault, "oneiron.agent.derive-verbs-other").expect("another agent");
    grant_derive_rows(&vault, &[agent, other]).expect("the agents' policy rows");
    let run = lease_run(&vault, agent).expect("the agent's live run");
    let other_run = lease_run(&vault, other).expect("the other agent's live run");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let turn = put(&vault, ENTITY_TYPE_TURN, &body);
    Fixture {
        _dir: dir,
        vault,
        agent,
        run,
        other_run,
        person,
        turn,
    }
}

/// The wire `spec` of one claim about the fixture's person, citing its TURN
/// at the version the agent's own read serves.
fn one_claim(fixture: &Fixture) -> Value {
    let version = source_version(
        &fixture.vault,
        fixture.agent,
        EdgeActorClass::Agent,
        fixture.turn,
    )
    .expect("read")
    .expect("the agent reads the TURN");
    json!({
        "items": [{
            "kind": "claim",
            "spec": {
                "local": "drink",
                "predicate": "profile.drink",
                "subject": { "stored": fixture.person },
                "value": "an oat milk flat white",
                "confidence": 0.9,
                "evidence": [{ "stored": fixture.turn }],
            },
        }],
        "sources": [version],
    })
}

/// Commits [`one_claim`] on the agent's run: the batch and the claim.
fn committed(fixture: &Fixture) -> (EntityId, EntityId) {
    let answer = fixture
        .run
        .commit(&fixture.vault, one_claim(fixture))
        .expect("the batch commits");
    let item = &answer["items"][0];
    assert_eq!(item["local"], "drink");
    assert_eq!(item["kind"], "claim");
    assert_eq!(item["landed"], true, "the claim lands: {answer}");
    let id = |value: &Value| {
        EntityId::from_hex(value.as_str().expect("an id")).expect("a 32-character hex id")
    };
    let claim = id(&item["rows"][0]);
    assert_eq!(
        claim_lifecycle(&fixture.vault, claim).expect("read"),
        Some("active".to_owned())
    );
    (id(&answer["batch"]), claim)
}

fn active(fixture: &Fixture, claim: EntityId) -> bool {
    claim_lifecycle(&fixture.vault, claim).expect("read") == Some("active".to_owned())
}

#[test]
fn the_committing_agent_lands_a_batch_and_takes_it_back() {
    let fixture = fixture();
    let (batch, claim) = committed(&fixture);
    assert_eq!(
        batches_of(&fixture.vault, fixture.agent).expect("read"),
        vec![batch],
        "the batch is recorded under the run's actor"
    );

    let answer = fixture
        .run
        .revert(&fixture.vault, batch)
        .expect("the agent reverts its own batch");
    assert_eq!(answer["reverted"], json!(["drink"]), "{answer}");
    assert_eq!(answer["left"], json!([]), "{answer}");
    assert!(!active(&fixture, claim));
}

#[test]
fn the_owner_takes_back_any_batch() {
    let fixture = fixture();
    let (batch, claim) = committed(&fixture);
    let answer = revert_as_owner(&fixture.vault, batch).expect("the owner reverts the batch");
    assert_eq!(answer["reverted"], json!(["drink"]), "{answer}");
    assert_eq!(answer["left"], json!([]), "{answer}");
    assert!(!active(&fixture, claim));
}

#[test]
fn another_agents_run_may_not_take_the_batch_back() {
    let fixture = fixture();
    let (batch, claim) = committed(&fixture);
    let refusal = fixture
        .other_run
        .revert(&fixture.vault, batch)
        .expect_err("a third actor is refused");
    assert!(
        format!("{refusal:?}").contains("gate.deny.derive.revert_not_yours"),
        "{refusal:?}"
    );
    assert!(active(&fixture, claim), "the claim stands");
}

#[test]
fn the_wire_names_no_actor() {
    let fixture = fixture();
    let mut request = one_claim(&fixture);
    request["actor"] = json!(fixture.person);
    fixture
        .run
        .commit(&fixture.vault, request)
        .expect_err("a request that names an actor is refused");
    let mut request = one_claim(&fixture);
    request["items"][0]["spec"]["source"] = json!("user_stated");
    fixture
        .run
        .commit(&fixture.vault, request)
        .expect_err("an item that names a source class is refused");
    assert!(
        batches_of(&fixture.vault, fixture.agent)
            .expect("read")
            .is_empty(),
        "nothing is committed"
    );
}

#[test]
fn the_wire_carries_no_person_about_item() {
    let fixture = fixture();
    let request = json!({
        "items": [{
            "kind": "person_about",
            "spec": {
                "local": "about",
                "person": { "stored": fixture.person },
                "written_from": "00".repeat(32),
                "lines": [{ "band": 0, "text": "A person on the roster." }],
            },
        }],
        "sources": [],
    });
    let refusal = fixture
        .run
        .commit(&fixture.vault, request)
        .expect_err("a person's about lines are not a wire item");
    assert_eq!(refusal.code, MEMORY_CODE_BAD_REQUEST, "{refusal:?}");
    assert!(
        batches_of(&fixture.vault, fixture.agent)
            .expect("read")
            .is_empty(),
        "nothing is committed"
    );
}

#[test]
fn by_name_off_a_host_the_verbs_ask_for_an_attached_run() {
    let fixture = fixture();
    let memory = fixture.vault.memory(fixture.agent, EdgeActorClass::Agent);
    let commit = json!({ "live_run": "none", "spec": one_claim(&fixture) });
    let revert = json!({ "batch": EntityId::now() });
    for (verb, input) in [
        ("vault.derive.commit", commit),
        ("vault.derive.revert", revert),
    ] {
        let refusal = invoke(&memory, verb, input).expect_err(verb);
        assert_eq!(
            refusal.code, MEMORY_CODE_LEASE_REQUIRED,
            "{verb}: {refusal:?}"
        );
    }
}
