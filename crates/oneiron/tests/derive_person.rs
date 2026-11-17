//! The person item of a derivation batch (untangle 6.9h, S69-C-KINDS = A):
//! an agent names a PERSON it found in a TURN it reads, through
//! `vault.derive.commit` on its live run, and the engine mints it as the
//! Dreamer's extraction does, under the agent's derive verdict. The engine
//! keeps the name rule (a bounded span of the TURN's words), the speaker
//! rule, the id (derived, never the caller's) and the mint door's refusal of
//! a taken id. A batch revert archives the PERSON while no other row's
//! claim names it, after taking back the batch's own claims about it.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_person`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    batches_of, claim_lifecycle, claim_subject, derive_item_receipts, row_live, source_version,
};
use oneiron::test_doors::derive_person::{cleanup_lists, person_body};
use oneiron::test_doors::derive_verbs::{LiveRun, define_agent, grant_derive_rows, lease_run};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

const READER: &str = "reader";

const NAME_UNREAD: &str = "gate.deny.derive.person_name_unread";
const SOURCE_INADMISSIBLE: &str = "gate.deny.derive.person_source_inadmissible";
const ID_TAKEN: &str = "gate.deny.derive.person_id_taken";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

/// A TURN holding its own `words`, spoken by `speaker`.
fn turn(vault: &Vault, speaker: &str, words: &str) -> EntityId {
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([
        ("speaker", speaker),
        ("text", words),
    ]))
    .expect("a TURN body");
    put(vault, ENTITY_TYPE_TURN, &body)
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    agent: EntityId,
    run: LiveRun,
}

/// A vault with one agent the owner's policy lets derive, on a leased run.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let agent = define_agent(&vault, "oneiron.agent.derive-person").expect("an agent");
    grant_derive_rows(&vault, &[agent]).expect("the agent's policy rows");
    let run = lease_run(&vault, agent).expect("the agent's live run");
    Fixture {
        _dir: dir,
        vault,
        agent,
        run,
    }
}

/// The wire item naming `name` in `turns`, as `local`.
fn person(local: &str, name: &str, turns: &[EntityId]) -> Value {
    let evidence: Vec<Value> = turns.iter().map(|turn| json!({ "stored": turn })).collect();
    json!({
        "kind": "person",
        "spec": { "local": local, "name": name, "evidence": evidence },
    })
}

/// The wire item of a claim about `subject` citing `turn`, as `local`.
fn claim(local: &str, subject: Value, turn: EntityId) -> Value {
    json!({
        "kind": "claim",
        "spec": {
            "local": local,
            "predicate": "profile.drink",
            "subject": subject,
            "value": "an oat milk flat white",
            "confidence": 0.9,
            "evidence": [{ "stored": turn }],
        },
    })
}

/// Commits `items` on `run`, citing each of `sources` at the version
/// `agent`'s own read serves; the wire answer.
fn commit_on(
    vault: &Vault,
    agent: EntityId,
    run: &LiveRun,
    items: Vec<Value>,
    sources: &[EntityId],
) -> Value {
    let versions: Vec<Value> = sources
        .iter()
        .map(|source| {
            let version = source_version(vault, agent, EdgeActorClass::Agent, *source)
                .expect("read")
                .expect("the agent reads the source");
            serde_json::to_value(version).expect("a version")
        })
        .collect();
    run.commit(vault, json!({ "items": items, "sources": versions }))
        .expect("the batch commits")
}

fn commit(fixture: &Fixture, items: Vec<Value>, sources: &[EntityId]) -> Value {
    commit_on(&fixture.vault, fixture.agent, &fixture.run, items, sources)
}

fn id(value: &Value) -> EntityId {
    EntityId::from_hex(value.as_str().expect("an id")).expect("a 32-character hex id")
}

/// The one item of `answer`: whether it landed, its first row, its reasons.
fn only_item(answer: &Value) -> (bool, Option<EntityId>, Vec<String>) {
    let items = answer["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{answer}");
    let item = &items[0];
    let reasons = item["reasons"]
        .as_array()
        .expect("reasons")
        .iter()
        .map(|reason| reason.as_str().expect("a token").to_owned())
        .collect();
    (
        item["landed"].as_bool().expect("landed"),
        item["rows"]
            .as_array()
            .and_then(|rows| rows.first())
            .map(id),
        reasons,
    )
}

#[test]
fn a_person_named_in_a_turn_lands_with_its_receipt() {
    let fixture = fixture();
    let said = turn(&fixture.vault, "user", "I had lunch with Ann today.");
    let answer = commit(&fixture, vec![person("ann", "Ann", &[said])], &[said]);
    let (landed, row, reasons) = only_item(&answer);
    assert!(landed, "the person lands: {answer}");
    assert!(reasons.is_empty(), "{answer}");
    assert_eq!(answer["items"][0]["kind"], "person", "{answer}");
    let person = row.expect("the PERSON it minted");
    assert!(row_live(&fixture.vault, person).expect("read"));
    assert_eq!(
        person_body(&fixture.vault, person)
            .expect("read")
            .and_then(|body| body.name),
        Some("Ann".to_owned()),
        "the PERSON holds the name as the TURN spells it"
    );
    assert!(
        cleanup_lists(&fixture.vault, person).expect("read"),
        "it is the extraction mint's row: empty, the cleanup lists it"
    );
    let receipts = derive_item_receipts(&fixture.vault, &person).expect("read");
    let [receipt] = receipts.as_slice() else {
        panic!("one receipt for the person: {receipts:?}");
    };
    assert_eq!(receipt.outcome, "approved");
    assert_eq!(receipt.reasons, vec!["gate.allow.derive.person".to_owned()]);
    assert!(
        receipt.grant_ref.is_some(),
        "the receipt names what judged it"
    );
    assert_eq!(
        batches_of(&fixture.vault, fixture.agent).expect("read"),
        vec![id(&answer["batch"])],
        "the batch is recorded under the run's actor"
    );
}

#[test]
fn a_later_claim_names_the_person_by_its_local_name() {
    let fixture = fixture();
    let said = turn(
        &fixture.vault,
        "user",
        "Coffee with Ann: an oat milk flat white, as every Tuesday.",
    );
    let answer = commit(
        &fixture,
        vec![
            person("ann", "Ann", &[said]),
            claim("lunch", json!({ "local": "ann" }), said),
        ],
        &[said],
    );
    let items = answer["items"].as_array().expect("items");
    assert_eq!(items[0]["landed"], true, "{answer}");
    assert_eq!(items[1]["landed"], true, "{answer}");
    let person = id(&items[0]["rows"][0]);
    let claim = id(&items[1]["rows"][0]);
    assert_eq!(
        claim_subject(&fixture.vault, claim).expect("read"),
        Some(person),
        "the claim is about the PERSON the batch minted"
    );
}

#[test]
fn the_revert_takes_back_the_claim_then_archives_the_person() {
    let fixture = fixture();
    let said = turn(
        &fixture.vault,
        "user",
        "Coffee with Ann: an oat milk flat white, as every Tuesday.",
    );
    let answer = commit(
        &fixture,
        vec![
            person("ann", "Ann", &[said]),
            claim("lunch", json!({ "local": "ann" }), said),
        ],
        &[said],
    );
    let person = id(&answer["items"][0]["rows"][0]);
    let claim = id(&answer["items"][1]["rows"][0]);
    let reverted = fixture
        .run
        .revert(&fixture.vault, id(&answer["batch"]))
        .expect("the agent reverts its own batch");
    assert_eq!(reverted["reverted"], json!(["lunch", "ann"]), "{reverted}");
    assert_eq!(reverted["left"], json!([]), "{reverted}");
    assert_ne!(
        claim_lifecycle(&fixture.vault, claim).expect("read"),
        Some("active".to_owned())
    );
    assert!(
        !row_live(&fixture.vault, person).expect("read"),
        "the PERSON no longer reads"
    );
    assert!(
        fixture
            .vault
            .archived_entity(&person)
            .expect("read")
            .is_some(),
        "it is archived, for the owner's restore, never unborn"
    );
}

#[test]
fn a_person_another_batch_claims_about_stays_born() {
    let fixture = fixture();
    let said = turn(
        &fixture.vault,
        "user",
        "Coffee with Ann: an oat milk flat white, as every Tuesday.",
    );
    let minted = commit(&fixture, vec![person("ann", "Ann", &[said])], &[said]);
    let person = id(&minted["items"][0]["rows"][0]);
    let claimed = commit(
        &fixture,
        vec![claim("lunch", json!({ "stored": person }), said)],
        &[said],
    );
    assert_eq!(claimed["items"][0]["landed"], true, "{claimed}");
    let reverted = fixture
        .run
        .revert(&fixture.vault, id(&minted["batch"]))
        .expect("the agent reverts its own batch");
    assert_eq!(reverted["reverted"], json!([]), "{reverted}");
    assert_eq!(
        reverted["left"],
        json!([{ "local": "ann", "reason": "derive.revert.inverse_refused" }]),
        "{reverted}"
    );
    assert!(row_live(&fixture.vault, person).expect("read"));
}

#[test]
fn a_name_the_words_do_not_bound_is_refused() {
    let fixture = fixture();
    let said = turn(&fixture.vault, "user", "I met Ann-Marie at the station.");
    for name in ["Ann", "Bob", "   ", "42"] {
        let answer = commit(&fixture, vec![person("p", name, &[said])], &[said]);
        let (landed, _, reasons) = only_item(&answer);
        assert!(!landed, "{name:?}: {answer}");
        assert_eq!(reasons, vec![NAME_UNREAD.to_owned()], "{name:?}: {answer}");
    }
    let answer = commit(
        &fixture,
        vec![person("p", "  ann-marie ", &[said])],
        &[said],
    );
    assert!(
        only_item(&answer).0,
        "the whole name, in any case: {answer}"
    );
}

#[test]
fn a_source_that_is_no_user_or_assistant_turn_is_refused() {
    let fixture = fixture();
    let system = turn(&fixture.vault, "system", "Ann joined the workspace.");
    let row = put(&fixture.vault, ENTITY_TYPE_PERSON, b"Ann");
    for source in [system, row] {
        let answer = commit(&fixture, vec![person("p", "Ann", &[source])], &[source]);
        let (landed, _, reasons) = only_item(&answer);
        assert!(!landed, "{answer}");
        assert_eq!(reasons, vec![SOURCE_INADMISSIBLE.to_owned()], "{answer}");
    }
}

#[test]
fn a_person_minted_again_in_the_same_lineage_is_refused_as_taken() {
    let fixture = fixture();
    let said = turn(&fixture.vault, "user", "I had lunch with Ann today.");
    let first = commit(&fixture, vec![person("ann", "Ann", &[said])], &[said]);
    assert!(only_item(&first).0, "{first}");
    let again = commit(&fixture, vec![person("ann", "ann", &[said])], &[said]);
    let (landed, _, reasons) = only_item(&again);
    assert!(!landed, "one id for one person in one lineage: {again}");
    assert_eq!(reasons, vec![ID_TAKEN.to_owned()], "{again}");
}

#[test]
fn the_wire_names_no_person_id_or_target() {
    let fixture = fixture();
    let said = turn(&fixture.vault, "user", "I had lunch with Ann today.");
    let hidden = put(&fixture.vault, ENTITY_TYPE_PERSON, b"Ann");
    for (field, value) in [
        ("id", json!(hidden)),
        ("dedupe_target", json!({ "stored": hidden })),
        ("source_audience", json!({ "private": false })),
    ] {
        let mut item = person("ann", "Ann", &[said]);
        item["spec"][field] = value;
        let refusal = fixture
            .run
            .commit(&fixture.vault, json!({ "items": [item], "sources": [] }))
            .expect_err(field);
        assert_eq!(
            refusal.code, MEMORY_CODE_BAD_REQUEST,
            "{field}: {refusal:?}"
        );
    }
    assert!(
        batches_of(&fixture.vault, fixture.agent)
            .expect("read")
            .is_empty(),
        "nothing is committed"
    );
}

#[test]
fn an_agent_with_no_derive_rows_is_refused() {
    let fixture = fixture();
    let other =
        define_agent(&fixture.vault, "oneiron.agent.derive-person-other").expect("another agent");
    let other_run = lease_run(&fixture.vault, other).expect("its live run");
    let said = turn(&fixture.vault, "user", "I had lunch with Ann today.");
    let answer = commit_on(
        &fixture.vault,
        other,
        &other_run,
        vec![person("ann", "Ann", &[said])],
        &[said],
    );
    let (landed, _, reasons) = only_item(&answer);
    assert!(!landed, "{answer}");
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.no_landing_rows".to_owned()],
        "{answer}"
    );
}
