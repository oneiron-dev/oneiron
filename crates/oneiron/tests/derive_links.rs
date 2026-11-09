//! Identity-link items of a derivation batch (untangle 6.7b, decision C-4):
//! a SameAs lands as its proposed coreference status claim, and its edge is
//! applied only under the owner's standing nightly-link grant; a topology
//! judgment needs the agent's own `topology_seal` Grant.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_links`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Distinct, Named, SameAs, claim_lifecycle, commit, commit_claims,
    mint_nightly_links, same_as_edge,
};
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

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
    dreamer: EntityId,
    person: EntityId,
    first: EntityId,
    second: EntityId,
}

/// A vault whose Dreamer landed two claims about one person, each citing a
/// TURN.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let turn = put(&vault, ENTITY_TYPE_TURN, &body);
    let claim = |local, value| Claim {
        local,
        predicate: "preference.coffee",
        subject: Named::Stored(person),
        value: json!(value),
        evidence: vec![Named::Stored(turn)],
    };
    let committed = commit_claims(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-claims",
        &[
            claim("first", "an oat milk flat white"),
            claim("second", "a flat white with oat milk"),
        ],
    )
    .expect("the claims commit");
    let [first, second] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    assert!(first.landed && second.landed, "{:?}", committed.items);
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        first: first.rows[0],
        second: second.rows[0],
    }
}

fn commit_one(fixture: &Fixture, item: Derived) -> (bool, Vec<EntityId>, Vec<String>) {
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-links",
        &[item],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    (item.landed, item.rows.clone(), item.reasons.clone())
}

fn same_as(source: EntityId, target: EntityId) -> Derived {
    Derived::SameAs(SameAs {
        local: "same_as",
        source: Named::Stored(source),
        target: Named::Stored(target),
    })
}

#[test]
fn the_dreamers_same_as_lands_as_a_proposal() {
    let fixture = fixture();
    let (landed, rows, reasons) = commit_one(&fixture, same_as(fixture.first, fixture.second));
    assert!(landed, "the proposal lands: {reasons:?}");
    let [status] = rows.as_slice() else {
        panic!("one status claim: {rows:?}");
    };
    assert_eq!(
        claim_lifecycle(&fixture.vault, *status).expect("read"),
        Some("active".to_owned())
    );
    assert!(
        !same_as_edge(&fixture.vault, fixture.first, fixture.second).expect("read"),
        "no grant applies the edge"
    );
}

#[test]
fn the_owners_nightly_link_grant_applies_the_dreamers_same_as() {
    let fixture = fixture();
    mint_nightly_links(&fixture.vault).expect("the owner's grant");
    let (landed, _, reasons) = commit_one(&fixture, same_as(fixture.first, fixture.second));
    assert!(landed, "the proposal lands: {reasons:?}");
    assert!(
        same_as_edge(&fixture.vault, fixture.first, fixture.second).expect("read"),
        "the owner's grant applies the edge"
    );
}

#[test]
fn a_same_as_joins_two_claims() {
    let fixture = fixture();
    let (landed, _, reasons) = commit_one(&fixture, same_as(fixture.first, fixture.person));
    assert!(!landed);
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.same_as_not_claims".to_owned()]
    );
}

#[test]
fn a_topology_judgment_needs_the_agents_own_grant() {
    let fixture = fixture();
    let other = put(&fixture.vault, ENTITY_TYPE_PERSON, b"someone else");
    let (landed, _, reasons) = commit_one(
        &fixture,
        Derived::Distinct(Distinct {
            local: "distinct",
            a: fixture.person,
            b: other,
            grant: EntityId::now(),
            apply: false,
        }),
    );
    assert!(!landed);
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.topology_needs_grant".to_owned()]
    );
}
