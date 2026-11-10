//! Reverting a derivation batch (untangle 6.7c, decision C-2): the committing
//! actor reverts its own batch and the owner reverts any; each item is
//! undone only while its rows stand at the revision the commit recorded, and
//! an item changed since is left alone and listed.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_revert`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derivation_floor::define_agent;
use oneiron::test_doors::derive::{
    Claim, Derived, Named, Supersede, claim_lifecycle, commit, commit_claims, revert,
    revert_as_owner,
};
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const READER: &str = "reader";
const CHANGED_SINCE: &str = "derive.revert.changed_since";

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
    turn: EntityId,
    batch: EntityId,
    tea: EntityId,
    coffee: EntityId,
}

fn claim(
    fixture_person: EntityId,
    turn: EntityId,
    local: &'static str,
    predicate: &'static str,
) -> Claim {
    Claim {
        local,
        predicate,
        subject: Named::Stored(fixture_person),
        value: json!(local),
        evidence: vec![Named::Stored(turn)],
    }
}

/// A vault whose Dreamer committed one batch of two claims.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let turn = put(&vault, ENTITY_TYPE_TURN, &body);
    let committed = commit_claims(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-1",
        &[
            claim(person, turn, "tea", "preference.tea"),
            claim(person, turn, "coffee", "preference.coffee"),
        ],
    )
    .expect("the batch commits");
    let [tea, coffee] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    assert!(tea.landed && coffee.landed, "{:?}", committed.items);
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        turn,
        batch: committed.batch,
        tea: tea.rows[0],
        coffee: coffee.rows[0],
    }
}

fn active(fixture: &Fixture, claim: EntityId) -> bool {
    claim_lifecycle(&fixture.vault, claim).expect("read") == Some("active".to_owned())
}

#[test]
fn the_actor_reverts_its_own_batch() {
    let fixture = fixture();
    let (reverted, left) = revert(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        fixture.batch,
    )
    .expect("revert")
    .expect("the Dreamer may revert its own batch");
    assert_eq!(reverted, vec!["coffee".to_owned(), "tea".to_owned()]);
    assert!(left.is_empty(), "{left:?}");
    assert!(!active(&fixture, fixture.tea));
    assert!(!active(&fixture, fixture.coffee));
}

#[test]
fn an_item_changed_since_is_left_alone_and_listed() {
    let fixture = fixture();
    // A later batch supersedes the tea claim.
    let later = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-2",
        &[
            Derived::Claim(claim(
                fixture.person,
                fixture.turn,
                "green_tea",
                "preference.tea",
            )),
            Derived::Supersede(Supersede {
                local: "replace_tea",
                new: Named::Local("green_tea"),
                old: Named::Stored(fixture.tea),
            }),
        ],
    )
    .expect("the later batch commits");
    assert!(
        later.items.iter().all(|item| item.landed),
        "{:?}",
        later.items
    );

    let (reverted, left) = revert(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        fixture.batch,
    )
    .expect("revert")
    .expect("the Dreamer may revert its own batch");
    assert_eq!(reverted, vec!["coffee".to_owned()]);
    assert_eq!(left, vec![("tea".to_owned(), CHANGED_SINCE.to_owned())]);
    assert!(!active(&fixture, fixture.coffee));
}

#[test]
fn the_owner_reverts_any_batch() {
    let fixture = fixture();
    let (reverted, left) = revert_as_owner(&fixture.vault, fixture.batch)
        .expect("revert")
        .expect("the owner may revert any batch");
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(reverted, vec!["coffee".to_owned(), "tea".to_owned()]);
    assert!(!active(&fixture, fixture.tea));
    assert!(!active(&fixture, fixture.coffee));
}

#[test]
fn another_agent_may_not_revert_the_batch() {
    let fixture = fixture();
    let agent = define_agent(&fixture.vault).expect("an agent");
    assert_eq!(
        revert(&fixture.vault, agent, EdgeActorClass::Agent, fixture.batch).expect("revert"),
        Err(vec!["gate.deny.derive.revert_not_yours".to_owned()])
    );
    assert!(active(&fixture, fixture.tea));
}
