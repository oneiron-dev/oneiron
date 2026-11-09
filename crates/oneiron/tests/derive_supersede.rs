//! Supersession items of a derivation batch (untangle 6.7a-2): a claim an
//! agent derived replaces one its live `derive` grant reaches, through the
//! claim lifecycle's own supersession, and never over user-stated truth.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_supersede`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Named, Supersede, claim_lifecycle, commit, refusal_receipt,
};
use oneiron::test_doors::steward::{STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, dreamer, stand_steward_grant};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const READER: &str = "reader";
const PROTECTED: &str = "gate.deny.derive.supersede_protected_source";
const LACKS_DERIVE: &str = "gate.deny.derive.grant_lacks_derive";

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
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let turn = put(&vault, ENTITY_TYPE_TURN, &body);
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        turn,
    }
}

fn coffee(fixture: &Fixture, local: &'static str, value: &str) -> Derived {
    Derived::Claim(Claim {
        local,
        predicate: "preference.coffee",
        subject: Named::Stored(fixture.person),
        value: json!(value),
        evidence: vec![Named::Stored(fixture.turn)],
    })
}

/// Lands one derived claim; its id.
fn landed_claim(fixture: &Fixture, value: &str) -> EntityId {
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-first",
        &[coffee(fixture, "first", value)],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the first claim lands: {item:?}");
    item.rows[0]
}

#[test]
fn a_derived_claim_supersedes_one_the_grant_reaches() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-second",
        &[
            coffee(&fixture, "second", "a cortado"),
            Derived::Supersede(Supersede {
                local: "replace_first",
                new: Named::Local("second"),
                old: Named::Stored(first),
            }),
        ],
    )
    .expect("commit");
    let [second, replace] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    assert!(second.landed, "{second:?}");
    assert!(replace.landed, "the supersession lands: {replace:?}");
    assert_eq!(
        claim_lifecycle(&fixture.vault, first).expect("read"),
        Some("superseded".to_owned())
    );
    assert_eq!(
        claim_lifecycle(&fixture.vault, second.rows[0]).expect("read"),
        Some("active".to_owned())
    );
}

#[test]
fn a_derived_claim_never_supersedes_user_stated_truth() {
    let fixture = fixture();
    let mut body = ClaimBody::new(
        "preference.coffee",
        ClaimSubject::Entity(fixture.person),
        rmpv::Value::from("a black filter coffee"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::UserStated);
    let stated = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_claim(&stated, &body, TimeRange { start: at, end: at }, at)
        .expect("the owner's own claim");

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-over-stated",
        &[
            coffee(&fixture, "derived", "a cortado"),
            Derived::Supersede(Supersede {
                local: "over_stated",
                new: Named::Local("derived"),
                old: Named::Stored(stated),
            }),
        ],
    )
    .expect("commit");
    let [derived, over_stated] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    assert!(derived.landed, "the derived claim itself lands: {derived:?}");
    assert!(!over_stated.landed, "it never closes the stated claim");
    assert_eq!(over_stated.reasons, vec![PROTECTED.to_owned()]);
    assert_eq!(
        refusal_receipt(&fixture.vault, committed.batch, "over_stated").expect("read"),
        Some(vec![PROTECTED.to_owned()])
    );
    assert_eq!(
        claim_lifecycle(&fixture.vault, stated).expect("read"),
        Some("active".to_owned()),
        "the stated claim stands"
    );
}

#[test]
fn a_supersession_needs_the_derive_grant() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let second = landed_claim(&fixture, "a cortado");
    stand_steward_grant(
        &fixture.vault,
        fixture.dreamer,
        &[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB],
    )
    .expect("a grant without derive");

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-narrowed",
        &[Derived::Supersede(Supersede {
            local: "replace_first",
            new: Named::Stored(second),
            old: Named::Stored(first),
        })],
    )
    .expect("commit");
    let [replace] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(!replace.landed);
    assert_eq!(replace.reasons, vec![LACKS_DERIVE.to_owned()]);
    assert_eq!(
        claim_lifecycle(&fixture.vault, first).expect("read"),
        Some("active".to_owned())
    );
}
