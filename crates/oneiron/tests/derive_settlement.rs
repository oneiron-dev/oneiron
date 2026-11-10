//! Supersession and settlement items of a derivation batch (untangle 6.7a):
//! a claim an agent derived replaces one its live `derive` grant reaches,
//! through the claim lifecycle's own supersession, and never over
//! user-stated truth; an agent answers an open conflict its grant reaches
//! through the conflict settlement's own door.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_settlement`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derivation_floor::{define_agent, write_derived_claim};
use oneiron::test_doors::derive::{
    Claim, Derived, Named, Settle, Settlement, Supersede, claim_lifecycle, commit, open_conflict,
    refusal_receipt,
};
use oneiron::test_doors::steward::{
    STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, dreamer, stand_steward_grant,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const READER: &str = "reader";
const PROTECTED: &str = "gate.deny.derive.supersede_protected_source";
const REPLACEMENT_UNSETTLED: &str = "gate.deny.derive.supersede_replacement_unsettled";
const LACKS_DERIVE: &str = "gate.deny.derive.grant_lacks_derive";
const SETTLE_REFUSED: &str = "gate.deny.derive.settle_refused";

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
        // A proposal, so the owner's write meets no criticality confirm; the
        // UserStated guard holds it all the same.
        ClaimApprovalStatus::Proposed,
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
    assert!(
        derived.landed,
        "the derived claim itself lands: {derived:?}"
    );
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

/// Writes the owner's own user-stated claim about the fixture's person; its
/// id. A proposal, so the write meets no criticality confirm.
fn stated_claim(fixture: &Fixture, value: &str) -> EntityId {
    let mut body = ClaimBody::new(
        "preference.coffee",
        ClaimSubject::Entity(fixture.person),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Proposed,
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
    stated
}

#[test]
fn a_stored_user_stated_replacement_never_closes_user_stated_truth() {
    let fixture = fixture();
    let stated = stated_claim(&fixture, "a black filter coffee");
    let borrowed = stated_claim(&fixture, "an espresso");

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-borrowed-replacement",
        &[Derived::Supersede(Supersede {
            local: "over_stated",
            new: Named::Stored(borrowed),
            old: Named::Stored(stated),
        })],
    )
    .expect("commit");
    let [over_stated] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(
        !over_stated.landed,
        "an agent never closes the stated claim: {over_stated:?}"
    );
    assert_eq!(over_stated.reasons, vec![PROTECTED.to_owned()]);
    assert_eq!(
        claim_lifecycle(&fixture.vault, stated).expect("read"),
        Some("active".to_owned()),
        "the stated claim stands"
    );
}

#[test]
fn a_replacement_still_proposed_closes_nothing() {
    let fixture = fixture();
    let accepted = landed_claim(&fixture, "an oat milk flat white");
    let agent = define_agent(&fixture.vault).expect("an agent");
    let proposal = write_derived_claim(&fixture.vault, agent, fixture.person, &[fixture.turn])
        .expect("the write door answers")
        .unwrap_or_else(|codes| panic!("the proposal lands: {codes:?}"));
    assert_eq!(
        fixture
            .vault
            .get_claim(&proposal)
            .expect("read")
            .expect("the proposal")
            .approval,
        ClaimApprovalStatus::Proposed,
        "the replacement waits for its approval"
    );

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-proposed-replacement",
        &[Derived::Supersede(Supersede {
            local: "replace_accepted",
            new: Named::Stored(proposal),
            old: Named::Stored(accepted),
        })],
    )
    .expect("commit");
    let [replace] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(
        !replace.landed,
        "a proposal closes no accepted claim: {replace:?}"
    );
    assert_eq!(replace.reasons, vec![REPLACEMENT_UNSETTLED.to_owned()]);
    assert_eq!(
        claim_lifecycle(&fixture.vault, accepted).expect("read"),
        Some("active".to_owned()),
        "the accepted claim stands while its replacement waits"
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

#[test]
fn a_derived_settlement_keeps_one_member_of_an_open_conflict() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let second = landed_claim(&fixture, "a cortado");
    let marker = open_conflict(&fixture.vault, second, first).expect("an open conflict");

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-settle",
        &[Derived::Settle(Settle {
            local: "keep_second",
            marker: Named::Stored(marker),
            settlement: Settlement::Keep(Named::Stored(second)),
        })],
    )
    .expect("commit");
    let [settled] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(settled.landed, "the settlement lands: {settled:?}");
    assert_eq!(
        claim_lifecycle(&fixture.vault, first).expect("read"),
        Some("superseded".to_owned()),
        "the other member is superseded by the kept one"
    );
    assert_eq!(
        claim_lifecycle(&fixture.vault, second).expect("read"),
        Some("active".to_owned())
    );
}

#[test]
fn a_settlement_of_a_row_that_is_no_open_conflict_is_refused() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-not-a-conflict",
        &[Derived::Settle(Settle {
            local: "settle_a_claim",
            marker: Named::Stored(first),
            settlement: Settlement::Dismiss,
        })],
    )
    .expect("commit");
    let [settled] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(!settled.landed);
    assert_eq!(settled.reasons, vec![SETTLE_REFUSED.to_owned()]);
}

#[test]
fn a_settlement_needs_the_derive_grant() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let second = landed_claim(&fixture, "a cortado");
    let marker = open_conflict(&fixture.vault, second, first).expect("an open conflict");
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
        "run-settle-narrowed",
        &[Derived::Settle(Settle {
            local: "keep_second",
            marker: Named::Stored(marker),
            settlement: Settlement::Keep(Named::Stored(second)),
        })],
    )
    .expect("commit");
    let [settled] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(!settled.landed);
    assert_eq!(settled.reasons, vec![LACKS_DERIVE.to_owned()]);
    assert_eq!(
        claim_lifecycle(&fixture.vault, first).expect("read"),
        Some("active".to_owned())
    );
}
