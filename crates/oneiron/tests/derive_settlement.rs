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
    Claim, Derived, Named, Settle, Settlement, Supersede, claim_lifecycle, commit,
    define_auto_agent, grant_derive_rows, open_conflict, refusal_receipt,
};
use oneiron::test_doors::steward::{
    STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, STEWARD_VERBS, dreamer, receive_steward_grant_row,
    stand_steward_grant, steward_grant_rows,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const READER: &str = "reader";
const PROTECTED: &str = "gate.deny.derive.supersede_protected_source";
const REPLACEMENT_UNSETTLED: &str = "gate.deny.derive.supersede_replacement_unsettled";
const LACKS_DERIVE: &str = "gate.deny.derive.grant_lacks_derive";
const LIFECYCLE: &str = "gate.deny.derive.supersede_lifecycle";
const OUTSIDE_GRANT: &str = "gate.deny.derive.outside_grant";
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
fn a_stale_replacement_closes_nothing() {
    let fixture = fixture();
    let old = landed_claim(&fixture, "an oat milk flat white");
    let mut body = ClaimBody::new(
        "preference.coffee",
        ClaimSubject::Entity(fixture.person),
        rmpv::Value::from("a cortado"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::Observed);
    body.stale = true;
    let new = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_claim(&new, &body, TimeRange { start: at, end: at }, at)
        .expect("a stale observed claim");
    let stored = fixture
        .vault
        .get_claim(&new)
        .expect("read")
        .expect("the replacement");
    assert!(stored.stale, "the stored replacement is stale");
    assert!(matches!(
        stored.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ));
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-stale-replacement",
        &[Derived::Supersede(Supersede {
            local: "replace_with_stale",
            new: Named::Stored(new),
            old: Named::Stored(old),
        })],
    )
    .expect("commit");
    let [replace] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(
        !replace.landed,
        "a stale replacement closes no accepted claim: {replace:?}"
    );
    assert_eq!(replace.reasons, vec![REPLACEMENT_UNSETTLED.to_owned()]);
    assert_eq!(
        claim_lifecycle(&fixture.vault, old).expect("read"),
        Some("active".to_owned()),
        "the accepted claim stands while its replacement is stale"
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
fn a_supersession_over_a_claim_outside_the_actors_read_answers_as_one_over_no_claim() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let second = landed_claim(&fixture, "a cortado");
    let stated = stated_claim(&fixture, "a black filter coffee");
    // Derive and archive with no read: the grant still reaches every claim,
    // and the Dreamer reads none.
    stand_steward_grant(
        &fixture.vault,
        fixture.dreamer,
        &["derive", STEWARD_ARCHIVE_VERB],
    )
    .expect("a grant without read");

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-unread-pair",
        &[
            Derived::Supersede(Supersede {
                local: "replace_unread",
                new: Named::Stored(second),
                old: Named::Stored(first),
            }),
            Derived::Supersede(Supersede {
                local: "replace_stated",
                new: Named::Stored(second),
                old: Named::Stored(stated),
            }),
            Derived::Supersede(Supersede {
                local: "replace_none",
                new: Named::Stored(second),
                old: Named::Stored(EntityId::now()),
            }),
        ],
    )
    .expect("commit");
    let [unread, over_stated, none] = committed.items.as_slice() else {
        panic!("three items: {:?}", committed.items);
    };
    assert!(
        !unread.landed,
        "a claim its actor does not read is not closed: {unread:?}"
    );
    assert_eq!(unread.reasons, vec![LIFECYCLE.to_owned()]);
    assert_eq!(
        over_stated.reasons, unread.reasons,
        "the refusal does not say an unread claim is user-stated"
    );
    assert_eq!(
        none.reasons, unread.reasons,
        "a claim outside the read and one that was never stored answer alike"
    );
    assert_eq!(
        claim_lifecycle(&fixture.vault, first).expect("read"),
        Some("active".to_owned()),
        "the unread claim stands"
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

/// Every standing Steward grant row decides, never the newest alone: a row
/// another of the owner's machines stood can only narrow the reach.
#[test]
fn a_settlement_needs_derive_in_every_standing_steward_row() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let second = landed_claim(&fixture, "a cortado");
    let marker = open_conflict(&fixture.vault, second, first).expect("an open conflict");
    // The older row gives no `derive`. A newer row gives every verb, as
    // another machine's default arrives here. Both stand.
    let older = stand_steward_grant(
        &fixture.vault,
        fixture.dreamer,
        &[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB],
    )
    .expect("a grant without derive");
    let newer = receive_steward_grant_row(&fixture.vault, fixture.dreamer, &STEWARD_VERBS)
        .expect("a newer row with every verb");
    assert!(older < newer, "the row with every verb is the newest");
    assert_eq!(
        steward_grant_rows(&fixture.vault, fixture.dreamer)
            .expect("rows")
            .len(),
        2,
        "both rows stand"
    );

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-settle-two-rows",
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
    assert!(
        !settled.landed,
        "the older row without derive still narrows: {settled:?}"
    );
    assert_eq!(settled.reasons, vec![LACKS_DERIVE.to_owned()]);
    assert_eq!(
        claim_lifecycle(&fixture.vault, first).expect("read"),
        Some("active".to_owned())
    );
}

#[test]
fn a_settlement_of_a_conflict_outside_the_actors_read_is_refused() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let second = landed_claim(&fixture, "a cortado");
    let marker = open_conflict(&fixture.vault, second, first).expect("an open conflict");
    // Derive and archive with no read: the grant still reaches the marker,
    // and the Dreamer reads neither it nor its members.
    stand_steward_grant(
        &fixture.vault,
        fixture.dreamer,
        &["derive", STEWARD_ARCHIVE_VERB],
    )
    .expect("a grant without read");

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-settle-unread",
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
    assert!(
        !settled.landed,
        "a conflict its actor does not read is not settled: {settled:?}"
    );
    assert_eq!(settled.reasons, vec![SETTLE_REFUSED.to_owned()]);
    assert!(settled.rows.is_empty(), "no member's id is answered");
    assert_eq!(
        claim_lifecycle(&fixture.vault, first).expect("read"),
        Some("active".to_owned()),
        "both members stand"
    );
}

#[test]
fn a_settlement_naming_no_stored_row_is_refused_alone() {
    let fixture = fixture();

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-settle-nothing",
        &[
            Derived::Settle(Settle {
                local: "settle_nothing",
                marker: Named::Stored(EntityId::now()),
                settlement: Settlement::Dismiss,
            }),
            coffee(&fixture, "beside_it", "a cortado"),
        ],
    )
    .expect("the batch commits: a marker that names no row refuses its own item");
    let [settled, beside_it] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    assert!(!settled.landed);
    assert_eq!(settled.reasons, vec![SETTLE_REFUSED.to_owned()]);
    assert_eq!(
        refusal_receipt(&fixture.vault, committed.batch, "settle_nothing").expect("read"),
        Some(vec![SETTLE_REFUSED.to_owned()])
    );
    assert!(beside_it.landed, "the item beside it lands: {beside_it:?}");
}

#[test]
fn an_agent_with_no_steward_grant_settles_and_supersedes_nothing() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let second = landed_claim(&fixture, "a cortado");
    let third = landed_claim(&fixture, "an espresso");
    let marker = open_conflict(&fixture.vault, second, first).expect("an open conflict");
    // An ordinary agent that reads the vault and lands what it derives at
    // Auto. It holds no Steward grant, and no conflict review Grant.
    let agent = define_auto_agent(&fixture.vault).expect("an agent");
    grant_derive_rows(&fixture.vault, &[agent]).expect("the agent's derive rows");

    let committed = commit(
        &fixture.vault,
        agent,
        EdgeActorClass::Agent,
        "run-no-steward-grant",
        &[
            Derived::Settle(Settle {
                local: "dismiss",
                marker: Named::Stored(marker),
                settlement: Settlement::Dismiss,
            }),
            Derived::Supersede(Supersede {
                local: "replace_third",
                new: Named::Stored(second),
                old: Named::Stored(third),
            }),
        ],
    )
    .expect("commit");
    let [dismiss, replace_third] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    assert!(
        !dismiss.landed,
        "landing rows alone settle no conflict: {dismiss:?}"
    );
    assert_eq!(dismiss.reasons, vec![OUTSIDE_GRANT.to_owned()]);
    assert!(
        !replace_third.landed,
        "landing rows alone close no stored claim: {replace_third:?}"
    );
    assert_eq!(replace_third.reasons, vec![OUTSIDE_GRANT.to_owned()]);
    assert_eq!(
        claim_lifecycle(&fixture.vault, third).expect("read"),
        Some("active".to_owned())
    );

    // The conflict is still open: the Dreamer, which settles with no grant
    // step, answers it.
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-dreamer-settles",
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
    assert!(
        settled.landed,
        "the conflict the agent could not settle is still open: {settled:?}"
    );
}
