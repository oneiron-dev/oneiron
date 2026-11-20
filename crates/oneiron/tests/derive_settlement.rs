//! Supersession and settlement items of a derivation batch (untangle 6.7a):
//! a claim an agent derived replaces one its live `derive` grant reaches,
//! through the claim lifecycle's own supersession, and never over
//! user-stated truth; an agent answers an open conflict its grant reaches
//! through the conflict settlement's own door. A settlement about a PERSON
//! under the vault cleanup's archive marker restores her (FIX
//! DREAMER-DIRECT-CLAIM-WRITERS-LAND-ON-ARCHIVED-PERSON). The owner's hold on a
//! subject's conflict review stops a settlement by every actor (FIX
//! DERIVE-SETTLE-HOLD-NAMES-STAMP-ACTOR).
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_settlement`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_consolidation::ConflictReviewScope;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derivation_floor::{define_agent, write_derived_claim};
use oneiron::test_doors::derive::{
    Claim, Derived, Named, Settle, Settlement, Supersede, batch_items, claim_lifecycle, commit,
    define_auto_agent, grant_derive_rows, open_conflict, open_conflict_with_alternative,
    open_conflict_with_imported_alternative, refusal_receipt, revert_as_owner, witness_turn,
};
use oneiron::test_doors::steward::{
    STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, STEWARD_VERBS, dreamer, owner,
    receive_steward_grant_row, stand_steward_grant, steward_grant_rows,
};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use serde_json::json;

const READER: &str = "reader";
const PROTECTED: &str = "gate.deny.derive.supersede_protected_source";
const REPLACEMENT_UNSETTLED: &str = "gate.deny.derive.supersede_replacement_unsettled";
const LACKS_DERIVE: &str = "gate.deny.derive.grant_lacks_derive";
const LIFECYCLE: &str = "gate.deny.derive.supersede_lifecycle";
const OUTSIDE_GRANT: &str = "gate.deny.derive.outside_grant";
const SETTLE_REFUSED: &str = "gate.deny.derive.settle_refused";
const SETTLE_OWNER_HOLD: &str = "gate.deny.derive.settle_owner_hold";

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

#[test]
fn a_derived_keep_of_imported_words_stages_it_and_the_revert_takes_it_back() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let (marker, alternative) =
        open_conflict_with_imported_alternative(&fixture.vault, first, "a cortado")
            .expect("an open conflict with an imported alternative");

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-keep-imported",
        &[Derived::Settle(Settle {
            local: "keep_imported",
            marker: Named::Stored(marker),
            settlement: Settlement::Keep(Named::Stored(alternative)),
        })],
    )
    .expect("commit");
    let recorded = batch_items(&fixture.vault, committed.batch)
        .expect("read")
        .expect("the batch record");
    let [settled] = recorded.as_slice() else {
        panic!("one item: {recorded:?}");
    };
    assert!(settled.landed, "the imported Keep stages: {settled:?}");
    let [staged, recorded_marker] = settled.rows.as_slice() else {
        panic!("the staged proposal and the marker: {settled:?}");
    };
    assert_eq!(
        *recorded_marker, marker,
        "the marker follows the staged proposal: {settled:?}"
    );
    assert_eq!(
        settled.approval.as_deref(),
        Some("proposed"),
        "the staged proposal waits for review: {settled:?}"
    );
    let staged_body = fixture
        .vault
        .get_claim(staged)
        .expect("read")
        .expect("the staged proposal");
    assert_ne!(
        staged_body.predicate, "core.conflict.resolved",
        "the first row stages the kept words, not an answer"
    );
    assert_eq!(
        staged_body.approval,
        ClaimApprovalStatus::Proposed,
        "the staged proposal waits for review"
    );
    assert_eq!(staged_body.source, Some(ClaimSource::Imported));
    let marker_is_open = || {
        fixture
            .vault
            .memory(fixture.dreamer, EdgeActorClass::System)
            .open_conflicts(None, Some(fixture.person), usize::MAX)
            .expect("open conflicts")
            .iter()
            .any(|conflict| conflict.marker == marker)
    };
    assert!(
        marker_is_open(),
        "the marker stays open beside the staged proposal"
    );
    assert_eq!(
        claim_lifecycle(&fixture.vault, first).expect("read"),
        Some("active".to_owned()),
        "no member is superseded while the proposal waits"
    );

    let (reverted, left) = revert_as_owner(&fixture.vault, committed.batch)
        .expect("revert")
        .expect("the owner may revert any batch");
    assert_eq!(reverted, vec!["keep_imported".to_owned()]);
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(
        claim_lifecycle(&fixture.vault, *staged).expect("read"),
        Some("retracted".to_owned()),
        "the revert takes the staged proposal back"
    );
    assert!(marker_is_open(), "the marker stays open after the revert");
}

/// A derived Keep of imported words that `derive.revert` took back leaves its alternative
/// keepable: the next derived Keep of it is accepted and stages it again at a fresh id, the
/// first proposal stays retracted, and the marker stays open.
#[test]
fn a_derived_keep_the_revert_took_back_stages_afresh_on_the_next_keep() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let (marker, alternative) =
        open_conflict_with_imported_alternative(&fixture.vault, first, "a cortado")
            .expect("an open conflict with an imported alternative");
    let keep = |run: &str| {
        let committed = commit(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            run,
            &[Derived::Settle(Settle {
                local: "keep_imported",
                marker: Named::Stored(marker),
                settlement: Settlement::Keep(Named::Stored(alternative)),
            })],
        )
        .expect("commit");
        let recorded = batch_items(&fixture.vault, committed.batch)
            .expect("read")
            .expect("the batch record");
        (committed.batch, recorded)
    };
    let marker_is_open = || {
        fixture
            .vault
            .memory(fixture.dreamer, EdgeActorClass::System)
            .open_conflicts(None, Some(fixture.person), usize::MAX)
            .expect("open conflicts")
            .iter()
            .any(|conflict| conflict.marker == marker)
    };

    let (batch, recorded) = keep("run-keep-imported");
    let [first_try] = recorded.as_slice() else {
        panic!("one item: {recorded:?}");
    };
    assert!(first_try.landed, "the imported Keep stages: {first_try:?}");
    let [staged, _] = first_try.rows.as_slice() else {
        panic!("the staged proposal and the marker: {first_try:?}");
    };
    let (reverted, left) = revert_as_owner(&fixture.vault, batch)
        .expect("revert")
        .expect("the owner may revert any batch");
    assert_eq!(reverted, vec!["keep_imported".to_owned()]);
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(
        claim_lifecycle(&fixture.vault, *staged).expect("read"),
        Some("retracted".to_owned()),
        "the revert takes the staged proposal back"
    );

    let (_, recorded) = keep("run-keep-imported-again");
    let [second_try] = recorded.as_slice() else {
        panic!("one item: {recorded:?}");
    };
    assert!(
        second_try.landed,
        "a Keep after the revert is accepted: {second_try:?}"
    );
    let [restaged, recorded_marker] = second_try.rows.as_slice() else {
        panic!("the staged proposal and the marker: {second_try:?}");
    };
    assert_eq!(*recorded_marker, marker);
    assert_ne!(
        restaged, staged,
        "it stages at a fresh id: the first proposal never reopens"
    );
    assert_eq!(
        second_try.approval.as_deref(),
        Some("proposed"),
        "the new proposal waits for review: {second_try:?}"
    );
    let restaged_body = fixture
        .vault
        .get_claim(restaged)
        .expect("read")
        .expect("the staged proposal");
    assert_eq!(restaged_body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(restaged_body.source, Some(ClaimSource::Imported));
    assert_eq!(
        claim_lifecycle(&fixture.vault, *restaged).expect("read"),
        Some("active".to_owned()),
        "the new proposal is live"
    );
    assert_eq!(
        claim_lifecycle(&fixture.vault, *staged).expect("read"),
        Some("retracted".to_owned()),
        "the first proposal stays retracted"
    );
    assert!(
        marker_is_open(),
        "the marker stays open beside the new proposal"
    );
}

/// A plain retraction after owner approval makes the staged Keep's alternative keepable again.
/// FIX KEEP-HISTORY-APPROVED-THEN-RETRACTED-STAGED-KEEP-BLOCKS-ALTERNATIVE;
/// lead ruling 21 Nov, INTENT-17 row 5 = B.
#[test]
fn a_staged_keep_the_owner_approved_and_then_retracted_leaves_its_alternative_keepable() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let (marker, alternative) =
        open_conflict_with_imported_alternative(&fixture.vault, first, "a cortado")
            .expect("FIXTURE: an open conflict with an imported alternative");
    let keep = |run: &str| {
        let committed = commit(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            run,
            &[Derived::Settle(Settle {
                local: "keep_imported",
                marker: Named::Stored(marker),
                settlement: Settlement::Keep(Named::Stored(alternative)),
            })],
        )
        .expect("commit the Keep batch");
        batch_items(&fixture.vault, committed.batch)
            .expect("read")
            .expect("the batch record")
    };
    let read_open_marker = || {
        fixture
            .vault
            .memory(fixture.dreamer, EdgeActorClass::System)
            .open_conflicts(None, Some(fixture.person), usize::MAX)
            .expect("read the person's open conflicts")
            .into_iter()
            .find(|conflict| conflict.marker == marker)
    };

    let recorded = keep("run-keep-imported");
    let [first_try] = recorded.as_slice() else {
        panic!("FIXTURE: one Keep item: {recorded:?}");
    };
    assert!(
        first_try.landed,
        "FIXTURE: the imported Keep stages: {first_try:?}"
    );
    let [staged, recorded_marker] = first_try.rows.as_slice() else {
        panic!("FIXTURE: the staged proposal and the marker: {first_try:?}");
    };
    assert_eq!(
        *recorded_marker, marker,
        "FIXTURE: the marker follows the staged proposal: {first_try:?}"
    );
    assert_eq!(
        *staged, alternative,
        "FIXTURE: the first Keep uses the selector's id"
    );
    let staged_body = fixture
        .vault
        .get_claim(staged)
        .expect("read")
        .expect("FIXTURE: the staged Keep");
    assert_eq!(
        staged_body.approval,
        ClaimApprovalStatus::Proposed,
        "FIXTURE: the first Keep waits for approval"
    );
    assert_eq!(
        staged_body.lifecycle,
        ClaimLifecycleStatus::Active,
        "FIXTURE: the first Keep is active"
    );

    let owner_id = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    fixture
        .vault
        .approve_machine_claim_as(*staged, WriteActor::new(owner_id, EdgeActorClass::Human))
        .expect("FIXTURE: the owner approves the staged Keep without settling the conflict");
    let approved = fixture
        .vault
        .get_claim(staged)
        .expect("read")
        .expect("FIXTURE: the approved Keep");
    assert_eq!(
        approved.approval,
        ClaimApprovalStatus::Approved,
        "FIXTURE: the owner's approval stands"
    );
    assert_eq!(
        approved.lifecycle,
        ClaimLifecycleStatus::Active,
        "FIXTURE: the approved Keep is still active"
    );
    let conflict = read_open_marker().expect("FIXTURE: approval leaves the marker open");
    assert_eq!(
        claim_lifecycle(&fixture.vault, first).expect("read"),
        Some("active".to_owned()),
        "FIXTURE: approval does not supersede the first claim"
    );
    assert!(
        !conflict
            .alternatives
            .iter()
            .any(|entry| entry.id == alternative),
        "FIXTURE: the standing approved Keep represents its alternative"
    );

    fixture
        .vault
        .memory(owner_id, EdgeActorClass::Human)
        .claim_retract(&staged.to_hex())
        .expect("FIXTURE: the owner retracts the approved Keep");
    let retracted = fixture
        .vault
        .get_claim(staged)
        .expect("read")
        .expect("FIXTURE: the retracted Keep remains stored");
    assert_eq!(
        retracted.lifecycle,
        ClaimLifecycleStatus::Retracted,
        "FIXTURE: the plain retraction closes the approved Keep"
    );
    assert_eq!(
        retracted.approval,
        ClaimApprovalStatus::Approved,
        "FIXTURE: retraction preserves the owner's approval"
    );

    let conflict = read_open_marker().expect("the plain retraction leaves the marker open");
    assert_eq!(
        conflict
            .alternatives
            .iter()
            .filter(|entry| entry.id == alternative)
            .count(),
        1,
        "the alternative is keepable again after its approved staged Keep was retracted"
    );

    let recorded = keep("run-keep-imported-again");
    let [second_try] = recorded.as_slice() else {
        panic!("one Keep item: {recorded:?}");
    };
    assert!(
        second_try.landed,
        "a Keep after the retraction is accepted: {second_try:?}"
    );
    let [restaged, recorded_marker] = second_try.rows.as_slice() else {
        panic!("the staged proposal and the marker: {second_try:?}");
    };
    assert_eq!(
        *recorded_marker, marker,
        "the marker follows the new proposal: {second_try:?}"
    );
    assert_ne!(restaged, staged, "the next Keep stages at a fresh id");
    assert_eq!(
        second_try.approval.as_deref(),
        Some("proposed"),
        "the new proposal waits for review: {second_try:?}"
    );
    let restaged_body = fixture
        .vault
        .get_claim(restaged)
        .expect("read")
        .expect("the new Keep");
    assert_eq!(
        restaged_body.approval,
        ClaimApprovalStatus::Proposed,
        "the restaged claim waits for approval"
    );
    assert_eq!(
        restaged_body.lifecycle,
        ClaimLifecycleStatus::Active,
        "the new proposal is live"
    );
    assert_eq!(
        restaged_body.source,
        Some(ClaimSource::Imported),
        "the words are still imported"
    );
    assert_eq!(
        claim_lifecycle(&fixture.vault, *staged).expect("read"),
        Some("retracted".to_owned()),
        "the first Keep stays retracted"
    );
    assert_eq!(
        claim_lifecycle(&fixture.vault, first).expect("read"),
        Some("active".to_owned()),
        "the new proposal does not supersede the first claim"
    );
    let conflict = read_open_marker().expect("the marker stays open beside the new proposal");
    assert!(
        !conflict
            .alternatives
            .iter()
            .any(|entry| entry.id == alternative),
        "the new pending Keep represents the alternative again"
    );
}

/// Puts the vault cleanup's archive marker on the fixture's PERSON after claims about her
/// stand: the stranded state a vault keeps from a claim written about her after the cleanup
/// archived her, before her claim writers restored her (FIX
/// DREAMER-DIRECT-CLAIM-WRITERS-LAND-ON-ARCHIVED-PERSON).
fn archive_person(fixture: &Fixture) {
    archive_as_cleanup(&fixture.vault, &fixture.person).expect("the archive marker");
    assert!(
        fixture
            .vault
            .archived_entity(&fixture.person)
            .expect("read")
            .is_some(),
        "the cleanup's archive marker stands on her"
    );
}

/// Whether the fixture's PERSON is back: no archive marker stands on her.
fn person_restored(fixture: &Fixture) -> bool {
    fixture
        .vault
        .archived_entity(&fixture.person)
        .expect("read")
        .is_none()
}

/// ARCH-0073 §6, "a re-mention restores the archived record": the answer a settlement
/// writes about a PERSON under the cleanup's archive marker is a new mention of her, and the
/// settlement's own write restores her.
#[test]
fn a_derived_settlement_about_an_archived_person_restores_her() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let second = landed_claim(&fixture, "a cortado");
    let marker = open_conflict(&fixture.vault, second, first).expect("an open conflict");
    archive_person(&fixture);

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-settle-archived",
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
    assert!(
        person_restored(&fixture),
        "the answer is a new mention of her: it restored her"
    );
}

/// ARCH-0073 §6: the retained alternative a Keep lands about a PERSON under the cleanup's
/// archive marker is a new mention of her, and the settlement's own write restores her.
#[test]
fn a_derived_keep_of_an_alternative_about_an_archived_person_restores_her() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let (marker, alternative) = open_conflict_with_alternative(&fixture.vault, first, "a cortado")
        .expect("an open conflict with a retained alternative");
    archive_person(&fixture);

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-keep-alternative-archived",
        &[Derived::Settle(Settle {
            local: "keep_alternative",
            marker: Named::Stored(marker),
            settlement: Settlement::Keep(Named::Stored(alternative)),
        })],
    )
    .expect("commit");
    let [settled] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(settled.landed, "the Keep lands: {settled:?}");
    assert_eq!(
        claim_lifecycle(&fixture.vault, alternative).expect("read"),
        Some("active".to_owned()),
        "the kept alternative stands"
    );
    assert!(
        person_restored(&fixture),
        "the kept alternative is a new mention of her: it restored her"
    );
}

/// ARCH-0073 §6: kept imported words about a PERSON under the cleanup's archive marker stage
/// in the import's review with no answer written, and the staged proposal is a new mention of
/// her: its own write restores her.
#[test]
fn a_derived_keep_of_imported_words_about_an_archived_person_restores_her() {
    let fixture = fixture();
    let first = landed_claim(&fixture, "an oat milk flat white");
    let (marker, alternative) =
        open_conflict_with_imported_alternative(&fixture.vault, first, "a cortado")
            .expect("an open conflict with an imported alternative");
    archive_person(&fixture);

    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-keep-imported-archived",
        &[Derived::Settle(Settle {
            local: "keep_imported",
            marker: Named::Stored(marker),
            settlement: Settlement::Keep(Named::Stored(alternative)),
        })],
    )
    .expect("commit");
    let [settled] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(settled.landed, "the imported Keep stages: {settled:?}");
    assert_eq!(
        settled.approval.as_deref(),
        Some("proposed"),
        "the staged proposal waits for review: {settled:?}"
    );
    assert!(
        person_restored(&fixture),
        "the staged proposal is a new mention of her: it restored her"
    );
}

/// One open conflict between two of the Dreamer's claims about a person, in a vault its
/// owner holds open, so the owner's hold door answers. This is the fixture of
/// `tests/conflicts_page.rs`.
struct OwnedConflict {
    _dir: tempfile::TempDir,
    vault: Vault,
    dreamer: EntityId,
    person: EntityId,
    first: EntityId,
    marker: EntityId,
}

fn owned_conflict() -> OwnedConflict {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(open_dreamer_vault(dir.path(), READER).expect("vault"));
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("the owned vault");
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor().expect("the owner");
    let person = EntityId::now();
    seed_named_person(&vault, &person, "owen", vault.now_recorded_at()).expect("a person");
    let turn = witness_turn(&vault, "call me owen").expect("a witnessed turn");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS).expect("the Dreamer's grant");
    let mut members = Vec::new();
    for (run, value) in [
        ("run-first", "an oat milk flat white"),
        ("run-second", "a cortado"),
    ] {
        let committed = commit(
            &vault,
            dreamer,
            EdgeActorClass::System,
            run,
            &[Derived::Claim(Claim {
                local: "claim",
                predicate: "preference.coffee",
                subject: Named::Stored(person),
                value: json!(value),
                evidence: vec![Named::Stored(turn)],
            })],
        )
        .expect("commit");
        let [item] = committed.items.as_slice() else {
            panic!("one item: {:?}", committed.items);
        };
        assert!(item.landed, "the claim lands: {item:?}");
        members.push(item.rows[0]);
    }
    let marker = open_conflict(&vault, members[1], members[0]).expect("an open conflict");
    OwnedConflict {
        _dir: dir,
        vault,
        dreamer,
        person,
        first: members[0],
        marker,
    }
}

impl OwnedConflict {
    /// The owner holds the conflict review of the conflict's subject.
    fn hold(&self) {
        let proof = owner(&self.vault).expect("the owner's proof");
        let owner_actor = self.vault.ensure_embedded_owner_actor().expect("the owner");
        self.vault
            .memory(owner_actor, EdgeActorClass::Human)
            .hold_dreamer_conflict_review(&proof, ConflictReviewScope::Subject(self.person))
            .expect("the owner's hold");
    }

    /// Commits one Dismiss of the conflict as `actor` of `class`: whether it landed, and
    /// its refusal reasons.
    fn dismiss_as(&self, actor: EntityId, class: EdgeActorClass, run: &str) -> (bool, Vec<String>) {
        let committed = commit(
            &self.vault,
            actor,
            class,
            run,
            &[Derived::Settle(Settle {
                local: "dismiss",
                marker: Named::Stored(self.marker),
                settlement: Settlement::Dismiss,
            })],
        )
        .expect("commit");
        let [item] = committed.items.as_slice() else {
            panic!("one item: {:?}", committed.items);
        };
        (item.landed, item.reasons.clone())
    }
}

/// The owner's hold on a subject's conflict review leaves its conflicts to the owner,
/// whoever asks (lead ruling of 21 Nov 2026). The one hold an owner mints names the
/// Dreamer. An agent other than the Dreamer, whose Steward grant gives `derive` over the
/// marker and which lands what it derives, is refused as the Dreamer is.
#[test]
fn the_owners_hold_stops_a_settlement_by_an_agent_other_than_the_dreamer() {
    let conflict = owned_conflict();
    let agent = define_auto_agent(&conflict.vault).expect("an agent");
    grant_derive_rows(&conflict.vault, &[agent]).expect("the agent's derive rows");
    stand_steward_grant(&conflict.vault, agent, &STEWARD_VERBS).expect("the agent's grant");
    conflict.hold();

    let (landed, reasons) =
        conflict.dismiss_as(agent, EdgeActorClass::Agent, "run-agent-dismisses");
    assert!(
        !landed,
        "a held conflict is the owner's to answer: {reasons:?}"
    );
    assert_eq!(reasons, vec![SETTLE_OWNER_HOLD.to_owned()]);
    assert_eq!(
        claim_lifecycle(&conflict.vault, conflict.first).expect("read"),
        Some("active".to_owned()),
        "the refused settlement closes no member"
    );
}

/// The Dreamer's own settlement through a derivation batch is refused under the hold.
#[test]
fn the_owners_hold_stops_a_settlement_by_the_dreamer() {
    let conflict = owned_conflict();
    conflict.hold();

    let (landed, reasons) = conflict.dismiss_as(
        conflict.dreamer,
        EdgeActorClass::System,
        "run-dreamer-dismisses",
    );
    assert!(
        !landed,
        "a held conflict is the owner's to answer: {reasons:?}"
    );
    assert_eq!(reasons, vec![SETTLE_OWNER_HOLD.to_owned()]);
}
