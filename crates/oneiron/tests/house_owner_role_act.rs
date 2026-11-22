//! HOUSE-OWNER-ROLE-VIA-ADD-OWNER (Engine RULING HOUSE-UNBIND-AUTHORITY = A:
//! "an Owner-role house link goes through propose_add_owner, so a vault that
//! enabled a veto wait applies it the same as for a human Owner add"):
//! `propose_house_owner_role` starts the `add_owner` act that seats the
//! workspace's house at the Owner role. The act waits the vault's
//! owner-change wait, an Owner may object inside its objection window, and
//! its executor seats the house by its link with one bind receipt. With no
//! wait the act completes at once.
//!
//! The door is new, so this file builds on the head only; its red pins are
//! in `house_owner_role_waits.rs`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test house_owner_role_act`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "house_owner_role/fixture.rs"]
mod fixture;

use fixture::{DAY, Org, WORKSPACE};
use oneiron::federation::{FederationGrantRole as Role, SharedVaultChange};

#[test]
fn the_house_owner_act_waits_then_seats_the_house() {
    let org = Org::new();
    org.owner_change_wait_days(1);
    org.vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Deputy)
        .expect("the house runs the org as Deputy");
    let started = org.vault.now_recorded_at();

    let act = org
        .vault
        .propose_house_owner_role(&org.owner_proof, WORKSPACE)
        .expect("the owner starts the house's Owner seat");
    assert_eq!(act.act, "add_owner", "the act a person's Owner add starts");
    assert!(!act.completed, "the act waits the owner-change wait");
    assert!(act.deadline >= started + DAY, "{act:?}");
    let events = org.house_seat_events();
    assert!(
        events.iter().any(|event| event.act_id == act.id),
        "the co-Owner is told: {events:?}"
    );
    assert!(
        org.vault
            .execute_completed_shared_act(&org.owner_proof, &act.id, Some(&org.issuer))
            .is_err(),
        "the act does not run inside its wait"
    );
    assert_eq!(org.bound_roles(), ["deputy"], "the house stays Deputy");

    org.pass(act.deadline);
    let executed = org
        .vault
        .execute_completed_shared_act(&org.owner_proof, &act.id, Some(&org.issuer))
        .expect("the matured act runs");
    assert_eq!(
        executed.receipt.change,
        SharedVaultChange::MemberRoleChanged {
            member: org.house.to_hex(),
            from: Role::Deputy,
            to: Role::Owner,
        }
    );
    assert_eq!(
        org.bound_roles(),
        ["deputy", "owner"],
        "the executor seats the house at Owner with one bind receipt naming the owner"
    );
    assert!(
        org.vault
            .propose_house_owner_role(&org.owner_proof, WORKSPACE)
            .is_err(),
        "a house already an Owner takes no second act"
    );
}

#[test]
fn a_second_owner_objects_and_the_house_is_not_seated() {
    let org = Org::new();
    org.add_owner_objection_window();

    let act = org
        .vault
        .propose_house_owner_role(&org.owner_proof, WORKSPACE)
        .expect("the owner starts the house's Owner seat");
    assert!(!act.completed, "the act waits its objection window");
    org.vault
        .change_authority_objection(&org.co_owner_proof, &act.id, true)
        .expect("the co-Owner objects inside the window");

    org.pass(act.deadline);
    assert!(
        org.vault
            .execute_completed_shared_act(&org.owner_proof, &act.id, Some(&org.issuer))
            .is_err(),
        "an act a live Owner objects to does not run"
    );
    assert!(
        org.bound_roles().is_empty(),
        "the house holds no Owner seat after the objection"
    );
}

#[test]
fn with_no_wait_the_house_owner_act_completes_at_once() {
    let org = Org::new();

    let act = org
        .vault
        .propose_house_owner_role(&org.owner_proof, WORKSPACE)
        .expect("the owner starts the house's Owner seat");
    assert!(act.completed, "no wait: the act completes at once");
    let executed = org
        .vault
        .execute_completed_shared_act(&org.owner_proof, &act.id, Some(&org.issuer))
        .expect("the act runs at once");
    assert_eq!(
        executed.receipt.change,
        SharedVaultChange::MemberAdded {
            member: org.house.to_hex(),
            role: Role::Owner,
        }
    );
    assert_eq!(org.bound_roles(), ["owner"]);
}
