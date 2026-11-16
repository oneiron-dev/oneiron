//! HOUSE-OWNER-ROLE-VIA-ADD-OWNER (Engine RULING HOUSE-UNBIND-AUTHORITY = A,
//! 10 Nov 08:46; ARCH-0043 #vault-owner-changes; ARCH-0063 #house-bind):
//! seating the workspace's house mind at the Owner role makes it a co-Owner,
//! so it skips no wait the vault set for a person's Owner add.
//!
//! On main `set_house_role(.., owner)` and a bind at Owner wrote the Owner
//! grant at once, past the vault's owner-change wait and its objection
//! window. Now both refuse an Owner seat that an `add_owner` act would hold,
//! writing nothing, and name the door that starts that act
//! (`house_owner_role_act.rs` runs it). With no wait (the default) the seat
//! is still instant.
//!
//! Red on main: `an_owner_house_seat_skips_no_enabled_owner_change_wait`,
//! `an_owner_house_seat_skips_no_objection_window` and
//! `a_bind_at_owner_that_the_wait_would_hold_is_refused` (the house is
//! seated at once). Guard, green on main too:
//! `an_owner_house_seat_is_instant_with_the_wait_off`.
//!
//! Every call here is on main, so the file builds on main and on the head.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test house_owner_role_waits`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "house_owner_role/fixture.rs"]
mod fixture;

use fixture::{Org, WORKSPACE};
use oneiron::federation::FederationGrantRole as Role;

/// The refusal names the wait and the door that starts the act.
fn assert_waits(error: &oneiron::Error) {
    let text = error.to_string();
    assert!(text.contains("owner-change wait"), "{text}");
    assert!(text.contains("propose_house_owner_role"), "{text}");
}

#[test]
fn an_owner_house_seat_skips_no_enabled_owner_change_wait() {
    let org = Org::new();
    org.owner_change_wait_days(1);

    let error = org
        .vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Owner)
        .expect_err("an Owner seat skips no owner-change wait");
    assert_waits(&error);
    assert!(
        org.bound_roles().is_empty(),
        "the refused seat writes no grant and keeps no receipt"
    );
    org.vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Admin)
        .expect("a seat below Owner is instant");
    assert_eq!(org.bound_roles(), ["admin"]);
}

#[test]
fn an_owner_house_seat_skips_no_objection_window() {
    let org = Org::new();
    org.add_owner_objection_window();

    let error = org
        .vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Owner)
        .expect_err("an Owner seat skips no objection window");
    assert_waits(&error);
    assert!(org.bound_roles().is_empty());
}

#[test]
fn a_bind_at_owner_that_the_wait_would_hold_is_refused() {
    let org = Org::new();
    org.owner_change_wait_days(1);
    let signer = org
        .vault
        .owner_project_signer(&org.issuer)
        .expect("the owner's project signer");

    let error = org
        .vault
        .bind_workspace_house_leader(WORKSPACE, Role::Owner, &org.owner_proof, &signer)
        .expect_err("a bind at Owner skips no owner-change wait");
    assert_waits(&error);
    assert!(
        org.bound_roles().is_empty(),
        "the refused bind writes nothing"
    );

    org.vault
        .bind_workspace_house_leader(WORKSPACE, Role::Deputy, &org.owner_proof, &signer)
        .expect("a bind below Owner is instant");
    assert_eq!(org.bound_roles(), ["deputy"]);
    let error = org
        .vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Owner)
        .expect_err("raising the house to Owner skips no wait either");
    assert_waits(&error);
    assert_eq!(org.bound_roles(), ["deputy"], "the house stays Deputy");
}

#[test]
fn an_owner_house_seat_is_instant_with_the_wait_off() {
    let org = Org::new();

    org.vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Owner)
        .expect("the owner seats the house at Owner");
    assert_eq!(
        org.bound_roles(),
        ["owner"],
        "with no wait the house is an Owner at once, as before"
    );
    org.vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Owner)
        .expect("the same seat again is a retry");
    assert_eq!(
        org.bound_roles(),
        ["owner"],
        "a retry keeps no second receipt"
    );
}
