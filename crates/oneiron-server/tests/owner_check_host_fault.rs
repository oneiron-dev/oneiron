//! The owner door answers a host fault its check meets with 500, never with
//! its 403 (FIX-LIST [MEMBER-SELECTOR-SOCKET], Astra review of #8018 T3). A
//! sync client stops on a 403 to its upgrade and never redials it, so a
//! passing store failure at the home must not read as a refusal of the
//! credential; on the tree before this fix the door answered every error
//! its check met with 403.
//!
//! The door's answer is read through the `oneiron_test_support` door
//! (`oneiron_server::test_doors::owner_check`):
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test owner_check_host_fault`.
#![cfg(oneiron_test_support)]

use oneiron_server::test_doors::owner_check::owner_check_failure_status;

#[test]
fn a_host_fault_in_the_owner_check_answers_500() {
    assert_eq!(owner_check_failure_status(&oneiron::Error::MapFull), 500);
    assert_eq!(
        owner_check_failure_status(&oneiron::Error::Io(std::io::Error::other(
            "the vault store could not be read"
        ))),
        500
    );
}

#[test]
fn a_refusal_in_the_owner_check_answers_403() {
    let not_owner = oneiron::Error::Gate(oneiron::error::GateError::ConsentOwnerNotAuthenticated(
        "actor is deleted, not an owner",
    ));
    assert_eq!(owner_check_failure_status(&not_owner), 403);
    let other = oneiron::Error::InvalidConfig("principal_ref is unusable".to_owned());
    assert_eq!(owner_check_failure_status(&other), 403);
}
