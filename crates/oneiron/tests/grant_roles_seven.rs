//! The grant roles after the lead's 11 Nov 11:38 ruling (VS-CHECKIN-NAMES = A
//! with the roles, VS-OLD-NAMES = A), part R1: `deputy` is a grant role on the
//! Admin envelope, with Admin's starting powers and its own check-in column;
//! `auditor` and the `audit` preset are refused, with no alias. A Deputy
//! passes the role guards that name Admin: the weave Admin proof and the
//! erase ask (review round 1 of #7071).
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test grant_roles_seven`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::check_in::RolePreset;
use oneiron::federation::{
    EraseAskKind, FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::test_doors::grant_roles::{
    default_membership_verbs, erase_ask_kind, is_weave_admin_role,
};
use oneiron::{EntityId, Vault, VaultConfig};

const SHARED: u64 = 42;

#[test]
fn deputy_is_a_grant_role_with_its_own_token() {
    assert_eq!(
        FederationGrantRole::parse("deputy"),
        Some(FederationGrantRole::Deputy)
    );
    assert_eq!(FederationGrantRole::Deputy.as_str(), "deputy");
    assert!(
        FederationGrantRole::Deputy.is_admin(),
        "a Deputy holds Admin's powers"
    );
    assert_eq!(
        RolePreset::of_grant_role(FederationGrantRole::Deputy),
        RolePreset::Deputy,
        "a Deputy reads its own check-in column, not Admin's"
    );
}

#[test]
fn deputy_rides_only_the_admin_envelope() {
    let grant = |preset| {
        FederationGrant::new(
            FederationGrantScope::vault(SHARED),
            EntityId::now(),
            FederationGrantRole::Deputy,
            preset,
        )
    };
    grant(FederationGrantPreset::Admin)
        .validate()
        .expect("a Deputy on the Admin envelope");
    for preset in [
        FederationGrantPreset::Owner,
        FederationGrantPreset::Member,
        FederationGrantPreset::ReadOnly,
    ] {
        assert!(
            grant(preset).validate().is_err(),
            "a Deputy never rides the {preset:?} envelope"
        );
    }
}

#[test]
fn deputy_starts_with_the_admin_powers_of_the_shipped_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let holder = EntityId::now();
    let admin = default_membership_verbs(&vault, FederationGrantRole::Admin, SHARED, holder)
        .expect("the Admin row");
    let deputy = default_membership_verbs(&vault, FederationGrantRole::Deputy, SHARED, holder)
        .expect("the shipped policy has a Deputy row");
    assert_eq!(deputy, admin, "a Deputy starts with Admin's powers");
    let deputy = deputy.expect("a bounded verb set");
    assert!(deputy.iter().any(|verb| verb == "org:add-member"));
    assert!(
        !deputy
            .iter()
            .any(|verb| verb == "org:root" || verb == "owner:veto"),
        "the org root and the veto stay the Owner's: {deputy:?}"
    );
}

#[test]
fn auditor_and_the_audit_preset_are_refused() {
    assert_eq!(FederationGrantRole::parse("auditor"), None);
    assert_eq!(FederationGrantPreset::parse("audit"), None);
    assert_eq!(
        FederationGrantRole::parse("viewer"),
        Some(FederationGrantRole::Viewer),
        "viewer stays until the label PR"
    );
}

#[test]
fn a_deputy_passes_the_weave_admin_role_guard_and_an_owner_does_not() {
    for role in [FederationGrantRole::Admin, FederationGrantRole::Deputy] {
        assert!(
            is_weave_admin_role(role),
            "a {role:?} reads the weave as an Admin, behind its step-up"
        );
    }
    for role in [
        FederationGrantRole::Owner,
        FederationGrantRole::Steward,
        FederationGrantRole::Member,
        FederationGrantRole::Viewer,
        FederationGrantRole::Delegate,
        FederationGrantRole::Guest,
    ] {
        assert!(
            !is_weave_admin_role(role),
            "a {role:?} is no weave Admin; an Owner reads as the Owner"
        );
    }
}

#[test]
fn a_deputys_erase_ask_is_a_proposal_as_an_admins_is() {
    assert_eq!(
        erase_ask_kind(FederationGrantRole::Deputy),
        Some(EraseAskKind::Proposal),
        "a Deputy proposes an erase as an Admin does"
    );
    assert_eq!(
        erase_ask_kind(FederationGrantRole::Admin),
        Some(EraseAskKind::Proposal)
    );
    assert_eq!(
        erase_ask_kind(FederationGrantRole::Member),
        Some(EraseAskKind::Request)
    );
    for role in [
        FederationGrantRole::Owner,
        FederationGrantRole::Steward,
        FederationGrantRole::Viewer,
        FederationGrantRole::Delegate,
        FederationGrantRole::Guest,
    ] {
        assert_eq!(erase_ask_kind(role), None, "a {role:?} makes no erase ask");
    }
}
