//! The engine's default Steward grants are not the owner's act (lead 10 Nov
//! 06:5x; Engine S6C-PLACE-1 = A). When a host first opens the vault, the
//! engine stands the Dreamer's and the Coach's default grants, and the
//! owner's authority log gains no entry for them: the receipt must not say
//! the owner decided something he did not. When the owner later narrows a
//! default grant, that narrowing is his act and is logged.
//!
//! Uses only doors the base has, so on the base it runs and fails.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test engine_default_owner_act`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::SystemAgentGrantNarrowing;
use oneiron::receipt::AuthorityAuditQuery;
use oneiron::test_doors::coach::coach;
use oneiron::test_doors::steward::{STEWARD_READ_VERB, open_owner_carrier_vault, owner};

/// How many entries the owner's authority audit lists.
fn logged(vault: &Vault, owner: &AuthenticatedOwner) -> usize {
    vault
        .authority_audit(
            owner,
            &AuthorityAuditQuery {
                limit: Some(500),
                ..AuthorityAuditQuery::default()
            },
        )
        .expect("the owner's audit")
        .rows
        .len()
}

#[test]
fn the_default_grants_write_no_owner_act_and_his_narrowing_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");

    let before = logged(&vault, &owner);
    vault
        .provision_system_agent_grants()
        .expect("the engine's defaults");
    assert_eq!(
        logged(&vault, &owner),
        before,
        "the engine's default grants add no entry to the owner's authority log"
    );

    // The owner narrows the Coach's default to `read`: his act, logged.
    let keep = BTreeSet::from([STEWARD_READ_VERB.to_owned()]);
    let SystemAgentGrantNarrowing::ConfirmRequired { confirm, .. } = vault
        .narrow_system_agent_grant(&owner, coach, &keep, None)
        .expect("the narrowing warning")
    else {
        panic!("the Coach's default grant is system-critical");
    };
    vault
        .narrow_system_agent_grant(&owner, coach, &keep, Some(confirm))
        .expect("the owner narrows a default grant");
    assert!(
        logged(&vault, &owner) > before,
        "the owner's narrowing is his act"
    );
}
