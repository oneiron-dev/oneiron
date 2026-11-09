//! The opt-out of a system agent's grant (untangle 6.3c; S6-4 amended): a
//! narrowing of a system-critical grant returns what breaks and changes
//! nothing until the owner confirms that list; then it applies, and the
//! record keeps that he chose it. The door never widens.
//!
//! Written by reading: the oneiron lib test target does not compile on main
//! (26 Oct decree). The applying half signs the owner's revoke and mint, so
//! its fixture must carry an owner act (an install machine profile), as the
//! owner's agent-grant door does.
use super::*;
use crate::federation::grant_scope::{STEWARD_READ_VERB, STEWARD_VERBS};

fn verbs(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn fixture() -> (
    tempfile::TempDir,
    Vault,
    AuthenticatedOwner,
    EntityId,
    EntityId,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).expect("vault");
    crate::test_util::provision_engine_machines(&vault);
    let owner_ref = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner_ref,
            &owner_ref.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner proof");
    let dreamer = vault.dreamer_authority().expect("dreamer").entity_ref();
    (dir, vault, owner, owner_ref, dreamer)
}

#[test]
fn narrowing_the_dreamers_grant_warns_and_waits_for_the_owners_confirm() {
    let (_dir, vault, owner, owner_ref, dreamer) = fixture();
    let grant = vault
        .stand_steward_grant_for_test(dreamer, &STEWARD_VERBS)
        .expect("grant");
    let keep = verbs(&[STEWARD_READ_VERB]);

    // Asked without a confirm: what breaks, and nothing changes.
    let SystemAgentGrantNarrowing::ConfirmRequired {
        warning,
        breaks,
        confirm,
    } = vault
        .narrow_system_agent_grant(&owner, dreamer, &keep, None)
        .expect("narrowing")
    else {
        panic!("a system-critical narrowing asks first");
    };
    assert_eq!(warning, SYSTEM_AGENT_GRANT_NARROWING_WARNING);
    assert_eq!(
        breaks,
        vec![SystemFunction::Consolidation, SystemFunction::RecallUpkeep]
    );
    assert!(vault.dreamer_weave_reach().expect("reach").ready());

    // A confirm of another list applies nothing.
    let other = confirm_token(grant, &BTreeSet::new(), &breaks);
    assert!(matches!(
        vault
            .narrow_system_agent_grant(&owner, dreamer, &keep, Some(other))
            .expect("narrowing"),
        SystemAgentGrantNarrowing::ConfirmRequired { .. }
    ));
    assert!(vault.dreamer_weave_reach().expect("reach").ready());

    // A verb no Steward holds refuses.
    assert!(matches!(
        vault.narrow_system_agent_grant(&owner, dreamer, &verbs(&["write"]), None),
        Err(Error::InvalidConfig(_))
    ));

    // Confirmed: the owner's revoke and narrower mint apply.
    let SystemAgentGrantNarrowing::Narrowed {
        grant: Some(narrower),
        breaks: confirmed,
    } = vault
        .narrow_system_agent_grant(&owner, dreamer, &keep, Some(confirm))
        .expect("narrowing")
    else {
        panic!("the confirmed narrowing applies");
    };
    assert_eq!(confirmed, breaks);
    let reach = vault.dreamer_weave_reach().expect("reach");
    assert!(reach.reads && !reach.lands_auto, "{reach:?}");

    // The record keeps that the owner chose it.
    let records = vault.system_agent_narrowings(dreamer).expect("records");
    let [(_, record)] = records.as_slice() else {
        panic!("one narrowing record, found {}", records.len());
    };
    assert_eq!(record.owner, owner_ref);
    assert_eq!(record.revoked, grant);
    assert_eq!(record.minted, Some(narrower));
    assert_eq!(record.before, verbs(&STEWARD_VERBS));
    assert_eq!(record.after, keep);
    assert_eq!(record.confirmed, breaks);

    // The door never widens: the grant back is the owner's own grant.
    assert!(matches!(
        vault.narrow_system_agent_grant(&owner, dreamer, &verbs(&STEWARD_VERBS), None),
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn revoking_the_dreamers_grant_whole_is_an_opt_out_the_host_keeps() {
    let (_dir, vault, owner, _, dreamer) = fixture();
    vault
        .stand_steward_grant_for_test(dreamer, &STEWARD_VERBS)
        .expect("grant");
    let none = BTreeSet::new();
    let SystemAgentGrantNarrowing::ConfirmRequired { confirm, .. } = vault
        .narrow_system_agent_grant(&owner, dreamer, &none, None)
        .expect("narrowing")
    else {
        panic!("a whole revoke asks first");
    };
    assert!(matches!(
        vault
            .narrow_system_agent_grant(&owner, dreamer, &none, Some(confirm))
            .expect("narrowing"),
        SystemAgentGrantNarrowing::Narrowed { grant: None, .. }
    ));
    let reach = vault.dreamer_weave_reach().expect("reach");
    assert!(!reach.reads && !reach.lands_auto, "{reach:?}");

    // The host's next open mints nothing: the owner's opt-out stands.
    vault.provision_system_agent_grants().expect("provision");
    let txn = vault.store.env.read_txn().expect("txn");
    assert_eq!(
        vault
            .system_agent_grant_state_in(&txn, dreamer)
            .expect("state"),
        Some(SystemAgentGrantState::OptedOut)
    );
}
