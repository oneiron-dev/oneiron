//! The opt-out of a system agent's grant (untangle 6.3c; S6-4 amended), on a
//! grant the host's first mint signed as the owner's act. Narrowing a
//! system-critical grant returns what breaks and changes nothing until the
//! owner confirms that list; then the owner's signed revoke and narrower mint
//! apply, and the record keeps that the owner chose it. The door never
//! widens. Revoked whole, the grant becomes an opt-out the host's next open
//! keeps. On the base there is no narrowing door.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_grant_narrowing`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::federation::{
    SYSTEM_AGENT_GRANT_NARROWING_WARNING, SystemAgentGrantNarrowing, SystemFunction,
};
use oneiron::test_doors::steward::{
    GrantMark, STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, STEWARD_VERBS, WeaveReach, dreamer,
    grant_mark, open_owner_carrier_vault, owner, weave_reach,
};

fn verbs(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

const READY: WeaveReach = WeaveReach {
    reads: true,
    lands_auto: true,
};

#[test]
fn narrowing_the_dreamers_minted_grant_warns_and_waits_for_the_owners_confirm() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    vault.provision_system_agent_grants().expect("first mint");
    let Some(GrantMark::Minted { grant, .. }) = grant_mark(&vault, dreamer).expect("mark") else {
        panic!("the first mint stands");
    };
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
    assert_eq!(weave_reach(&vault).expect("reach"), READY);

    // A wrong token applies nothing.
    assert!(matches!(
        vault
            .narrow_system_agent_grant(&owner, dreamer, &keep, Some([7; 32]))
            .expect("narrowing"),
        SystemAgentGrantNarrowing::ConfirmRequired { .. }
    ));
    assert_eq!(weave_reach(&vault).expect("reach"), READY);

    // A verb no Steward holds is refused.
    assert!(
        vault
            .narrow_system_agent_grant(&owner, dreamer, &verbs(&["write"]), None)
            .is_err()
    );

    // Confirmed: the owner's signed revoke and narrower mint apply.
    let SystemAgentGrantNarrowing::Narrowed {
        grant: Some(narrower),
        breaks: confirmed,
    } = vault
        .narrow_system_agent_grant(&owner, dreamer, &keep, Some(confirm))
        .expect("confirmed narrowing")
    else {
        panic!("the confirmed narrowing applies");
    };
    assert_eq!(confirmed, breaks);
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        WeaveReach {
            reads: true,
            lands_auto: false
        },
        "read stays, landing stops"
    );
    assert_eq!(
        grant_mark(&vault, dreamer).expect("mark"),
        Some(GrantMark::Minted {
            grant: narrower,
            verbs: keep.clone()
        })
    );

    // The record keeps that the owner chose it.
    let records = vault.system_agent_narrowings(dreamer).expect("records");
    let [(_, record)] = records.as_slice() else {
        panic!("one narrowing record, found {}", records.len());
    };
    assert_eq!(record.revoked, grant);
    assert_eq!(record.minted, Some(narrower));
    assert_eq!(record.before, verbs(&STEWARD_VERBS));
    assert_eq!(record.after, keep);
    assert_eq!(record.confirmed, breaks);

    // The door never widens.
    assert!(
        vault
            .narrow_system_agent_grant(&owner, dreamer, &verbs(&STEWARD_VERBS), None)
            .is_err(),
        "a widening is refused"
    );
}

#[test]
fn revoking_the_dreamers_minted_grant_whole_is_an_opt_out_the_host_keeps() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    vault.provision_system_agent_grants().expect("first mint");
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
            .expect("confirmed revoke"),
        SystemAgentGrantNarrowing::Narrowed { grant: None, .. }
    ));
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        WeaveReach {
            reads: false,
            lands_auto: false
        }
    );

    // The host's next open mints nothing: the owner's opt-out stands.
    vault.provision_system_agent_grants().expect("next open");
    assert_eq!(
        grant_mark(&vault, dreamer).expect("mark"),
        Some(GrantMark::OptedOut)
    );
}

/// Narrows the Dreamer's grant to `keep`, confirming the breaks when the
/// door asks; the breaks the applied narrowing carries.
fn narrow_confirming(
    vault: &oneiron::Vault,
    owner: &oneiron::consent::AuthenticatedOwner,
    dreamer: oneiron::EntityId,
    keep: &BTreeSet<String>,
) -> Vec<SystemFunction> {
    let confirm = match vault
        .narrow_system_agent_grant(owner, dreamer, keep, None)
        .expect("narrowing")
    {
        SystemAgentGrantNarrowing::ConfirmRequired { confirm, .. } => confirm,
        SystemAgentGrantNarrowing::Narrowed { breaks, .. } => return breaks,
        SystemAgentGrantNarrowing::Unchanged => panic!("the narrowing drops a verb"),
    };
    let SystemAgentGrantNarrowing::Narrowed { breaks, .. } = vault
        .narrow_system_agent_grant(owner, dreamer, keep, Some(confirm))
        .expect("confirmed narrowing")
    else {
        panic!("the confirmed narrowing applies");
    };
    breaks
}

/// Review of #6914: the history was keyed by the agent and the recording
/// second, so a second narrowing in that second replaced the first record.
#[test]
fn every_narrowing_stays_in_the_record_when_several_share_a_second() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    vault.provision_system_agent_grants().expect("first mint");

    // Four narrowings back to back, one verb fewer each time.
    let steps = [
        verbs(&STEWARD_VERBS),
        verbs(&[STEWARD_READ_VERB, "derive", STEWARD_ARCHIVE_VERB]),
        verbs(&[STEWARD_READ_VERB, "derive"]),
        verbs(&[STEWARD_READ_VERB]),
        BTreeSet::new(),
    ];
    for keep in &steps[1..] {
        narrow_confirming(&vault, &owner, dreamer, keep);
    }

    let records = vault.system_agent_narrowings(dreamer).expect("records");
    assert_eq!(
        records.len(),
        steps.len() - 1,
        "one record for each narrowing: {records:?}"
    );
    for (index, (_, record)) in records.iter().enumerate() {
        assert_eq!(record.before, steps[index], "narrowing {index}, before");
        assert_eq!(record.after, steps[index + 1], "narrowing {index}, after");
    }
    assert!(
        records.windows(2).all(|pair| pair[0].0 <= pair[1].0),
        "oldest first: {records:?}"
    );
}

/// Review of #6914: the strength archive is judged by the landing verdict, so
/// a grant without `derive` archives nothing. The warning named consolidation
/// only.
#[test]
fn dropping_derive_warns_that_recall_upkeep_stops_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    vault.provision_system_agent_grants().expect("first mint");
    let keep = verbs(&[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB, "delete"]);
    let both = vec![SystemFunction::Consolidation, SystemFunction::RecallUpkeep];

    let SystemAgentGrantNarrowing::ConfirmRequired { breaks, .. } = vault
        .narrow_system_agent_grant(&owner, dreamer, &keep, None)
        .expect("narrowing")
    else {
        panic!("a system-critical narrowing asks first");
    };
    assert_eq!(breaks, both, "the warning names both functions");

    assert_eq!(narrow_confirming(&vault, &owner, dreamer, &keep), both);
    let records = vault.system_agent_narrowings(dreamer).expect("records");
    let [(_, record)] = records.as_slice() else {
        panic!("one narrowing record, found {}", records.len());
    };
    assert_eq!(record.confirmed, both, "the record keeps both");
}
