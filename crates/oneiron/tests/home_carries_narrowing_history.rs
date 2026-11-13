//! A home move carries the owner's narrowing history
//! (STEWARD-NARROWING-RECEIPT-LOCAL; Engine RULING ROW4-NARROWING-HISTORY =
//! A, 13 Nov 21:09). The owner's signed revokes and mints reach every
//! machine, but the record of each narrowing the owner applied (the verbs
//! before and after and the breaks the owner confirmed) lived only in this
//! node's table, which no home move carried: a move lost it. Now the home
//! handoff carries it as one more section, with the agent and the owner as
//! actor parts: a move loses nothing, a second carry changes nothing, and a
//! record one of whose actor parts did not open lands nothing.
//!
//! Needs the doors and the `sync` feature:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test home_carries_narrowing_history`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::collections::BTreeSet;

use oneiron::federation::{SystemAgentGrantNarrowing, SystemAgentNarrowing};
use oneiron::test_doors::home_sections::carry_narrowing_history;
use oneiron::test_doors::steward::{STEWARD_READ_VERB, dreamer, open_owner_carrier_vault, owner};
use oneiron::{EntityId, Vault};

/// The vault in `dir` whose owner narrowed its Dreamer to `read`, confirming
/// the breaks; the Dreamer and its narrowing history.
fn narrowed_home(dir: &std::path::Path) -> (Vault, EntityId, Vec<(u64, SystemAgentNarrowing)>) {
    let vault = open_owner_carrier_vault(dir).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let agent = dreamer(&vault).expect("the Dreamer");
    vault.provision_system_agent_grants().expect("first mint");
    let keep: BTreeSet<String> = [STEWARD_READ_VERB.to_owned()].into_iter().collect();
    let SystemAgentGrantNarrowing::ConfirmRequired { confirm, .. } = vault
        .narrow_system_agent_grant(&owner, agent, &keep, None)
        .expect("the warning")
    else {
        panic!("narrowing the Dreamer needs the owner's confirm");
    };
    assert!(matches!(
        vault
            .narrow_system_agent_grant(&owner, agent, &keep, Some(confirm))
            .expect("the confirmed narrowing"),
        SystemAgentGrantNarrowing::Narrowed { .. }
    ));
    let history = vault.system_agent_narrowings(agent).expect("the history");
    assert_eq!(history.len(), 1, "one narrowing recorded at the old home");
    (vault, agent, history)
}

fn history(vault: &Vault, agent: EntityId) -> Vec<(u64, SystemAgentNarrowing)> {
    vault.system_agent_narrowings(agent).expect("the history")
}

#[test]
fn a_home_move_carries_the_narrowing_history() {
    let (old_dir, new_dir) = (
        tempfile::tempdir().expect("tempdir"),
        tempfile::tempdir().expect("tempdir"),
    );
    let (old_home, agent, recorded) = narrowed_home(old_dir.path());
    let new_home = open_owner_carrier_vault(new_dir.path()).expect("the new home");
    assert!(history(&new_home, agent).is_empty());

    assert!(
        carry_narrowing_history(&old_home, &new_home, &[])
            .expect("the home move carries the narrowing history"),
        "the section applies"
    );
    assert_eq!(
        history(&new_home, agent),
        recorded,
        "the new home holds the record the old home held: what the owner confirmed"
    );

    assert!(
        carry_narrowing_history(&old_home, &new_home, &[])
            .expect("the home move carries the narrowing history again"),
        "an equal record is a no-op, never a Conflict"
    );
    assert_eq!(history(&new_home, agent), recorded);
}

#[test]
fn a_record_whose_actor_part_did_not_open_lands_nothing() {
    let (old_dir, new_dir) = (
        tempfile::tempdir().expect("tempdir"),
        tempfile::tempdir().expect("tempdir"),
    );
    let (old_home, agent, recorded) = narrowed_home(old_dir.path());
    let new_home = open_owner_carrier_vault(new_dir.path()).expect("the new home");
    let narrowed_by = recorded[0].1.owner;

    for withheld in [narrowed_by, agent] {
        assert!(
            carry_narrowing_history(&old_home, &new_home, &[withheld])
                .expect("the home move carries the narrowing history"),
            "a row whose actor did not open is no Conflict"
        );
        assert!(
            history(&new_home, agent).is_empty(),
            "a record lands only with both its agent and its owner"
        );
    }
}
