//! A holder's schedule move lands on a new home (FABLE-6918-2). The Coach,
//! a holder of `engine.controls.wake_cadence`, moves the schedule of the
//! owner's free-time policy; a home move carries the policy row, and the new
//! home adopts it. The move keeps the authority of the set it moves, so the
//! adoption judges the owner's set as before and the moved policy lands. On
//! the base the move stamps the Coach's Steward grant, the adoption judges
//! that grant under `free_time_policy_set`, refuses it, and the new home
//! keeps the policy before the move.
//!
//! The new home here is the same vault with its policy row put back as it
//! stood before the move: a home that has not seen the move. The rows go
//! through the policy table's own export and adoption.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test free_time_policy_handoff`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use oneiron::dreamer_runner::{FreeTimeCadence, FreeTimePolicyInput, FreeTimeSchedule};
use oneiron::test_doors::coach::{coach, define_agent};
use oneiron::test_doors::free_time_handoff::{
    adopt_policy_rows, export_policy_rows, put_stored_policy_row, stored_policy_row,
};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};

fn schedule(hour: u8) -> FreeTimeSchedule {
    FreeTimeSchedule {
        cadence: FreeTimeCadence::Nightly,
        hour,
        minute: 0,
        zone: "Asia/Tokyo".to_owned(),
    }
}

#[test]
fn a_holders_schedule_move_lands_on_the_new_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let agent = define_agent(&vault).expect("an agent");
    let set = vault
        .set_free_time_policy(
            &owner,
            None,
            agent,
            0,
            FreeTimePolicyInput {
                total_units: 50_000,
                schedule: schedule(3),
                pinned_split: None,
                cap_shown_at_ms: 1_000,
            },
        )
        .expect("the owner's policy");
    let before_the_move = stored_policy_row(&vault, agent)
        .expect("row")
        .expect("the owner's row");

    let (_, moved) = vault
        .set_free_time_schedule_as_holder(coach, agent, set.revision, schedule(4))
        .expect("the Coach's move");
    let carried = export_policy_rows(&vault).expect("the rows a move carries");

    // The new home has the owner's policy and has not seen the move.
    put_stored_policy_row(&vault, agent, &before_the_move).expect("the home before the move");
    assert_eq!(
        vault.free_time_policy(agent).expect("policy"),
        Some(set),
        "the new home holds the owner's set"
    );
    assert!(
        adopt_policy_rows(&vault, &carried).expect("adoption"),
        "the carried rows apply"
    );
    assert_eq!(
        vault.free_time_policy(agent).expect("policy"),
        Some(moved),
        "the holder-moved policy must land on the new home"
    );
}

#[test]
fn the_owners_own_set_lands_on_the_new_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    vault.provision_system_agent_grants().expect("first mint");
    let agent = define_agent(&vault).expect("an agent");
    let input = |hour| FreeTimePolicyInput {
        total_units: 50_000,
        schedule: schedule(hour),
        pinned_split: None,
        cap_shown_at_ms: 1_000,
    };
    let set = vault
        .set_free_time_policy(&owner, None, agent, 0, input(3))
        .expect("the owner's policy");
    let before = stored_policy_row(&vault, agent)
        .expect("row")
        .expect("the owner's row");
    let reset = vault
        .set_free_time_policy(&owner, None, agent, set.revision, input(4))
        .expect("the owner's second set");
    let carried = export_policy_rows(&vault).expect("the rows a move carries");

    put_stored_policy_row(&vault, agent, &before).expect("the home before the second set");
    assert!(
        adopt_policy_rows(&vault, &carried).expect("adoption"),
        "the carried rows apply"
    );
    assert_eq!(
        vault.free_time_policy(agent).expect("policy"),
        Some(reset),
        "the owner's later set lands"
    );
}
