//! FIX 23218: a view that holds an agent world edit's Grant refused reads the edit's world under
//! the install's cap, the fold with no vouch with the same edit undone, unless only edits after a
//! settled handoff stand in the world.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::authority_world_undo::capped_agent_world_edit_read;

#[test]
fn a_refused_agent_world_edit_leaves_the_install_cap_on_its_world() {
    assert_eq!(capped_agent_world_edit_read(true, true, true), "MyMachines");
}

#[test]
fn the_capped_fixture_reads_the_widening_uncapped_and_the_narrowing_capped() {
    assert_eq!(capped_agent_world_edit_read(true, false, false), "Everywhere");
    assert_eq!(capped_agent_world_edit_read(true, true, false), "MyMachines");
}

#[test]
fn a_refused_agent_world_edit_beside_only_fresh_edits_leaves_its_world_uncapped() {
    assert_eq!(capped_agent_world_edit_read(false, true, false), "MyMachines");
    assert_eq!(capped_agent_world_edit_read(false, true, true), "Everywhere");
}
