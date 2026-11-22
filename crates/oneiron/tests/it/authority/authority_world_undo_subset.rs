//! FIX 22381: refusing agent world edits removes their effects, whichever of a world's agent edits
//! they are: two of three concurrent ones, or an edit together with the earlier one it replaced.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::authority_world_undo::{
    concurrent_agent_world_edits_read, sequential_agent_world_edits_read,
};

#[test]
fn refused_subset_of_concurrent_agent_world_edits_has_no_effect() {
    assert_eq!(concurrent_agent_world_edits_read(&[0, 1]), "MyMachines");
}

#[test]
fn the_fixture_folds_conflicted_with_no_edit_refused() {
    assert_eq!(
        concurrent_agent_world_edits_read(&[]),
        concat!(
            "Conflicted { contenders: {",
            "EntityId([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]), ",
            "EntityId([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2])",
            "} }",
        ),
    );
}

#[test]
fn refused_agent_world_edit_and_the_refused_edit_it_replaced_have_no_effect() {
    assert_eq!(sequential_agent_world_edits_read(&[0, 1]), "Everywhere");
}

#[test]
fn the_sequential_fixture_reads_its_last_edit_or_the_edit_it_replaced() {
    assert_eq!(
        sequential_agent_world_edits_read(&[]),
        "OneMachine(EntityId([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]))",
    );
    assert_eq!(sequential_agent_world_edits_read(&[1]), "MyMachines");
}
