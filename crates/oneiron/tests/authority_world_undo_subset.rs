//! FIX 22381: refusing two of three concurrent agent world edits removes their effects.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::authority_world_undo::concurrent_agent_world_edits_read;

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
