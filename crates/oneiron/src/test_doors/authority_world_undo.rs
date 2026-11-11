//! The concurrent agent world-edit fixture for FIX 22381.
//! Compiled only under `--cfg oneiron_test_support`; never API.

/// FIX 22381: one world with three concurrent live agent world privacy edits, each carried by its own machine
/// on the same parents (the same revision): `OneMachine(a)`, `OneMachine(b)` and `MyMachines`, in that order.
/// Folds the log, holds back the edits at `refused` (indices into that order) as a view whose rows hold their
/// Grants refused does (`carried_act::hold_back_agent_acts`), and answers the world's read
/// (`fold.world_privacy(world).read`) as its `Debug` text.
pub fn concurrent_agent_world_edits_read(refused: &[usize]) -> String {
    crate::authority::world_undo_door::concurrent_agent_world_edits_read(refused)
}
