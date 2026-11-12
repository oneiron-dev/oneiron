//! The agent world-edit fixtures for FIX 22381 and FIX 23218.
//! Compiled only under `--cfg oneiron_test_support`; never API.

/// FIX 22381: one world with three concurrent live agent world privacy edits, each carried by its own machine
/// on the same parents (the same revision): `OneMachine(a)`, `OneMachine(b)` and `MyMachines`, in that order.
/// Folds the log, holds back the edits at `refused` (indices into that order) as a view whose rows hold their
/// Grants refused does (`carried_act::hold_back_agent_acts`), and answers the world's read
/// (`fold.world_privacy(world).read`) as its `Debug` text.
pub fn concurrent_agent_world_edits_read(refused: &[usize]) -> String {
    crate::authority::world_undo_door::concurrent_agent_world_edits_read(refused)
}

/// FIX 22381 (review P1-1 of #7075): one world that one agent edited twice under one Grant, each edit carried by
/// the same machine: `MyMachines`, then `OneMachine(m)` on it, which replaced the first. Folds the log, holds back
/// the edits at `refused` (indices into that order) as a view whose rows hold their Grants refused does, and answers
/// the world's read as its `Debug` text.
pub fn sequential_agent_world_edits_read(refused: &[usize]) -> String {
    crate::authority::world_undo_door::sequential_agent_world_edits_read(refused)
}

/// FIX 23218: one world that three machines marked "yours" edit on the same parents: an owner narrowing to
/// `MyMachines` on the first, which a later owner widening to `Everywhere` on the same machine replaced; an agent
/// edit that keeps the world (`Everywhere`) on the third; and, with `owner_edit_beside`, an owner edit to
/// `Everywhere` on the second. With `no_vouch_cap`, caps the fold as an install does whose fold with no vouch lacks
/// the widening, a row after a settled handoff (`install_fold::NoVouch::cap`). With `agent_edit_refused`, holds the
/// agent edit back as a view whose rows hold its Grant refused does. Answers the world's read
/// (`fold.world_privacy(world).read`) as its `Debug` text.
pub fn capped_agent_world_edit_read(
    owner_edit_beside: bool,
    no_vouch_cap: bool,
    agent_edit_refused: bool,
) -> String {
    crate::authority::world_undo_door::capped_agent_world_edit_read(
        owner_edit_beside,
        no_vouch_cap,
        agent_edit_refused,
    )
}
