//! What an erased actor leaves in another agent's free-time rows (FIX 8875,
//! stage 1): one field scrub per row kind that can keep a second actor. A
//! policy keeps who set it and the linked machine it was said on; a cycle
//! keeps the note its author wrote. The live erase (`erase`) runs these, and
//! the home handoff's carrier is to run the same ones, so the two never keep
//! separate lists of fields. An erased attribution reads as absent, never
//! as another actor, and no authority reads these audit fields.

use super::cycle::FreeTimeCycle;
use super::policy::FreeTimePolicyRecord;
use crate::EntityId;
use crate::authority::ActSurface;

/// `record`'s policy in force without `actor`'s attribution: who set it,
/// when that was `actor`, and the linked machine it, or the clear the row
/// witnesses, was said on, when that machine was `actor`. The settings,
/// revision, times and `prior`, and the record's act witnesses, stay as
/// they were, never hashed again. Whether it changed.
pub(super) fn scrub_policy_attribution(
    record: &mut FreeTimePolicyRecord,
    actor: &EntityId,
) -> bool {
    let mut changed = false;
    // A clear's witness keeps the machine it was said on too (FIX 5721).
    if let Some(ActSurface::LinkedDevice { machine }) = record.clear_surface
        && machine == *actor
    {
        record.clear_surface = None;
        changed = true;
    }
    let Some(policy) = record.policy.as_mut() else {
        return changed;
    };
    if policy.set_by == Some(*actor) {
        policy.set_by = None;
        changed = true;
    }
    if policy.set_by_agent == Some(*actor) {
        policy.set_by_agent = None;
        policy.set_grant = None;
        changed = true;
    }
    if matches!(policy.surface, Some(ActSurface::LinkedDevice { machine }) if machine == *actor) {
        policy.surface = None;
        changed = true;
    }
    changed
}

/// `cycle` without the note `actor` wrote on it: the cycle, its items and
/// every other fact stay. Whether it changed.
pub(super) fn scrub_cycle_note(cycle: &mut FreeTimeCycle, actor: &EntityId) -> bool {
    if cycle
        .owner_note
        .as_ref()
        .is_some_and(|note| note.author == *actor)
    {
        cycle.owner_note = None;
        return true;
    }
    false
}
