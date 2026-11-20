//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/identity/erase.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::maintenance::identity::IdentityAsk;
use oneiron_contracts::entity_id::EntityId;

/// Takes the erased `id` out of `ask`: none when the ask's own mention is
/// in it or no option is left (no candidate and no provisional entity of
/// its own), else whether it changed.
pub fn erase_from_ask(ask: &mut IdentityAsk, id: &EntityId) -> Option<bool> {
    if ask.turn == *id || ask.message == *id {
        return None;
    }
    let before = ask.candidates.len();
    ask.candidates.retain(|each| each != id);
    let mut changed = ask.candidates.len() != before;
    if ask.provisional == Some(*id) {
        ask.provisional = None;
        changed = true;
    }
    if ask.surfaced_turn == Some(*id) {
        ask.surfaced_turn = None;
        changed = true;
    }
    if ask.candidates.is_empty() && ask.provisional.is_none() {
        return None;
    }
    Some(changed)
}

/// Takes the erased `id` out of a kept copy of an ask: the copy is none
/// once its mention is in `id` or no option is left. True when it changed.
pub fn erase_snapshot(ask: &mut Option<IdentityAsk>, id: &EntityId) -> bool {
    let outcome = match ask.as_mut() {
        Some(held) => erase_from_ask(held, id),
        None => return false,
    };
    match outcome {
        Some(changed) => changed,
        None => {
            *ask = None;
            true
        }
    }
}
