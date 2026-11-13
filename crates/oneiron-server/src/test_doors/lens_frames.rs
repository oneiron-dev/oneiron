//! Door for `tests/lens_frame_state_door.rs`: moves a held card's `$state`
//! as an accepted local event moves it, so the test reads that state back
//! through the card's own route. No card the default lens renders carries a
//! local action, so no event can move it there.

use oneiron::lens::{GeneratedUiStateSnapshot, LensRenderId};

use crate::server::SyncServer;

/// Moves the held `$state` of card `card_id` to `state`, re-charged to the
/// retained line as an event's move is. `false` when the server holds no
/// such card.
pub async fn move_held_state(
    server: &SyncServer,
    card_id: &str,
    state: GeneratedUiStateSnapshot,
) -> bool {
    let Ok(card) = LensRenderId::new(card_id) else {
        return false;
    };
    let Some(held) = server.lens_frames.card(&card) else {
        return false;
    };
    let mut current = held.state.lock().await;
    if !server.lens_frames.restate(&held, &state) {
        return false;
    }
    *current = state;
    true
}
