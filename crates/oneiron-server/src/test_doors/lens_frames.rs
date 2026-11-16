//! Doors for `tests/lens_frame_state_door.rs`: moves a held card's `$state`
//! as an accepted local event moves it, so the test reads that state back
//! through the card's own route. No card the default lens renders carries a
//! local action, so no event can move it there. [`set_owner_proof`] and
//! [`set_weave_admin_proof`] hold a card as the owner lens and the weave
//! Admin lens hold theirs: both render through a model route no fixture
//! there has.

use oneiron::EntityId;
use oneiron::lens::{GeneratedUiStateSnapshot, LensRenderId};

use crate::lens_frames::HeldCardProof;
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

/// Holds card `card_id` as one the owner lens rendered under an Owner
/// proof, as `/v1/owner/weave/lens` and `/v1/owner/weave/digest` hold
/// theirs. `false` when the server holds no such card.
pub fn set_owner_proof(server: &SyncServer, card_id: &str) -> bool {
    LensRenderId::new(card_id)
        .is_ok_and(|card| server.lens_frames.set_proof(&card, HeldCardProof::Owner))
}

/// Holds card `card_id` as one the weave Admin lens rendered under the
/// Admin membership grant `membership_grant`, as `vault.weave.admin.lens`
/// and `vault.weave.admin.digest` hold theirs. `false` when the server
/// holds no such card.
pub fn set_weave_admin_proof(
    server: &SyncServer,
    card_id: &str,
    membership_grant: EntityId,
) -> bool {
    LensRenderId::new(card_id).is_ok_and(|card| {
        server
            .lens_frames
            .set_proof(&card, HeldCardProof::WeaveAdmin { membership_grant })
    })
}
