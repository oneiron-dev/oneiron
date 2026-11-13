//! Doors for `tests/lens_frame_state_door.rs`: moves a held card's `$state`
//! as an accepted local event moves it, so the test reads that state back
//! through the card's own route. No card the default lens renders carries a
//! local action, so no event can move it there. A run's live re-render of a
//! card with `$state` is held through [`replace_run_card`], and its held
//! state read back through [`held_state`]: no lens a run renders today
//! declares `$state`.

use oneiron::EntityId;
use oneiron::claim::ScopedReadActorKey;
use oneiron::lens::{
    GeneratedUiRender, GeneratedUiStateSnapshot, LensPrincipalBinding, LensRenderFrame,
    LensRenderId,
};
use oneiron::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};

use crate::lens_frames::CardOwner;
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

/// Holds `render` as run `run`'s card for its live subscription
/// `subscription`, as the run's live re-render holds it: it replaces the
/// card the run last held for that subscription and carries that card's
/// `$state`. Answers the render as held. The frame binds the run's own read
/// key and mints no backing ref, so `render` binds no row.
pub async fn replace_run_card(
    server: &SyncServer,
    run: EntityId,
    subscription: &str,
    render: GeneratedUiRender,
) -> MemoryResult<GeneratedUiRender> {
    let key = ScopedReadActorKey::new(run.to_hex())
        .ok_or_else(|| MemoryError::new(MEMORY_CODE_INTERNAL, "a run id names a read key", &[]))?;
    let frame = LensRenderFrame::new(
        render.card_id.clone(),
        LensPrincipalBinding::of_read_key(key)?,
    );
    let owner = CardOwner {
        creator_run: run.to_hex(),
        subscription: Some(subscription.to_owned()),
    };
    server
        .lens_frames
        .replace_for_run(run, frame, render.clone(), owner)?;
    Ok(render)
}

/// The held `$state` of card `card_id`; `None` when the server holds no
/// such card.
pub async fn held_state(server: &SyncServer, card_id: &str) -> Option<GeneratedUiStateSnapshot> {
    let card = LensRenderId::new(card_id).ok()?;
    let held = server.lens_frames.card(&card)?;
    let state = held.state.lock().await.clone();
    Some(state)
}
