//! Re-admit kept room pins through the same projection and P7 as fresh pins.

use std::collections::BTreeSet;

use crate::auth::CoreAuth;
use crate::error::ApiError;
use oneiron::{DisclosureContext, EntityId, MemoriesSection, Vault};

pub(crate) fn room_pins_admitted(
    vault: &Vault,
    auth: &CoreAuth,
    room: Option<EntityId>,
    documents: &BTreeSet<EntityId>,
    disclosure: Option<&DisclosureContext>,
) -> Result<bool, ApiError> {
    if documents.is_empty() {
        return Ok(true);
    }
    let Some(room) = room else {
        return Ok(false);
    };
    let Some(memory) = super::board_memory(vault, auth) else {
        return Ok(false);
    };
    // This is a read only: reprojecting the current pins records no delivery
    // receipt and spends no once answer.
    let mut section = MemoriesSection::pins_only(None);
    let admitted = super::include_board_room_pins(&memory, room, disclosure, &mut section)?;
    let admitted: BTreeSet<_> = admitted.into_iter().map(|pin| pin.target).collect();
    Ok(documents.is_subset(&admitted))
}
