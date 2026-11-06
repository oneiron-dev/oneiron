//! Core half of `entity_doc::sync::birth_fields`: its store-layer items live in `oneiron_store::entity_doc::sync::birth_fields` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::entity_doc::sync::birth_fields::*;

use crate::EntityId;
use crate::entity_doc::TextField;
use crate::registry::ENTITY_TYPE_TURN;

/// The field `kind`'s lazy birth keeps its text in; `None` for a kind with no
/// rule here.
pub(super) fn field(kind: u8) -> Option<TextField> {
    match kind {
        ENTITY_TYPE_TURN => Some(TextField::MapField(TURN_TEXT.to_owned())),
        _ => None,
    }
}
