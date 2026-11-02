//! The turn-body decoder and the entity-ref key validator.

use std::io::Cursor;

use rmpv::Value;

use super::super::support::{TURN_BODY_FACET_REF_KEY, TURN_BODY_WORLD_REF_KEY};
use crate::entity_id::EntityId;

pub(crate) struct TurnBodyFacts {
    pub(crate) speaker: Option<String>,
    pub(crate) text: Option<String>,
    pub(crate) world_ref: Option<EntityId>,
    pub(crate) facet_ref: Option<EntityId>,
    /// The turn is from an imported transcript (ARCH-0027): its evidence is
    /// `Imported` whatever its speaker.
    pub(crate) imported: bool,
    /// The source the import stamp names, when it is one non-empty string.
    pub(crate) import_source: Option<String>,
}

/// The ONE turn-body decoder. In-crate planners (the ONE-1685 session-close
/// wake) share it so a turn's GATE-10 role can never be read one way by the
/// scan and another way by the planner: first-wins across the `spkr|speaker`
/// alias set, exactly as [`super::enumerate_admissible_turns`] admits it.
pub(crate) fn decode_turn_body(raw: &[u8]) -> TurnBodyFacts {
    let mut facts = TurnBodyFacts {
        speaker: None,
        text: None,
        world_ref: None,
        facet_ref: None,
        imported: false,
        import_source: None,
    };
    let Ok(value) = rmpv::decode::read_value(&mut Cursor::new(raw)) else {
        return facts;
    };
    let Value::Map(entries) = value else {
        return facts;
    };
    for (key, value) in entries {
        match key.as_str() {
            Some("spkr" | "speaker") => {
                if facts.speaker.is_none() {
                    facts.speaker = value.as_str().map(str::to_owned);
                }
            }
            Some("txt" | "text") => {
                if facts.text.is_none() {
                    facts.text = value.as_str().map(str::to_owned);
                }
            }
            Some(TURN_BODY_WORLD_REF_KEY) => facts.world_ref = entity_ref_from_value(&value),
            Some(TURN_BODY_FACET_REF_KEY) => facts.facet_ref = entity_ref_from_value(&value),
            // Present at all, whatever its value: a malformed stamp fails toward
            // the lower trust class, never up.
            Some(crate::memory::IMPORTED_SOURCE_KEY) => {
                facts.imported = true;
                facts.import_source = value.as_str().filter(|s| !s.is_empty()).map(str::to_owned);
            }
            _ => {}
        }
    }
    facts
}

/// Validator for the documented opt-in `world_ref`/`facet_ref` turn-body
/// keys: exactly 16 MessagePack-binary bytes forming a valid entity id.
#[must_use]
pub fn entity_ref_from_value(value: &Value) -> Option<EntityId> {
    let Value::Binary(bytes) = value else {
        return None;
    };
    let raw: [u8; 16] = bytes.as_slice().try_into().ok()?;
    EntityId::from_bytes(raw).ok()
}
