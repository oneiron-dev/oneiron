//! The canonical-birth field rules of the kinds besides MESSAGE whose text
//! the sync plane births lazily (FIX 11794; L01 01:24 YES): which field of a
//! record's body holds its text, which bodies the birth takes, and the body
//! with that text replaced by the document pointer. MESSAGE's own rule stays
//! `split_content`; the dispatch beside it reads these. A body no rule takes
//! keeps its text in its sequence rows, as before.
//!
//! - TURN: its `txt` string, in a canonical MessagePack map that holds no
//!   other text alias (`text`), no editable metadata field and no document
//!   pointer yet. A turn that carries its text under `text`, or under both,
//!   is not born here.

use crate::EntityId;
use crate::entity_doc::TextField;
use crate::registry::ENTITY_TYPE_TURN;

/// The field a born record's body names its document by.
const POINTER: &str = "entity_doc_ref";
/// The field a TURN's lazy birth takes its text from.
const TURN_TEXT: &str = "txt";
/// The TURN text alias whose presence keeps a turn out of the birth.
const TURN_ALIAS: &str = "text";

/// The field `kind`'s lazy birth keeps its text in; `None` for a kind with no
/// rule here.
pub(super) fn field(kind: u8) -> Option<TextField> {
    match kind {
        ENTITY_TYPE_TURN => Some(TextField::MapField(TURN_TEXT.to_owned())),
        _ => None,
    }
}

/// `kind`'s canonical text in `body`, and `body` with it replaced by the
/// pointer to `entity`'s document, as its birth writes it; `None` for a kind
/// with no rule here or a body its rule does not take.
pub(super) fn split(kind: u8, body: &[u8], entity: &EntityId) -> Option<(String, Vec<u8>)> {
    match kind {
        ENTITY_TYPE_TURN => split_map_field(body, TURN_TEXT, &[TURN_ALIAS], entity),
        _ => None,
    }
}

/// The string under `field` in `body`, a canonical MessagePack map with
/// string keys that names it once and holds none of `aliases`, no editable
/// metadata field and no pointer, and the map with it removed and the
/// pointer to `entity` added last, as `split_content` leaves a MESSAGE.
fn split_map_field(
    body: &[u8],
    field: &str,
    aliases: &[&str],
    entity: &EntityId,
) -> Option<(String, Vec<u8>)> {
    let mut cursor = body;
    let rmpv::Value::Map(mut fields) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    if !cursor.is_empty() {
        return None;
    }
    // One spelling: the bytes every machine splits are the bytes it re-encodes.
    let mut canonical = Vec::new();
    rmpv::encode::write_value(&mut canonical, &rmpv::Value::Map(fields.clone())).ok()?;
    if canonical != body {
        return None;
    }
    let mut slot = None;
    for (at, (key, _)) in fields.iter().enumerate() {
        let key = key.as_str()?;
        if key == field {
            if slot.replace(at).is_some() {
                return None;
            }
        } else if key == POINTER || aliases.contains(&key) || crate::ports::is_metadata_field(key) {
            return None;
        }
    }
    let (_, value) = fields.remove(slot?);
    let text = value.as_str()?.to_owned();
    fields.push((
        rmpv::Value::from(POINTER),
        rmpv::Value::from(entity.to_hex()),
    ));
    let mut pointer = Vec::new();
    rmpv::encode::write_value(&mut pointer, &rmpv::Value::Map(fields)).ok()?;
    Some((text, pointer))
}
