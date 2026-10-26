//! Whether a stored SUMMARY is an epoch summary, in every form it is stored
//! in (Astra 1384e).

use rmpv::Value;

use super::epoch::KEY_EPOCH_TEXT;
use super::withdrawn::WithdrawnKeyframe;
use super::{EPOCH_SUMMARY_BODY_KEYS, decode_epoch_summary_body};
use crate::entity_id::EntityId;
use crate::error::Result;

/// What a stored SUMMARY body is, whichever form it is stored in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoredEpoch {
    /// No epoch summary.
    No,
    /// An epoch summary, its text inline or on the document plane.
    Yes,
    /// A document pointer that keeps an epoch's keyframe, whose head in this
    /// transaction does not complete it. A reader holds it as an epoch it
    /// cannot place.
    Unresolved,
}

impl StoredEpoch {
    /// Whether a reader takes the row as an epoch summary.
    pub(crate) fn may_be(self) -> bool {
        self != Self::No
    }
}

/// Whether the stored SUMMARY body `body` of `id` is an epoch summary, in
/// every form it is stored in (Astra 1384e). When its owner moves its text to
/// the document plane, the row keeps every other key beside a pointer. The
/// row decides the shape and the document's head only completes it (Astra
/// 1384f): a pointer that keeps every keyframe key is an epoch when its head
/// supplies the text and the strict codec passes with a stand-in there, and
/// one it cannot place otherwise; a pointer without them is none. No text
/// edit changes the keyframe, and the document is never loaded. A withdrawn
/// epoch keeps only its keyframe, with no text and no pointer, and is one.
pub(crate) fn stored_epoch_in(
    dbs: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<StoredEpoch> {
    if decode_epoch_summary_body(body).is_ok() || WithdrawnKeyframe::decode(body).is_ok() {
        return Ok(StoredEpoch::Yes);
    }
    let mut cursor = body;
    let Ok(Value::Map(mut fields)) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(StoredEpoch::No);
    };
    let keys = fields.len();
    fields.retain(|(key, _)| key.as_str() != Some("entity_doc_ref"));
    let keyframe = EPOCH_SUMMARY_BODY_KEYS
        .iter()
        .filter(|key| **key != KEY_EPOCH_TEXT)
        .all(|key| fields.iter().any(|(held, _)| held.as_str() == Some(*key)));
    if fields.len() == keys || !keyframe {
        return Ok(StoredEpoch::No);
    }
    if !cursor.is_empty() {
        return Ok(StoredEpoch::Unresolved);
    }
    pointer_epoch_in(dbs, txn, id, fields)
}

/// [`stored_epoch_in`] for the other keys, `fields`, of a pointer row that
/// keeps an epoch's keyframe.
fn pointer_epoch_in(
    dbs: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    mut fields: Vec<(Value, Value)>,
) -> Result<StoredEpoch> {
    let Some(crate::entity_doc::TextField::MapField(field)) =
        crate::entity_doc::pointer_field_in(dbs, txn, id)?
    else {
        return Ok(StoredEpoch::Unresolved);
    };
    if field != KEY_EPOCH_TEXT {
        return Ok(StoredEpoch::Unresolved);
    }
    // U+FFFC, the object replacement character, stands for the text.
    fields.push((Value::from(field), Value::from("\u{fffc}")));
    let mut keyframe = Vec::new();
    rmpv::encode::write_value(&mut keyframe, &Value::Map(fields))
        .map_err(|_| crate::error::Error::InvariantViolation("MessagePack encode failed"))?;
    Ok(if decode_epoch_summary_body(&keyframe).is_ok() {
        StoredEpoch::Yes
    } else {
        StoredEpoch::Unresolved
    })
}
