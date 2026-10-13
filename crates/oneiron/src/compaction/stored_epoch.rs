//! Whether a stored SUMMARY is an epoch summary, in every form it is stored
//! in (Astra 1384e).

use rmpv::Value;

use super::decode_epoch_summary_body;
use crate::entity_id::EntityId;
use crate::error::Result;

/// What a stored SUMMARY body is, whichever form it is stored in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoredEpoch {
    /// No epoch summary.
    No,
    /// An epoch summary, its text inline or on the document plane.
    Yes,
    /// A document pointer no head stands for in this transaction. It may be
    /// an epoch summary, so a reader holds it as one it cannot place.
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
/// the document plane, the row keeps every other key beside a pointer, and the
/// document's head names the field it holds. The keyframe in those keys,
/// which no text edit changes, makes it an epoch: the codec decides with that
/// field standing in, and the document is never loaded.
pub(crate) fn stored_epoch_in(
    dbs: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<StoredEpoch> {
    if decode_epoch_summary_body(body).is_ok() {
        return Ok(StoredEpoch::Yes);
    }
    let mut cursor = body;
    let Ok(Value::Map(mut fields)) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(StoredEpoch::No);
    };
    let keys = fields.len();
    fields.retain(|(key, _)| key.as_str() != Some("entity_doc_ref"));
    if fields.len() == keys {
        return Ok(StoredEpoch::No);
    }
    if !cursor.is_empty() {
        return Ok(StoredEpoch::Unresolved);
    }
    pointer_epoch_in(dbs, txn, id, fields)
}

/// [`stored_epoch_in`] for a pointer row's other keys, `fields`.
#[cfg(feature = "sync")]
fn pointer_epoch_in(
    dbs: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    mut fields: Vec<(Value, Value)>,
) -> Result<StoredEpoch> {
    let Some(field) = crate::entity_doc::pointer_field_in(dbs, txn, id)? else {
        return Ok(StoredEpoch::Unresolved);
    };
    let crate::entity_doc::TextField::MapField(name) = field else {
        return Ok(StoredEpoch::No);
    };
    // U+FFFC, the object replacement character, stands for the text.
    fields.push((Value::from(name), Value::from("\u{fffc}")));
    let mut keyframe = Vec::new();
    rmpv::encode::write_value(&mut keyframe, &Value::Map(fields))
        .map_err(|_| crate::error::Error::InvariantViolation("MessagePack encode failed"))?;
    Ok(if decode_epoch_summary_body(&keyframe).is_ok() {
        StoredEpoch::Yes
    } else {
        StoredEpoch::No
    })
}

/// Without the document plane no head can stand for a pointer. The signature
/// is the document plane's, whose head read is fallible.
#[cfg(not(feature = "sync"))]
#[expect(clippy::unnecessary_wraps)]
fn pointer_epoch_in(
    _dbs: &impl crate::side_table::SideTableDbs,
    _txn: &heed::RoTxn<'_>,
    _id: &EntityId,
    _fields: Vec<(Value, Value)>,
) -> Result<StoredEpoch> {
    Ok(StoredEpoch::Unresolved)
}
