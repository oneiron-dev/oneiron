//! The receipt bodies an archive writes in a carried row's derivation
//! envelope (fix list row 15416): the rows a receipt's body was made from
//! count as carried only through a body the copy writes.

use serde_json::Value;

use crate::batch::export::ExportDerivationEnvelope;

/// The id of each receipt of `envelope` whose body its row `written`, as the
/// nulling pass left it, still holds: a preserved receipt the pass kept with
/// its body, in the place the envelope lists it (fix list row 15416).
pub(super) fn written_receipt_bodies<'a>(
    envelope: &'a ExportDerivationEnvelope,
    written: &'a Value,
) -> impl Iterator<Item = String> + 'a {
    let rows = written.get("receipts").and_then(Value::as_array);
    envelope
        .receipts
        .iter()
        .enumerate()
        .filter(move |(at, source)| {
            matches!(
                source,
                crate::batch::export::ExportReceiptSource::Preserved { .. }
            ) && rows
                .and_then(|rows| rows.get(*at))
                .and_then(|row| row.get("body"))
                .is_some_and(|body| !body.is_null())
        })
        .map(|(_, source)| source.receipt_id().to_owned())
}
