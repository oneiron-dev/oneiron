//! The entities a journal item's landing names, kept on the item where its
//! door lands or refuses it (FIX 11151, 11175).

use super::apply::ShapeItemState;
use super::live::ShapeSources;
use crate::EntityId;

/// The receipt refs a landing that rests at `state` keeps: the rows its
/// door listed in `landing`, and the entity a landed receipt names when the
/// door returned one. `None` when the door lists no rows (`landing` is
/// `None`), when a read it ran could not be followed, or when the item did
/// not land or refuse. The journal's own listing `sources` takes the same
/// rows, as when the door listed into it.
pub(super) fn landing_receipt_refs(
    state: &ShapeItemState,
    landing: Option<ShapeSources>,
    sources: &mut ShapeSources,
) -> Option<Vec<String>> {
    let Some(rows) = landing?.into_rows() else {
        sources.unknown();
        return None;
    };
    for id in &rows {
        sources.list(*id);
    }
    let returned = match state {
        ShapeItemState::Landed { receipt, .. } => EntityId::from_hex(receipt).ok(),
        ShapeItemState::Refused { .. } | ShapeItemState::FileRefused { .. } => None,
        _ => return None,
    };
    let mut refs: Vec<String> = rows.iter().map(EntityId::to_hex).collect();
    if let Some(id) = returned.filter(|id| !rows.contains(id)) {
        refs.push(id.to_hex());
    }
    Some(refs)
}
