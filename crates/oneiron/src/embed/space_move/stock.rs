use super::{BTreeSet, InputKind, KindSlotBindings, SpaceRef};

pub(in crate::embed) fn stock_move_kinds(bindings: &KindSlotBindings) -> BTreeSet<InputKind> {
    let incumbent = bindings
        .text
        .clone()
        .map_or(SpaceRef::TextIndex, SpaceRef::Declared);
    InputKind::ALL
        .into_iter()
        .filter(|kind| incumbent.serves(bindings, *kind))
        .collect()
}
