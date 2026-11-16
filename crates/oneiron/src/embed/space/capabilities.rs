//! What a redeclared space keeps for the slots and worlds that use it (FIX 9832).

use std::collections::BTreeSet;

use heed::RoTxn;

use super::{EmbeddingSpace, InputKind, kind_slot_bindings_in_txn};
use crate::embed::space_move::moving_kind_in_txn;
use crate::embed::world_space::WorldTextSpaces;
use crate::error::Result;
use crate::store::Store;

/// `declared` as the declaration writer stores it over `existing`, the same space at the same
/// width (FIX 9832). A slot bound to the space, or carried to it by an open move, keeps the input
/// kind it fills and the query towers its queries enter by, its own kind's and the text tower,
/// until an explicit move or rebind releases it. A world whose model order names the space as
/// its text space keeps text the same way, until the owner changes that order (DEC-0005
/// #private-world-vectors): a redeclaration without text would otherwise end the world's hold
/// on its rows, and send them to the vault's index or a rung its order never named. Every other
/// change applies at once. The world orders are read under the hosting posture the store was
/// opened with. The setup records publish the space as stored, so they read what it serves. No
/// declaration is refused for it.
///
/// # Errors
/// A store failure.
pub(crate) fn reconcile_bound_space_capabilities_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    existing: &EmbeddingSpace,
    declared: &EmbeddingSpace,
) -> Result<EmbeddingSpace> {
    let bindings = kind_slot_bindings_in_txn(store, txn)?;
    let mut used = BTreeSet::new();
    for kind in InputKind::ALL {
        if bindings.space_for(kind) == Some(existing.id.as_str())
            || moving_kind_in_txn(store, txn, kind)?.as_deref() == Some(existing.id.as_str())
        {
            used.insert(kind);
        }
    }
    if WorldTextSpaces::read_for_store_in(store, store.privacy_posture, txn)?.names(&existing.id) {
        used.insert(InputKind::Text);
    }
    let mut effective = declared.clone();
    if used.is_empty() {
        return Ok(effective);
    }
    effective
        .accepts
        .extend(existing.accepts.intersection(&used).copied());
    let towers: BTreeSet<InputKind> = used.iter().copied().chain([InputKind::Text]).collect();
    effective
        .query_towers
        .extend(existing.query_towers.intersection(&towers).copied());
    Ok(effective)
}
