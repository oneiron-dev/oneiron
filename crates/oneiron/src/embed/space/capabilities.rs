//! What a redeclared space keeps for the slots that use it (FIX 9832).

use std::collections::BTreeSet;

use heed::RoTxn;

use super::{EmbeddingSpace, InputKind, kind_slot_bindings_in_txn};
use crate::embed::space_move::moving_kind_in_txn;
use crate::error::Result;
use crate::side_table::SideTableDbs;

/// `declared` as the declaration writer stores it over `existing`, the same space at the same
/// width (FIX 9832). A slot bound to the space, or carried to it by an open move, keeps the input
/// kind it fills and the query towers its queries enter by, its own kind's and the text tower,
/// until an explicit move or rebind releases it; every other change applies at once. The
/// setup records publish the space as stored, so they read what it serves. No declaration is
/// refused for it.
///
/// # Errors
/// A store failure.
pub(crate) fn reconcile_bound_space_capabilities_in_txn(
    store: &impl SideTableDbs,
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
