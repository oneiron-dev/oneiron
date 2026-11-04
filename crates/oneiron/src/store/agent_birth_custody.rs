//! Physical custody of a birthed agent's captured source, read side: which
//! asset holds a child's source, which children a captured input fed, and
//! which carriers an erased entity reaches. The agent definition layer
//! (`agent_def`) writes and retires these rows; the store's erase and
//! deletion-receipt paths read them.
use crate::side_table::{self, Raw, SideTable};
use crate::store::agent_birth_identity::birth_source_id;
use crate::{
    entity_id::EntityId,
    error::{Error, Result},
    store::Store,
};
use std::collections::BTreeSet;

/// Which asset entity currently holds custody of a birthed agent's captured
/// source. Key: the birthed child's id; value: the holder asset's id.
pub(crate) const OWNED: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::AGENT_DEF_BIRTH_CUSTODY_OWNED);
/// Empty-marker index from a captured dependency input to a birthed-agent
/// child. Key: the input's id, then the child's id.
pub(crate) const INPUT: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::AGENT_DEF_BIRTH_INPUT);
pub(crate) fn birth_carriers_for_holder_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    child: &EntityId,
) -> Result<Vec<EntityId>> {
    match OWNED.get(store, txn, child)? {
        None => Ok(vec![]),
        Some(id) => {
            if id != birth_source_id(child)? {
                return Err(Error::CorruptedIndex("agent source custody ID"));
            }
            Ok(vec![id])
        }
    }
}
pub(crate) fn birth_custody_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    child: &EntityId,
) -> Result<bool> {
    for id in birth_carriers_for_erased_entity_in_txn(store, txn, child)? {
        if crate::ports::EntityStoreRead::port_entity_present(store, txn, &id)? {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(crate) fn children_for_input(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    input: &EntityId,
) -> Result<Vec<EntityId>> {
    Ok(INPUT
        .scan_from(store, txn, input.as_bytes())?
        .into_iter()
        .map(|((_, child), ())| child)
        .collect())
}
/// Includes direct ownership and copies of this input. Index entries grant no
/// authority over the child rows: only their captured ASSET payloads are scoped.
pub(crate) fn birth_carriers_for_erased_entity_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    input: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut carriers = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut pending = vec![*input];
    while let Some(input) = pending.pop() {
        if !visited.insert(input) {
            continue;
        }
        let mut children = children_for_input(store, txn, &input)?;
        children.push(input);
        for child in children {
            for carrier in birth_carriers_for_holder_in_txn(store, txn, &child)? {
                if carriers.insert(carrier) {
                    pending.push(carrier);
                }
            }
        }
    }
    Ok(carriers.into_iter().collect())
}
