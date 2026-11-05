//! Retirement of copied agent source when a captured input is erased.
use super::birth_custody::retire_birth_source_holder_in_txn;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::side_table::{self, Raw, SideTable};
use crate::store::agent_birth_custody::{
    INPUT, birth_carriers_for_holder_in_txn, children_for_input,
};
use crate::{
    entity_id::EntityId,
    error::{Error, Result},
    store::Store,
};
use std::collections::BTreeSet;

/// Empty marker: a captured dependency input has been retired.
const RETIRED_INPUT: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::AGENT_DEF_BIRTH_INPUT_RETIRED);

pub(super) fn check_inputs(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    inputs: &BTreeSet<EntityId>,
) -> Result<()> {
    for input in inputs {
        if RETIRED_INPUT.contains(store, txn, input)?
            || store.port_deletion_marked(txn, DeletionMarker::HardDelete, input)?
            || store.off_record_sessions.contains_entity(input)?
        {
            return Err(Error::Artifact(
                crate::error::ArtifactError::InvalidAgentDefBody(
                    "captured source input was retired",
                ),
            ));
        }
    }
    Ok(())
}
pub(super) fn bind_inputs(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    source: &super::portable_source::AgentBirthSource,
) -> Result<()> {
    let child = source.child()?;
    for input in source.dependencies()? {
        INPUT.put(store, txn, &(input, child), &())?;
    }
    Ok(())
}
pub(super) fn retire_input(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    input: &EntityId,
) -> Result<()> {
    let store = write.store;
    let mut children = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut pending = vec![*input];
    while let Some(input) = pending.pop() {
        if !visited.insert(input) {
            continue;
        }
        RETIRED_INPUT.put(store, txn, &input, &())?;
        for child in children_for_input(store, txn, &input)? {
            if children.insert(child) {
                pending.extend(birth_carriers_for_holder_in_txn(store, txn, &child)?);
            }
        }
    }
    // Seal the full dependent set before calling deindex. Its normal custody
    // hook then sees retired sources, so even adversarial cross-links cannot
    // turn a long dependency chain into recursive stack growth.
    let children = children
        .into_iter()
        .filter_map(
            |child| match super::birth_custody::birth_source_retired(store, txn, &child) {
                Ok(true) => None,
                Ok(false) => Some(Ok(child)),
                Err(error) => Some(Err(error)),
            },
        )
        .collect::<Result<Vec<_>>>()?;
    for child in &children {
        super::birth_custody::mark_birth_source_retired(store, txn, child)?;
    }
    for child in children {
        retire_birth_source_holder_in_txn(write, txn, &child)?;
    }
    Ok(())
}
/// Tombstone-first erasure has no live row to deindex, but still retires inputs.
pub(crate) fn retire_birth_sources_for_entity_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    input: &EntityId,
) -> Result<()> {
    let store = write.store;
    retire_input(write, txn, input)?;
    retire_birth_source_holder_in_txn(write, txn, input)
}
