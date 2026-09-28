//! Retirement of copied agent source when a captured input is erased.
use super::birth_custody::{birth_carriers_for_holder_in_txn, retire_birth_source_holder_in_txn};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::{
    entity_id::EntityId,
    error::{Error, Result},
    store::Store,
};
use std::collections::BTreeSet;

/// Empty-marker index from a captured dependency input to a birthed-agent
/// child. Key: the input's id, then the child's id.
const INPUT: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::AGENT_DEF_BIRTH_INPUT);
/// Empty marker: a captured dependency input has been retired.
const RETIRED_INPUT: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::AGENT_DEF_BIRTH_INPUT_RETIRED);
/// The ARCH-0023b global local hard-delete marker (owned by
/// `crate::deletion::tombstone`); read-only here for the retired/deleted check.
const HARD_DELETE_MARKER: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_HARD_DELETE_MARKER);

pub(super) fn check_inputs(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    inputs: &BTreeSet<EntityId>,
) -> Result<()> {
    for input in inputs {
        if RETIRED_INPUT.contains(store, txn, input)?
            || HARD_DELETE_MARKER.contains(store, txn, &HexId(*input))?
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
fn children_for_input(
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
pub(super) fn retire_input(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    input: &EntityId,
) -> Result<()> {
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
        retire_birth_source_holder_in_txn(store, txn, &child)?;
    }
    Ok(())
}
/// Tombstone-first erasure has no live row to deindex, but still retires inputs.
pub(crate) fn retire_birth_sources_for_entity_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    input: &EntityId,
) -> Result<()> {
    retire_input(store, txn, input)?;
    retire_birth_source_holder_in_txn(store, txn, input)
}
