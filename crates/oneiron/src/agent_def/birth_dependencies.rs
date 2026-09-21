//! Retirement of copied agent source when a captured input is erased.
use super::birth_custody::{birth_carriers_for_holder_in_txn, retire_birth_source_holder_in_txn};
use crate::{
    entity_id::EntityId,
    error::{Error, Result},
    store::Store,
};
use std::collections::BTreeSet;
const INPUT: &[u8] = b"agent_def/birth-input/v1\0";
const RETIRED_INPUT: &[u8] = b"agent_def/birth-input-retired/v1\0";
fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}
pub(super) fn check_inputs(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    inputs: &BTreeSet<EntityId>,
) -> Result<()> {
    for input in inputs {
        if store
            .vault_meta
            .get(txn, &key(RETIRED_INPUT, input))?
            .is_some()
            || store
                .sync_state
                .get(txn, &format!("dt:{}", input.to_hex()))?
                .is_some()
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
        let mut binding = key(INPUT, &input);
        binding.extend_from_slice(child.as_bytes());
        store.vault_meta.put(txn, &binding, &[])?;
    }
    Ok(())
}
fn children_for_input(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    input: &EntityId,
) -> Result<Vec<EntityId>> {
    let prefix = key(INPUT, input);
    let mut children = Vec::new();
    for row in store.vault_meta.prefix_iter(txn, &prefix)? {
        let (key, value) = row?;
        if !value.is_empty() {
            return Err(Error::CorruptedIndex("agent birth input binding"));
        }
        children.push(crate::entity_id::parse_entity_id(
            &key[prefix.len()..],
            "agent birth input child",
        )?);
    }
    Ok(children)
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
        store
            .vault_meta
            .put(txn, &key(RETIRED_INPUT, &input), &[])?;
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
