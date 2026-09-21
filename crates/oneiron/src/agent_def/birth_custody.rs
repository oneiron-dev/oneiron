//! Physical custody of captured agent source, without authorship or delete grants.
use super::portable_source::{birth_source_id, decode_birth_source};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET};
use crate::{
    entity_id::EntityId,
    error::{Error, Result},
    store::Store,
};
const OWNED: &[u8] = b"agent_def/birth-custody/v1\0";
const BINDING: &[u8] = b"agent_def/birth-asset-binding/v1\0";
const RETIRED: &[u8] = b"agent_def/birth-retired/v1\0";
fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}
fn invalid() -> Error {
    Error::Artifact(crate::error::ArtifactError::InvalidAgentDefBody(
        "agent birth source custody retired or mismatched",
    ))
}
pub(super) fn birth_source_retired(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    child: &EntityId,
) -> Result<bool> {
    Ok(store.vault_meta.get(txn, &key(RETIRED, child))?.is_some())
}
pub(super) fn mark_birth_source_retired(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    child: &EntityId,
) -> Result<()> {
    store.vault_meta.put(txn, &key(RETIRED, child), &[])?;
    Ok(())
}
pub(super) fn check_birth_custody(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    child: &EntityId,
) -> Result<()> {
    if store.vault_meta.get(txn, &key(RETIRED, child))?.is_some()
        || store
            .sync_state
            .get(txn, &format!("dt:{}", child.to_hex()))?
            .is_some()
        || store.off_record_sessions.contains_entity(child)?
    {
        return Err(invalid());
    }
    if let Some(raw) = store.entities.get(txn, child.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("agent birth holder header"))?;
        if header.entity_type != ENTITY_TYPE_AGENT_DEF || raw.len() == ENTITY_METADATA_HEADER_LEN {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(super) fn check_registered_birth_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    bytes: &[u8],
) -> Result<()> {
    let Some(binding) = store.vault_meta.get(txn, &key(BINDING, id))? else {
        return Ok(());
    };
    let child = crate::entity_id::parse_entity_id(&binding, "agent birth asset binding")?;
    if kind != ENTITY_TYPE_ASSET
        || decode_birth_source(bytes)?.is_none_or(|source| source.child().ok() != Some(child))
    {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn stage_birth_custody_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    kind: u8,
    bytes: &[u8],
) -> Result<()> {
    if kind == ENTITY_TYPE_ASSET
        && let Some(source) = decode_birth_source(bytes)?
    {
        let child = source.child()?;
        super::birth_dependencies::bind_inputs(store, txn, &source)?;
        store
            .vault_meta
            .put(txn, &key(OWNED, &child), id.as_bytes())?;
        store
            .vault_meta
            .put(txn, &key(BINDING, id), child.as_bytes())?;
    }
    if kind != ENTITY_TYPE_AGENT_DEF && store.vault_meta.get(txn, &key(OWNED, id))?.is_some() {
        retire_birth_source_holder_in_txn(store, txn, id)?;
    }
    Ok(())
}
pub(crate) fn birth_carriers_for_holder_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    child: &EntityId,
) -> Result<Vec<EntityId>> {
    match store.vault_meta.get(txn, &key(OWNED, child))? {
        None => Ok(vec![]),
        Some(raw) => {
            let id = crate::entity_id::parse_entity_id(&raw, "agent source custody ID")?;
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
    for id in super::birth_dependencies::birth_carriers_for_erased_entity_in_txn(store, txn, child)?
    {
        if store.entities.get(txn, id.as_bytes())?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Source-only retirement also records tombstone-before-source arrival. It
/// does not write a generic tombstone, restore authority, or remove the child.
pub(crate) fn retire_birth_source_holder_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    child: &EntityId,
) -> Result<()> {
    mark_birth_source_retired(store, txn, child)?;
    for id in birth_carriers_for_holder_in_txn(store, txn, child)? {
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("agent source carrier header"))?;
        if header.entity_type != ENTITY_TYPE_ASSET {
            return Err(Error::CorruptedIndex("agent source carrier type"));
        }
        let source = decode_birth_source(&raw[ENTITY_METADATA_HEADER_LEN..])?
            .ok_or(Error::CorruptedIndex("agent source carrier body"))?;
        if source.child()? != *child {
            return Err(Error::CorruptedIndex("agent source carrier holder"));
        }
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, &id)?;
        crate::ppr::invalidate_ppr_for_delete(store, txn, &id, &neighbors)?;
        if graph {
            crate::ppr::increment_graph_version(store, txn)?;
        }
        if vector {
            crate::hnsw::increment_vector_version(store, txn)?;
        }
    }
    Ok(())
}
pub(crate) fn remove_birth_custody_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if let Some(raw) = store.entities.get(txn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("agent source delete header"))?;
        if header.entity_type == ENTITY_TYPE_ASSET
            && let Some(source) = decode_birth_source(&raw[ENTITY_METADATA_HEADER_LEN..])?
        {
            // Direct carrier deletion retires its payload, never its agent row.
            store
                .vault_meta
                .put(txn, &key(RETIRED, &source.child()?), &[])?;
            super::birth_dependencies::retire_input(store, txn, id)?;
            return Ok(());
        }
        if header.entity_type == ENTITY_TYPE_AGENT_DEF {
            return super::birth_dependencies::retire_birth_sources_for_entity_in_txn(
                store, txn, id,
            );
        }
    }
    super::birth_dependencies::retire_input(store, txn, id)?;
    if store.vault_meta.get(txn, &key(OWNED, id))?.is_some() {
        retire_birth_source_holder_in_txn(store, txn, id)?;
    }
    Ok(())
}
