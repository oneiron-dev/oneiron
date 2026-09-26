//! Physical custody of captured agent source, without authorship or delete grants.
use super::portable_source::{birth_source_id, decode_birth_source};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::{
    entity_id::EntityId,
    error::{Error, Result},
    store::Store,
};

/// Which asset entity currently holds custody of a birthed agent's captured
/// source. Key: the birthed child's id; value: the holder asset's id.
const OWNED: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::AGENT_DEF_BIRTH_CUSTODY_OWNED);
/// Binds a captured-source ASSET id back to the child agent it was birthed
/// for. Key: the asset's id; value: the child's id.
const BINDING: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::AGENT_DEF_BIRTH_ASSET_BINDING);
/// Empty marker: an agent's birth source has been retired.
const RETIRED: SideTable<EntityId, (), Raw> = SideTable::new(&side_table::AGENT_DEF_BIRTH_RETIRED);
/// The ARCH-0023b global local hard-delete marker (owned by
/// `crate::deletion::tombstone`); read-only here for the retired/deleted check.
const HARD_DELETE_MARKER: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_HARD_DELETE_MARKER);

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
    RETIRED.contains(store, txn, child)
}
pub(super) fn mark_birth_source_retired(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    child: &EntityId,
) -> Result<()> {
    RETIRED.put(store, txn, child, &())
}
pub(super) fn check_birth_custody(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    child: &EntityId,
) -> Result<()> {
    if RETIRED.contains(store, txn, child)?
        || HARD_DELETE_MARKER.contains(store, txn, &HexId(*child))?
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
    let Some(child) = BINDING.get(store, txn, id)? else {
        return Ok(());
    };
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
        OWNED.put(store, txn, &child, id)?;
        BINDING.put(store, txn, id, &child)?;
    }
    if kind != ENTITY_TYPE_AGENT_DEF && OWNED.contains(store, txn, id)? {
        retire_birth_source_holder_in_txn(store, txn, id)?;
    }
    Ok(())
}
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
            RETIRED.put(store, txn, &source.child()?, &())?;
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
    if OWNED.contains(store, txn, id)? {
        retire_birth_source_holder_in_txn(store, txn, id)?;
    }
    Ok(())
}
