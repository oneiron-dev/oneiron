//! Identifier-only source custody. Binding never confers receipt or claim authority.
use super::codec::{ReceiptArchive, decode, invalid};
use crate::{
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    entity_id::EntityId,
    error::{Error, Result},
    registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM},
    store::Store,
};
use std::collections::BTreeSet;
const OWNED: &[u8] = b"receipt/archive-owned/v1\0";
const BINDING: &[u8] = b"receipt/archive-binding/v1\0";
const RETIRED_HOLDER: &[u8] = b"receipt/archive-holder-retired/v1\0";
const RETIRED_SOURCE: &[u8] = b"receipt/archive-source-retired/v1\0";
fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}
fn owned_key(holder: &EntityId, id: &EntityId) -> Vec<u8> {
    let mut key = key(OWNED, holder);
    key.extend_from_slice(id.as_bytes());
    key
}
fn retired(store: &Store, txn: &heed::RoTxn<'_>, prefix: &[u8], id: &EntityId) -> Result<bool> {
    Ok(store.vault_meta.get(txn, &key(prefix, id))?.is_some()
        || store
            .sync_state
            .get(txn, &format!("dt:{}", id.to_hex()))?
            .is_some()
        || store.off_record_sessions.contains_entity(id)?)
}

pub(crate) fn validate_receipt_archive_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    body: &[u8],
) -> Result<()> {
    let source = if kind == ENTITY_TYPE_ASSET {
        decode(body)?
    } else {
        None
    };
    if store.vault_meta.get(txn, &key(BINDING, id))?.is_some() && source.is_none() {
        return Err(invalid());
    }
    let Some(source) = source else {
        return Ok(());
    };
    let holder = source.holder()?;
    if source.id()? != *id
        || holder == *id
        || retired(store, txn, RETIRED_HOLDER, &holder)?
        || retired(store, txn, RETIRED_SOURCE, id)?
    {
        return Err(invalid());
    }
    if let Some(raw) = store.entities.get(txn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("receipt source header"))?;
        if header.entity_type != ENTITY_TYPE_ASSET || raw[ENTITY_METADATA_HEADER_LEN..] != *body {
            return Err(invalid());
        }
    }
    if let Some(raw) = store.entities.get(txn, holder.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("receipt source holder"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM
            || !super::codec::is_inert_holder(&raw[ENTITY_METADATA_HEADER_LEN..])
        {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(crate) fn stage_receipt_archive_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    kind: u8,
    body: &[u8],
) -> Result<()> {
    if kind == ENTITY_TYPE_ASSET
        && let Some(source) = decode(body)?
    {
        let holder = source.holder()?;
        store.vault_meta.put(txn, &owned_key(&holder, id), &[])?;
        store
            .vault_meta
            .put(txn, &key(BINDING, id), holder.as_bytes())?;
    }
    if (kind != ENTITY_TYPE_CLAIM || !super::codec::is_inert_holder(body))
        && !receipt_archives_for_holder(store, txn, id)?.is_empty()
    {
        retire_receipt_archives_for_holder(store, txn, id)?;
    }
    Ok(())
}
pub(crate) fn receipt_archives_for_holder(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<Vec<EntityId>> {
    let prefix = key(OWNED, holder);
    let mut ids = Vec::new();
    for entry in store.vault_meta.prefix_iter(txn, &prefix)? {
        let (key, _) = entry?;
        let raw = key.strip_prefix(prefix.as_slice()).ok_or(invalid())?;
        let id = crate::entity_id::parse_entity_id(raw, "receipt archive index")?;
        if store
            .vault_meta
            .get(txn, &self::key(BINDING, &id))?
            .as_deref()
            != Some(holder.as_bytes().as_slice())
        {
            return Err(Error::CorruptedIndex("receipt archive binding"));
        }
        ids.push(id);
    }
    Ok(ids)
}
pub(super) fn read_source(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ReceiptArchive>> {
    if retired(store, txn, RETIRED_SOURCE, id)? {
        return Ok(None);
    }
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("receipt source header"));
    };
    if header.entity_type != ENTITY_TYPE_ASSET {
        return Err(invalid());
    }
    let source = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?.ok_or(invalid())?;
    if source.id()? != *id {
        return Err(invalid());
    }
    if retired(store, txn, RETIRED_HOLDER, &source.holder()?)?
        || !source.matches_holder(store, txn)?
    {
        return Ok(None);
    }
    if !crate::secret_rotation::exhaust_taint_refs_in_txn(store, txn, id)?.is_empty() {
        return Ok(None);
    }
    Ok(Some(source))
}
/// Premark the full source-only closure before deindexing. An adversarial pending
/// carrier chain cannot recurse through callbacks or grant deletion of a holder.
pub(crate) fn retire_receipt_archives_for_holder(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    holder: &EntityId,
) -> Result<()> {
    if store
        .vault_meta
        .get(txn, &key(RETIRED_HOLDER, holder))?
        .is_some()
    {
        return Ok(());
    }
    let mut pending = vec![*holder];
    let mut visited = BTreeSet::new();
    let mut sources = BTreeSet::new();
    while let Some(holder) = pending.pop() {
        if !visited.insert(holder) {
            continue;
        }
        store
            .vault_meta
            .put(txn, &key(RETIRED_HOLDER, &holder), &[])?;
        for id in receipt_archives_for_holder(store, txn, &holder)? {
            store.vault_meta.put(txn, &key(RETIRED_SOURCE, &id), &[])?;
            sources.insert(id);
            pending.push(id);
        }
    }
    for id in sources {
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("receipt source delete"))?;
        let source = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?.ok_or(invalid())?;
        if header.entity_type != ENTITY_TYPE_ASSET || source.id()? != id {
            return Err(invalid());
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
pub(crate) fn remove_receipt_archive_custody(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if store.vault_meta.get(txn, &key(BINDING, id))?.is_some() {
        store.vault_meta.put(txn, &key(RETIRED_SOURCE, id), &[])?;
    }
    retire_receipt_archives_for_holder(store, txn, id)
}

pub(crate) fn receipt_archive_custody_exists(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<bool> {
    for id in receipt_archives_for_holder(store, txn, holder)? {
        if store.entities.get(txn, id.as_bytes())?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Deletion intent retires this ID as a possible not-yet-seen source too.
/// Kind-change cleanup uses the narrower holder retirement above instead.
pub(crate) fn retire_receipt_archives_for_erased_id(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    store.vault_meta.put(txn, &key(RETIRED_SOURCE, id), &[])?;
    retire_receipt_archives_for_holder(store, txn, id)
}
