//! Identifier-only source custody. Binding never confers receipt or claim authority.
use super::codec::{ReceiptArchive, decode, invalid};
use crate::{
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    entity_id::EntityId,
    error::{Error, Result},
    registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM},
    side_table::{self, HexId, Raw, SideTable},
    store::Store,
};
use std::collections::BTreeSet;

/// Index of archived receipt-source ids currently owned by one holder claim.
/// Key: id16 (holder) + id16 (source).
const OWNED: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::RECEIPT_ARCHIVE_OWNED);
/// Binds one archived receipt-source ASSET to the inert holder CLAIM it documents. Key: id16.
const BINDING: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::RECEIPT_ARCHIVE_BINDING);
/// Dedupe slot: which archived receipt-source id currently occupies one
/// (holder, body hash, receipt id) triple. Key: id16 (holder) + hex64 (body
/// sha256) + string (receipt id).
const SLOT: SideTable<(EntityId, [u8; 64], String), EntityId, Raw> =
    SideTable::new(&side_table::RECEIPT_ARCHIVE_SLOT);
/// Marks a holder CLAIM whose archived receipt-source closure has been retired. Key: id16.
const RETIRED_HOLDER: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::RECEIPT_ARCHIVE_HOLDER_RETIRED);
/// Marks one archived receipt-source ASSET id as retired. Key: id16.
const RETIRED_SOURCE: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::RECEIPT_ARCHIVE_SOURCE_RETIRED);
/// The ARCH-0023b global local hard-delete marker (owned by
/// `crate::deletion::tombstone`); read-only here for the retired/deleted check.
const HARD_DELETE_MARKER: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_HARD_DELETE_MARKER);

fn slot_key(source: &ReceiptArchive) -> Result<(EntityId, [u8; 64], String)> {
    let hash: [u8; 64] = source
        .body_sha256
        .as_bytes()
        .try_into()
        .map_err(|_| invalid())?;
    Ok((
        source.holder()?,
        hash,
        source.source.receipt_id().to_owned(),
    ))
}
fn retired(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    table: SideTable<EntityId, (), Raw>,
    id: &EntityId,
) -> Result<bool> {
    Ok(table.contains(store, txn, id)?
        || HARD_DELETE_MARKER.contains(store, txn, &HexId(*id))?
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
    if BINDING.contains(store, txn, id)? && source.is_none() {
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
    if let Some(bound) = SLOT.get(store, txn, &slot_key(&source)?)?
        && bound != *id
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
            || (super::codec::digest(&raw[ENTITY_METADATA_HEADER_LEN..]) == source.body_sha256
                && !source.matches_body(&raw[ENTITY_METADATA_HEADER_LEN..]))
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
        SLOT.put(store, txn, &slot_key(&source)?, id)?;
        OWNED.put(store, txn, &(holder, *id), &())?;
        BINDING.put(store, txn, id, &holder)?;
    }
    let owned = receipt_archives_for_holder(store, txn, id)?;
    if !owned.is_empty() {
        if kind != ENTITY_TYPE_CLAIM || !super::codec::is_inert_holder(body) {
            retire_receipt_archives_for_holder(store, txn, id)?;
        } else {
            // Pending source delivery must not reserve or veto a legitimate
            // holder. Retire a now-provably-uncited payload, not the claim.
            let hash = super::codec::digest(body);
            for source_id in owned {
                let Some(raw) = store.entities.get(txn, source_id.as_bytes())? else {
                    continue;
                };
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("pending receipt source"))?;
                let source = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?.ok_or(invalid())?;
                if header.entity_type != ENTITY_TYPE_ASSET
                    || source.id()? != source_id
                    || source.holder()? != *id
                {
                    return Err(invalid());
                }
                if source.body_sha256 == hash && !source.matches_body(body) {
                    RETIRED_SOURCE.put(store, txn, &source_id, &())?;
                    erase_source_payload(store, txn, &source_id)?;
                }
            }
        }
    }
    Ok(())
}
pub(crate) fn receipt_archives_for_holder(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for ((_, id), ()) in OWNED.scan_from(store, txn, holder.as_bytes())? {
        if BINDING.get(store, txn, &id)?.as_ref() != Some(holder) {
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
    if source.id()? != *id || SLOT.get(store, txn, &slot_key(&source)?)?.as_ref() != Some(id) {
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
    if RETIRED_HOLDER.contains(store, txn, holder)? {
        return Ok(());
    }
    let mut pending = vec![*holder];
    let mut visited = BTreeSet::new();
    let mut sources = BTreeSet::new();
    while let Some(holder) = pending.pop() {
        if !visited.insert(holder) {
            continue;
        }
        RETIRED_HOLDER.put(store, txn, &holder, &())?;
        for id in receipt_archives_for_holder(store, txn, &holder)? {
            RETIRED_SOURCE.put(store, txn, &id, &())?;
            sources.insert(id);
            pending.push(id);
        }
    }
    for id in sources {
        erase_source_payload(store, txn, &id)?;
    }
    Ok(())
}
fn erase_source_payload(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(());
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("receipt source delete"))?;
    let source = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?.ok_or(invalid())?;
    if header.entity_type != ENTITY_TYPE_ASSET || source.id()? != *id {
        return Err(invalid());
    }
    let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, id)?;
    crate::ppr::invalidate_ppr_for_delete(store, txn, id, &neighbors)?;
    if graph {
        crate::ppr::increment_graph_version(store, txn)?;
    }
    if vector {
        crate::hnsw::increment_vector_version(store, txn)?;
    }
    Ok(())
}
pub(crate) fn remove_receipt_archive_custody(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if BINDING.contains(store, txn, id)? {
        RETIRED_SOURCE.put(store, txn, id, &())?;
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
    RETIRED_SOURCE.put(store, txn, id, &())?;
    retire_receipt_archives_for_holder(store, txn, id)
}
