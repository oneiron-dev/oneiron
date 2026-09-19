//! Source-prefix dependency index and deletion invalidation in the caller's transaction.
use super::SourceSpan;
use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::store::ManifestDbs;
use crate::store::Store;
use heed::{RoTxn, RwTxn};
pub(super) const DEP: &[u8] = b"ports:dependency:v1:";
const STALE: &[u8] = b"ports:stale:v1:";
const TOMBSTONE: &[u8] = b"ports:tombstone:v1:";
pub(super) fn tombstone_key(id: &EntityId) -> Vec<u8> {
    [TOMBSTONE, id.as_bytes()].concat()
}
pub(super) fn stale_key(id: &EntityId) -> Vec<u8> {
    [STALE, id.as_bytes()].concat()
}
pub(super) fn source_prefix(source: SourceSpan) -> Vec<u8> {
    [
        DEP,
        source.document.as_bytes(),
        &source.frontier.to_be_bytes(),
    ]
    .concat()
}
pub(crate) fn record_dependency_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    source: SourceSpan,
    dependent: &EntityId,
) -> Result<()> {
    if source.document == *dependent {
        return Err(Error::InvariantViolation("self dependency"));
    }
    let visibility = super::TombstoneStoreRead::port_deletion_state(store, txn, &source.document)?;
    if visibility.deleted || visibility.stale {
        return Err(Error::EntityNotFound);
    }
    let key = [source_prefix(source).as_slice(), dependent.as_bytes()].concat();
    store.vault_meta().put(txn, &key, &[])?;
    let reverse = [
        super::regeneration::reverse_prefix(dependent).as_slice(),
        source.document.as_bytes(),
        &source.frontier.to_be_bytes(),
    ]
    .concat();
    store.vault_meta().put(txn, &reverse, &[])?;
    Ok(())
}
pub(super) fn list_by_source(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    source: SourceSpan,
) -> Result<Vec<EntityId>> {
    scan_dependents(store, txn, &source_prefix(source))
}
fn scan_dependents(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<EntityId>> {
    let mut result = std::collections::BTreeSet::new();
    for (count, row) in store.vault_meta().prefix_iter(txn, prefix)?.enumerate() {
        if count >= 100_000 {
            return Err(Error::IndexOverflow("source dependents"));
        }
        let (key, _) = row?;
        if key.len() != DEP.len() + 40 {
            return Err(Error::CorruptedIndex("source dependency key"));
        }
        let id = EntityId::from_bytes(
            key[key.len() - 16..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("dependent id"))?,
        )?;
        result.insert(id);
    }
    Ok(result.into_iter().collect())
}
pub(crate) fn stale_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(store.vault_meta().get(txn, &stale_key(id))?.is_some())
}
pub(super) fn mark_stale_in_txn(store: &Store, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    // A second invalidation after a regenerated write fences its completion.
    let revision = store
        .entities
        .get(txn, id.as_bytes())?
        .map(|raw| {
            EntityMetadataHeader::parse(&raw)
                .map(|h| h.learned_at)
                .ok_or(Error::CorruptedIndex("stale entity header"))
        })
        .transpose()?
        .unwrap_or(0);
    store
        .vault_meta
        .put(txn, &stale_key(id), &revision.to_be_bytes())?;
    crate::bm25::deindex_text(store, txn, id)?;
    let had_vector = store.vectors.delete(txn, id.as_bytes())?;
    crate::hnsw::hnsw_deindex(store, txn, id)?;
    if had_vector {
        crate::hnsw::increment_vector_version(store, txn)?;
    }
    crate::ppr::invalidate_ppr_for_delete(store, txn, id, &[])?;
    Ok(())
}
/// An entity delete erases every source version; one document-prefix scan
/// visits only its k dependency rows. No entity or edge table is scanned.
pub(crate) fn invalidate_source_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    document: &EntityId,
) -> Result<()> {
    use super::JobQueue;
    let prefix = [DEP, document.as_bytes()].concat();
    let dependents = scan_dependents(store, txn, &prefix)?;
    for dependent in dependents {
        if super::EntityStoreRead::port_entity_record(store, txn, &dependent)?
            .is_some_and(|row| row.entity_type == crate::registry::ENTITY_TYPE_EVENT)
            && crate::calendar::origin::survives_source_deletion(store, txn, dependent)?
        {
            continue;
        }
        mark_stale_in_txn(store, txn, &dependent)?;
        let payload = [document.as_bytes().as_slice(), dependent.as_bytes()].concat();
        crate::attempt_queue::AttemptQueue::from_store(store).port_job_enqueue(
            txn,
            crate::attempt_queue::EnqueueAttempt {
                kind: "derived.regenerate".into(),
                payload,
                dedupe_key: Some(format!("{}:{}", document.to_hex(), dependent.to_hex())),
                run_id: None,
                now: 0,
            },
        )?;
    }
    Ok(())
}
/// DerivedFrom is dependent→source. This hook also serves session overlays.
pub(crate) fn record_derived_edge_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    dependent: &EntityId,
    source: &EntityId,
) -> Result<()> {
    let raw = store
        .entities()
        .get(txn, source.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("dependency source header"))?;
    super::DependencyIndex::port_dependency_put(
        store,
        txn,
        SourceSpan {
            document: *source,
            frontier: header.learned_at,
        },
        dependent,
    )
}
/// Typed sourceFrontiers rows carry document id and a numeric revision. This
/// decoder deliberately does not guess at opaque CRDT frontier strings.
pub(crate) fn record_source_frontiers_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    bytes: &[u8],
) -> Result<()> {
    let Ok(body) = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)) else {
        return Ok(());
    };
    let Some(frontiers) = super::lmdb_entity::field(&body, "sourceFrontiers") else {
        return Ok(());
    };
    let Some(frontiers) = frontiers.as_array() else {
        return Err(Error::CorruptedIndex("sourceFrontiers"));
    };
    for span in frontiers {
        // Existing EVENT uses opaque strings with separate evidenceTurnIds.
        // Their dependencies are maintained by the DerivedFrom edge hook.
        if span.as_str().is_some() {
            continue;
        }
        let document = super::lmdb_entity::field(span, "document")
            .ok_or(Error::CorruptedIndex("source document"))?;
        let document = match document {
            rmpv::Value::Binary(bytes) => EntityId::from_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("source document"))?,
            )?,
            rmpv::Value::String(value) => EntityId::from_hex(
                value
                    .as_str()
                    .ok_or(Error::CorruptedIndex("source document"))?,
            )?,
            _ => return Err(Error::CorruptedIndex("source document")),
        };
        let frontier = super::lmdb_entity::field(span, "frontier")
            .and_then(rmpv::Value::as_u64)
            .ok_or(Error::CorruptedIndex("source frontier"))?;
        super::DependencyIndex::port_dependency_put(
            store,
            txn,
            SourceSpan { document, frontier },
            id,
        )?;
    }
    Ok(())
}
