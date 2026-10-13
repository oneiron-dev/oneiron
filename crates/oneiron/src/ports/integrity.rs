//! Source-prefix dependency index and deletion invalidation in the caller's transaction.
use super::SourceSpan;
use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::settings::CarriedWorlds;
use crate::store::ManifestDbs;
use crate::store::Store;
use heed::{RoTxn, RwTxn};
pub(super) const DEP: &[u8] = b"ports:dependency:v1:";
const STALE: &[u8] = b"ports:stale:v1:";
const TOMBSTONE: &[u8] = b"ports:tombstone:v1:";
const WITHDRAWN: &[u8] = b"ports:withdrawn:v1:";
pub(super) fn tombstone_key(id: &EntityId) -> Vec<u8> {
    [TOMBSTONE, id.as_bytes()].concat()
}
pub(super) fn stale_key(id: &EntityId) -> Vec<u8> {
    [STALE, id.as_bytes()].concat()
}
pub(super) fn withdrawn_key(id: &EntityId) -> Vec<u8> {
    [WITHDRAWN, id.as_bytes()].concat()
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
/// The worlds a deletion withdrew epoch summary `id` for: where the words it
/// took sat, which the summary can no longer trace once that source, its
/// stamp or its edges are gone. `None` where no deletion withdrew it.
pub(crate) fn withdrawn_worlds_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<CarriedWorlds>> {
    store
        .vault_meta()
        .get(txn, &withdrawn_key(id))?
        .map(|raw| CarriedWorlds::decode(&raw))
        .transpose()
}
/// Adds `worlds` to what epoch summary `id` was withdrawn for; whether that
/// grew it. Any other row records nothing.
pub(crate) fn record_withdrawn_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    worlds: &CarriedWorlds,
) -> Result<bool> {
    if *worlds == CarriedWorlds::default()
        || !super::EntityStoreRead::port_entity_record(store, txn, id)?.is_some_and(|row| {
            row.entity_type == crate::registry::ENTITY_TYPE_SUMMARY
                && crate::compaction::decode_epoch_summary_body(&row.body).is_ok()
        })
    {
        return Ok(false);
    }
    let mut recorded = withdrawn_worlds_in(store, txn, id)?.unwrap_or_default();
    if !recorded.absorb(worlds) {
        return Ok(false);
    }
    store
        .vault_meta
        .put(txn, &withdrawn_key(id), &recorded.encode())?;
    Ok(true)
}
pub(super) fn mark_stale_in_txn(store: &Store, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    withdraw_in_txn(store, txn, id, &CarriedWorlds::default())
}
/// Marks `id` stale, withdrawn for `worlds`: where the words of the source
/// whose deletion withdrew it sat.
fn withdraw_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    worlds: &CarriedWorlds,
) -> Result<()> {
    mark_one_stale_in_txn(store, txn, id)?;
    record_withdrawn_in_txn(store, txn, id, worlds)?;
    // An epoch summary copies the words of what it was written from, so it
    // is withdrawn with any of them, through nested epochs (agent-runtime-v1
    // §d7), for the same worlds. A worklist, not recursion: no chain's depth
    // reaches the stack. A stale one is walked again only when this adds a
    // world to it.
    let mut pending = epoch_dependents_in_txn(store, txn, id)?;
    while let Some(next) = pending.pop() {
        let grew = record_withdrawn_in_txn(store, txn, &next, worlds)?;
        let stale = stale_in_txn(store, txn, &next)?;
        if stale && !grew {
            continue;
        }
        if !stale {
            mark_one_stale_in_txn(store, txn, &next)?;
        }
        pending.extend(epoch_dependents_in_txn(store, txn, &next)?);
    }
    Ok(())
}

fn mark_one_stale_in_txn(store: &Store, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    // A derived claim can retain erased upstream bytes while its own entity
    // body remains. Remove every saved digest that copied it in this txn;
    // clearing the stale bit on regeneration must never revive an old copy.
    crate::claim::invalidate_weave_digest_source_in_txn(store, txn, id)?;
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
    crate::embed::record_embedding_device_in_txn(store, txn, id, None)?;
    crate::hnsw::hnsw_deindex(store, txn, id)?;
    if had_vector {
        crate::hnsw::increment_vector_version(store, txn)?;
    }
    crate::ppr::invalidate_ppr_for_delete(store, txn, id, &[])?;
    // Withdrawn words are never embedded: a queued or leased fill finds no
    // current marker, so it neither sends them out nor writes a vector back.
    store.clear_pending_embedding(txn, id)?;
    // A stale edge.provenance wrapper stops justifying its edge in this txn.
    crate::provenance::refresh_stale_wrapper_in_txn(store, txn, id)
}

/// The epoch summaries written from `id`.
fn epoch_dependents_in_txn(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
    let prefix = [DEP, id.as_bytes()].concat();
    let mut epochs = Vec::new();
    for dependent in scan_dependents(store, txn, &prefix)? {
        let epoch = super::EntityStoreRead::port_entity_record(store, txn, &dependent)?
            .is_some_and(|row| {
                row.entity_type == crate::registry::ENTITY_TYPE_SUMMARY
                    && crate::compaction::decode_epoch_summary_body(&row.body).is_ok()
            });
        if epoch {
            epochs.push(dependent);
        }
    }
    Ok(epochs)
}
/// An entity delete erases every source version; one document-prefix scan
/// visits only its k dependency rows. No entity or edge table is scanned.
pub(crate) fn invalidate_source_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    document: &EntityId,
) -> Result<()> {
    use super::JobQueue;
    crate::claim::invalidate_weave_digest_source_in_txn(store, txn, document)?;
    let prefix = [DEP, document.as_bytes()].concat();
    let dependents = scan_dependents(store, txn, &prefix)?;
    // Where the deleted words sat, read while the row, its stamp and its
    // edges still stand: an epoch summary it withdraws keeps them as its
    // own. A source no one can place withdraws it for an unknown world, and
    // the deletion goes on.
    let worlds = if dependents.is_empty() {
        CarriedWorlds::default()
    } else {
        crate::settings::carried_worlds_in(store, txn, document).unwrap_or(CarriedWorlds {
            worlds: std::collections::BTreeSet::new(),
            unknown: true,
        })
    };
    store.vault_meta.delete(txn, &withdrawn_key(document))?;
    for dependent in dependents {
        if super::EntityStoreRead::port_entity_record(store, txn, &dependent)?
            .is_some_and(|row| row.entity_type == crate::registry::ENTITY_TYPE_EVENT)
            && crate::calendar::origin::survives_source_deletion(store, txn, dependent)?
        {
            continue;
        }
        withdraw_in_txn(store, txn, &dependent, &worlds)?;
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
