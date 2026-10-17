//! Source-prefix dependency index and deletion invalidation in the caller's transaction.
use super::SourceSpan;
use super::dependent_walk::DependentWalkDoor;
use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::calendar::origin::survives_source_deletion;
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
    let admitted = store.vault_meta().get(txn, &key)?.is_none();
    store.vault_meta().put(txn, &key, &[])?;
    let reverse = [
        super::regeneration::reverse_prefix(dependent).as_slice(),
        source.document.as_bytes(),
        &source.frontier.to_be_bytes(),
    ]
    .concat();
    store.vault_meta().put(txn, &reverse, &[])?;
    if admitted {
        super::dependent_walk::settle_admitted_in_txn(store, txn, source, dependent)?;
    }
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
    // A read never refuses for how many rows a source holds (rule 5).
    let mut result = std::collections::BTreeSet::new();
    for row in store.vault_meta().prefix_iter(txn, prefix)? {
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
/// Whether `id` reads as withdrawn: marked stale, or a dependent a pending
/// walk withdraws before its batch reaches it.
pub(crate) fn stale_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(marked_stale_in(store, txn, id)?
        || super::dependent_walk::pending_withdrawal_in(store, txn, id)?.is_some())
}
/// Whether a withdrawal has reached `id` itself. The walk judges its own
/// progress by this, never by what a pending walk says.
fn marked_stale_in(store: &impl ManifestDbs, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store.vault_meta().get(txn, &stale_key(id))?.is_some())
}
/// Whether a source `dependent` is recorded as derived from no longer stands
/// in this snapshot. It needs no mark from the deletion, so a failed or
/// rolled-back mark still withdraws (I2). Only `dependent`'s own reverse rows
/// are read (I4). An EVENT that outlives its source stays, as the walk
/// leaves it.
pub(super) fn source_withdrawn_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    dependent: &EntityId,
) -> Result<bool> {
    for source in super::regeneration::sources_of(store, txn, dependent)? {
        if source_stands_in(store, txn, &source.document)? {
            continue;
        }
        let row = store.entities().get(txn, dependent.as_bytes())?;
        let event = row
            .and_then(|raw| EntityMetadataHeader::parse(&raw))
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_EVENT);
        return Ok(!(event && survives_source_deletion(store, txn, *dependent)?));
    }
    Ok(false)
}
/// Whether `source` still stands for what was derived from it: present, not
/// removed, not withdrawn, its body not flagged stale. An archive keeps the
/// row whole and a CLAIM's `stale` is a status, so neither withdraws.
fn source_stands_in(store: &impl ManifestDbs, txn: &RoTxn<'_>, source: &EntityId) -> Result<bool> {
    let Some(raw) = store.entities().get(txn, source.as_bytes())? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("dependency source header"))?;
    let flagged = header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        && super::safe_read::body_is_stale(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]);
    Ok(!flagged
        && !super::lmdb_visibility::removed_in_txn(store, txn, source)?
        && !stale_in_txn(store, txn, source)?)
}
/// The worlds a deletion, or the loss of a source edge, withdrew epoch summary
/// `id` for: where the words it took sat, which the summary can no longer
/// trace once that source, its stamp or its edges are gone. `None` where
/// nothing withdrew it.
pub(crate) fn withdrawn_worlds_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<CarriedWorlds>> {
    let recorded = recorded_withdrawn_in(store, txn, id)?;
    // A pending walk withdraws an epoch summary for its source's worlds
    // before its batch records them.
    let pending = match super::dependent_walk::pending_withdrawal_in(store, txn, id)? {
        Some(worlds) if worlds != CarriedWorlds::default() && epoch_summary_in(store, txn, id)? => {
            worlds
        }
        _ => return Ok(recorded),
    };
    let mut worlds = recorded.unwrap_or_default();
    worlds.absorb(&pending);
    Ok(Some(worlds))
}
/// What the withdrawals that reached `id` recorded.
fn recorded_withdrawn_in(
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
    if *worlds == CarriedWorlds::default() || !epoch_summary_in(store, txn, id)? {
        return Ok(false);
    }
    let mut recorded = recorded_withdrawn_in(store, txn, id)?.unwrap_or_default();
    if !recorded.absorb(worlds) {
        return Ok(false);
    }
    store
        .vault_meta
        .put(txn, &withdrawn_key(id), &recorded.encode())?;
    Ok(true)
}
/// Retires what epoch summary `id` was withdrawn for once its words have left
/// this device: the historical sweep has rewritten every window that held
/// them, after its purge scrubbed the queued updates. Until then everything
/// keeps it: a standalone tombstone, a regeneration, an erase and the purge
/// itself ([`keep_deleted_worlds_in_txn`]).
pub(crate) fn retire_withdrawn_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    store.vault_meta.delete(txn, &withdrawn_key(id))?;
    Ok(())
}
/// A deletion takes epoch summary `id`'s body from its row, but its words stay
/// in window history, and after a soft erase in updates already queued, which
/// every door judges by this id (Sol round 21). So its record keeps every
/// world the body carried, read while its body, stamp and edges still stand.
pub(crate) fn keep_deleted_worlds_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if epoch_summary_in(store, txn, id)? {
        let worlds = carried_or_unknown(store, txn, id);
        record_withdrawn_in_txn(store, txn, id, &worlds)?;
    }
    Ok(())
}
/// A put that rewrites epoch summary `id` into a SUMMARY body that is no
/// epoch ends every walk at it: its edges stop saying where the words sat that
/// a summary written from it still holds (Sol round 21). Its record keeps
/// every world the old body carried, read before the new body lands. A body
/// that is no epoch in any form (a pointer that keeps the keyframe still is
/// one) changes the words each summary written from it copied, so each is
/// withdrawn as a changed source withdraws it, for those worlds (Wonder
/// P2-1): no reader then takes one through a walk that stops here.
pub(crate) fn keep_worlds_of_unmade_epoch_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<()> {
    if entity_type != crate::registry::ENTITY_TYPE_SUMMARY
        || crate::compaction::decode_epoch_summary_body(body).is_ok()
    {
        return Ok(());
    }
    let unmade = epoch_summary_in(store, txn, id)?
        && crate::compaction::stored_epoch_in(store, txn, id, body)?
            == crate::compaction::StoredEpoch::No;
    keep_deleted_worlds_in_txn(store, txn, id)?;
    if unmade {
        invalidate_source_in_txn(store, txn, id, DependentWalkDoor::UnmadeEpoch)?;
    }
    Ok(())
}
/// Removing epoch summary `summary`'s `DerivedFrom` edge to `source` withdraws
/// it as deleting `source` would: its body keeps the words, and the edge that
/// said where they sat is gone. An ASSET_TEXT losing a source is withdrawn
/// the same way, since the edge was a conjunct of who reads it (facet rule
/// C). The removal is never refused, so a peer's echo of its own purge
/// converges.
pub(crate) fn withdraw_from_lost_source_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    summary: &EntityId,
    source: &EntityId,
) -> Result<()> {
    if !epoch_summary_in(store, txn, summary)? {
        if super::EntityStoreRead::port_entity_record(store, txn, summary)?
            .is_some_and(|row| row.entity_type == crate::registry::ENTITY_TYPE_ASSET_TEXT)
            && !marked_stale_in(store, txn, summary)?
        {
            mark_stale_in_txn(store, txn, summary)?;
        }
        return Ok(());
    }
    let worlds = carried_or_unknown(store, txn, source);
    if marked_stale_in(store, txn, summary)?
        && !record_withdrawn_in_txn(store, txn, summary, &worlds)?
    {
        return Ok(());
    }
    withdraw_words_in_txn(store, txn, summary, &worlds)
}
/// Where the words of `source` sit, read while its row, stamp and edges still
/// stand, whatever its body holds. A source no one can place is unknown, and
/// the write goes on.
fn carried_or_unknown(store: &Store, txn: &RoTxn<'_>, source: &EntityId) -> CarriedWorlds {
    crate::settings::carried_worlds_in(store, txn, source).unwrap_or(CarriedWorlds {
        worlds: std::collections::BTreeSet::new(),
        unknown: true,
    })
}
/// What invalidating `source` captures: [`carried_or_unknown`], except for a
/// row a purge already removed. That purge read it before it went and
/// withdrew every summary written from it, so a repeat (a peer's late
/// tombstone) changes no record. A row that still stands is read, even an
/// empty one: a deletion marker is intent, not proof of a capture.
pub(super) fn carried_now(
    store: &Store,
    txn: &RoTxn<'_>,
    source: &EntityId,
) -> Result<CarriedWorlds> {
    if super::EntityStoreRead::port_entity_raw(store, txn, source)?.is_none()
        && crate::deletion::row_deletion_marked(store, txn, source, None)?
    {
        return Ok(CarriedWorlds::default());
    }
    Ok(carried_or_unknown(store, txn, source))
}
/// Whether `id` is an epoch summary in whatever form it is stored, a pointer
/// no head stands for included (Astra 1384e).
pub(super) fn epoch_summary_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    match super::EntityStoreRead::port_entity_record(store, txn, id)? {
        Some(row) if row.entity_type == crate::registry::ENTITY_TYPE_SUMMARY => {
            Ok(crate::compaction::stored_epoch_in(store, txn, id, &row.body)?.may_be())
        }
        _ => Ok(false),
    }
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
    // §d7), for the same worlds.
    let pending = epoch_dependents_in_txn(store, txn, id)?;
    withdraw_epochs_in_txn(store, txn, pending, worlds)
}
/// [`withdraw_in_txn`], then an epoch summary's words leave its row. Its
/// worlds are recorded and every epoch written from it withdrawn first,
/// while its body still classifies them.
fn withdraw_words_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    worlds: &CarriedWorlds,
) -> Result<()> {
    withdraw_in_txn(store, txn, id, worlds)?;
    crate::compaction::scrub_withdrawn_epoch_in_txn(store, txn, id)?;
    crate::compaction::scrub_withdrawn_fold_summary_in_txn(store, txn, id)
}

/// Withdraws the epoch summaries in `pending` for `worlds`, and those written
/// from them. A worklist, not recursion: no chain's depth reaches the stack.
/// A stale one is not marked again, and is walked again only when this adds
/// a world to it. Each one walked keeps only its keyframe once those written
/// from it are found.
pub(super) fn withdraw_epochs_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    mut pending: Vec<EntityId>,
    worlds: &CarriedWorlds,
) -> Result<()> {
    while let Some(next) = pending.pop() {
        let grew = record_withdrawn_in_txn(store, txn, &next, worlds)?;
        let stale = marked_stale_in(store, txn, &next)?;
        if stale && !grew {
            continue;
        }
        if !stale {
            mark_one_stale_in_txn(store, txn, &next)?;
        }
        pending.extend(epoch_dependents_in_txn(store, txn, &next)?);
        crate::compaction::scrub_withdrawn_epoch_in_txn(store, txn, &next)?;
    }
    Ok(())
}

fn mark_one_stale_in_txn(store: &Store, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    // A stale TURN or MESSAGE leaves the words its turn says: the Dreamer's
    // sieve and projector rows of them go as an erasure's do, while the
    // MESSAGE still names its turn.
    crate::dreamer_wake::erase_in_txn(store, txn, id)?;
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
        if epoch_summary_in(store, txn, &dependent)? {
            epochs.push(dependent);
        }
    }
    Ok(epochs)
}
/// An entity delete erases every source version; one document-prefix scan
/// visits only its k dependency rows, a batch at a time past the walk's
/// batch row ([`super::dependent_walk`]). No entity or edge table is scanned,
/// and no count refuses the walk.
pub(crate) fn invalidate_source_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    document: &EntityId,
    door: DependentWalkDoor,
) -> Result<()> {
    crate::claim::invalidate_weave_digest_source_in_txn(store, txn, document)?;
    super::dependent_walk::begin_in_txn(store, txn, document, door)
}
/// Withdraws one dependent of `document` for `worlds` and queues its
/// regeneration; an EVENT that outlives its source stays.
pub(super) fn withdraw_dependent_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    document: &EntityId,
    dependent: &EntityId,
    worlds: &CarriedWorlds,
) -> Result<()> {
    use super::JobQueue;
    if super::EntityStoreRead::port_entity_record(store, txn, dependent)?
        .is_some_and(|row| row.entity_type == crate::registry::ENTITY_TYPE_EVENT)
        && crate::calendar::origin::survives_source_deletion(store, txn, *dependent)?
    {
        return Ok(());
    }
    withdraw_words_in_txn(store, txn, dependent, worlds)?;
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
