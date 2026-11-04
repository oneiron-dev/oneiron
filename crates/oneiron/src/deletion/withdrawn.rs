//! A withdrawn record's Shell generation (FIX 931).
//!
//! A reply TURN that copied a scope summary's words keeps them after the
//! sources they came from are withdrawn: it is marked stale, but its body
//! still holds them. Its withdrawn generation takes the physical scrub an
//! epoch summary's takes, except that what stands in for it is its Shell: its
//! exact 25-byte header and no body. Its graph edges, stale mark,
//! dependencies, worlds and fences stay. No tombstone, `dt:` marker or
//! whole-id deletion is written, and no HEAD moves. The historical sweep's
//! obligation is staged first, so every window carrier and queued send of the
//! generation follows it.
//!
//! A machine of the owner's that receives the Shell cutoff withdraws its
//! resident copy the same way: the carried cutoff is itself the authority.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreMaintenance, EntityStoreRead, ScrubbedRecord};
use crate::registry::{ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::store::Store;

use super::sweep_queue::{WithdrawnReplacement, enqueue_withdrawn_generation_in_txn};

/// Takes stale record `id`'s words from its row and from the carriers beside
/// it on this device, in the caller's transaction. The historical sweep's
/// obligation for its generation, the row's own `learned_at`, is staged
/// before anything changes; a TURN's DAG topology is pinned content-free
/// next; then its document, row revisions, short-id rows and L2 cache go, and
/// the row keeps its header byte for byte. Whether it scrubbed: an absent or
/// header-only row, one not marked stale and any SUMMARY are left as they are
/// (an epoch summary's own scrub keeps its keyframe, and a scope summary
/// keeps its editor history).
pub(crate) fn scrub_withdrawn_record_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(raw) = store.port_entity_raw(txn, id)? else {
        return Ok(false);
    };
    if raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Ok(false);
    }
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("withdrawn record header"))?;
    if header.entity_type == ENTITY_TYPE_SUMMARY || !crate::ports::stale_in_txn(store, txn, id)? {
        return Ok(false);
    }
    let at = crate::ports::recorded_at_in_txn(store, txn)?;
    enqueue_withdrawn_generation_in_txn(
        store,
        txn,
        id,
        header.learned_at,
        WithdrawnReplacement::Shell,
        at,
    )?;
    if header.entity_type == ENTITY_TYPE_TURN {
        crate::conversation_dag::capture_withdrawn_record_in_txn(store, txn, id)?;
    }
    crate::entity_doc::erase_in_txn(store, txn, id)?;
    crate::vault::entity_revision::remove_entity_revisions(store, txn, id)?;
    crate::batch::delete_short_id_rows_for_id(store, txn, id)?;
    store
        .l2_base_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .erase(id, store.env.info().last_txn_id);
    store.port_entity_scrub(txn, id, ScrubbedRecord::Shell, at)
}

/// Whether `id` still holds words here of a generation at or below `cutoff`,
/// a Shell cutoff another machine of this vault carries. A SUMMARY never
/// takes a Shell.
#[cfg(feature = "sync")]
pub(crate) fn holds_withdrawn_record_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    cutoff: u64,
) -> Result<bool> {
    let Some(row) = store.port_entity_record(txn, id)? else {
        return Ok(false);
    };
    Ok(row.learned_at <= cutoff && !row.body.is_empty() && row.entity_type != ENTITY_TYPE_SUMMARY)
}

/// Withdraws `id` here as the withdrawal on the machine that cut it off at
/// `cutoff` did, when [`holds_withdrawn_record_in`]: it is marked stale and
/// leaves every projection of its words, then takes
/// [`scrub_withdrawn_record_in_txn`]. Whether it withdrew; a repeat finds the
/// Shell and changes nothing.
#[cfg(feature = "sync")]
pub(crate) fn withdraw_received_record_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    cutoff: u64,
) -> Result<bool> {
    if !holds_withdrawn_record_in(store, txn, id, cutoff)? {
        return Ok(false);
    }
    crate::ports::mark_received_withdrawn_in_txn(store, txn, id)?;
    scrub_withdrawn_record_in_txn(store, txn, id)
}
