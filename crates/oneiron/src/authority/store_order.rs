//! The store-order index over AUTHORITY_LOG rows (FIX 12369).
//!
//! Each authority row first stored here takes the next sequence in the same
//! write transaction that stores it, beside its first-seen sidecar, so a
//! resumed fold range-scans only the rows stored past its continuation
//! instead of every id in the hash-keyed type index. The index is derived:
//! it carries no authority of its own, a restore rebuilds it, and any doubt
//! about it answers with the type-index scan the fold always had. No fold
//! value ever depends on it.

use std::collections::BTreeSet;
use std::ops::Bound;

use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::EntityId;

/// Sequence -> the stored row's entity id.
const STORE_ORDER: SideTable<u64, [u8; 16], Raw> =
    SideTable::new(&side_table::AUTHLOG_STORE_ORDER);
/// The index's state as 9 raw bytes: whether the one-shot backfill (or a
/// checkpoint rebuild) has sequenced every row stored before the index
/// existed, then the next free sequence as u64be.
const STORE_ORDER_STATE: SideTable<(), [u8; 9], Raw> =
    SideTable::new(&side_table::AUTHLOG_STORE_ORDER_STATE);

/// The index's state, read leniently: a state row that does not decode
/// reads as no state (incomplete, nothing sequenced). The fold then takes
/// its type-index scan and the backfill resequences from the stored rows;
/// a damaged derived row never bricks a fold or a put.
fn read_state(store: &Store, txn: &heed::RoTxn<'_>) -> Result<(bool, u64)> {
    Ok(match STORE_ORDER_STATE.get_lenient(store, txn, &())? {
        Some(bytes) => (
            bytes[0] != 0,
            u64::from_be_bytes(
                bytes[1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("authority store order state"))?,
            ),
        ),
        None => (false, 0),
    })
}

fn write_state(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    complete: bool,
    next: u64,
) -> Result<()> {
    let mut bytes = [0u8; 9];
    bytes[0] = u8::from(complete);
    bytes[1..].copy_from_slice(&next.to_be_bytes());
    STORE_ORDER_STATE.put(store, txn, &(), &bytes)
}

/// Sequences `id`, a row this put stores for the first time, in the put's
/// own transaction: the row and its sequence commit or abort together, so
/// committed sequences are gap-free in commit order. Called only where the
/// row's first-seen sidecar is first written, so a re-put never takes a
/// second sequence.
pub(crate) fn note_first_stored_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let (complete, next) = read_state(store, txn)?;
    STORE_ORDER.put(store, txn, &next, id.as_bytes())?;
    let next = next
        .checked_add(1)
        .ok_or(Error::CorruptedIndex("authority store order exhausted"))?;
    write_state(store, txn, complete, next)
}

/// The next free sequence where the index is complete (every stored row
/// sequenced exactly once), else None: the fold then takes its type-index
/// scan, as a vault the backfill has not run on always has.
pub(super) fn complete_next_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Option<u64>> {
    let (complete, next) = read_state(store, txn)?;
    Ok(complete.then_some(next))
}

/// The highest sequence a fold of the whole stored log in `txn` read,
/// where the index is complete: the continuation that fold leaves carries
/// it and the next fold resumes by sequence. None where the index is
/// incomplete or holds no row.
pub(super) fn complete_max_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Option<u64>> {
    Ok(complete_next_in_txn(store, txn)?.and_then(|next| next.checked_sub(1)))
}

/// The store ids sequenced past `after` and below `next`, in sequence
/// order: the tail a fold resuming from a continuation that folded every
/// sequence up to `after` still has to read. None on any inconsistency
/// (a gap, a short scan, an id that does not read back): the caller falls
/// back to the type-index scan, never to a partial tail.
pub(super) fn tail_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    after: u64,
    next: u64,
) -> Result<Option<Vec<EntityId>>> {
    let Some(first) = after.checked_add(1) else {
        return Ok(None);
    };
    let Some(expected) = next.checked_sub(first) else {
        return Ok(None);
    };
    let mut ids = Vec::new();
    for row in STORE_ORDER.iter_range(store, txn, Bound::Excluded(&after), Bound::Excluded(&next))?
    {
        let Ok((seq, bytes)) = row else {
            return Ok(None);
        };
        if seq != first + ids.len() as u64 {
            return Ok(None);
        }
        let Ok(id) = EntityId::from_bytes(bytes) else {
            return Ok(None);
        };
        ids.push(id);
    }
    Ok((ids.len() as u64 == expected).then_some(ids))
}

/// The one-shot backfill, and the index's repair: where the index is not
/// complete, resequence every stored AUTHORITY_LOG row in type-index
/// order (fold order does not depend on it; the fold sorts each tail
/// itself) and mark it complete. Resequencing rather than appending keeps
/// no bookkeeping to disagree with: a damaged index or state is rebuilt
/// whole from the stored rows. Whether it ran: false where the index is
/// already complete, so the caller advances the fold generation and drops
/// the cached fold only on the run that changed the store - a continuation
/// cached before it carries no sequence, or a stale one after a repair.
pub(crate) fn backfill_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<bool> {
    let (complete, _) = read_state(store, txn)?;
    if complete {
        return Ok(false);
    }
    let mut ids = Vec::new();
    for id in store.port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)? {
        ids.push(id?);
    }
    STORE_ORDER.delete_from(store, txn, &[])?;
    sequence_all_in_txn(store, txn, ids)?;
    Ok(true)
}

/// Sequences `ids` from zero in the given order and marks the index
/// complete over exactly them.
fn sequence_all_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    ids: impl IntoIterator<Item = EntityId>,
) -> Result<()> {
    let mut next = 0u64;
    for id in ids {
        STORE_ORDER.put(store, txn, &next, id.as_bytes())?;
        next = next
            .checked_add(1)
            .ok_or(Error::CorruptedIndex("authority store order exhausted"))?;
    }
    write_state(store, txn, true, next)
}

/// The checkpoint rebuild's index: a restore bypasses the put chokepoint
/// that sequences live puts, so the restored AUTHORITY_LOG rows are
/// sequenced afresh in id order and the index marked complete. Sequences
/// need not match the source vault's: the fold continuation that reads
/// them is per-Store and reopens empty, so only within-vault monotonicity
/// matters. Any sequence a kept live row left is dropped first.
pub(crate) fn rebuild_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    rows: &[(EntityId, Vec<u8>)],
) -> Result<()> {
    STORE_ORDER.delete_from(store, txn, &[])?;
    let mut ids = BTreeSet::new();
    for (id, raw) in rows {
        let header = EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
            ids.insert(*id);
        }
    }
    sequence_all_in_txn(store, txn, ids)
}
