//! The edge and redirty feeds (untangle slice 6.8b): the two sources the store's change log does
//! not carry. Edge writes and removals append nothing to the change log, and a TURN whose MESSAGE
//! words change keeps its own version. Each feed row is written in the change's own commit, and
//! only while a subscription follows the feed, so a vault with no follower writes nothing and
//! pays one seek. Rows go with the housekeeping prune once every follower acknowledged them, and
//! with an erase of either end or of the TURN.

use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::{
    Candidate, FeedEdge, FeedEntry, FeedEntryKind, FeedOp, FeedPosition, FeedSource, Judge,
    Position, Scanned, source_followed_in_txn,
};
use crate::claim::PointRead;
use crate::edge::EdgeKind;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Error, Result, Vault};

const EDGES: SideTable<u64, EdgeRow, Named> = SideTable::new(&side_table::FEED_EDGE);
const EDGE_NEXT: SideTable<(), u64, Named> = SideTable::new(&side_table::FEED_EDGE_NEXT);
const REDIRTY: SideTable<u64, RedirtyRow, Named> = SideTable::new(&side_table::FEED_REDIRTY);
const REDIRTY_NEXT: SideTable<(), u64, Named> = SideTable::new(&side_table::FEED_REDIRTY_NEXT);

/// One edge added or removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EdgeRow {
    source: EntityId,
    /// The edge kind's stored byte.
    kind: u8,
    target: EntityId,
    added: bool,
    recorded_at: u64,
}

/// One TURN whose words changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RedirtyRow {
    turn: EntityId,
    recorded_at: u64,
}

/// Records, in the edge write's own `txn`, that `source -kind-> target` was added (`added`) or
/// removed, while a subscription follows edges; otherwise it writes nothing.
///
/// # Errors
///
/// The follower seek, the sequence overflowing, or the write.
pub(crate) fn record_edge_change_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    source: &EntityId,
    kind: EdgeKind,
    target: &EntityId,
    added: bool,
) -> Result<()> {
    if !source_followed_in_txn(store, txn, FeedSource::Edges)? {
        return Ok(());
    }
    let sequence = next_sequence_in_txn(store, txn, EDGE_NEXT, "feed edge sequence")?;
    let row = EdgeRow {
        source: *source,
        kind: kind as u8,
        target: *target,
        added,
        recorded_at: crate::ports::recorded_at_in_txn(store, txn)?,
    };
    EDGES.put(store, txn, &sequence, &row)
}

/// Records, in the commit that changes them, that `turn`'s words changed with no new version of
/// its own, while a subscription follows redirty notices; otherwise it writes nothing.
///
/// # Errors
///
/// The follower seek, the sequence overflowing, or the write.
pub(crate) fn record_redirty_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    if !source_followed_in_txn(store, txn, FeedSource::Redirty)? {
        return Ok(());
    }
    let sequence = next_sequence_in_txn(store, txn, REDIRTY_NEXT, "feed redirty sequence")?;
    let row = RedirtyRow {
        turn: *turn,
        recorded_at: crate::ports::recorded_at_in_txn(store, txn)?,
    };
    REDIRTY.put(store, txn, &sequence, &row)
}

fn next_sequence_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    next: SideTable<(), u64, Named>,
    what: &'static str,
) -> Result<u64> {
    let sequence = next
        .get(store, txn, &())?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow(what))?;
    next.put(store, txn, &(), &sequence)?;
    Ok(sequence)
}

/// The last edge feed sequence handed out, or `None` before the first.
pub(super) fn edge_head_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Option<u64>> {
    Ok(EDGE_NEXT
        .get(store, txn, &())?
        .filter(|sequence| *sequence > 0))
}

/// The last redirty feed sequence handed out, or `None` before the first.
pub(super) fn redirty_head_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Option<u64>> {
    Ok(REDIRTY_NEXT
        .get(store, txn, &())?
        .filter(|sequence| *sequence > 0))
}

/// Up to `limit` edge feed rows after `after`: each shown when the subscriber's lane shows both
/// ends now.
pub(super) fn edges_after_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<Position>,
    limit: usize,
) -> Result<Scanned> {
    let after = match after {
        None => None,
        Some(Position::Edges(sequence)) => Some(sequence),
        Some(_) => {
            return Err(Error::CorruptedIndex(
                "an edges cursor names another source",
            ));
        }
    };
    let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    let mut scanned = Scanned {
        entries: Vec::new(),
        through: None,
        more: false,
    };
    for row in EDGES.iter_range(&vault.store, txn, start, Bound::Unbounded)? {
        if scanned.entries.len() >= limit {
            scanned.more = true;
            break;
        }
        let (sequence, row) = row?;
        let position = Position::Edges(sequence);
        scanned.through = Some(position);
        let Some(kind) = EdgeKind::try_from_u8(row.kind) else {
            continue;
        };
        let Some(record) = vault.store.port_entity_record(txn, &row.source)? else {
            continue;
        };
        scanned.entries.push(Candidate {
            entry: FeedEntry {
                position: FeedPosition::of(position)?,
                kind: FeedEntryKind::Edge,
                op: if row.added {
                    FeedOp::EdgeAdded
                } else {
                    FeedOp::EdgeRemoved
                },
                entity: row.source,
                entity_type: record.entity_type,
                actor: None,
                recorded_at: row.recorded_at,
                revision: None,
                edge: Some(FeedEdge {
                    source: row.source,
                    kind: kind.name().to_owned(),
                    target: row.target,
                }),
            },
            judge: Judge::ReadBoth(PointRead::id(row.source), PointRead::id(row.target)),
        });
    }
    Ok(scanned)
}

/// Up to `limit` redirty feed rows after `after`: each shown when the subscriber's lane shows
/// the TURN now.
pub(super) fn redirty_after_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<Position>,
    limit: usize,
) -> Result<Scanned> {
    let after = match after {
        None => None,
        Some(Position::Redirty(sequence)) => Some(sequence),
        Some(_) => {
            return Err(Error::CorruptedIndex(
                "a redirty cursor names another source",
            ));
        }
    };
    let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    let mut scanned = Scanned {
        entries: Vec::new(),
        through: None,
        more: false,
    };
    for row in REDIRTY.iter_range(&vault.store, txn, start, Bound::Unbounded)? {
        if scanned.entries.len() >= limit {
            scanned.more = true;
            break;
        }
        let (sequence, row) = row?;
        let position = Position::Redirty(sequence);
        scanned.through = Some(position);
        let Some(record) = vault.store.port_entity_record(txn, &row.turn)? else {
            continue;
        };
        scanned.entries.push(Candidate {
            entry: FeedEntry {
                position: FeedPosition::of(position)?,
                kind: FeedEntryKind::Redirty,
                op: FeedOp::Redirty,
                entity: row.turn,
                entity_type: record.entity_type,
                actor: None,
                recorded_at: row.recorded_at,
                revision: None,
                edge: None,
            },
            judge: Judge::Read(PointRead::id(row.turn)),
        });
    }
    Ok(scanned)
}

/// The rows of `source`'s feed at or below `floor` (every row when `None`), at most `max_rows`,
/// read in `txn` for a later write to delete.
pub(super) fn passed_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source: FeedSource,
    floor: Option<Position>,
    max_rows: usize,
) -> Result<Vec<u64>> {
    let end = match (source, floor) {
        (_, None) => None,
        (FeedSource::Edges, Some(Position::Edges(sequence)))
        | (FeedSource::Redirty, Some(Position::Redirty(sequence))) => Some(sequence),
        _ => return Err(Error::CorruptedIndex("a feed floor names another source")),
    };
    let end = end.as_ref().map_or(Bound::Unbounded, Bound::Included);
    let mut rows = Vec::new();
    match source {
        FeedSource::Edges => {
            for row in EDGES.iter_range(store, txn, Bound::Unbounded, end)? {
                if rows.len() >= max_rows {
                    break;
                }
                rows.push(row?.0);
            }
        }
        FeedSource::Redirty => {
            for row in REDIRTY.iter_range(store, txn, Bound::Unbounded, end)? {
                if rows.len() >= max_rows {
                    break;
                }
                rows.push(row?.0);
            }
        }
        FeedSource::Changes | FeedSource::Settlements => {}
    }
    Ok(rows)
}

/// Deletes the rows `sequences` names from `source`'s feed, in the caller's write.
pub(super) fn delete_rows_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    source: FeedSource,
    sequences: &[u64],
) -> Result<()> {
    for sequence in sequences {
        match source {
            FeedSource::Edges => {
                EDGES.delete(store, txn, sequence)?;
            }
            FeedSource::Redirty => {
                REDIRTY.delete(store, txn, sequence)?;
            }
            FeedSource::Changes | FeedSource::Settlements => {}
        }
    }
    Ok(())
}

/// Deletes every edge row with an end in `ids` and every redirty row naming one, in the
/// caller's erase write. One complete scan of each feed: they hold only rows a follower has not
/// acknowledged.
pub(super) fn scrub_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    ids: &BTreeSet<EntityId>,
) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut edges = Vec::new();
    for row in EDGES.iter_from(store, txn, &[])? {
        let (sequence, row) = row?;
        if ids.contains(&row.source) || ids.contains(&row.target) {
            edges.push(sequence);
        }
    }
    let mut redirty = Vec::new();
    for row in REDIRTY.iter_from(store, txn, &[])? {
        let (sequence, row) = row?;
        if ids.contains(&row.turn) {
            redirty.push(sequence);
        }
    }
    delete_rows_in_txn(store, txn, FeedSource::Edges, &edges)?;
    delete_rows_in_txn(store, txn, FeedSource::Redirty, &redirty)
}
