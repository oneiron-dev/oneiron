//! The prune of the engine's own hook feeds: the settlement, tick and
//! inbound rows every binding has passed (FIX 22121, FIX 22141, FIX 22154,
//! FIX 22178). The runner prunes them at the end of each pass, with a
//! binding to run or none, hooks on or off, after releasing the due watcher
//! TASKs at its start; each housekeeping pass, the owner's run now and
//! `oneiron maintain` included, prunes them once by the same rule after its
//! own release, so a host that runs no runner keeps the feeds bounded (FIX
//! 22180). The claim changelog is not pruned here.

use crate::runtime_hooks::source::{self, FactPosition, FactSource};
use crate::runtime_hooks::store::{self, CursorRow};
use crate::skill_hub::pack_catalog::HookPhase;
use crate::{EntityId, Result, Vault};

/// Prunes the hook feeds once: at the end of each runner pass, retained or
/// not, with no binding to run, and with hooks off, when no binding moves
/// its cursor (FIX 22121, FIX 22154, FIX 22178), and in each housekeeping
/// pass after its tick release (FIX 22180). It takes the rows at or below
/// the lowest stored cursor of every fact binding enabled in the prune's own
/// snapshot, held back or not, and of every change feed subscription that
/// follows the feed (untangle slice 6.8), or every row while neither is, at most
/// `max_rows` a feed, planned in that snapshot and deleted in one write only
/// when there are any; that write keeps each planned row a subscription made
/// since the snapshot has not passed (review #6897). The pass's own binding list is not the floor: a
/// binding enabled since the pass began holds its rows too (review #6767).
/// Each such binding moves its cursor past each row it takes or skips, so a
/// row below the floor is one no binding reads again. A binding enabled
/// after the snapshot starts at the feed head, past every planned row, or,
/// new to the tick feed, before the earliest open TASK's tick, which the
/// tick prune keeps. Nothing goes from a feed while a binding stands at its
/// start or holds no cursor there.
///
/// The floor reads stored cursors only, never a runner's own state, so a
/// housekeeping prune runs beside a live runner: a run in flight stands past
/// its binding's stored cursor, which moves only in the write that commits
/// it, and a stored cursor on these feeds moves only forward, a run or skip
/// advancing it and a re-enable or restart placing it at the feed head. Two
/// prunes racing each plan in their own snapshot and delete in their own
/// write. The writes commit one after the other, so the later one finds no
/// row where the earlier deleted it, its delete of that row changes nothing,
/// and each row goes once.
pub(crate) fn prune_hook_feeds(vault: &Vault, max_rows: usize) -> Result<()> {
    let planned = {
        let rtxn = vault.store.env.read_txn()?;
        let readers: Vec<EntityId> = vault
            .pack_hook_binding_rows_in_txn(&rtxn)?
            .into_iter()
            .filter(|(_, binding)| binding.enabled && binding.selector.phase == HookPhase::Fact)
            .map(|(id, _)| id)
            .collect();
        let mut planned = Vec::new();
        for source in [
            FactSource::Settlement,
            FactSource::Schedule,
            FactSource::SurfaceInbound,
        ] {
            let Some(floor) = floor_in_txn(vault, &rtxn, &readers, source)? else {
                continue;
            };
            let rows = source::passed_rows_in_txn(vault, &rtxn, floor, max_rows)?;
            if !rows.is_empty() {
                planned.push((source, rows));
            }
        }
        planned
    };
    if planned.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        for (source, rows) in &planned {
            let rows = still_passed_in_txn(vault, txn, *source, rows)?;
            source::delete_feed_rows_in_txn(vault, txn, *source, &rows)?;
        }
        Ok(())
    })
}

/// The planned `rows` of `source` that every change feed subscription has
/// still passed, read in the prune's own write (review #6897): a
/// subscription made after the plan's snapshot, one that starts at the
/// feed's beginning above all, holds the rows its cursor has not passed,
/// though no binding reads them again. A binding enabled after the snapshot
/// starts past every planned row, so only the subscriptions are read again.
fn still_passed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: FactSource,
    rows: &[u64],
) -> Result<Vec<u64>> {
    Ok(match crate::feeds::floor_in_txn(vault, txn, source)? {
        crate::feeds::FeedFloor::Unfollowed => rows.to_vec(),
        crate::feeds::FeedFloor::AtStart => Vec::new(),
        crate::feeds::FeedFloor::At(floor) => rows
            .iter()
            .copied()
            .filter(|row| row_position(source, *row).is_some_and(|position| position <= floor))
            .collect(),
    })
}

/// The position of row `row` of `source`'s hook feed; `None` for the claim
/// changelog, which this prune never takes.
const fn row_position(source: FactSource, row: u64) -> Option<FactPosition> {
    match source {
        FactSource::Settlement => Some(FactPosition::Settlement(source::SettlementPosition(row))),
        FactSource::Schedule => Some(FactPosition::Schedule(source::SchedulePosition(row))),
        FactSource::SurfaceInbound => Some(FactPosition::SurfaceInbound(
            source::SurfaceInboundPosition(row),
        )),
        FactSource::ClaimChangelog => None,
    }
}

/// The lowest stored cursor of `readers` and of every change feed
/// subscription following `source` (untangle slice 6.8), read in `txn`; with
/// neither, the feed's head, as a binding enabled later starts there or, new
/// to the tick feed, before an open TASK's kept tick (FIX 22154). `None`
/// while the feed is empty, or while a reader or a subscription stands at
/// the source's start or a reader holds no cursor there.
fn floor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    readers: &[EntityId],
    source: FactSource,
) -> Result<Option<FactPosition>> {
    let mut floor: Option<FactPosition> = match crate::feeds::floor_in_txn(vault, txn, source)? {
        crate::feeds::FeedFloor::Unfollowed if readers.is_empty() => {
            return source::head_in_txn(vault, txn, source);
        }
        crate::feeds::FeedFloor::Unfollowed => None,
        crate::feeds::FeedFloor::AtStart => return Ok(None),
        crate::feeds::FeedFloor::At(position) => Some(position),
    };
    for id in readers {
        let Some(position) =
            store::cursor_in_txn(vault, txn, *id, source)?.and_then(CursorRow::position)
        else {
            return Ok(None);
        };
        floor = Some(floor.map_or(position, |held| held.min(position)));
    }
    Ok(floor)
}
