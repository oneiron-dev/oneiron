//! The runner's work on the engine's own hook feeds: a pass releases the
//! due watcher TASKs into the tick feed (FIX 4749), and at its end, with a
//! binding to run or none, hooks on or off, prunes the settlement, tick and
//! inbound rows every binding has passed (FIX 22121, FIX 22141, FIX 22154,
//! FIX 22178). The claim changelog is not pruned here.

use crate::runtime_hooks::filter;
use crate::runtime_hooks::source::{self, FactKind, FactPosition, FactSource};
use crate::runtime_hooks::store::{self, CursorRow};
use crate::skill_hub::pack_catalog::{HookPhase, PackHookBinding};
use crate::{EntityId, Result, Vault};

use super::Pass;

impl Pass<'_, '_> {
    /// Releases the due watcher TASKs into the tick feed, when `source` is
    /// the tick feed and a binding here can take a tick.
    pub(super) fn release_ticks(
        &mut self,
        source: FactSource,
        bindings: &[(EntityId, PackHookBinding)],
    ) -> Result<()> {
        if source != FactSource::Schedule
            || !bindings.iter().any(|(_, binding)| {
                filter::verbs_admit_kind(&binding.selector.verbs, FactKind::ScheduleTick)
            })
        {
            return Ok(());
        }
        let now = self.vault.store.clock.now_recorded_at();
        self.report.more |= source::release_due_ticks(self.vault, now)?;
        Ok(())
    }
}

/// Prunes the hook feeds once at the end of each pass, retained or not, with
/// no binding to run, and with hooks off, when no binding moves its cursor
/// (FIX 22121, FIX 22154, FIX 22178): the rows at or below the lowest
/// stored cursor of every fact binding enabled in the prune's own snapshot,
/// held back or not, or every row while none is enabled, at most
/// `max_rows` a feed, planned in that snapshot and deleted in one write only
/// when there are any. The pass's own binding list is not the floor: a
/// binding enabled since the pass began holds its rows too (review #6767).
/// Each such binding moves its cursor past each row it takes or skips, so a
/// row below the floor is one no binding reads again. A binding enabled
/// after the snapshot starts at the feed head, past every planned row, or,
/// new to the tick feed, before the earliest open TASK's tick, which the
/// tick prune keeps. Nothing goes from a feed while a binding stands at its
/// start or holds no cursor there.
pub(super) fn prune_hook_feeds(vault: &Vault, max_rows: usize) -> Result<()> {
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
            source::delete_feed_rows_in_txn(vault, txn, *source, rows)?;
        }
        Ok(())
    })
}

/// The lowest stored cursor of `readers` in `source`, read in `txn`; with no
/// reader, the feed's head, as a binding enabled later starts there or, new
/// to the tick feed, before an open TASK's kept tick (FIX 22154). `None`
/// while the feed is empty, or while a reader stands at the source's start
/// or holds no cursor there.
fn floor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    readers: &[EntityId],
    source: FactSource,
) -> Result<Option<FactPosition>> {
    if readers.is_empty() {
        return source::head_in_txn(vault, txn, source);
    }
    let mut floor: Option<FactPosition> = None;
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
