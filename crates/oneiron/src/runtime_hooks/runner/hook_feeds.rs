//! The runner's work on the engine's own hook feeds: a pass releases the
//! due watcher TASKs into the tick feed (FIX 4749), and at its end prunes
//! the settlement, tick and inbound rows every binding has passed
//! (FIX 22121, FIX 22141). The claim changelog is not pruned here.

use crate::runtime_hooks::filter;
use crate::runtime_hooks::source::{self, FactKind, FactPosition, FactSource};
use crate::runtime_hooks::store::{self, CursorRow};
use crate::skill_hub::pack_catalog::PackHookBinding;
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

    /// Prunes the three hook feeds once at the end of each pass, retained
    /// or not (FIX 22121, FIX 22141): the rows at or below the lowest stored
    /// cursor of `bindings`, every enabled fact binding of the vault, at
    /// most `max_rows` a feed, planned in a snapshot and deleted in one
    /// write only when there are any. Each such binding moves its cursor
    /// past each row it takes or skips, so a row below the floor is one no
    /// binding reads again, and a feed no binding reads is pruned too. A
    /// binding enabled meanwhile starts at the feed head, or, new to the tick
    /// feed, before the earliest open TASK's tick, which the tick prune
    /// keeps. Nothing goes from a feed while a binding stands at its start.
    pub(super) fn prune_hook_feeds(
        &self,
        bindings: &[(EntityId, PackHookBinding)],
        max_rows: usize,
    ) -> Result<()> {
        let planned = {
            let rtxn = self.vault.store.env.read_txn()?;
            let mut planned = Vec::new();
            for source in [
                FactSource::Settlement,
                FactSource::Schedule,
                FactSource::SurfaceInbound,
            ] {
                let Some(floor) = floor_in_txn(self.vault, &rtxn, bindings, source)? else {
                    continue;
                };
                let rows = source::passed_rows_in_txn(self.vault, &rtxn, floor, max_rows)?;
                if !rows.is_empty() {
                    planned.push((source, rows));
                }
            }
            planned
        };
        if planned.is_empty() {
            return Ok(());
        }
        self.vault.with_write_txn_grouped(|txn| {
            for (source, rows) in &planned {
                source::delete_feed_rows_in_txn(self.vault, txn, *source, rows)?;
            }
            Ok(())
        })
    }
}

/// The lowest stored cursor of `bindings` in `source`, read in `txn`; `None`
/// with no binding, or while one stands at the source's start.
fn floor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    bindings: &[(EntityId, PackHookBinding)],
    source: FactSource,
) -> Result<Option<FactPosition>> {
    let mut floor: Option<FactPosition> = None;
    for (id, _) in bindings {
        let Some(position) =
            store::cursor_in_txn(vault, txn, *id, source)?.and_then(CursorRow::position)
        else {
            return Ok(None);
        };
        floor = Some(floor.map_or(position, |held| held.min(position)));
    }
    Ok(floor)
}
