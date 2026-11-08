//! The runner's work on the two watcher feeds (FIX 4749): a pass releases
//! the due watcher TASKs into the tick feed, and the write that moves a
//! pass's cursors prunes the tick or inbound rows every binding has passed.
//! The claim changelog and the settlement feed are not pruned here.

use crate::runtime_hooks::filter;
use crate::runtime_hooks::source::{self, FactKind, FactPosition, FactSource};
use crate::runtime_hooks::store::{self, CursorRow};
use crate::skill_hub::pack_catalog::PackHookBinding;
use crate::{EntityId, Result};

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

    /// Prunes `source`'s rows at or before the lowest cursor of `bindings`,
    /// every enabled fact binding, at most `max_rows`, in the write that
    /// moved their cursors. Each such binding holds a cursor in every source
    /// and moves it past each row it takes or skips, so a row below the
    /// floor is one no binding reads again, and a feed no binding reads is
    /// pruned too. A binding enabled later starts at the feed head, or, new
    /// to the tick feed, before the earliest open TASK's tick, which the
    /// tick prune keeps. Nothing goes when `source` is no watcher feed, when
    /// a binding stands at the source's start, or in a pass that finishes
    /// retained runs, which holds one binding, not the vault's.
    pub(super) fn prune_watcher_feed_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source: FactSource,
        bindings: &[(EntityId, PackHookBinding)],
        max_rows: usize,
    ) -> Result<()> {
        if !matches!(source, FactSource::Schedule | FactSource::SurfaceInbound)
            || self.retained.is_some()
        {
            return Ok(());
        }
        let mut floor: Option<FactPosition> = None;
        for (id, _) in bindings {
            let Some(position) =
                store::cursor_in_txn(self.vault, txn, *id, source)?.and_then(CursorRow::position)
            else {
                return Ok(());
            };
            floor = Some(floor.map_or(position, |held| held.min(position)));
        }
        match floor {
            Some(floor) => source::prune_passed_in_txn(self.vault, txn, floor, max_rows),
            None => Ok(()),
        }
    }
}
