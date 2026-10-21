//! The threads an off-record room's copy carries, for its export's audit
//! and notices (FIX 6427, 6681), split from its parent.

use super::{MembershipWindow, OffRecordSession, OffRecordTalkTurn, Talk};
use crate::entity_id::EntityId;
use crate::workspace_roster::ExportThreadRoots;

impl Talk {
    /// Notes the root of the thread `turn` is of, read from its stored
    /// `body`, as the turn is first gathered.
    pub(super) fn thread_root(&mut self, turn: EntityId, entity_type: u8, body: &[u8]) {
        if let Some(root) = crate::memory::turn_thread_root(entity_type, body) {
            self.roots.entry(*turn.as_bytes()).or_insert(root);
        }
    }

    /// [`Self::finish`], beside the root of each thread a turn it keeps is
    /// of: the threads the copy carries (FIX 6427). Each root's binding is
    /// read in `session`'s view, in `txn`, while its caller holds the
    /// stretch, so its members are still told should the stretch close
    /// before the audit (FIX 6681). A view that does not read is logged and
    /// leaves each root its id alone; it never fails the copy.
    pub(super) fn finish_with_roots(
        mut self,
        windows: Option<&[MembershipWindow]>,
        session: &OffRecordSession<'_>,
        txn: &heed::RoTxn<'_>,
    ) -> (Vec<OffRecordTalkTurn>, ExportThreadRoots) {
        let roots = std::mem::take(&mut self.roots);
        let turns = self.finish(windows);
        let mut carried = ExportThreadRoots::default();
        carried.extend(
            turns
                .iter()
                .filter_map(|turn| roots.get(&turn.turn).copied()),
        );
        match session.read_view() {
            Ok(view) => carried.capture_in(&view.read(), txn),
            Err(error) => tracing::warn!(%error, "off-record export: its threads not read"),
        }
        (turns, carried)
    }
}
