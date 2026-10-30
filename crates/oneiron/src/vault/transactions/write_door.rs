//! The vault's classed write door: one logical write in the single writer's
//! group commit, and the work its transaction queued for after the commit.

use crate::Vault;
use crate::error::Error;
use crate::store::{BackupWriteClass, Callback, Rows};
#[cfg(feature = "sync")]
use crate::sync::federation_burst::check_active_in_txn as check_federation_imports_in_txn;

/// A build without sync runs no federation import, so a write has no
/// import authority to recheck (FIX 4248).
#[cfg(not(feature = "sync"))]
fn check_federation_imports_in_txn(
    _vault: &Vault,
    _txn: &heed::RoTxn<'_>,
) -> crate::error::Result<()> {
    Ok(())
}

impl Vault {
    /// [`Self::write_txn_door`] for a write of `class` (FIX 6730): one that
    /// changes no content runs as a group of its own and moves no backup
    /// watermark (`store::backup_change`).
    pub(super) fn write_txn_door_classed<F, T, E>(
        &self,
        callback: Callback,
        class: BackupWriteClass,
        f: F,
    ) -> std::result::Result<T, E>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
        E: From<Error>,
    {
        // Scan checks raised since the last write are kept first, in a write
        // of their own (no scan opens one). It takes the writer where this
        // write is about to, holding nothing more: no answer exists yet to
        // carry a permit another write waits on.
        self.keep_waiting_scan_checks();
        // One logical write in the single writer's group commit: the closure
        // runs in a transaction of its own, and `Ok` comes back only once the
        // shared commit is durable.
        let stale_sweep = crate::federation::StaleSweepWatch::begin(self);
        // Read on the calling thread: the group may run this closure on
        // another member's (FIX 11607).
        let rederive = !crate::scope_summary::rederive_deferred();
        let (
            result,
            approved_vad_ids,
            proactivity_changed,
            (task_ids, rows, room_joins, pad_windows, settled_tasks, notifications_changed),
            retirement_staged,
        ) = self.store.group_write_classed(callback, class, |wtxn| {
            let retirements_before = match self.store.gate_retirements_staged_in_txn(wtxn) {
                Ok(staged) => staged,
                Err(err) => return Rows::Discard(Err(E::from(err))),
            };
            // A credential erase this write stages finishes after it (KS-6 part 2).
            let credentials_before = crate::store::credential_erases_staged();
            let rekeys = crate::channel_identity::AssignmentRekeys::begin(&self.store);
            let (result, postcommit) = {
                let _active_write_txn = crate::store::active_write_txn_guard();
                let vad_scope = crate::batch::VadPostcommitScope::new(self, wtxn);
                // A key this write's mask found raises its notice here.
                match check_federation_imports_in_txn(self, wtxn)
                    .map_err(E::from)
                    .and_then(|()| f(wtxn))
                    .and_then(|result| {
                        crate::secret_custody::raise_found_key_notices_in_txn(self, wtxn)
                            .map_err(E::from)?;
                        Ok(result)
                    }) {
                    Ok(result) => (result, vad_scope.finish()),
                    Err(err) => return Rows::Discard(Err(err)),
                }
            };
            if let Err(err) = rekeys.finish(&self.store, wtxn) {
                return Rows::Discard(Err(E::from(err)));
            }
            if rederive && let Err(err) = crate::scope_summary::rederive_changed_in_txn(self, wtxn)
            {
                return Rows::Discard(Err(E::from(err)));
            }
            // FIX 7957: each row this write changed leaves its window a
            // durable marker, so a crash before the live mirror loses no edit.
            #[cfg(feature = "sync")]
            if let Err(err) = self.mark_pending_mirrors_in_txn(wtxn, &postcommit.rows) {
                return Rows::Discard(Err(E::from(err)));
            }
            let approved =
                match self.resolved_dreamer_vad_approvals_in_txn(wtxn, postcommit.vad_ids) {
                    Ok(approved) => approved,
                    Err(err) => return Rows::Discard(Err(E::from(err))),
                };
            // The approval's commit carries its consolidation debt (FIX 9598).
            if !approved.is_empty() {
                let now = self.store.clock.now_recorded_at();
                let owed = crate::store::owe_claim_vad_in_txn(&self.store, wtxn, &approved, now);
                if let Err(err) = owed {
                    return Rows::Discard(Err(E::from(err)));
                }
            }
            // A claim delete applied in this write staged its key's
            // retirement; destroy the key after the commit, not at the
            // next retention pass.
            match self.store.gate_retirements_staged_in_txn(wtxn) {
                Ok(staged) => Rows::Commit((
                    result,
                    approved,
                    postcommit.proactivity_changed,
                    (
                        postcommit.task_ids,
                        postcommit.rows,
                        postcommit.room_joins,
                        postcommit.pad_windows,
                        postcommit.settled_tasks,
                        postcommit.notifications_changed,
                    ),
                    staged != retirements_before
                        || crate::store::credential_erases_staged() != credentials_before,
                )),
                Err(err) => Rows::Discard(Err(E::from(err))),
            }
        })?;
        self.store.notify_attempt_observers();
        if proactivity_changed {
            self.store.notify_proactivity_changes();
        }
        self.store.notify_task_updates(task_ids);
        // FIX 3084: a notification this write put or marked wakes the live
        // queries that follow notifications, now that it is durable.
        if notifications_changed {
            self.store.notify_notification_updates();
        }
        // The owner's waiting shed looks again (FIX 10157).
        self.wake_owner_shed();
        // FIX 1140: a TASK this write settled wakes its peer-result waiters
        // now that it is durable. A wake that does not go out is left to the
        // wake pass and never fails this write.
        if !settled_tasks.is_empty() {
            crate::task_verb::highway_runner::wake_settled_tasks(
                self,
                &settled_tasks,
                self.store.clock.now_recorded_at(),
            );
        }
        // A row written after its window loaded reaches it only through the
        // live mirror.
        #[cfg(feature = "sync")]
        self.note_committed_rows(rows);
        #[cfg(not(feature = "sync"))]
        drop((rows, room_joins));
        // FIX 3321: a join this write filed reaches the live window of its
        // room or thread, now that it is durable.
        #[cfg(feature = "sync")]
        if !room_joins.is_empty() {
            let joins: Vec<&str> = room_joins.iter().map(String::as_str).collect();
            self.refresh_room_rows_in_live_windows(&joins, &[]);
        }
        // FIX 3334: a WORLD delete this write applied staged its pads'
        // tombstones; they publish now, not at each window's next load.
        self.publish_pad_tombstones_after_commit(&pad_windows);
        if retirement_staged {
            self.finish_gate_decision_retirements_after_commit();
        }
        // A replicated, replayed or composed authority row stamps the worlds
        // of a pact it ended, as the authority door does (H213).
        stale_sweep.finish()?;
        // Approval is durable now, with its debt. The canonical consolidator
        // opens its own writer; its failure is returned without rolling back
        // Approved, and the debt stays for the housekeeping pass (FIX 9598,
        // 10680). The clock is observed only when there is an approval to
        // consolidate.
        if !approved_vad_ids.is_empty() {
            let now = self.store.clock.now_recorded_at();
            for id in approved_vad_ids {
                self.consolidate_claim_vad_now(&id, now)?;
            }
        }
        Ok(result)
    }

    /// Whether a write through the door with nothing of its own would still
    /// do per-write work (FIX 11664). A timer pass whose opening write would
    /// carry none of it skips that write.
    #[doc(hidden)]
    pub fn write_door_work_due(&self) -> crate::error::Result<bool> {
        // One entry per piggyback the door above carries: a piggyback added
        // there is added here too.
        let txn = self.store.env.read_txn()?;
        let due = [
            // keep_waiting_scan_checks
            self.store.pending_scan_checks.any_waiting(),
            // StaleSweepWatch::finish
            self.store
                .federation_stale_sweep_owed
                .load(std::sync::atomic::Ordering::Acquire),
            // raise_found_key_notices_in_txn
            crate::secret_custody::found_key_notices_due_in_txn(self, &txn)?,
            // rederive_changed_in_txn, unless this thread defers it
            !crate::scope_summary::rederive_deferred()
                && crate::scope_summary::rederive_owed_in_txn(self, &txn)?,
        ];
        Ok(due.contains(&true))
    }

    /// The wakes an empty write's commit sends, sent with no write: every
    /// attempt observer and the owner's waiting shed look again (FIX 11664).
    #[doc(hidden)]
    pub fn send_empty_commit_wakes(&self) {
        self.store.notify_attempt_observers();
        self.wake_owner_shed();
    }
}
