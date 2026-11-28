//! The issuer's records of a vault machine's jobs that no dispatch row holds (pass 33 row R4;
//! 5.1, 7.9 and 8.5):
//! - `JOB_ORPHAN`: a key a node holds that this issuer never dispatched or no longer knows,
//!   found by the reconcile before the first dispatch to that node, stopped while it lives, and
//!   kept with its terminal receipt and the seconds it occupied, which no family is charged for;
//! - `MACHINE_JOB_GUARD`: the issuer's half of the drain guard. It counts the machine's own
//!   failures in a row from what the issuer observes, unreachable dispatches included. Once the
//!   machine is drained, the issuer starts no job there until door 12 clears it, or until a
//!   passed readiness check clears it under `machines.drain.clear_by = after_readiness_check`
//!   (the default; [`Vault::clear_machine_job_drain_after_check`]). A caller's stop neither
//!   counts nor resets; a run past the fast-exit window resets;
//! - `JOB_RETURN`: what the issuer did with an ended key's outputs, and the acknowledgement
//!   that lets the node clean them ([`job_return`]).
//!
//! The signed receipts are oneiron-server's `gpu_execution_node::wire` types; these rows keep
//! their exact codec bytes.

pub mod clear_drain_door;
mod job_return;
pub(crate) mod setting_keys;
pub(crate) mod tables;

use serde::{Deserialize, Serialize};

pub use clear_drain_door::{
    CLEAR_DRAIN_VERB, MachineDrainClearRequest, MachineDrainCleared, clear_drain_as,
    clear_drain_embedded,
};
pub use job_return::{HandoffReturn, JobReturn, ReturnRefusal};
pub use setting_keys::MachineJobSettings;

use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

const JOB_ORPHANS: SideTable<String, JobOrphan, Named> = SideTable::new(&side_table::JOB_ORPHAN);
const MACHINE_JOB_GUARDS: SideTable<String, MachineJobGuard, Named> =
    SideTable::new(&side_table::MACHINE_JOB_GUARD);

/// The occupied seconds of an orphan that ran, recorded against the allocation generation its
/// receipt's hold named, charged to no family (EM-15 = A).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnattributedSeconds {
    /// The reservation the node's receipt named.
    pub reservation: String,
    pub generation: u64,
    pub secs: u64,
    pub recorded_at_ms: u64,
}

/// A key a node holds that this issuer has no dispatch row for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobOrphan {
    pub machine: EntityId,
    /// The node's key.
    pub key: String,
    /// The node's state of the key when the issuer last listed or asked it, by its wire name.
    pub state: String,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
    /// When the issuer first asked the node to stop the live key.
    #[serde(default)]
    pub stop_sent_at_ms: Option<u64>,
    /// The node's terminal receipt of the key, in the job codec, once it ended.
    #[serde(default)]
    pub ended: Option<Vec<u8>>,
    /// The seconds it occupied, once recorded.
    #[serde(default)]
    pub unattributed: Option<UnattributedSeconds>,
}

impl JobOrphan {
    /// The row's key: `<machine hex>#<node key>`.
    #[must_use]
    pub fn row_key(machine: EntityId, key: &str) -> String {
        format!("{}#{key}", machine.to_hex())
    }

    /// Whether the node still runs or holds the key: it has no terminal receipt yet.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.ended.is_none()
    }
}

/// Why the issuer drained a machine, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineDrain {
    pub why: String,
    pub at_ms: u64,
}

/// How one ended or unanswered dispatch counts for the machine's guard (7.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineJobOutcome {
    /// The machine's own failure: a lost box, a launch refused for a device, fence or unit
    /// reason, an unconfirmed release, an end inside the fast-exit window, a dispatch it never
    /// answered, or a node figure above the issuer's bracket. Counts.
    MachineFailure { why: String },
    /// A run past the fast-exit window ended. Resets.
    RanPastFastExit,
    /// A caller's stop, a withdrawn key, a refusal the node wrote down for the request's own
    /// reason. Neither counts nor resets.
    NotTheMachines,
}

/// The issuer's half of the drain guard for one machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineJobGuard {
    pub machine: EntityId,
    pub failures_in_a_row: u32,
    /// The newest failure the count holds.
    #[serde(default)]
    pub last_failure: Option<String>,
    /// While drained, why and since when.
    #[serde(default)]
    pub drained: Option<MachineDrain>,
    pub updated_at_ms: u64,
}

impl MachineJobGuard {
    fn fresh(machine: EntityId, now_ms: u64) -> Self {
        Self {
            machine,
            failures_in_a_row: 0,
            last_failure: None,
            drained: None,
            updated_at_ms: now_ms,
        }
    }
}

/// Why door 12 did not clear a machine's drain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClearDrainRefusal {
    /// The issuer has not drained this machine.
    #[error("machine_not_drained")]
    NotDrained,
}

impl Vault {
    /// The orphan row of `key` on `machine`.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn job_orphan(&self, machine: EntityId, key: &str) -> crate::Result<Option<JobOrphan>> {
        let txn = self.store.env.read_txn()?;
        JOB_ORPHANS.get(&self.store, &txn, &JobOrphan::row_key(machine, key))
    }

    /// Every orphan of `machine`, in key order; every orphan of every machine with `None`.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn job_orphans(&self, machine: Option<EntityId>) -> crate::Result<Vec<JobOrphan>> {
        let txn = self.store.env.read_txn()?;
        let prefix = machine.map(|machine| format!("{}#", machine.to_hex()));
        let rows = JOB_ORPHANS.scan_from(
            &self.store,
            &txn,
            prefix.as_deref().unwrap_or_default().as_bytes(),
        )?;
        Ok(rows.into_iter().map(|(_, row)| row).collect())
    }

    /// Writes what the issuer saw of `key` on `machine` at `now_ms` in one durable write: a new
    /// row the first time, then `change` applied to the row that stands. `state` is the node's
    /// state of the key by its wire name; `None` keeps the row's (`unknown` on a new row).
    /// Answers the row as written.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn record_job_orphan(
        &self,
        machine: EntityId,
        key: &str,
        state: Option<&str>,
        now_ms: u64,
        change: impl FnOnce(&mut JobOrphan),
    ) -> crate::Result<JobOrphan> {
        let row_key = JobOrphan::row_key(machine, key);
        self.with_write_txn(|txn| {
            let mut row = JOB_ORPHANS
                .get(&self.store, txn, &row_key)?
                .unwrap_or_else(|| JobOrphan {
                    machine,
                    key: key.to_owned(),
                    state: state.unwrap_or("unknown").to_owned(),
                    first_seen_at_ms: now_ms,
                    last_seen_at_ms: now_ms,
                    stop_sent_at_ms: None,
                    ended: None,
                    unattributed: None,
                });
            if let Some(state) = state {
                state.clone_into(&mut row.state);
            }
            row.last_seen_at_ms = row.last_seen_at_ms.max(now_ms);
            change(&mut row);
            JOB_ORPHANS.put(&self.store, txn, &row_key, &row)?;
            Ok(row)
        })
    }

    /// The issuer's guard of `machine`; `None` before its first counted end.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn machine_job_guard(&self, machine: EntityId) -> crate::Result<Option<MachineJobGuard>> {
        let txn = self.store.env.read_txn()?;
        MACHINE_JOB_GUARDS.get(&self.store, &txn, &machine.to_hex())
    }

    /// Why the issuer drained `machine`, while it is drained: the start gate refuses a job
    /// there with it.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn machine_job_drained(&self, machine: EntityId) -> crate::Result<Option<MachineDrain>> {
        Ok(self
            .machine_job_guard(machine)?
            .and_then(|guard| guard.drained))
    }

    /// Counts `outcome` for `machine` in one durable write: a machine failure adds one and,
    /// at `jobs.drain.after_failures` in a row, drains the machine; a run past the fast-exit
    /// window resets the count; anything else changes nothing. A drained machine stays drained
    /// until door 12 clears it or, under `machines.drain.clear_by = after_readiness_check`, a
    /// passed readiness check that the node ran after the issuer read this row
    /// ([`Self::clear_machine_job_drain_after_check`]). Answers the guard as written.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn count_machine_job_outcome(
        &self,
        machine: EntityId,
        outcome: &MachineJobOutcome,
        now_ms: u64,
    ) -> crate::Result<MachineJobGuard> {
        let after = self.machine_job_settings(machine)?.drain_after_failures;
        let row_key = machine.to_hex();
        self.with_write_txn(|txn| {
            let mut guard = MACHINE_JOB_GUARDS
                .get(&self.store, txn, &row_key)?
                .unwrap_or_else(|| MachineJobGuard::fresh(machine, now_ms));
            match outcome {
                MachineJobOutcome::MachineFailure { why } => {
                    guard.failures_in_a_row = guard.failures_in_a_row.saturating_add(1);
                    guard.last_failure = Some(why.clone());
                    if guard.drained.is_none() && guard.failures_in_a_row >= after {
                        guard.drained = Some(MachineDrain {
                            why: format!(
                                "drained after {} failed jobs in a row; the last: {why}",
                                guard.failures_in_a_row
                            ),
                            at_ms: now_ms,
                        });
                    }
                }
                MachineJobOutcome::RanPastFastExit => {
                    guard.failures_in_a_row = 0;
                    guard.last_failure = None;
                }
                MachineJobOutcome::NotTheMachines => return Ok(guard),
            }
            guard.updated_at_ms = now_ms;
            MACHINE_JOB_GUARDS.put(&self.store, txn, &row_key, &guard)?;
            Ok(guard)
        })
    }

    /// Door 12's write: clears the issuer's drain of `machine` and its count, in one durable
    /// write. Who may call it is the door's check against `machines.drain.clear_by`.
    ///
    /// # Errors
    ///
    /// A store failure; inside, [`ClearDrainRefusal::NotDrained`] for a machine the issuer has
    /// not drained.
    pub fn clear_machine_job_drain(
        &self,
        machine: EntityId,
        now_ms: u64,
    ) -> crate::Result<Result<MachineJobGuard, ClearDrainRefusal>> {
        let row_key = machine.to_hex();
        self.with_write_txn(|txn| {
            let Some(mut guard) = MACHINE_JOB_GUARDS.get(&self.store, txn, &row_key)? else {
                return Ok(Err(ClearDrainRefusal::NotDrained));
            };
            if guard.drained.is_none() {
                return Ok(Err(ClearDrainRefusal::NotDrained));
            }
            guard.drained = None;
            guard.failures_in_a_row = 0;
            guard.last_failure = None;
            guard.updated_at_ms = now_ms;
            MACHINE_JOB_GUARDS.put(&self.store, txn, &row_key, &guard)?;
            Ok(Ok(guard))
        })
    }

    /// The readiness check's clear of the issuer's drain (pass 34 row Q4, CG-2 row 9: "a drained
    /// machine clears itself once its readiness check passes"), in one durable write.
    /// `read_before` is `machine`'s guard row as the issuer read it before asking the node for
    /// the passed check; the caller orders the check after that read on the node's own clock.
    /// The drain and its count clear when both hold:
    /// - `machines.drain.clear_by` for `machine`, read in the same write, is
    ///   `after_readiness_check`;
    /// - the row is still `read_before`.
    ///
    /// A row that changed since that read is the newer word, and nothing changes: a failure
    /// counted after the read (a late terminal receipt, a reserve's cutoff) or door 12's clear.
    /// Nothing changes either under any other `clear_by`, or for a machine the issuer has not
    /// drained. Answers the drain it cleared.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn clear_machine_job_drain_after_check(
        &self,
        machine: EntityId,
        read_before: &MachineJobGuard,
        now_ms: u64,
    ) -> crate::Result<Option<MachineDrain>> {
        let row_key = machine.to_hex();
        self.with_write_txn(|txn| {
            let clear_by = crate::machine_policy::setting_keys::DRAIN_CLEAR_BY
                .read_in_txn(self, txn, &[], Some(&row_key))?
                .value;
            if clear_by != crate::machine_policy::DrainClearBy::AfterReadinessCheck {
                return Ok(None);
            }
            let Some(mut guard) = MACHINE_JOB_GUARDS.get(&self.store, txn, &row_key)? else {
                return Ok(None);
            };
            if guard != *read_before {
                return Ok(None);
            }
            let Some(drain) = guard.drained.take() else {
                return Ok(None);
            };
            guard.failures_in_a_row = 0;
            guard.last_failure = None;
            guard.updated_at_ms = now_ms;
            MACHINE_JOB_GUARDS.put(&self.store, txn, &row_key, &guard)?;
            Ok(Some(drain))
        })
    }
}
