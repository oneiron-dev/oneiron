//! The issuer's status-side Setting keys (pass 33 row R4; pass 34 sections 2.4 and 6.3; the lead's
//! POLICY AS SETTINGS, 25 Nov 00:04): each number and each choice the issuer's status side makes
//! is a key with today's value as its default, read here and nowhere else.

use crate::error::Result;
use crate::machine_policy::DrainClearBy;
use crate::machine_policy::setting_keys::DRAIN_CLEAR_BY;
use crate::setting::Kind;
use crate::{EntityId, Vault};

fn three_failures() -> u32 {
    3
}

fn one_hour_secs() -> u64 {
    3_600
}

fn two_steps() -> u32 {
    2
}

fn five_secs() -> u64 {
    5
}

crate::setting::setting_keys! {
    /// How many of a machine's own failures in a row, as the issuer observes them (a lost box,
    /// a refused launch, an unconfirmed release, an end inside the fast-exit window, a dispatch
    /// the machine never answered), drain it on the issuer (pass 33, 7.9). Default 3; 0 is read
    /// as 1. A caller's stop neither counts nor resets; a run past the window resets. Fewer is
    /// tighter.
    pub(crate) JOBS_DRAIN_AFTER_FAILURES: u32 = "jobs.drain.after_failures" {
        kind: Kind::new(three_failures).lower(),
    };
    /// An end this soon after the launch, in seconds, counts against the machine's drain guard
    /// (pass 33, 7.9), on the issuer as on the node. Default 5. Longer counts more ends: longer
    /// is tighter.
    pub(crate) JOBS_DRAIN_FAST_EXIT_SECS: u64 = "jobs.drain.fast_exit_secs" {
        kind: Kind::new(five_secs).higher(),
    };
    /// How long past its start window and its maximum a job that shows unconfirmed waits before
    /// the owner may write it off (pass 33, door 10 and 8.5), in seconds. Default 3,600: by then
    /// any launch from the dispatch met its cutoff. Longer is tighter.
    pub(crate) JOBS_WRITE_OFF_WAIT_SECS: u64 = "jobs.write_off.wait_secs" {
        kind: Kind::new(one_hour_secs).higher(),
    };
    /// After how many job steps without a newer receipt a job's status says its node
    /// observation is stale (pass 33, door 8). Default 2. It changes what the status shows,
    /// never what runs.
    pub(crate) JOBS_STATUS_STALE_AFTER_STEPS: u32 = "jobs.status.stale_after_steps" {
        kind: Kind::new(two_steps).neutral(),
    };
}

/// The issuer's status-side settings, read once per use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineJobSettings {
    /// `machines.drain.clear_by` for the machine read (declared in `machine_policy`).
    pub clear_by: DrainClearBy,
    /// `jobs.drain.after_failures`, at least 1.
    pub drain_after_failures: u32,
    /// `jobs.drain.fast_exit_secs`.
    pub fast_exit_secs: u64,
    /// `jobs.write_off.wait_secs`.
    pub write_off_wait_secs: u64,
    /// `jobs.status.stale_after_steps`.
    pub stale_after_steps: u32,
}

impl Vault {
    /// The issuer's status-side settings, with `machines.drain.clear_by` for `machine`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn machine_job_settings(&self, machine: EntityId) -> Result<MachineJobSettings> {
        let item = machine.to_hex();
        self.with_read_snapshot(|txn| {
            Ok(MachineJobSettings {
                clear_by: DRAIN_CLEAR_BY
                    .read_in_txn(self, txn, &[], Some(&item))?
                    .value,
                drain_after_failures: JOBS_DRAIN_AFTER_FAILURES
                    .read_in_txn(self, txn, &[], None)?
                    .value
                    .max(1),
                fast_exit_secs: JOBS_DRAIN_FAST_EXIT_SECS
                    .read_in_txn(self, txn, &[], None)?
                    .value,
                write_off_wait_secs: JOBS_WRITE_OFF_WAIT_SECS
                    .read_in_txn(self, txn, &[], None)?
                    .value,
                stale_after_steps: JOBS_STATUS_STALE_AFTER_STEPS
                    .read_in_txn(self, txn, &[], None)?
                    .value,
            })
        })
    }
}
