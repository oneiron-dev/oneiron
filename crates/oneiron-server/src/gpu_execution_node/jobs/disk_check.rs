//! The disk check (design pass 33, 7.9; FIX EXEC-NODE-DISK-CHECK-UNBUILT):
//! every `disk_check_secs` the engine measures each launched key's payload
//! through its job unit ([`super::JobUnit::payload_usage`]) and ends a key
//! whose payload passed its disk request as `DiskLimit`.
//!
//! How far a job can pass its request (review r13 R13-05 and R13-07 of
//! #10512):
//! - `disk_check_secs` is the period a pass is planned at, not a bound on
//!   the time between two measures of one key. A pass measures up to
//!   [`DISK_MEASURES_AT_ONCE`] keys at once, batch after batch, so a key is
//!   measured again within the period plus the slowest measure of each
//!   batch up to its own (each at most the walk's time bound).
//! - The speed a job fills its payload at is bounded only where the scope
//!   gives `write_rate_cap` (the unit's `IOWriteBandwidthMax`), which a
//!   template may require. That cap limits writes to the device: a file
//!   system with delayed allocation reserves space for buffered writes
//!   before they reach the device, up to the unit's dirty pages (a share of
//!   its `MemoryMax`), and metadata reaches the device through the file
//!   system's journal, outside the unit's cap. So the overshoot is about the
//!   rate times the time between two measures, plus the unit's dirty pages.
//!   Without the cap no rate is bounded, and the node's disk reserve and its
//!   state floor are what is left. `fallocate` and io_uring are refused by
//!   the unit's system call filter, which each job checks for itself.
//! - A quota the file system enforces for each payload is the complete
//!   mechanism; design 7.9 makes it a later node setting (FIX
//!   EXEC-NODE-PAYLOAD-QUOTA).
//!
//! The measures run outside the admission lock, since a walk may take
//! seconds. The end takes the lock and acts only while the service is open
//! and the key is still launched (R13-08).

use std::thread;

use super::admission::mib_bytes;
use super::journal::EndingCause;
use super::payload_usage::{PayloadUsage, PayloadWalkBounds};
use super::{JobKeyId, NodeGate, NodeJobs};
use crate::gpu_execution_node::wire::JobState;

/// The most payloads one pass measures at once: each is one root handler
/// of the job control socket.
pub const DISK_MEASURES_AT_ONCE: usize = 8;

/// A key the disk check measures: launched and not ending.
struct MeasuredKey {
    key: String,
    id: JobKeyId,
    limit_bytes: u64,
}

/// What the disk check's end of one key did.
enum DiskEnd {
    /// The key is `Ending { DiskLimit }` and its unit was asked to stop.
    Ending,
    /// Nothing to end: the service closed, the gate is not open, or the key
    /// ended or began to end meanwhile.
    NotApplicable,
    /// The `Ending` record did not land.
    RecordFailed(String),
}

impl NodeJobs {
    /// One pass of the disk check. Each key that is `Launching` or
    /// `Running` is measured against its request's `disk_mib`; one whose
    /// payload passes it (or cannot be measured within the node's walk
    /// bounds, `payload_depth_max` and `payload_entries_max`) moves to
    /// `Ending { DiskLimit }` and its unit is stopped. A payload that was
    /// not measured this time is measured at the next pass. It blocks.
    ///
    /// When the node file does not read (an edit in progress), the walk
    /// takes the widest bounds a node file may set, and a payload it cannot
    /// measure is not ended this pass: the node's own bounds are not known
    /// (review r13 R13-09).
    ///
    /// Returns the keys it asked to end.
    pub fn check_payload_disk(&self) -> Vec<String> {
        if self.service_closed() {
            return Vec::new();
        }
        let launched = self.launched_keys();
        if launched.is_empty() {
            return Vec::new();
        }
        let policy = self.parts().admission.job_settings().payload_walk;
        let bounds = policy.clone().unwrap_or_else(PayloadWalkBounds::widest);
        let mut ended = Vec::new();
        for batch in launched.chunks(DISK_MEASURES_AT_ONCE) {
            // A closed service measures and ends nothing more (review r12
            // R12-07).
            if self.service_closed() {
                break;
            }
            for (measured, usage) in batch.iter().zip(self.measure_batch(batch, &bounds)) {
                let usage = match usage {
                    Ok(usage) => usage,
                    Err(error) => {
                        tracing::warn!(key = %measured.key, %error, "job payload not measured; the next disk check measures it again");
                        continue;
                    }
                };
                if !usage.passes(measured.limit_bytes) {
                    continue;
                }
                if policy.is_none() && matches!(usage, PayloadUsage::Unmeasurable { .. }) {
                    tracing::warn!(key = %measured.key, usage = %usage.render(), "job payload not measurable while the node file does not read; not ended this pass");
                    continue;
                }
                tracing::warn!(
                    key = %measured.key,
                    usage = %usage.render(),
                    limit_bytes = measured.limit_bytes,
                    "job payload passed its disk request; the key ends as disk_limit"
                );
                match self.end_for_disk(&measured.key) {
                    DiskEnd::Ending => ended.push(measured.key.clone()),
                    DiskEnd::NotApplicable => {}
                    DiskEnd::RecordFailed(error) => {
                        // The record did not land, perhaps on the very disk
                        // the job filled: the unit is stopped all the same,
                        // and the end handling names its end from the end
                        // record (review r12 R12-09). A service that closed
                        // meanwhile leaves the key to the next one.
                        tracing::error!(key = %measured.key, %error, "job key over its disk request not journaled as ending; its unit is stopped anyway");
                        if !self.service_closed() {
                            self.stop_unit(&measured.key);
                            ended.push(measured.key.clone());
                        }
                    }
                }
            }
        }
        ended
    }

    /// Measures every key of `batch` at once, one thread each; a key whose
    /// thread did not start is measured on this one.
    fn measure_batch(
        &self,
        batch: &[MeasuredKey],
        bounds: &PayloadWalkBounds,
    ) -> Vec<Result<PayloadUsage, String>> {
        thread::scope(|scope| {
            let started: Vec<_> = batch
                .iter()
                .map(|measured| {
                    thread::Builder::new()
                        .name("oneiron-node-disk-measure".to_owned())
                        .spawn_scoped(scope, move || self.measure(measured, bounds))
                })
                .collect();
            started
                .into_iter()
                .zip(batch)
                .map(|(started, measured)| match started {
                    Ok(handle) => handle
                        .join()
                        .unwrap_or_else(|_| Err("the measure's thread panicked".to_owned())),
                    Err(_) => self.measure(measured, bounds),
                })
                .collect()
        })
    }

    /// One key's measure, stopping past its request.
    fn measure(
        &self,
        measured: &MeasuredKey,
        bounds: &PayloadWalkBounds,
    ) -> Result<PayloadUsage, String> {
        let payload_dir = measured.id.payload_dir(&self.paths().work_dir);
        self.parts()
            .units
            .payload_usage(&measured.id, &payload_dir, measured.limit_bytes, bounds)
            .map_err(|error| error.to_string())
    }

    /// Moves a key over its disk request to `Ending { DiskLimit }` and asks
    /// for its unit's stop, under the admission lock, and only while the
    /// service is open, its gate is open and the key is still `Launching` or
    /// `Running` (review r13 R13-08): a service that closed while the
    /// measure ran, or a key that ended or began to end meanwhile, is left
    /// as it is.
    fn end_for_disk(&self, key: &str) -> DiskEnd {
        let mut book = self.lock();
        if self.service_closed() || book.gate != NodeGate::Open {
            return DiskEnd::NotApplicable;
        }
        let now = self.now();
        let Some(journal) = book.journal.as_mut() else {
            return DiskEnd::NotApplicable;
        };
        let Some(known) = journal.table().get(key).cloned() else {
            return DiskEnd::NotApplicable;
        };
        if !matches!(known.state, JobState::Launching | JobState::Running) {
            return DiskEnd::NotApplicable;
        }
        match self.begin_ending(journal, &known, EndingCause::DiskLimit, &now) {
            Ok(()) => DiskEnd::Ending,
            Err(error) => DiskEnd::RecordFailed(error.to_string()),
        }
    }

    /// Every key whose unit may run now and has not begun to end, with its
    /// request's disk in bytes.
    fn launched_keys(&self) -> Vec<MeasuredKey> {
        let book = self.lock();
        if book.gate != NodeGate::Open {
            return Vec::new();
        }
        let Some(journal) = book.journal.as_ref() else {
            return Vec::new();
        };
        journal
            .table()
            .iter()
            .filter(|known| matches!(known.state, JobState::Launching | JobState::Running))
            .filter_map(|known| {
                let disk_mib = known
                    .reserve
                    .as_ref()
                    .map(|reserve| reserve.pin.request.disk_mib)
                    .or_else(|| {
                        known
                            .submit
                            .as_ref()
                            .map(|signed| signed.submit.pin.request.disk_mib)
                    })?;
                Some(MeasuredKey {
                    key: known.key.clone(),
                    id: known.id.clone(),
                    limit_bytes: mib_bytes(disk_mib),
                })
            })
            .collect()
    }
}
