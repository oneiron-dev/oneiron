//! The disk check (design pass 33, 7.9; FIX EXEC-NODE-DISK-CHECK-UNBUILT):
//! every `disk_check_secs` the engine measures each launched key's payload
//! through its job unit ([`super::JobUnit::payload_usage`]) and ends a key
//! whose payload passed its disk request as `DiskLimit`. The kernel caps the
//! unit's write rate to the payload device, so a job passes its request by
//! at most that rate times the period, which the node's disk reserve
//! absorbs.
//!
//! The measures run outside the admission lock, since a walk may take
//! seconds; the end takes the lock and acts only on a key that is still
//! launched ([`NodeJobs::end_key`]).

use super::admission::mib_bytes;
use super::journal::EndingCause;
use super::{JobKeyId, NodeGate, NodeJobs};
use crate::gpu_execution_node::wire::JobState;

/// A key the disk check measures: launched and not ending.
struct MeasuredKey {
    key: String,
    id: JobKeyId,
    limit_bytes: u64,
}

impl NodeJobs {
    /// One pass of the disk check. Each key that is `Launching` or
    /// `Running` is measured against its request's `disk_mib`; one whose
    /// payload passes it (or cannot be measured within the walk's bounds)
    /// moves to `Ending { DiskLimit }` and its unit is stopped. A payload
    /// that was not measured this time is measured at the next pass. It
    /// blocks.
    ///
    /// Returns the keys it asked to end.
    pub fn check_payload_disk(&self) -> Vec<String> {
        if self.service_closed() {
            return Vec::new();
        }
        let mut ended = Vec::new();
        for measured in self.launched_keys() {
            let payload_dir = measured.id.payload_dir(&self.paths().work_dir);
            let usage = match self.parts().units.payload_usage(
                &measured.id,
                &payload_dir,
                measured.limit_bytes,
            ) {
                Ok(usage) => usage,
                Err(error) => {
                    tracing::warn!(key = %measured.key, %error, "job payload not measured; the next disk check measures it again");
                    continue;
                }
            };
            if !usage.passes(measured.limit_bytes) {
                continue;
            }
            tracing::warn!(
                key = %measured.key,
                usage = %usage.render(),
                limit_bytes = measured.limit_bytes,
                "job payload passed its disk request; the key ends as disk_limit"
            );
            match self.end_key(&measured.key, EndingCause::DiskLimit) {
                Ok(()) => ended.push(measured.key),
                Err(error) => {
                    tracing::warn!(key = %measured.key, %error, "job key over its disk request not ended yet; the next disk check ends it");
                }
            }
        }
        ended
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
