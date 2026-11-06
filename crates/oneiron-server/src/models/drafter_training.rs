//! A drafter training job's place on its target's device work line (FIX
//! 14974). The trainer runs on the GPU the target's managed EXL3 worker
//! serves from, so it queues on that device's admission as background work
//! of the memory its recipe declares: serving calls go first, and the
//! admission may unload an idle worker to make room. Where this process
//! launches no such worker, or its row names no device, the job runs
//! unmediated, as a call to such a row does.

use oneiron::drafter::DrafterTarget;
use oneiron::llm::WorkCancel;
use oneiron_driver::{AdmissionStop, DeviceGrant, WorkEnvelope};

use super::worker_host::{self, BoundWork};

/// One training job's ticket on its device, or none where the job runs
/// unmediated. Dropped before its grant, the ticket is cancelled; the grant
/// itself is held until it is dropped.
pub(crate) struct DrafterTrainingSlot {
    work: Option<BoundWork>,
}

impl DrafterTrainingSlot {
    /// The ticket of a job for `target` that declares `memory_mib` of device
    /// memory, held by `holder` and cancelled with `cancel`.
    #[must_use]
    pub(crate) fn queue(
        target: &DrafterTarget,
        holder: &str,
        memory_mib: u64,
        cancel: &WorkCancel,
    ) -> Self {
        let envelope = WorkEnvelope {
            kv_increment_mib: Some(0),
            workspace_mib: Some(memory_mib),
        };
        Self {
            work: worker_host::drafter_training_work(target, holder, envelope, cancel),
        }
    }

    /// The device the job queues on; `None` while it runs unmediated.
    #[must_use]
    pub(crate) fn device(&self) -> Option<&str> {
        self.work.as_ref().and_then(BoundWork::device)
    }

    /// Waits until the job is the device's next runnable work and its memory
    /// is granted, unloading an idle worker where the admission says so.
    /// `None` for a job that runs unmediated.
    ///
    /// # Errors
    /// The device line stopped, or the ticket was cancelled.
    pub(crate) async fn acquire(&mut self) -> Result<Option<DeviceGrant>, AdmissionStop> {
        let Some(work) = self.work.as_mut() else {
            return Ok(None);
        };
        work.wait_runnable().await?;
        work.execution_grant().await
    }
}
