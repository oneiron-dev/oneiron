//! Door 10, `vault.gpu.jobs.write_off` (pass 33 row R4, 8.5): the owner closes the hold of a
//! job whose end its backend cannot confirm. The backend first closes its dispatch for good, so
//! nothing is sent for the key again; then the job ends `unconfirmed` and its chunk settles
//! zero. The write-off is final. A receipt that arrives later is evidence only: it never
//! settles the job again. It says nothing about a process, and it never lets the key start
//! again. When a work order made the job, the same write ends the order's attempt
//! `written_off` (pass 34, Q1), so the order starts nothing more on its own. When the job is a
//! line unit's, the same write ends its claim written off by this owner, so no hold stays open
//! (pass 33, 8.4).

use crate::consent::AuthenticatedOwner;
use crate::gpu_line::{UnitEndReport, settle_unit_in_txn};
use crate::llm::run_admission::CallOutcome;
use crate::{EntityId, Vault};

use super::{
    GPU_JOBS, GpuEndReason, GpuJob, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobState,
};

/// The job the write-off wrote, or why its write refused.
type Written = Result<GpuJob, GpuJobError>;

impl Vault {
    /// The owner writes off the live job `id` on `connector`, its backend: the backend closes
    /// the chunk's dispatch (it refuses a chunk whose end it can still confirm), then the job
    /// ends with reason `unconfirmed`, no billed seconds, and a settlement of zero units for a
    /// chunk this host holds the permit of. A repeat after the job ended is
    /// [`GpuJobError::Ended`].
    ///
    /// # Errors
    ///
    /// [`GpuJobError::NotFound`]; [`GpuJobError::Ended`] for a job that is not live, or whose
    /// chunk changed after its backend closed the old chunk's dispatch;
    /// [`GpuJobError::Connector`] with the backend's refusal; an owner proof that no longer
    /// holds; a store failure.
    pub fn write_off_gpu_job(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        owner.revalidate(self)?;
        let job = self.load_gpu_job(id)?;
        if !job.state.is_live() {
            return Err(GpuJobError::Ended);
        }
        // The chunk whose dispatch the backend closes: the write below ends only that chunk.
        let closed_key = job.chunk().map(|chunk| chunk.idempotency_key.clone());
        connector.write_off(&job, now_ms)?;
        let written = self.with_write_txn_grouped(|txn| -> crate::Result<Written> {
            let Some(mut job) = GPU_JOBS.get(&self.store, txn, id)? else {
                return Ok(Err(GpuJobError::NotFound));
            };
            let by = owner.revalidate_in_txn(self, txn)?;
            if !job.state.is_live() {
                return Ok(Err(GpuJobError::Ended));
            }
            // The job stopped and resumed since the backend closed its chunk's dispatch: the
            // new chunk's dispatch is open, so this write ends nothing.
            if job.chunk().map(|chunk| &chunk.idempotency_key) != closed_key.as_ref() {
                return Ok(Err(GpuJobError::Ended));
            }
            let chunk = job.chunk_mut()?;
            let paid = permits.holds_chunk(id, &chunk.idempotency_key);
            chunk.billed_secs = None;
            chunk.unbilled_secs = 0;
            if paid {
                chunk.settled_units = Some(0);
            }
            job.stop = None;
            job.resume_quote = None;
            job.state = GpuJobState::Ended {
                reason: GpuEndReason::Unconfirmed,
            };
            self.put_gpu_job_in_txn(txn, &mut job, now_ms)?;
            // A unit's job holds no permit: its claim is its hold, and it ends in this write.
            // A claim that already ended keeps its terminal.
            if let Some(claim) = &job.claim {
                let report = UnitEndReport::WrittenOff { by };
                let _ = settle_unit_in_txn(self, txn, claim, &job.id, &report, now_ms)?;
            }
            // A job no order made leaves every order alone.
            self.order_attempt_written_off_in_txn(txn, id, now_ms)?;
            Ok(Ok(job))
        })??;
        // Settled after the write, as an end settles: a settled chunk is never admitted again.
        if let Some(chunk) = written.chunk()
            && let Some(permit) = permits.take_for_chunk(&written.id, &chunk.idempotency_key)
        {
            let _ = permit.settle(CallOutcome::Used(0));
        }
        Ok(written)
    }
}
