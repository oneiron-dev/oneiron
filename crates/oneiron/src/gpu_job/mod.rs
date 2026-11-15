//! Customer GPU jobs on the host's account (CROSS-ARCH-0023 lifecycle, C2).
//!
//! A job runs as chunks. Each chunk is quoted on a host offer (the rate times
//! its maximum run time plus startup, teardown and rounding), reserved whole
//! through the run admission before anything starts, created at the provider
//! under an idempotency key, then stepped by the host: the job is told to
//! checkpoint at 50, 80 and 95 percent of its maximum, the customer's warning
//! at 95 percent commits in their inbox, and at the maximum the job stops only
//! after a checkpoint taken after that warning (C2). The stop carries an
//! add-funds notice, and a resume starts the next chunk from that checkpoint.
//! A chunk settles its billed time at confirmed termination, never above its
//! quote; the rest of the reservation goes back.
//!
//! The record is one side-table row per job, so a restarted host takes up the
//! same state. The engine decides; the host only calls its provider through a
//! [`GpuJobConnector`] and holds the live chunks' permits in
//! [`GpuJobPermits`].
use serde::{Deserialize, Serialize};

use crate::llm::run_admission::{
    CheckpointRef, JobMaximum, JobSignal, JobStartRefused, LeaseUnit, MaximumStop, ResumeRefused,
    RunDenied,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

mod connector;
mod offer;
mod permits;
mod start;
mod step;
pub(crate) mod tables;

pub use connector::{
    GpuConnectorError, GpuJobConnector, GpuJobSignal, GpuJobSpec, GpuResourceRef,
    GpuResourceStatus, GpuTermination,
};
pub use offer::{GPU_QUOTE_VALID_MS, GpuJobQuote, GpuJobRequest, GpuOffer, PriceShape};
pub use permits::GpuJobPermits;

/// Producer of the customer's 95 percent warning.
pub const GPU_JOB_WARNING_PRODUCER: &str = "gpu_job.warning";
/// Producer of the add-funds notice at a stop at the maximum.
pub const GPU_JOB_STOPPED_PRODUCER: &str = "gpu_job.stopped_at_maximum";

const GPU_JOBS: SideTable<EntityId, GpuJob, Named> = SideTable::new(&side_table::GPU_JOB);

/// The unit a job's maximum and run time are counted in.
fn seconds() -> LeaseUnit {
    LeaseUnit::new("seconds").expect("a valid lease unit")
}

/// Why a GPU job door refused.
#[derive(Debug, thiserror::Error)]
pub enum GpuJobError {
    #[error(transparent)]
    Vault(#[from] crate::Error),
    #[error(transparent)]
    Start(JobStartRefused),
    #[error(transparent)]
    Resume(ResumeRefused),
    /// The run admission refused the reservation; nothing was written or
    /// created.
    #[error("the run admission refused the job: {0}")]
    Denied(RunDenied),
    #[error("a GPU offer must be priced at our list price, not {0:?}")]
    PriceShape(PriceShape),
    #[error("the quote's price does not fit")]
    QuoteOverflow,
    #[error("the offer changed since its quote; quote again")]
    QuoteChanged,
    #[error("the quote expired; quote again")]
    QuoteExpired,
    #[error("this quote already started its job; quote again")]
    QuoteUsed,
    #[error("the admission is not this job's run")]
    AdmissionMismatch,
    #[error("no such GPU job")]
    NotFound,
    #[error("the GPU job has ended")]
    Ended,
    #[error(transparent)]
    Connector(#[from] connector::GpuConnectorError),
}

/// Where a job's offer was: what the customer bought, not the binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuOfferPin {
    pub name: String,
    pub class: String,
    pub provider: String,
    pub region: String,
    pub price_shape: PriceShape,
}

/// Why a chunk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuEndReason {
    /// The job's process ended by itself.
    Exited,
    /// Stopped at its maximum, after the warning and a checkpoint.
    AtMaximum,
    /// The customer's own end of their job.
    Cancelled,
    /// The provider lost the resource.
    Gone,
}

/// Where a job stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuJobState {
    /// The chunk is reserved; its resource is not known yet.
    Reserved,
    Running,
    /// Termination asked, not confirmed yet.
    Ending {
        reason: GpuEndReason,
    },
    /// Stopped at its maximum: its stop offers the resume.
    Stopped,
    Ended {
        reason: GpuEndReason,
    },
    /// The provider refused the chunk before any resource existed; nothing
    /// was billed.
    Held {
        reason: String,
    },
}

impl GpuJobState {
    /// Whether a chunk of the job holds a reservation the host steps.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Reserved | Self::Running | Self::Ending { .. })
    }
}

/// One chunk: one quote reserved whole and one provider resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuChunk {
    pub idempotency_key: String,
    pub quote: GpuJobQuote,
    /// The job's run time before this chunk.
    pub base_used_secs: u64,
    pub checkpoint_from: Option<CheckpointRef>,
    /// The admission's facts for this chunk's first permit.
    pub permit: serde_json::Value,
    /// The admission's dispatch check passed; the provider may hold a
    /// resource.
    pub dispatched: bool,
    pub resource: Option<GpuResourceRef>,
    /// This chunk's run time as its provider last reported it.
    pub used_secs: u64,
    /// The checkpoint percents the job was told, in order.
    pub signalled_percents: Vec<u8>,
    /// The newest checkpoint the provider reported, counted or not.
    pub newest_checkpoint: Option<CheckpointRef>,
    pub billed_secs: Option<u64>,
    /// What the chunk was billed, in its quote's unit: its billed time plus
    /// its overhead, never above its quote.
    pub settled_units: Option<u64>,
    /// Billed seconds past the quote: our cost, never the customer's.
    pub unbilled_secs: u64,
    /// A restarted host could not admit the chunk again: it runs on unpaid,
    /// for operations to see (`#gpu-chunks`: a running chunk is never cut for
    /// money).
    pub admission_lost: bool,
}

/// One customer GPU job.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJob {
    pub id: EntityId,
    /// Who started it; `None` after their erase.
    pub started_by: Option<EntityId>,
    pub offer: GpuOfferPin,
    pub job_type: String,
    pub image: String,
    pub maximum: JobMaximum,
    pub chunks: Vec<GpuChunk>,
    pub state: GpuJobState,
    /// The last stop at the maximum, with its add-funds notice and resume
    /// offer, until a resume takes it.
    pub stop: Option<MaximumStop>,
    /// Operations was told the job ran past its maximum by more than 10
    /// percent with no checkpoint to stop at.
    pub overrun_reported: bool,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    /// Bumped at every write; a write over a changed row is dropped.
    pub revision: u64,
}

impl GpuJob {
    /// The run name a job's admission must use, so its permits pay this job.
    #[must_use]
    pub fn admission_ref_of(id: &EntityId) -> String {
        format!("gpu_job:{}", id.to_hex())
    }

    #[must_use]
    pub fn admission_ref(&self) -> String {
        Self::admission_ref_of(&self.id)
    }

    /// The chunk running now, or the last one.
    #[must_use]
    pub fn chunk(&self) -> Option<&GpuChunk> {
        self.chunks.last()
    }

    fn chunk_mut(&mut self) -> crate::Result<&mut GpuChunk> {
        self.chunks
            .last_mut()
            .ok_or(crate::Error::InvariantViolation("a GPU job holds a chunk"))
    }

    fn spec(&self) -> crate::Result<GpuJobSpec> {
        let chunk = self
            .chunk()
            .ok_or(crate::Error::InvariantViolation("a GPU job holds a chunk"))?;
        Ok(GpuJobSpec {
            job: self.id.to_hex(),
            chunk: u32::try_from(self.chunks.len() - 1).unwrap_or(u32::MAX),
            job_type: self.job_type.clone(),
            image: self.image.clone(),
            inputs: chunk.quote.inputs.clone(),
            maximum_secs: chunk.quote.maximum_secs,
            checkpoint_from: chunk.checkpoint_from.clone(),
        })
    }
}

/// Run time past the maximum, at our cost, reported once for operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuOverrun {
    pub secs: u64,
    /// The overrun at the chunk's price, in `unit`.
    pub units: u64,
    pub unit: LeaseUnit,
}

/// What one step or door did to a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuJobStepReport {
    pub job: EntityId,
    pub state: GpuJobState,
    /// The job's run time over all its chunks.
    pub used_secs: u64,
    /// What this step's usage crossed.
    pub signals: Vec<JobSignal>,
    /// The notices this step wrote.
    pub notices: Vec<EntityId>,
    /// What this step settled, in the chunk's unit.
    pub settled_units: Option<u64>,
    /// Set once, when the job first runs more than 10 percent past its
    /// maximum with no stop.
    pub overrun: Option<GpuOverrun>,
}

impl GpuJobStepReport {
    fn of(job: &GpuJob) -> Self {
        Self {
            job: job.id,
            state: job.state.clone(),
            used_secs: job.maximum.used_units(),
            signals: Vec::new(),
            notices: Vec::new(),
            settled_units: None,
            overrun: None,
        }
    }
}

impl Vault {
    /// One GPU job's record.
    pub fn gpu_job(&self, id: &EntityId) -> crate::Result<Option<GpuJob>> {
        GPU_JOBS.get(&self.store, &self.store.env.read_txn()?, id)
    }

    /// Every GPU job of this vault.
    pub fn gpu_jobs(&self) -> crate::Result<Vec<GpuJob>> {
        let txn = self.store.env.read_txn()?;
        GPU_JOBS
            .iter_from(&self.store, &txn, &[])?
            .map(|row| row.map(|(_, job)| job))
            .collect()
    }

    /// The jobs a host steps: those with a live chunk.
    pub fn live_gpu_jobs(&self) -> crate::Result<Vec<EntityId>> {
        Ok(self
            .gpu_jobs()?
            .into_iter()
            .filter(|job| job.state.is_live())
            .map(|job| job.id)
            .collect())
    }

    fn load_gpu_job(&self, id: &EntityId) -> Result<GpuJob, GpuJobError> {
        self.gpu_job(id)?.ok_or(GpuJobError::NotFound)
    }

    /// Writes `job` if its stored row is still at `job.revision`, bumping
    /// it. Returns false, writing nothing, when another write came first.
    fn put_gpu_job_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        job: &mut GpuJob,
        now_ms: u64,
    ) -> crate::Result<bool> {
        let stored = GPU_JOBS.get(&self.store, txn, &job.id)?;
        if stored.as_ref().map(|row| row.revision) != Some(job.revision) {
            return Ok(false);
        }
        job.revision += 1;
        job.updated_at_ms = now_ms;
        GPU_JOBS.put(&self.store, txn, &job.id, job)?;
        Ok(true)
    }
}

/// Takes the erased actor out of every job they started (the side table's
/// actor scrub).
pub(crate) fn erase_job_starter_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    for (id, mut job) in GPU_JOBS.scan(&vault.store, wtxn)? {
        if job.started_by == Some(*actor) {
            job.started_by = None;
            GPU_JOBS.put(&vault.store, wtxn, &id, &job)?;
        }
    }
    Ok(())
}
