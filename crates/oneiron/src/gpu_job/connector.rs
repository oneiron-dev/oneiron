//! What the engine asks of a GPU provider backend (CROSS-ARCH-0023 C1 B: the
//! connectors live in OSS oneiron; C6 02: a backend only provisions). The
//! calls block: the host steps its jobs on its blocking pool. No backend ships
//! in the engine; the host registers its own.
use serde::{Deserialize, Serialize};

use crate::llm::run_admission::CheckpointRef;

/// The provider's id for one created resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GpuResourceRef(pub String);

/// What one chunk asks the provider to run. The backend adds its own account
/// and vault tags beside `job` and `chunk`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobSpec {
    pub job: String,
    pub chunk: u32,
    pub job_type: String,
    pub image: String,
    pub inputs: serde_json::Value,
    pub maximum_secs: u64,
    /// The checkpoint a resumed chunk starts from.
    pub checkpoint_from: Option<CheckpointRef>,
}

/// What the provider reports for a resource. `used_secs` counts this
/// resource's run time from the moment the provider reported it running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GpuResourceStatus {
    /// Created, not running yet: the customer's clock has not started.
    Pending,
    Running {
        used_secs: u64,
        /// The newest checkpoint the job saved, if any.
        checkpoint: Option<CheckpointRef>,
    },
    /// The job's process ended by itself.
    Exited { used_secs: u64 },
    /// The provider no longer knows the resource.
    Gone,
}

/// What the engine tells a running job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "signal", rename_all = "snake_case")]
pub enum GpuJobSignal {
    /// Usage reached this percent (50, 80 or 95) of the maximum: checkpoint
    /// now (lifecycle 04).
    CheckpointDue { percent: u8 },
    /// The maximum is used and no checkpoint counts yet: checkpoint now, the
    /// stop follows it (C2 03).
    CheckpointBeforeStop,
}

/// A termination's answer. Billing ends at a confirmed termination, not at
/// the request (lifecycle 05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "termination", rename_all = "snake_case")]
pub enum GpuTermination {
    Confirmed {
        billed_secs: u64,
    },
    /// Asked, not confirmed yet: the step asks again.
    Pending,
}

/// Why a provider call did not answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum GpuConnectorError {
    /// No answer in time: the call may have taken effect.
    #[error("the GPU provider did not answer in time")]
    Timeout,
    /// The provider refused the call; it took no effect.
    #[error("the GPU provider refused: {reason}")]
    Refused { reason: String },
    /// The provider could not be reached; the call may have taken effect.
    #[error("the GPU provider is unavailable: {reason}")]
    Unavailable { reason: String },
}

/// One GPU provider backend. A create carries the chunk's idempotency key,
/// and the engine looks a resource up by that key before it ever creates
/// again (`#gpu-uncertain` 01).
pub trait GpuJobConnector: Send + Sync {
    /// Creates the chunk's resource under `key`. The same key never makes a
    /// second resource.
    fn create(&self, key: &str, spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError>;

    /// The resource created under `key`, if the provider has one.
    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError>;

    fn status(&self, resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError>;

    fn signal(
        &self,
        resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError>;

    /// Asks for termination, and answers whether the provider confirmed it.
    /// Asked again until it does (`#gpu-uncertain` 02).
    fn terminate(&self, resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError>;
}
