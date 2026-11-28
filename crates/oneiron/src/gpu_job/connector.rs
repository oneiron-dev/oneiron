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
    /// The provider ended the job at its maximum seconds: a hard stop, with or
    /// without a checkpoint (design pass 33, 8.6).
    TimeLimit { used_secs: u64 },
    /// The provider no longer knows the resource.
    Gone,
    /// A session's chunk (row W1): the one run passed this chunk's paid end and goes on under
    /// the next paid chunk. The provider confirmed the slice and bills it `billed_secs`; nothing
    /// is terminated.
    Continued { used_secs: u64, billed_secs: u64 },
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
    /// A session's chunk whose slice the run had already passed (row W1): the termination
    /// stopped nothing, since the run goes on under the next paid chunk, which the step
    /// terminates next. The slice ran `used_secs` by its provider's measure and bills
    /// `billed_secs`, which can be less (the issuer's own bracket bounds it), so the next chunk
    /// counts its run time from the measure.
    Continued {
        used_secs: u64,
        billed_secs: u64,
    },
}

/// How a job ended, as its machine established it (design pass 33 section 5.3, the receipt's
/// end; pass 32 r2 section 7.3). A connector maps its backend's own end cause to this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum GpuJobEnd {
    /// The workload process exited with this code.
    Exited { code: i32 },
    /// The workload process ended on this signal.
    Signalled { signal: i32 },
    /// The machine ended it at the job's maximum seconds.
    TimeLimit,
    /// The machine ended it at its memory limit.
    MemoryLimit,
    /// The machine ended it at its disk limit.
    DiskLimit,
    /// The engine asked for the stop, after the launch.
    Stopped,
    /// The machine saw the job's grant or the machine's enrolment end.
    Revoked,
    /// Stopped before the launch: the workload never ran.
    Withdrawn,
    /// The machine refused the job at admission: the workload never ran.
    Refused { reason: String },
    /// A check inside the launch failed: the workload never ran.
    LaunchRefused { reason: String },
    /// The machine attests the job lost (a host reset, or a launch that left no trace).
    /// `last_seen_secs` is the run time the engine last saw, a lower bound.
    Lost { reason: String, last_seen_secs: u64 },
    /// A session's chunk (row W1): its slice ran to its paid end and the run went on under the
    /// next paid chunk. Not an end of the run.
    Continued,
}

impl GpuJobEnd {
    /// A key that never started bills zero (lead ruling LE-2 = A). This reports whether
    /// the machine withdrew or refused the key before it ran.
    #[must_use]
    pub fn never_ran(&self) -> bool {
        matches!(
            self,
            Self::Withdrawn | Self::Refused { .. } | Self::LaunchRefused { .. }
        )
    }

    /// The end as views show it: `exited(0)`, `time_limit`, `refused(no_device)`, ...
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Exited { code } => format!("exited({code})"),
            Self::Signalled { signal } => format!("signalled({signal})"),
            Self::TimeLimit => "time_limit".to_owned(),
            Self::MemoryLimit => "memory_limit".to_owned(),
            Self::DiskLimit => "disk_limit".to_owned(),
            Self::Stopped => "stopped".to_owned(),
            Self::Revoked => "revoked".to_owned(),
            Self::Withdrawn => "withdrawn".to_owned(),
            Self::Refused { reason } => format!("refused({reason})"),
            Self::LaunchRefused { reason } => format!("launch_refused({reason})"),
            Self::Lost { reason, .. } => format!("lost({reason})"),
            Self::Continued => "continued".to_owned(),
        }
    }
}

/// How a job's billed seconds were found (design pass 33 section 8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "meter", rename_all = "snake_case")]
pub enum MeterVerdict {
    /// The machine's measured seconds lie inside the engine's own bracket.
    Agreed,
    /// The machine's figure was above the engine's bracket: the bracket is billed.
    Bracketed { billed_secs: u64 },
    /// No measured seconds (a lost machine).
    Unknown,
}

/// One output file of a job, by hash: never its body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobOutput {
    pub name: String,
    /// Lower hex.
    pub sha256: String,
    pub bytes: u64,
}

/// A confirmed end, typed, as the job's machine established it (pass 32 r2 section 7.2 point 7;
/// pass 33 section 8.4). A lane's settle reads it, so a refused start, a lost machine and a time
/// limit reach the settle as what they are; the generic job states alone cannot carry them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobTerminal {
    pub end: GpuJobEnd,
    /// Occupied device time on the machine's clock, from the launch to the empty unit;
    /// `None` when unknown (a lost machine).
    pub measured_secs: Option<u64>,
    /// The seconds billed: never above the quote, the measured seconds or the engine's bracket;
    /// 0 when the workload never ran or the machine was lost.
    pub billed_secs: u64,
    pub meter: MeterVerdict,
    /// The machine that ran it.
    pub machine: Option<crate::EntityId>,
    /// The vendor's device id of the GPU it held.
    pub device_id: Option<String>,
    pub outputs: Vec<GpuJobOutput>,
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

    /// What the resource does now. For a session's next chunk (row W1),
    /// [`GpuConnectorError::Refused`] says its provider ended it before the
    /// run reached it, so it never runs; the engine settles it zero.
    fn status(&self, resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError>;

    fn signal(
        &self,
        resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError>;

    /// Asks for termination, and answers whether the provider confirmed it.
    /// Asked again until it does (`#gpu-uncertain` 02).
    fn terminate(&self, resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError>;

    /// Sends the session chunk under `key` (row W1): the paid continuation of the run the chunk
    /// under `continues` started, `spec.maximum_secs` past that run's current cutoff. It starts
    /// no process and holds no resource of its own: the provider bills the slice of the one run
    /// that falls in it, and answers its [`GpuResourceRef`], which `status` and `terminate`
    /// read. The same key never sends a second continuation; [`Self::find`] answers it after a
    /// call that did not answer. The default refuses: only a backend that runs sessions renews.
    ///
    /// # Errors
    ///
    /// [`GpuConnectorError::Refused`] when it took no effect; a timeout or an unavailable
    /// provider when it may have.
    fn renew(
        &self,
        key: &str,
        continues: &str,
        spec: &GpuJobSpec,
    ) -> Result<GpuResourceRef, GpuConnectorError> {
        let _ = (key, continues, spec);
        Err(GpuConnectorError::Refused {
            reason: "renew_not_offered".to_owned(),
        })
    }

    /// The four status fields of `job` for a backend that runs on one of the vault's own
    /// machines (pass 33 row R4, door 8), at `now_ms`, with the host's job step of `step_ms`
    /// (what a stale observation is counted in); `None` for every other backend, the default.
    fn node_view(
        &self,
        job: &super::GpuJob,
        now_ms: u64,
        step_ms: u64,
    ) -> Option<super::GpuJobNodeView> {
        let _ = (job, now_ms, step_ms);
        None
    }

    /// Writes off `job`'s current chunk on this backend (pass 33 row R4, door 10): the backend
    /// closes the chunk's dispatch for good, so nothing is sent for its key again, and answers
    /// `Ok` once it is closed, also when it already was. A backend refuses a chunk whose end it
    /// can still confirm. The default refuses: only a backend that runs on one of the vault's
    /// own machines writes off.
    ///
    /// # Errors
    ///
    /// [`GpuConnectorError::Refused`] with the reason; a store failure.
    fn write_off(&self, job: &super::GpuJob, now_ms: u64) -> Result<(), GpuConnectorError> {
        let _ = (job, now_ms);
        Err(GpuConnectorError::Refused {
            reason: "write_off_not_offered".to_owned(),
        })
    }

    /// One housekeeping pass of this backend outside any job's step (pass 33 row R4): the
    /// `vault_machine` backend asks its live orphan keys to stop and returns the results it
    /// still owes. The host's worker calls it once a round; the default does nothing.
    fn housekeeping(&self) {}
}
