//! What `vault.gpu.jobs.status` and `.list` add for a job that one of the vault's own machines
//! runs (pass 33 row R4, door 8): four separate fields, so that a time and a reason are never
//! one word.
//!
//! - `lifecycle`, from the built job state;
//! - `node`, the newest receipt the machine signed;
//! - `observed`, when the issuer received it, and whether that is older than
//!   `jobs.status.stale_after_steps` job steps;
//! - `accounting`: the money held, settled, unconfirmed (with why) or written off.
//!
//! A backend that runs on no machine of the vault has no such view. The `vault_machine`
//! backend builds it from its dispatch and observation rows; this module holds only the shape.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{GpuJob, GpuJobState};

/// Where a job stands, from the built job state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GpuJobLifecycle {
    /// Reserved, and no machine holds its key yet.
    Waiting,
    /// A machine holds the key, and its workload has not started. The `vault_machine` view
    /// reads it from the machine's newest receipt; [`GpuJobLifecycle::of`] alone sees it only
    /// for a reserved chunk whose resource is known.
    Assigned,
    Running,
    /// Its end was asked and is not confirmed yet.
    Ending,
    /// It ended, stopped at its maximum or was held: nothing more runs.
    Terminal,
}

impl GpuJobLifecycle {
    /// The lifecycle of `job` now.
    #[must_use]
    pub fn of(job: &GpuJob) -> Self {
        match &job.state {
            GpuJobState::Reserved => {
                if job.chunk().is_some_and(|chunk| chunk.resource.is_some()) {
                    Self::Assigned
                } else {
                    Self::Waiting
                }
            }
            GpuJobState::Running => Self::Running,
            GpuJobState::Ending { .. } => Self::Ending,
            GpuJobState::Stopped | GpuJobState::Ended { .. } | GpuJobState::Held { .. } => {
                Self::Terminal
            }
        }
    }
}

/// One output the machine hashed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GpuJobOutputView {
    pub name: String,
    /// Lower hex.
    pub sha256: String,
    pub bytes: u64,
    /// Whether it may travel to the issuer.
    pub returnable: bool,
}

/// The outputs as the machine's newest receipt names them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GpuJobOutputsView {
    /// Not hashed yet.
    Pending,
    Hashed {
        outputs: Vec<GpuJobOutputView>,
    },
    Failed {
        why: String,
    },
}

/// The machine's newest signed receipt of the job's current chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GpuJobNodeReport {
    /// The key's state on the machine: held, accepted, staging, launching, running, ending,
    /// ended.
    pub state: String,
    /// False: the workload process never existed and never can.
    pub started: bool,
    /// The end's kind once it ended: exited, signalled, time_limit, memory_limit, disk_limit,
    /// stopped, revoked, withdrawn, refused, launch_refused, lost.
    pub end: Option<String>,
    /// The end's detail: an exit code, a signal, a refusal's or a loss's reason.
    pub end_detail: Option<String>,
    /// Occupied seconds as the machine measured them; `None` when unknown, never zero for it.
    pub measured_secs: Option<u64>,
    pub cutoff_at_ms: Option<u64>,
    /// The device's release: not_held, held, confirmed, unconfirmed.
    pub release: String,
    pub outputs: GpuJobOutputsView,
}

/// When the issuer received the newest receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GpuJobObserved {
    /// The issuer's wall clock at its arrival.
    pub at_ms: u64,
    /// Whether it is older than `jobs.status.stale_after_steps` job steps.
    pub stale: bool,
}

/// Where the job's money stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GpuJobAccounting {
    /// The reservation still holds these units.
    Held { units: u64 },
    /// Settled once, at these units.
    Settled { units: u64 },
    /// The end is not confirmed, and the hold stays: why (the machine unreachable, its history
    /// lost, a kill it could not confirm).
    Unconfirmed { why: String },
    /// The owner wrote the job off: settled at zero, final.
    WrittenOff,
}

/// The four fields of door 8 for a job one of the vault's machines runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GpuJobNodeView {
    pub lifecycle: GpuJobLifecycle,
    /// The machine that runs the job, lower hex: fixed by its quote.
    pub machine: String,
    /// `None` before the machine answered any receipt.
    pub node: Option<GpuJobNodeReport>,
    /// `None` before the machine answered any receipt.
    pub observed: Option<GpuJobObserved>,
    pub accounting: GpuJobAccounting,
}
