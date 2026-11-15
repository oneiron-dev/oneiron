//! Doors for `tests/customer_gpu_job_maximum.rs` (row L10-31): the
//! `[gpu_jobs]` section as `serve` resolves it, a GPU backend registered on a
//! built server, an allocation on its host account, and one pass of its GPU
//! job worker, so a test does not wait on `step_secs`.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::gpu_job::{GpuJobConnector, GpuJobStepReport};
use oneiron::llm::run_admission::{Allocation, AllocationRef, LeaseUnit};

use crate::server::SyncServer;

/// The `[gpu_jobs]` section whose body is `section` (the lines under the
/// `[gpu_jobs]` header, offers as `[offers.<name>]` tables), read and checked
/// as `serve` reads and checks it.
///
/// # Errors
///
/// The refusal `serve` answers: an unknown key, a price shape other than
/// `at_oneiron_list`, a zero price, and the rest of its checks.
pub fn gpu_jobs_section(section: &str) -> anyhow::Result<crate::config::GpuJobsSettings> {
    let file: crate::config::gpu_jobs::GpuJobsFile = toml::from_str(section)?;
    file.resolve()
}

/// Registers `connector` as the GPU backend `name` on `server`.
pub fn register_gpu_backend(server: &SyncServer, name: &str, connector: Arc<dyn GpuJobConnector>) {
    server.gpu_jobs.register_backend(name, connector);
}

/// Grants `server`'s host account a fresh allocation of `units` `unit`, the
/// vault's paid credits a host-paid GPU job reserves on.
///
/// # Errors
///
/// A unit that is not one, or the account's refusal of the allocation.
pub fn grant_gpu_allocation(server: &SyncServer, units: u64, unit: &str) -> anyhow::Result<()> {
    server
        .host_account()
        .grant(Allocation {
            reference: AllocationRef {
                id: "gpu-job-test-allocation".to_owned(),
                generation: 1,
            },
            units,
            unit: LeaseUnit::new(unit).map_err(|error| anyhow::anyhow!("{error}"))?,
            wallet: None,
        })
        .map_err(|error| anyhow::anyhow!("{error:?}"))
}

/// One pass of the GPU job worker: one step of every live job, each with its
/// outcome as text when it refused.
pub fn step_gpu_jobs(server: &SyncServer) -> Vec<(EntityId, Result<GpuJobStepReport, String>)> {
    crate::gpu_host::step_live_jobs(server, crate::gpu_host::now_ms())
        .into_iter()
        .map(|(job, outcome)| (job, outcome.map_err(|error| error.to_string())))
        .collect()
}
