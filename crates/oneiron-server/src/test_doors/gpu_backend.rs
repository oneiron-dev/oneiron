//! Doors for `tests/customer_gpu_job_maximum.rs` (row L10-31) and
//! `tests/customer_cpu_job_seconds.rs` (row M3-D): the `[gpu_jobs]` section
//! as `serve` resolves it, a backend registered on a built server,
//! allocations on its host account, and one pass of its job worker, so a test
//! does not wait on `step_secs`.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::gpu_job::{GpuJobConnector, GpuJobStepReport};
use oneiron::llm::run_admission::{Allocation, AllocationRef, LeaseUnit};

use crate::gpu_execution_node::issuer::JobNodeClient;
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

/// Grants `server`'s host account its `[gpu_jobs.host_allocation]`, as each server start does
/// (R6-VAULT-MACHINE-FUNDING = A). Answers whether the account was granted the allocation now:
/// `false` when the section is absent or this account already holds it.
///
/// # Errors
///
/// The start's refusal: a managed server, or the account's refusal.
pub fn install_host_allocation(server: &SyncServer) -> anyhow::Result<bool> {
    crate::gpu_host::install_host_allocation_at_start(server)
}

/// Refuses a `[gpu_jobs]` section that names `[gpu_jobs.host_allocation]`, as a managed
/// server's start does.
///
/// # Errors
///
/// The section names one.
pub fn refuse_managed_host_allocation(
    settings: &crate::config::GpuJobsSettings,
) -> anyhow::Result<()> {
    crate::gpu_host::refuse_managed_host_allocation(settings)
}

/// Registers `connector` as the GPU backend `name` on `server`.
pub fn register_gpu_backend(server: &SyncServer, name: &str, connector: Arc<dyn GpuJobConnector>) {
    server.gpu_jobs.register_backend(name, connector);
}

/// Whether `server` has a GPU backend registered as `name`.
pub fn gpu_backend_registered(server: &SyncServer, name: &str) -> bool {
    server.gpu_jobs.backend(name).is_some()
}

/// Takes the GPU backend `name` off `server`, as a restart that no longer
/// registers it does.
pub fn unregister_gpu_backend(server: &SyncServer, name: &str) {
    server.gpu_jobs.remove_backend(name);
}

/// One pass of `server`'s GPU job worker, the pass `serve` runs every
/// `step_secs` and at each wake of the work-order loop
/// (`gpu_host::worker_pass`).
pub fn run_gpu_job_worker_pass(server: &Arc<SyncServer>) {
    crate::gpu_host::worker_pass(server);
}

/// Grants `server`'s host account a fresh allocation of `units` `unit`, the
/// vault's paid credits a host-paid GPU job reserves on.
///
/// # Errors
///
/// A unit that is not one, or the account's refusal of the allocation.
pub fn grant_gpu_allocation(server: &SyncServer, units: u64, unit: &str) -> anyhow::Result<()> {
    grant_allocation(server, "gpu-job-test-allocation", units, unit)
}

/// Grants `server`'s host account generation 1 of the walletless allocation
/// `id`, of `units` `unit`. The account keeps one allocation per unit, so a
/// test grants a `cpu_seconds` and a `gpu_seconds` allocation side by side
/// under two ids (row M3-D).
///
/// # Errors
///
/// A unit that is not one, or the account's refusal of the allocation.
pub fn grant_allocation(
    server: &SyncServer,
    id: &str,
    units: u64,
    unit: &str,
) -> anyhow::Result<()> {
    server
        .host_account()
        .grant(Allocation {
            reference: AllocationRef {
                id: id.to_owned(),
                generation: 1,
            },
            units,
            unit: LeaseUnit::new(unit).map_err(|error| anyhow::anyhow!("{error}"))?,
            wallet: None,
        })
        .map_err(|error| anyhow::anyhow!("{error:?}"))
}

/// Whether `server`'s GPU job worker starts, as `serve` starts it with every
/// pass admitted. A worker that starts is stopped at once. Call it inside a
/// Tokio runtime.
pub fn gpu_job_worker_starts(server: &Arc<SyncServer>) -> bool {
    let admit: crate::server::HousekeepingAdmission =
        Arc::new(|| Some(Box::new(()) as Box<dyn Send>));
    match crate::gpu_host::spawn_gpu_job_steps(Arc::clone(server), admit) {
        Some(worker) => {
            worker.abort();
            true
        }
        None => false,
    }
}

/// One tick of `server`'s GPU job worker, as its loop runs one with every pass
/// admitted (`gpu_host::worker_tick`): one worker pass, then the scheduled
/// readiness read the tick starts and does not wait for, or `None` when it
/// started none (one already runs). Call it inside a Tokio runtime.
pub async fn run_gpu_job_worker_tick(
    server: &Arc<SyncServer>,
) -> Option<tokio::task::JoinHandle<()>> {
    let admit: crate::server::HousekeepingAdmission =
        Arc::new(|| Some(Box::new(()) as Box<dyn Send>));
    crate::gpu_host::worker_tick(server, &admit).await
}

/// One pass of the GPU job worker: one step of every live job, each with its
/// outcome as text when it refused.
pub fn step_gpu_jobs(server: &SyncServer) -> Vec<(EntityId, Result<GpuJobStepReport, String>)> {
    crate::gpu_host::step_live_jobs(server, crate::gpu_host::now_ms())
        .into_iter()
        .map(|(job, outcome)| (job, outcome.map_err(|error| error.to_string())))
        .collect()
}

/// Answers `server`'s node calls (the work-order loop's and `vault.jobs.logs.tail`'s) through
/// `nodes` from now on. False when the loop already made its own client: call it before the
/// first order or tail.
pub fn use_job_nodes(server: &SyncServer, nodes: Arc<dyn JobNodeClient>) -> bool {
    server.gpu_jobs.orders().use_nodes(nodes)
}
