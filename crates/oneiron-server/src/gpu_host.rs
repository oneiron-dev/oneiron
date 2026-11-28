//! The host side of customer GPU jobs (CROSS-ARCH-0023 lifecycle, C2; row
//! L10-31). The engine decides every step of a job (`oneiron::gpu_job`); the
//! host holds what a step needs and cannot store: the backends that provision
//! each `[gpu_jobs]` offer, by name, and the live chunks' run permits. A
//! worker steps every live job every `step_secs` on the blocking pool, since
//! a backend's calls block.
//!
//! No backend ships here. Server start registers `vault_machine` when
//! `[gpu_jobs.vault_machine]` is enabled and this install is its issuer
//! (`gpu_execution_node::issuer::register_vault_machine_at_start`); a start on
//! an offer whose backend is not registered refuses before any reservation. Each job runs as its own
//! declared run, whose one line is the chunk's quote, reserved whole on this
//! server's host account (FRAUD-1: a host-paid offer draws on the vault's
//! paid allocation). A self-hosted server funds that account from `[gpu_jobs.host_allocation]` at
//! each start ([`install_host_allocation_at_start`]; R6-VAULT-MACHINE-FUNDING = A).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::EntityId;
use oneiron::gpu_job::{
    GpuConnectorError, GpuJob, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobQuote,
    GpuJobSignal, GpuJobSpec, GpuJobStepReport, GpuOffer, GpuResourceRef, GpuResourceStatus,
    GpuTermination,
};
use oneiron::llm::run_admission::{Allocation, BudgetLine, RunAdmission, RunDeclaration};

use crate::config::{GpuJobsSettings, GpuOfferSettings};
use crate::gpu_execution_node::issuer::{VAULT_MACHINE_BACKEND, not_the_issuer};
use crate::server::{HousekeepingAdmission, SyncServer};

/// The GPU backends this server registered, by name, and the run permits of
/// the chunks it runs.
#[derive(Default)]
pub(crate) struct GpuJobHost {
    backends: RwLock<BTreeMap<String, Arc<dyn GpuJobConnector>>>,
    permits: GpuJobPermits,
    /// The work-order loop's wake, lock and node client (pass 34, EM-22 = A: one worker).
    orders: crate::work_order_host::OrderLoop,
}

impl std::fmt::Debug for GpuJobHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuJobHost")
            .field("backends", &self.backend_names())
            .field("permits", &self.permits)
            .finish()
    }
}

impl GpuJobHost {
    /// Registers `connector` as the backend `name`, replacing any before it:
    /// `vault_machine` at server start, and the test door's fixtures.
    pub(crate) fn register_backend(&self, name: &str, connector: Arc<dyn GpuJobConnector>) {
        self.backends
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.to_owned(), connector);
    }

    /// Takes the backend `name` off this host, as a restart that no longer
    /// registers it does.
    #[cfg(oneiron_test_support)]
    pub(crate) fn remove_backend(&self, name: &str) {
        self.backends
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(name);
    }

    /// The backend registered as `name`.
    pub(crate) fn backend(&self, name: &str) -> Option<Arc<dyn GpuJobConnector>> {
        self.backends
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    fn backend_names(&self) -> Vec<String> {
        self.backends
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    /// Every registered backend, taken off the lock before any is called: a
    /// backend's calls block.
    pub(crate) fn registered_backends(&self) -> Vec<Arc<dyn GpuJobConnector>> {
        self.backends
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    pub(crate) fn permits(&self) -> &GpuJobPermits {
        &self.permits
    }

    /// The work-order loop this worker runs.
    pub(crate) fn orders(&self) -> &crate::work_order_host::OrderLoop {
        &self.orders
    }
}

/// Why a GPU job door or step could not reach its offer's backend.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GpuHostError {
    #[error("gpu_jobs.no_offer: this host posts no GPU offer named {0}")]
    NoOffer(String),
    #[error(
        "gpu_jobs.no_backend: no backend named {0} is registered on this host, so its offer cannot start a job"
    )]
    NoBackend(String),
    #[error(transparent)]
    Job(#[from] GpuJobError),
}

/// The offer named `name` and its registered backend.
pub(crate) fn offer_with_backend<'a>(
    server: &'a SyncServer,
    name: &str,
) -> Result<(&'a GpuOfferSettings, Arc<dyn GpuJobConnector>), GpuHostError> {
    let offer = server
        .config
        .gpu_jobs
        .offer(name)
        .ok_or_else(|| GpuHostError::NoOffer(name.to_owned()))?;
    let connector = server
        .gpu_jobs
        .backend(&offer.backend)
        .ok_or_else(|| GpuHostError::NoBackend(offer.backend.clone()))?;
    Ok((offer, connector))
}

/// The backend that runs `job`'s chunks: the one its row names (a job keeps
/// its backend, design pass 33, 8.1), so a withdrawn offer strands no job. A
/// row with no backend, written before the row named one, is reached through
/// its offer as this host posts it now.
pub(crate) fn job_backend(
    server: &SyncServer,
    job: &GpuJob,
) -> Result<Arc<dyn GpuJobConnector>, GpuHostError> {
    let name = match job.backend.as_deref() {
        Some(name) => name,
        None => server
            .config
            .gpu_jobs
            .offer(&job.offer.name)
            .map(|offer| offer.backend.as_str())
            .ok_or_else(|| GpuHostError::NoOffer(job.offer.name.clone()))?,
    };
    server
        .gpu_jobs
        .backend(name)
        .ok_or_else(|| GpuHostError::NoBackend(name.to_owned()))
}

/// The connector of a door over a job with no live chunk, which calls no
/// provider: such a job needs no offer or backend on this host. Every call
/// answers that the provider is unavailable, so a job that turned live in
/// between is left to the worker, which holds its backend.
pub(crate) struct NoProvider;

impl NoProvider {
    fn unavailable() -> GpuConnectorError {
        GpuConnectorError::Unavailable {
            reason: "no provider is called for a job with no live chunk".to_owned(),
        }
    }
}

impl GpuJobConnector for NoProvider {
    fn create(&self, _key: &str, _spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        Err(Self::unavailable())
    }

    fn find(&self, _key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        Err(Self::unavailable())
    }

    fn status(&self, _resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        Err(Self::unavailable())
    }

    fn signal(
        &self,
        _resource: &GpuResourceRef,
        _signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        Err(Self::unavailable())
    }

    fn terminate(&self, _resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        Err(Self::unavailable())
    }
}

/// The job's own run for the chunk `quote` prices: one line of the quote's
/// units, reserved whole, with the offer's connector named, on this server's
/// host account.
pub(crate) fn job_admission(
    server: &SyncServer,
    offer: &GpuOffer,
    quote: &GpuJobQuote,
) -> RunAdmission {
    chunk_admission(server, &offer.connector.connector, quote)
}

/// The job's own run for the chunk `quote` prices, naming the paid connector
/// `connector`: the offer's, which the host's config names after the offer.
fn chunk_admission(server: &SyncServer, connector: &str, quote: &GpuJobQuote) -> RunAdmission {
    let declaration = RunDeclaration::declared(BudgetLine {
        limit_units: quote.units,
        reserve_units: quote.units,
        unit: quote.unit.clone(),
    })
    .with_connector(connector.to_owned());
    server
        .ai
        .declared_run(
            GpuJob::admission_ref_of(&quote.job),
            declaration,
            Some(server.host_account()),
        )
        .admission()
        .clone()
}

/// The refusal of `[gpu_jobs.host_allocation]` on a managed server.
const MANAGED_HOST_ALLOCATION: &str = "gpu_jobs.host_allocation is refused on a managed server: its supervisor funds its host account";

/// Grants `server`'s host account the allocation `[gpu_jobs.host_allocation]` names, walletless,
/// before any job is started or taken up again (R6-VAULT-MACHINE-FUNDING = A; Engine 23:46). The
/// account lives in memory, so each start's account is fresh and each start grants the units
/// again: one process, one budget. Answers whether it granted them now: not when the section is
/// absent, and not when this account already holds the allocation. Every job still reserves and
/// settles on the host account (FRAUD-1).
///
/// # Errors
///
/// A managed server, or the account's refusal of the allocation: the start stops.
pub(crate) fn install_host_allocation_at_start(server: &SyncServer) -> anyhow::Result<bool> {
    let Some(settings) = &server.config.gpu_jobs.host_allocation else {
        return Ok(false);
    };
    anyhow::ensure!(server.managed_issuer.is_none(), MANAGED_HOST_ALLOCATION);
    let account = server.host_account();
    if account
        .status()
        .allocations
        .iter()
        .any(|selected| selected.reference == settings.reference)
    {
        return Ok(false);
    }
    let id = &settings.reference.id;
    account
        .grant(Allocation {
            reference: settings.reference.clone(),
            units: settings.units,
            unit: settings.unit.clone(),
            wallet: None,
        })
        .map_err(|refused| {
            anyhow::anyhow!("gpu_jobs.host_allocation {id}: the host account refused it: {refused}")
        })?;
    tracing::info!(
        id = %id,
        units = settings.units,
        unit = %settings.unit.as_str(),
        "gpu_jobs.host_allocation granted to the host account for this start"
    );
    Ok(true)
}

/// A managed server's start refuses `[gpu_jobs.host_allocation]`: its supervisor funds its host
/// account.
///
/// # Errors
///
/// The section is present.
pub(crate) fn refuse_managed_host_allocation(settings: &GpuJobsSettings) -> anyhow::Result<()> {
    anyhow::ensure!(settings.host_allocation.is_none(), MANAGED_HOST_ALLOCATION);
    Ok(())
}

/// Milliseconds since the Unix epoch, the clock quotes and steps read.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// One step of every live job at `now_ms`, each with its outcome. A job steps
/// on its own backend whether or not this host still posts its offer; a job
/// whose backend is not registered is not stepped and says why, and the next
/// pass tries again.
pub(crate) fn step_live_jobs(
    server: &SyncServer,
    now_ms: u64,
) -> Vec<(EntityId, Result<GpuJobStepReport, GpuHostError>)> {
    let live = match server.vault.live_gpu_jobs() {
        Ok(live) => live,
        Err(error) => {
            tracing::warn!(error = %error, "GPU job worker could not list live jobs");
            return Vec::new();
        }
    };
    live.into_iter()
        .map(|id| (id, step_one_job(server, &id, now_ms)))
        .collect()
}

fn step_one_job(
    server: &SyncServer,
    id: &EntityId,
    now_ms: u64,
) -> Result<GpuJobStepReport, GpuHostError> {
    let job = server
        .vault
        .gpu_job(id)
        .map_err(GpuJobError::from)?
        .ok_or(GpuJobError::NotFound)?;
    let chunk = job.chunk().ok_or(GpuJobError::NotFound)?;
    let connector = job_backend(server, &job)?;
    // The offer as posted now: its resume quote and a new permit's binding.
    // A withdrawn offer leaves the step neither (`gpu_job_step`).
    let offer = server
        .config
        .gpu_jobs
        .offer(&job.offer.name)
        .map(|posted| &posted.offer);
    let admission = match offer {
        Some(offer) => job_admission(server, offer, &chunk.quote),
        None => chunk_admission(server, &job.offer.name, &chunk.quote),
    };
    Ok(server.vault.gpu_job_step(
        id,
        offer,
        &admission,
        server.gpu_jobs.permits(),
        connector.as_ref(),
        now_ms,
    )?)
}

/// Whether this server has GPU job work at its start: an offer posted, a live
/// job, or an open work order, or it is the vault's issuer of vault machine jobs
/// with that section enabled, which reads its machines' readiness on a schedule
/// with no job work too (CG-2 row 9; REVIEW-10544 round 1 P1). A vault it
/// cannot read counts as work, so the worker starts and each pass says what it
/// could not read.
fn worker_has_work(server: &SyncServer) -> bool {
    if !server.config.gpu_jobs.offers.is_empty() {
        return true;
    }
    if server.config.gpu_jobs.vault_machine.enabled
        && not_the_issuer(server, VAULT_MACHINE_BACKEND).is_ok()
    {
        return true;
    }
    let work = server.vault.live_gpu_jobs().and_then(|live| {
        Ok(!live.is_empty()
            || server
                .vault
                .work_orders()?
                .iter()
                .any(|order| !order.state.is_terminal()))
    });
    work.unwrap_or_else(|error| {
        tracing::warn!(
            error = %error,
            "GPU job worker could not read the vault's jobs or work orders, so it starts"
        );
        true
    })
}

/// Starts the worker: every `step_secs`, and at each wake of the work-order
/// loop, one tick ([`worker_tick`]): one pass of the loop (pass 34, section 0)
/// and then one step of every live job, each pass admitted through `admit` as a
/// housekeeping pass is, so a vault frozen for reap steps nothing, and the
/// scheduled readiness read beside it. It starts when this server posts an
/// offer, holds a live job or an open work order, or is the enabled issuer of
/// vault machine jobs: a job keeps its backend after its offer is withdrawn
/// (design pass 33, 8.1), and steps to its settle. A server with none of them
/// starts no worker.
pub(crate) fn spawn_gpu_job_steps(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> Option<tokio::task::JoinHandle<()>> {
    if !worker_has_work(&server) {
        return None;
    }
    let tick = Duration::from_secs(server.config.gpu_jobs.step_secs);
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                () = server.gpu_jobs.orders().woken() => {}
            }
            // The tick does not wait for the readiness read it starts.
            drop(worker_tick(&server, &admit).await);
        }
    }))
}

/// One tick of the worker, admitted through `admit`: one [`worker_pass`], then
/// the scheduled readiness read of the machines no pass asked lately
/// ([`start_readiness_read`]), which the tick starts and does not wait for.
/// `None` when the tick was not admitted or started no read.
pub(crate) async fn worker_tick(
    server: &Arc<SyncServer>,
    admit: &HousekeepingAdmission,
) -> Option<tokio::task::JoinHandle<()>> {
    let admission = admit()?;
    let pass_at_ms = now_ms();
    let worker = Arc::clone(server);
    let pass = tokio::task::spawn_blocking(move || {
        let _admission = admission;
        worker_pass(&worker);
    })
    .await;
    if let Err(error) = pass {
        tracing::warn!(error = %error, "GPU job step pass failed");
    }
    start_readiness_read(server, admit, pass_at_ms)
}

/// Starts the scheduled readiness read after the worker's pass begun at
/// `pass_at_ms` (CG-2 row 9; `work_order_host::run_readiness_read`) on a
/// blocking thread of its own, so the worker's next passes run while an idle
/// machine is slow to answer (REVIEW-10544 round 1 P1). One read runs at a
/// time: while one runs, this starts none. The read is admitted through
/// `admit` as a pass is and holds its admission until it ends.
fn start_readiness_read(
    server: &Arc<SyncServer>,
    admit: &HousekeepingAdmission,
    pass_at_ms: u64,
) -> Option<tokio::task::JoinHandle<()>> {
    let running = server.gpu_jobs.orders().begin_readiness_read()?;
    let admission = admit()?;
    let server = Arc::clone(server);
    Some(tokio::task::spawn_blocking(move || {
        let _running = running;
        let _admission = admission;
        crate::work_order_host::run_readiness_read(&server, pass_at_ms, &now_ms);
    }))
}

/// One pass of the worker: one pass of the work-order loop (pass 34, section 0), one step of
/// every live job, then one housekeeping pass of every registered backend
/// ([`GpuJobConnector::housekeeping`]; pass 33 row R4, 8.5: the `vault_machine` backend asks
/// its live orphan keys to stop again and returns the results it still owes).
pub(crate) fn worker_pass(server: &Arc<SyncServer>) {
    crate::work_order_host::run_order_pass(server, now_ms());
    for (job, outcome) in step_live_jobs(server, now_ms()) {
        if let Err(error) = outcome {
            tracing::warn!(job = %job.to_hex(), error = %error, "GPU job step failed");
        }
    }
    for backend in server.gpu_jobs.registered_backends() {
        backend.housekeeping();
    }
}
