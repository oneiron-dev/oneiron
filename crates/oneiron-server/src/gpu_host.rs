//! The host side of customer GPU jobs (CROSS-ARCH-0023 lifecycle, C2; row
//! L10-31). The engine decides every step of a job (`oneiron::gpu_job`); the
//! host holds what a step needs and cannot store: the backends that provision
//! each `[gpu_jobs]` offer, by name, and the live chunks' run permits. A
//! worker steps every live job every `step_secs` on the blocking pool, since
//! a backend's calls block.
//!
//! No backend ships here: the registry is empty until a backend registers
//! (C6 02, GPU-LAUNCH-BACKENDS), and a start on an offer whose backend is
//! not registered refuses before any reservation. Each job runs as its own
//! declared run, whose one line is the chunk's quote, reserved whole on this
//! server's host account (FRAUD-1: a host-paid offer draws on the vault's
//! paid allocation).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::EntityId;
use oneiron::gpu_job::{
    GpuConnectorError, GpuJob, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobQuote,
    GpuJobSignal, GpuJobSpec, GpuJobStepReport, GpuOffer, GpuResourceRef, GpuResourceStatus,
    GpuTermination,
};
use oneiron::llm::run_admission::{BudgetLine, RunAdmission, RunDeclaration};

use crate::config::GpuOfferSettings;
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
    /// Registers `connector` as the backend `name`, replacing any before it.
    /// Only the test door registers one until a backend ships (C6 02,
    /// GPU-LAUNCH-BACKENDS); that backend's PR drops the gate.
    #[cfg(oneiron_test_support)]
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
/// job, or an open work order. A vault it cannot read counts as work, so the
/// worker starts and each pass says what it could not read.
fn worker_has_work(server: &SyncServer) -> bool {
    if !server.config.gpu_jobs.offers.is_empty() {
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
/// loop, one pass of the loop (pass 34, section 0) and then one step of every
/// live job, each pass admitted through `admit` as a housekeeping pass is, so
/// a vault frozen for reap steps nothing. It starts when this server posts an
/// offer, or holds a live job or an open work order: a job keeps its backend
/// after its offer is withdrawn (design pass 33, 8.1), and steps to its
/// settle. A server with none of them starts no worker.
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
            let Some(admission) = admit() else {
                continue;
            };
            let server = Arc::clone(&server);
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                crate::work_order_host::run_order_pass(&server, now_ms());
                for (job, outcome) in step_live_jobs(&server, now_ms()) {
                    if let Err(error) = outcome {
                        tracing::warn!(job = %job.to_hex(), error = %error, "GPU job step failed");
                    }
                }
            })
            .await;
            if let Err(error) = pass {
                tracing::warn!(error = %error, "GPU job step pass failed");
            }
        }
    }))
}
