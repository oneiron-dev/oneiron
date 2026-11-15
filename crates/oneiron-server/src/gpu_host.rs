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
    GpuJob, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobQuote, GpuJobStepReport, GpuOffer,
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
    pub(crate) fn register_backend(&self, name: &str, connector: Arc<dyn GpuJobConnector>) {
        self.backends
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.to_owned(), connector);
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

/// The job's own run for the chunk `quote` prices: one line of the quote's
/// units, reserved whole, with the offer's connector named, on this server's
/// host account.
pub(crate) fn job_admission(
    server: &SyncServer,
    offer: &GpuOffer,
    quote: &GpuJobQuote,
) -> RunAdmission {
    let declaration = RunDeclaration::declared(BudgetLine {
        limit_units: quote.units,
        reserve_units: quote.units,
        unit: quote.unit.clone(),
    })
    .with_connector(offer.connector.connector.clone());
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

/// One step of every live job at `now_ms`, each with its outcome. A job whose
/// offer this host no longer posts, or whose backend is not registered, is
/// not stepped and says why; the next pass tries again.
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
    let (offer, connector) = offer_with_backend(server, &job.offer.name)?;
    let admission = job_admission(server, &offer.offer, &chunk.quote);
    Ok(server.vault.gpu_job_step(
        id,
        &offer.offer,
        &admission,
        server.gpu_jobs.permits(),
        connector.as_ref(),
        now_ms,
    )?)
}

/// Starts the worker: every `step_secs`, one step of every live job, each
/// pass admitted through `admit` as a housekeeping pass is, so a vault frozen
/// for reap steps nothing. A server that posts no offer starts no worker.
pub(crate) fn spawn_gpu_job_steps(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> Option<tokio::task::JoinHandle<()>> {
    if server.config.gpu_jobs.offers.is_empty() {
        return None;
    }
    let tick = Duration::from_secs(server.config.gpu_jobs.step_secs);
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Some(admission) = admit() else {
                continue;
            };
            let server = Arc::clone(&server);
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
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
