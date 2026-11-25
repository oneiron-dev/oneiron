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
//! paid allocation).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::EntityId;
use oneiron::gpu_job::{
    GpuConnectorError, GpuJob, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobQuote,
    GpuJobRenewal, GpuJobSignal, GpuJobSpec, GpuJobStepReport, GpuOffer, GpuResourceRef,
    GpuResourceStatus, GpuTermination,
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
    let (offer, connector) = offer_with_backend(server, &job.offer.name)?;
    // Each chunk is admitted under its own quote's line, a session's next one too (row W1).
    let admission_of = |quote: &GpuJobQuote| job_admission(server, &offer.offer, quote);
    let renewal = GpuJobRenewal {
        lead_floor_ms: session_renew_lead_floor_ms(&server.config.gpu_jobs),
        admission: &admission_of,
    };
    Ok(server.vault.gpu_job_step_with_renewal(
        id,
        &offer.offer,
        server.gpu_jobs.permits(),
        connector.as_ref(),
        &renewal,
        now_ms,
    )?)
}

/// The least renewal lead a session's step may take (row W1): one step of the worker, three
/// bounded calls to the node (its offer, the submit, a status), the node's stop grace (its
/// default, 10 s: the issuer does not read a node's own) and its renewal margin before that
/// stop, and a second. A `jobs.sessions.renew_lead_secs` at or below it renews nothing.
fn session_renew_lead_floor_ms(settings: &crate::config::gpu_jobs::GpuJobsSettings) -> u64 {
    settings
        .step_secs
        .saturating_add(settings.vault_machine.call_timeout_secs.saturating_mul(3))
        .saturating_add(crate::gpu_execution_node::node_settings::STOP_GRACE_SECS_DEFAULT)
        .saturating_add(1)
        .saturating_mul(1_000)
        .saturating_add(crate::gpu_execution_node::jobs::RENEWAL_MARGIN_NS / 1_000_000)
}

/// Starts the worker: every `step_secs`, and at each wake of the work-order
/// loop, one pass of the loop (pass 34, section 0) and then one step of every
/// live job, each pass admitted through `admit` as a housekeeping pass is, so
/// a vault frozen for reap steps nothing. A server that posts no offer starts
/// no worker.
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
