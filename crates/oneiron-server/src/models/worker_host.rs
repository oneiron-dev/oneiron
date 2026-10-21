//! This process's model workers (FIX 8315, DESIGN-V2 §8, INFERENCE R2): one
//! supervisor per configured worker id, held process-wide, so a second
//! model runtime built in the same process reuses the first one's
//! supervisors instead of starting the workers again.
//!
//! A `managed` row's supervisor installs, launches, qualifies and stops its
//! worker; an `external` row's only probes it. Managed workers launch only
//! in a process that [`permit_worker_launch`] has marked: plain and embedded
//! serve do, and a managed per-vault process never does, since every vault
//! runs its own process and each would launch the same worker. There a
//! managed row stays unchecked and its provider is called as it is today.
//!
//! A configured rung reaches its worker by the row's explicit binding, its
//! provider and wire model ([`managed_worker`]); nothing is inferred from a
//! URL or a name. A row whose config changed gets a new supervisor once the
//! old one has drained and stopped; a row that is no longer configured keeps
//! its supervisor, since another runtime in the process may still use it.
mod bundle;
mod install;
mod launch_manifest;
mod launcher;
mod probe;
#[cfg(unix)]
mod process;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use oneiron::llm::{WorkerMode, WorkerStatus};
use oneiron_driver::{
    DeclaredEnvelope, DeviceLedger, InferenceWorker, WorkerPolicy, WorkerProbe, WorkerSpec,
};

use crate::config::models::{ProviderConfig, WorkerConfig, WorkerEnvelope};
use launch_manifest::LaunchSlot;
use launcher::{ProcessLauncher, Stores};
use probe::HouseProbe;

/// The process's one worker host, made when the first worker is configured
/// or the process is marked as the one that launches them.
static HOST: OnceLock<WorkerHost> = OnceLock::new();

#[derive(Default)]
struct WorkerHost {
    /// Whether this process may launch managed workers.
    launch_permitted: AtomicBool,
    workers: Mutex<BTreeMap<String, Hosted>>,
    stores: Arc<Stores>,
    ledgers: Mutex<BTreeMap<String, Arc<DeviceLedger>>>,
}

/// One configured worker and its supervisor.
struct Hosted {
    row: WorkerConfig,
    provider: ProviderConfig,
    worker: InferenceWorker,
}

/// Marks this process as the one that launches managed workers, and starts
/// any already configured. Plain and embedded serve call it before they
/// build their models; a managed per-vault process never does.
pub(crate) fn permit_worker_launch() {
    let host = HOST.get_or_init(WorkerHost::default);
    host.launch_permitted.store(true, Ordering::SeqCst);
    let managed: Vec<InferenceWorker> = host
        .lock()
        .values()
        .filter(|hosted| hosted.row.mode == WorkerMode::Managed)
        .map(|hosted| hosted.worker.clone())
        .collect();
    for worker in managed {
        worker.start();
    }
}

/// Puts `rows` under the process's supervisors, starting what is new, and
/// returns their status rows in config order. Nothing at all without rows.
pub(super) fn configure(
    rows: &[WorkerConfig],
    providers: &BTreeMap<String, ProviderConfig>,
) -> Vec<WorkerStatus> {
    if rows.is_empty() {
        return Vec::new();
    }
    let host = HOST.get_or_init(WorkerHost::default);
    let mut statuses = Vec::with_capacity(rows.len());
    let mut started = Vec::new();
    let mut replaced = Vec::new();
    {
        let mut workers = host.lock();
        for row in rows {
            let Some(provider) = providers.get(&row.binding.provider) else {
                continue;
            };
            let current = workers
                .get(&row.id)
                .filter(|hosted| hosted.row == *row && hosted.provider == *provider)
                .map(|hosted| hosted.worker.clone());
            let worker = match current {
                Some(worker) => worker,
                None => {
                    let worker = host.supervisor(row, provider);
                    let hosted = Hosted {
                        row: row.clone(),
                        provider: provider.clone(),
                        worker: worker.clone(),
                    };
                    match workers.insert(row.id.clone(), hosted) {
                        Some(old) => replaced.push((old.worker, worker.clone())),
                        None => started.push(worker.clone()),
                    }
                    worker
                }
            };
            statuses.push(worker.status());
        }
    }
    for worker in started {
        host.begin(&worker);
    }
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        for (old, new) in replaced {
            runtime.spawn(async move {
                old.retire().await;
                host.begin(&new);
            });
        }
    }
    statuses
}

/// Each row's status as its supervisor holds it now.
pub(super) fn refresh(statuses: &mut [WorkerStatus]) {
    let Some(host) = HOST.get() else {
        return;
    };
    let workers = host.lock();
    for status in statuses {
        if let Some(hosted) = workers.get(&status.worker_id) {
            *status = hosted.worker.status();
        }
    }
}

/// The managed worker a rung on `provider` calling `wire_model` is bound
/// to, when this process launches it. `None` leaves the rung as it is today.
pub(super) fn managed_worker(provider: &str, wire_model: &str) -> Option<InferenceWorker> {
    let host = HOST.get()?;
    if !host.launch_permitted.load(Ordering::Relaxed) {
        return None;
    }
    let workers = host.lock();
    workers
        .values()
        .find(|hosted| {
            hosted.row.mode == WorkerMode::Managed
                && hosted.row.binding.provider == provider
                && hosted.row.binding.model == wire_model
        })
        .map(|hosted| hosted.worker.clone())
}

impl WorkerHost {
    /// Starts a new supervisor's work: a managed worker launches where this
    /// process may launch, an external one is probed once.
    fn begin(&self, worker: &InferenceWorker) {
        match worker.spec().mode {
            WorkerMode::Managed => {
                if self.launch_permitted.load(Ordering::SeqCst) {
                    worker.start();
                }
            }
            WorkerMode::External => {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    let worker = worker.clone();
                    runtime.spawn(async move { worker.probe_once().await });
                }
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Hosted>> {
        self.workers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The device ledger for `device`, shared by every worker on it.
    fn ledger(&self, device: &str) -> Arc<DeviceLedger> {
        let mut ledgers = self.ledgers.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            ledgers
                .entry(device.to_owned())
                .or_insert_with(|| Arc::new(DeviceLedger::new(format!("cuda:{device}"), None))),
        )
    }

    /// A new supervisor for `row`, bound to `provider`.
    fn supervisor(&self, row: &WorkerConfig, provider: &ProviderConfig) -> InferenceWorker {
        let spec = WorkerSpec {
            worker_id: row.id.clone(),
            model: row.model.clone(),
            kind: row.kind,
            mode: row.mode,
            expected: row.expected.clone(),
        };
        match (&row.launch, row.mode) {
            (Some(launch), WorkerMode::Managed) => {
                let slot = Arc::new(LaunchSlot::default());
                let probe: Arc<dyn WorkerProbe> = Arc::new(HouseProbe::new(
                    provider,
                    None,
                    &row.binding.model,
                    Some(Arc::clone(&slot)),
                ));
                let launcher = Arc::new(ProcessLauncher::new(
                    row.clone(),
                    launch.clone(),
                    Arc::clone(&self.stores),
                    slot,
                ));
                let policy = WorkerPolicy {
                    idle_stop: launch.idle_stop_secs.map(Duration::from_secs),
                    ..WorkerPolicy::default()
                };
                let device = launch
                    .device
                    .as_deref()
                    .map(|device| (self.ledger(device), declared(launch.envelope)));
                InferenceWorker::managed(spec, launcher, probe, policy, device)
            }
            _ => {
                let probe = Arc::new(HouseProbe::new(
                    provider,
                    row.endpoint.as_deref(),
                    &row.binding.model,
                    None,
                ));
                InferenceWorker::external(spec, probe)
            }
        }
    }
}

fn declared(envelope: WorkerEnvelope) -> DeclaredEnvelope {
    DeclaredEnvelope {
        weights_mib: envelope.weights_mib,
        kv_mib: envelope.kv_mib,
        workspace_mib: envelope.workspace_mib,
        load_transient_mib: envelope.load_transient_mib,
    }
}
