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
//!
//! A managed EXL3 worker's launch also has a native socket (DESIGN-V2 §8,
//! V2-R1): its provider's calls to it go there ([`native_route`],
//! `models/native_exl3`), its qualification asks there, and its activity
//! poll reads its stats there.
mod bundle;
mod install;
mod launch_manifest;
mod launcher;
mod probe;
#[cfg(unix)]
mod process;
mod session;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use oneiron::llm::{WorkerKind, WorkerMode, WorkerStatus};
use oneiron_driver::{
    DeclaredEnvelope, DeviceLedger, InferenceWorker, WorkerPolicy, WorkerProbe, WorkerSpec,
};

use crate::config::models::{ProviderConfig, WorkerConfig, WorkerEnvelope};
use launch_manifest::LaunchSlot;
use launcher::{ProcessLauncher, Stores};
use probe::HouseProbe;

#[cfg(unix)]
pub(super) use session::open_turn;
pub(crate) use session::{
    AuthorityVerdict, CheckpointAuthority, ReplyCommit, RestoreClaim, SnapshotScope,
    reply_committed, turn_admitted,
};

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
    /// The sessions on its managed EXL3 workers (DESIGN-V2 R2).
    #[cfg(unix)]
    sessions: session::Registry,
}

/// One configured worker and its supervisor.
struct Hosted {
    row: WorkerConfig,
    provider: ProviderConfig,
    worker: InferenceWorker,
    /// A managed launch's record slot, which names its native socket.
    slot: Option<Arc<LaunchSlot>>,
}

impl Hosted {
    /// A managed EXL3 worker's launch slot: a launch whose record may name a
    /// native socket.
    fn native_slot(&self) -> Option<&Arc<LaunchSlot>> {
        if self.row.mode == WorkerMode::Managed && self.row.kind == WorkerKind::Exl3 {
            self.slot.as_ref()
        } else {
            None
        }
    }
}

/// A managed EXL3 worker's native route: its supervisor, and the slot its
/// launcher records each launch in, the launch's socket among it.
#[derive(Clone)]
pub(super) struct NativeRoute {
    pub(super) worker: InferenceWorker,
    slot: Arc<LaunchSlot>,
}

impl NativeRoute {
    /// The current launch's native socket and the digest of its launch
    /// manifest; `None` when it has no socket.
    pub(super) fn launch(&self) -> Option<(PathBuf, String)> {
        let record = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        let record = record.as_ref()?;
        Some((
            record.native_socket.clone()?,
            record.manifest_sha256.clone(),
        ))
    }
}

/// The process's worker host, made on first use.
#[cfg(unix)]
fn host() -> &'static WorkerHost {
    HOST.get_or_init(WorkerHost::default)
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

/// Attaches this process's snapshot port to `vault` (V2-R3): its lock
/// waits for every session of it here to be released, under the owner's
/// bound, and its erases drop them. Off Unix no session runs, so none is
/// attached and a lock only closes the vault's own admission.
pub(crate) fn install_snapshot_runtime(vault: &Arc<oneiron::Vault>) {
    #[cfg(unix)]
    session::install_snapshots(vault);
    #[cfg(not(unix))]
    let _ = vault;
}

/// Takes up the configured `[models.snapshots]` policy.
pub(super) fn snapshot_policy(policy: &crate::config::models::snapshots::SnapshotPolicy) {
    #[cfg(unix)]
    session::set_snapshot_policy(policy);
    #[cfg(not(unix))]
    let _ = policy;
}

/// Sealed snapshot parking as this process stands; `None` off Unix.
pub(super) fn snapshot_status() -> Option<super::SnapshotStatus> {
    #[cfg(unix)]
    let status = Some(session::snapshot_status());
    #[cfg(not(unix))]
    let status = None;
    status
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
                    let (worker, slot) = host.supervisor(row, provider);
                    let hosted = Hosted {
                        row: row.clone(),
                        provider: provider.clone(),
                        worker: worker.clone(),
                        slot,
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

/// Whether a managed EXL3 worker this process launches is bound to
/// `provider`: its chat transport then reaches that worker over its native
/// socket (`models/native_exl3`).
pub(super) fn serves_native(provider: &str) -> bool {
    let Some(host) = HOST.get() else {
        return false;
    };
    if !host.launch_permitted.load(Ordering::Relaxed) {
        return false;
    }
    host.lock()
        .values()
        .any(|hosted| hosted.native_slot().is_some() && hosted.row.binding.provider == provider)
}

/// The native route of the managed EXL3 worker a call on `provider` with
/// `wire_model` is bound to, when this process launches it and its current
/// launch has a native socket. `None` leaves the call on HTTP, as today.
pub(super) fn native_route(provider: &str, wire_model: &str) -> Option<NativeRoute> {
    let host = HOST.get()?;
    if !host.launch_permitted.load(Ordering::Relaxed) {
        return None;
    }
    let route = {
        let workers = host.lock();
        let hosted = workers.values().find(|hosted| {
            hosted.native_slot().is_some()
                && hosted.row.binding.provider == provider
                && hosted.row.binding.model == wire_model
        })?;
        NativeRoute {
            worker: hosted.worker.clone(),
            slot: Arc::clone(hosted.native_slot()?),
        }
    };
    route.launch().is_some().then_some(route)
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

    /// A new supervisor for `row`, bound to `provider`, with a managed
    /// launch's record slot.
    fn supervisor(
        &self,
        row: &WorkerConfig,
        provider: &ProviderConfig,
    ) -> (InferenceWorker, Option<Arc<LaunchSlot>>) {
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
                    Arc::clone(&slot),
                ));
                let policy = WorkerPolicy {
                    idle_stop: launch.idle_stop_secs.map(Duration::from_secs),
                    ..WorkerPolicy::default()
                };
                let device = launch
                    .device
                    .as_deref()
                    .map(|device| (self.ledger(device), declared(launch.envelope)));
                (
                    InferenceWorker::managed(spec, launcher, probe, policy, device),
                    Some(slot),
                )
            }
            _ => {
                let probe = Arc::new(HouseProbe::new(
                    provider,
                    row.endpoint.as_deref(),
                    &row.binding.model,
                    None,
                ));
                (InferenceWorker::external(spec, probe), None)
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
