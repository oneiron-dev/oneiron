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
//!
//! The media workers, VoxCPM2 speech and local ASR, are supervised the same
//! way (FIX 8318, `media_worker`): a media rung's call holds its worker's
//! lease from before its admission through its renders, its partial
//! settlement or its cancellation, and the worker runs one inference at a
//! time.
mod bundle;
mod install;
mod launch_manifest;
mod launcher;
mod media_worker;
mod probe;
#[cfg(unix)]
mod process;
mod session;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use oneiron::llm::run_admission::WorkContext;
use oneiron::llm::{
    CallSchedule, InferenceCallReceipt, SchedulingCapability, WorkClass, WorkerKind, WorkerMode,
    WorkerStatus,
};
use oneiron_driver::{
    AdmissionStop, DeclaredEnvelope, DeviceAdmission, DeviceGrant, DeviceLedger,
    ExecutorRegistration, InferenceWorker, PressureDecision, UnloadOutcome, WorkEnvelope,
    WorkRequest, WorkTicket, WorkerActivity, WorkerPolicy, WorkerProbe, WorkerSpec,
};

use crate::config::models::{ProviderConfig, WorkerConfig, WorkerEnvelope};
use futures_util::future::select_all;
use launch_manifest::LaunchSlot;
use launcher::{ProcessLauncher, Stores};
use probe::HouseProbe;
use serde_json::Value as JsonValue;

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
    admissions: Mutex<BTreeMap<String, Arc<DeviceAdmission>>>,
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

    /// The scheduling capability the qualifying hello proved for this launch.
    pub(super) fn scheduling_capability(&self) -> Option<SchedulingCapability> {
        self.slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|record| record.scheduling.clone())
    }
}

/// One native call's ticket and eventual grant. An early exit cancels an
/// unused ticket; once granted, `Call` owns the release/reap custody.
pub(super) struct BoundWork {
    ticket: Option<WorkTicket>,
    context: WorkContext,
    armed: bool,
}

impl BoundWork {
    #[must_use]
    pub(super) fn device(&self) -> Option<&str> {
        self.ticket.as_ref().map(|ticket| ticket.device.as_str())
    }

    #[must_use]
    pub(super) fn is_foreground(&self) -> bool {
        self.ticket.as_ref().map_or_else(
            || self.context.class == WorkClass::Foreground,
            |ticket| ticket.request.class == WorkClass::Foreground,
        )
    }

    pub(super) async fn wait_runnable(&self) -> Result<(), AdmissionStop> {
        match &self.ticket {
            Some(ticket) => ticket.wait_runnable().await,
            None => Ok(()),
        }
    }

    pub(super) async fn execution_grant(&mut self) -> Result<Option<DeviceGrant>, AdmissionStop> {
        let Some(ticket) = &self.ticket else {
            self.armed = false;
            return Ok(None);
        };
        let mut tried = BTreeSet::new();
        let mut victim_changes = Vec::new();
        loop {
            match ticket.resolve_pressure_excluding(&tried) {
                PressureDecision::Grant(grant) => {
                    self.armed = false;
                    return Ok(Some(grant));
                }
                PressureDecision::Stop(stop) => return Err(stop),
                PressureDecision::UnloadIdle(worker) => {
                    if let Some(victim) = hosted_worker(&worker) {
                        victim_changes.push(victim.subscribe_changed());
                    }
                    let _ = unload_idle_worker(&worker).await;
                    tried.insert(worker);
                    continue;
                }
                PressureDecision::ApprovedSmallerProfile(_) | PressureDecision::Wait => {}
            }

            // Arm every wake before the final no-room check. A deferred
            // victim whose own demand drops is heard through its worker watch;
            // admission hears grants, releases, loads and fresh idle rows.
            let changed = ticket.pressure_change();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match ticket.resolve_pressure_excluding(&tried) {
                PressureDecision::Grant(grant) => {
                    self.armed = false;
                    return Ok(Some(grant));
                }
                PressureDecision::Stop(stop) => return Err(stop),
                PressureDecision::UnloadIdle(_) => continue,
                PressureDecision::ApprovedSmallerProfile(_) | PressureDecision::Wait => {}
            }
            let victim_wake = async move {
                if victim_changes.is_empty() {
                    std::future::pending::<()>().await;
                } else {
                    select_all(victim_changes.into_iter().map(|mut receiver| async move {
                        let _ = receiver.changed().await;
                    }))
                    .await;
                }
            };
            tokio::pin!(victim_wake);
            let deadline = ticket.deadline();
            tokio::select! {
                () = changed.as_mut() => {},
                _ = victim_wake => {},
                () = async {
                    if let Some(deadline) = deadline {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    ticket.cancel();
                    return Err(AdmissionStop::Deadline);
                }
            }
            tried.clear();
            victim_changes = Vec::new();
        }
    }

    #[must_use]
    pub(super) fn schedule(&self, grant: Option<&DeviceGrant>) -> CallSchedule {
        CallSchedule {
            work_class: self
                .ticket
                .as_ref()
                .map_or(self.context.class, |ticket| ticket.request.class),
            priority: self.context.priority,
            deadline: self
                .ticket
                .as_ref()
                .map_or_else(|| self.context.deadline, |ticket| ticket.request.deadline),
            admission: grant.map(DeviceGrant::admission),
        }
    }
}

impl Drop for BoundWork {
    fn drop(&mut self) {
        if self.armed {
            if let Some(ticket) = &self.ticket {
                ticket.cancel();
            }
        }
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

/// The device ledger of the device managed worker `worker_id` launches on,
/// when its launch names one: what a snapshot transfer may take there.
#[cfg(unix)]
fn device_ledger(worker_id: &str) -> Option<Arc<DeviceLedger>> {
    let host = HOST.get()?;
    let device = host
        .lock()
        .get(worker_id)?
        .row
        .launch
        .as_ref()?
        .device
        .clone()?;
    host.ledgers
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&device)
        .cloned()
}

/// Runs the driver-owned restartable idle unload for one pressure victim.
async fn unload_idle_worker(worker_id: &str) -> UnloadOutcome {
    let worker = HOST.get().and_then(|host| {
        host.lock()
            .get(worker_id)
            .map(|hosted| hosted.worker.clone())
    });
    match worker {
        Some(worker) => worker.unload_if_idle().await,
        None => UnloadOutcome::NotRunning,
    }
}

/// Returns one hosted supervisor by id for a victim-watch subscription.
fn hosted_worker(worker_id: &str) -> Option<InferenceWorker> {
    HOST.get().and_then(|host| {
        host.lock()
            .get(worker_id)
            .map(|hosted| hosted.worker.clone())
    })
}

/// Takes a device ticket for one bound call before its worker acquire. No
/// device means the route keeps its existing unmediated path. `envelope` is
/// the call's incremental charge beyond the worker's steady declaration.
pub(super) fn admit_bound_work(
    worker: &InferenceWorker,
    context: WorkContext,
    envelope: WorkEnvelope,
) -> BoundWork {
    let ticket = HOST.get().and_then(|host| {
        let hosted = host.lock();
        let hosted = hosted.get(&worker.spec().worker_id)?;
        let device = hosted.row.launch.as_ref()?.device.as_deref()?;
        let admission = host.admission(device);
        let mut request = WorkRequest::new(
            hosted.row.id.clone(),
            worker.resource_class(),
            hosted.row.id.clone(),
        );
        request.envelope = envelope;
        request.class = context.class;
        request.priority = context.priority;
        request.deadline = context.deadline;
        request.parent = context.parent;
        request.cancel = context.cancel.shared();
        Some(admission.enqueue(request))
    });
    BoundWork {
        ticket,
        context,
        armed: true,
    }
}

/// Retains a sanitized physical receipt on the worker that made it.
pub(super) fn report_receipt(worker_id: &str, epoch: &str, receipt: InferenceCallReceipt) {
    if let Some(host) = HOST.get() {
        if let Some(hosted) = host.lock().get(worker_id) {
            hosted.worker.record_receipt(epoch, receipt);
        }
    }
}

/// Registers or refreshes one executor's idle row. Managed custody exists
/// only when this process may launch that worker; other work is recorded as
/// external and is never an unload target.
pub(super) fn register_device_executor(worker_id: &str, idle: bool) {
    let Some(host) = HOST.get() else {
        return;
    };
    let Some((device, external)) = host.lock().get(worker_id).and_then(|hosted| {
        let device = hosted.row.launch.as_ref()?.device.clone()?;
        let managed =
            hosted.row.mode == WorkerMode::Managed && host.launch_permitted.load(Ordering::SeqCst);
        Some((device, !managed))
    }) else {
        return;
    };
    host.admission(&device)
        .register_executor(ExecutorRegistration {
            worker_id: worker_id.to_owned(),
            external,
            idle,
        });
}

/// Publishes one worker-reported activity snapshot to both admission and
/// the supervisor without deriving either side from the other.
pub(super) fn report_device_activity(worker: &InferenceWorker, activity: WorkerActivity) {
    register_device_executor(&worker.spec().worker_id, activity.is_idle());
    worker.report(activity);
}

/// Cross-checks a worker's own device capacity report with the pre-load
/// query. The first valid report fills an unknown; a mismatch keeps the
/// device query and logs rather than silently rewriting capacity.
pub(super) fn report_device_stats(worker_id: &str, stats: &JsonValue) {
    let Some(host) = HOST.get() else {
        return;
    };
    let Some(device) = host
        .lock()
        .get(worker_id)
        .and_then(|hosted| hosted.row.launch.as_ref()?.device.clone())
    else {
        return;
    };
    let ledger = host.ledger(&device);
    let rows = stats.get("devices").and_then(JsonValue::as_array);
    let cuda_device = format!("cuda:{device}");
    let row = rows.and_then(|rows| {
        rows.iter()
            .find(|row| {
                row.get("device")
                    .and_then(JsonValue::as_str)
                    .is_some_and(|name| name == device.as_str() || name == cuda_device.as_str())
            })
            .or_else(|| (rows.len() == 1).then(|| rows.first()).flatten())
    });
    let Some(bytes) = row
        .and_then(|row| row.get("capacity_bytes"))
        .and_then(JsonValue::as_u64)
    else {
        return;
    };
    let capacity = bytes.saturating_add((1_u64 << 20) - 1) / (1_u64 << 20);
    match ledger.capacity() {
        None => ledger.set_capacity(Some(capacity)),
        Some(existing) if existing != capacity => {
            tracing::warn!(worker = worker_id, device = %device, existing, reported = capacity, "worker and host device capacities differ");
        }
        Some(_) => {}
    }
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

/// Copies every device queue and ledger into owner-facing status. No probe.
pub(super) fn refresh_devices(statuses: &mut Vec<super::status::DeviceStatus>) {
    let Some(host) = HOST.get() else {
        statuses.clear();
        return;
    };
    let admissions = host
        .admissions
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .values()
        .cloned()
        .collect::<Vec<_>>();
    *statuses = admissions
        .into_iter()
        .map(|admission| super::status::DeviceStatus::from_snapshot(admission.snapshot()))
        .collect();
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
        Arc::clone(ledgers.entry(device.to_owned()).or_insert_with(|| {
            Arc::new(DeviceLedger::new(
                format!("cuda:{device}"),
                query_capacity(device),
            ))
        }))
    }

    /// The one admission queue for `device`, sharing its memory ledger.
    fn admission(&self, device: &str) -> Arc<DeviceAdmission> {
        let mut admissions = self
            .admissions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            admissions
                .entry(device.to_owned())
                .or_insert_with(|| Arc::new(DeviceAdmission::new(device, self.ledger(device)))),
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
                let worker = InferenceWorker::managed(spec, launcher, probe, policy, device);
                if let Some(device) = launch.device.as_deref() {
                    let admission = self.admission(device);
                    worker.with_admission(Arc::clone(&admission));
                    let managed_here = self.launch_permitted.load(Ordering::SeqCst);
                    if !managed_here {
                        self.ledger(device).note_unmediated(&row.id, None);
                    }
                    admission.register_executor(ExecutorRegistration {
                        worker_id: row.id.clone(),
                        external: !managed_here,
                        idle: true,
                    });
                }
                (worker, Some(slot))
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

/// Total MiB for the configured CUDA device, without pooling or remapping
/// cards. Any unavailable query leaves capacity unknown, which admits today.
fn query_capacity(device: &str) -> Option<u64> {
    let device = device.trim();
    if device.is_empty() {
        return None;
    }
    let output = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=memory.total",
            "--format=csv,noheader,nounits",
            "--id",
            device,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .next()?
        .trim()
        .parse()
        .ok()
}

fn declared(envelope: WorkerEnvelope) -> DeclaredEnvelope {
    DeclaredEnvelope {
        weights_mib: envelope.weights_mib,
        kv_mib: envelope.kv_mib,
        workspace_mib: envelope.workspace_mib,
        load_transient_mib: envelope.load_transient_mib,
    }
}
