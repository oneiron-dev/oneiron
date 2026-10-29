//! One model worker's lifecycle (FIX 8315, DESIGN-V2 §8, INFERENCE R2): one
//! supervisor per worker, over an injected [`WorkerLauncher`] and the R1
//! [`WorkerProbe`].
//!
//! A `Managed` worker is installed, launched, qualified, stopped and
//! relaunched by this supervisor alone. An `External` worker is the
//! operator's: it is probed, and never installed, started, stopped,
//! restarted or unloaded here, and a call to it never waits here.
//!
//! Readiness is the probe's. After the launcher's liveness check answers
//! (an open port or a health route, never readiness), one qualification
//! input goes to each incarnation; an answer that misses evidence or
//! contradicts a pin parks the worker. The epoch is the worker's own, as the
//! probe observed it; the private incarnation counter only binds leases and
//! is never identity.
//!
//! Concurrent demand shares one install, one launch and one qualification.
//! [`InferenceWorker::acquire`] registers its demand before it waits, so a
//! call that arrives while the worker is stopped starts it, and the lease it
//! returns names the incarnation it was granted on. When that incarnation's
//! process exits, its leases are revoked: they no longer hold a drain or an
//! idle stop of the next one. A relaunch replays nothing: a call an exit cut
//! fails as it would have, under its caller's own retry authority.
//!
//! A stop always drains first: admission closes, every lease ends, and the
//! worker's own queued and active work reaches zero when it reports any.
//! Only then does the launcher terminate it, with its grace. No live call is
//! timed out, and no startup has a deadline.
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use oneiron::llm::{
    InferenceCallReceipt, ResourceClass, WorkerDescriptor, WorkerFailure, WorkerFailureDetail,
    WorkerKind, WorkerReadiness, WorkerStatus,
};
use tokio::sync::watch;

use super::inference::{WorkerProbe, WorkerSpec};
use super::inference_admission::{DeviceAdmission, LoadGrant};
use super::inference_device::{DeclaredEnvelope, DeviceLedger, ResidentReport, ResidentSource};

mod drive;

use drive::drive;

/// The waits before each relaunch after a crash or a transient failure, in
/// seconds; the last repeats without end. A qualified `Ready` starts the
/// list again.
pub const WORKER_CRASH_BACKOFF_SECS: [u64; 5] = [5, 10, 20, 40, 60];

/// What a drained worker gets between its terminate signal and its kill.
pub const WORKER_STOP_GRACE: Duration = Duration::from_secs(10);

/// How often a starting worker's liveness is checked before its one
/// qualification, and a draining worker's own work: a cheap check, never a
/// generation. No deadline ends either wait.
pub const WORKER_LIVENESS_POLL: Duration = Duration::from_secs(1);

/// How often a ready worker is asked what it holds: its queued and active
/// work and its resident memory, when it reports them.
pub const WORKER_ACTIVITY_POLL: Duration = Duration::from_secs(15);

/// Idle stop is off unless a worker's own config turns it on: a call that
/// does not come through a lease (a native decision read) would otherwise
/// find its worker stopped.
pub const DEFAULT_WORKER_IDLE_STOP: Option<Duration> = None;

/// A launcher's or a running worker's answer, in flight.
pub type LauncherFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why an install or a launch did not give a running worker. A permanent
/// failure (a pin that does not match, a refused licence, a missing file the
/// config names) parks the worker until its config changes; a transient one
/// (a transfer cut, a process that would not start) is tried again after the
/// backoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchFailure {
    pub failure: WorkerFailure,
    pub permanent: bool,
    pub reason: String,
}

impl LaunchFailure {
    #[must_use]
    pub fn permanent(failure: WorkerFailure, reason: impl Into<String>) -> Self {
        Self {
            failure,
            permanent: true,
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn transient(failure: WorkerFailure, reason: impl Into<String>) -> Self {
        Self {
            failure,
            permanent: false,
            reason: reason.into(),
        }
    }
}

/// How a worker's process ended, as its launcher saw it reaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerExit {
    pub description: String,
}

/// What a running worker reports it holds now: its queued and active
/// requests, and its resident device memory when it measures it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerActivity {
    pub queued: u64,
    pub active: u64,
    pub resident_mib: Option<u64>,
}

impl WorkerActivity {
    fn is_idle(&self) -> bool {
        self.queued == 0 && self.active == 0
    }
}

/// What installs and starts one kind of worker. The supervisor calls it; it
/// never decides when.
pub trait WorkerLauncher: Send + Sync {
    /// Makes every artifact `spec` runs from present and verified: weights,
    /// worker code, its environment, a native binary.
    fn install<'a>(&'a self, spec: &'a WorkerSpec)
    -> LauncherFuture<'a, Result<(), LaunchFailure>>;

    /// Starts one incarnation from the installed artifacts, and hands over
    /// its custody: the supervisor alone stops and reaps it.
    fn launch<'a>(
        &'a self,
        spec: &'a WorkerSpec,
    ) -> LauncherFuture<'a, Result<Box<dyn RunningWorker>, LaunchFailure>>;
}

/// One running incarnation, in the supervisor's custody.
pub trait RunningWorker: Send + Sync {
    /// Resolves once the process has exited and been reaped; at once after.
    fn exited(&self) -> LauncherFuture<'_, WorkerExit>;

    /// Whether the process answers its liveness check now: never readiness.
    fn live(&self) -> LauncherFuture<'_, bool>;

    /// What the worker reports it holds; `None` when it reports nothing, which
    /// is never idle.
    fn activity(&self) -> LauncherFuture<'_, Option<WorkerActivity>>;

    /// Sends the terminate signal to its own process group, waits `grace`,
    /// then kills and reaps that group alone. Called only after the drain.
    fn terminate(&self, grace: Duration) -> LauncherFuture<'_, WorkerExit>;

    /// Kills its own process group now and waits for the reaper: no drain,
    /// no grace, nothing asked of the worker. Called only for an abort
    /// ([`InferenceWorker::abort_incarnation`]). A launcher that names no
    /// way of its own terminates with no grace.
    fn abort(&self) -> LauncherFuture<'_, WorkerExit> {
        self.terminate(Duration::ZERO)
    }
}

/// The supervisor's timing for one worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerPolicy {
    /// How long a worker with no lease that reports zero queued and active
    /// work stays up; `None` keeps it up.
    pub idle_stop: Option<Duration>,
    pub stop_grace: Duration,
    pub liveness_poll: Duration,
    pub activity_poll: Duration,
}

impl Default for WorkerPolicy {
    fn default() -> Self {
        Self {
            idle_stop: DEFAULT_WORKER_IDLE_STOP,
            stop_grace: WORKER_STOP_GRACE,
            liveness_poll: WORKER_LIVENESS_POLL,
            activity_poll: WORKER_ACTIVITY_POLL,
        }
    }
}

/// Why a worker gave no lease: it is parked (failed or unverified) or
/// retired. A worker that is starting, backing off or stopped for idleness
/// never gives this: its callers wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerUnavailable {
    pub worker_id: String,
    pub readiness: WorkerReadiness,
    pub reason: Option<String>,
}

impl std::fmt::Display for WorkerUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "worker {} is not serving", self.worker_id)?;
        if let Some(reason) = &self.reason {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}

impl std::error::Error for WorkerUnavailable {}

/// Where a managed worker is in its life.
#[derive(Debug, Clone)]
enum Phase {
    Stopped,
    Installing,
    Starting,
    Qualifying,
    Ready(WorkerDescriptor),
    Draining,
    IdleStopped,
    Backoff,
    /// Parked until the config changes: a contradiction, a permanent
    /// install failure, or a qualification that missed evidence.
    Failed {
        readiness: WorkerReadiness,
        reason: String,
    },
}

#[derive(Debug)]
struct State {
    phase: Phase,
    /// A driver task is running this worker.
    driving: bool,
    /// The worker is being retired: no lease is granted again.
    retiring: bool,
    /// Callers waiting for readiness, not yet holding a lease.
    waiting: usize,
    /// The private counter leases bind to: one per incarnation.
    incarnation: u64,
    /// Leases held on the current incarnation.
    leases: usize,
    /// When a lease last began or ended.
    used_at: Option<Instant>,
    /// The worker's last activity report.
    activity: Option<WorkerActivity>,
    /// An external worker's last probe.
    probed: WorkerReadiness,
    /// The epoch the current incarnation qualified with, once it has.
    epoch: Option<String>,
    /// The incarnation an abort was asked for; it ends with no drain.
    abort: Option<u64>,
    /// A pressure decision asked for a restartable idle unload.
    unload_requested: bool,
    /// The last physical call receipt and its qualifying epoch, retained after exit.
    last_receipt: Option<(String, InferenceCallReceipt)>,
    /// The latest sanitized lifecycle failure, including prequalification failures.
    failure_detail: Option<WorkerFailureDetail>,
}

struct Inner {
    spec: WorkerSpec,
    launcher: Option<Arc<dyn WorkerLauncher>>,
    probe: Arc<dyn WorkerProbe>,
    policy: WorkerPolicy,
    device: Option<(Arc<DeviceLedger>, DeclaredEnvelope)>,
    admission: Mutex<Option<Arc<DeviceAdmission>>>,
    state: Mutex<State>,
    changed: watch::Sender<u64>,
}

/// One worker's supervisor. Clones share it.
#[derive(Clone)]
pub struct InferenceWorker {
    inner: Arc<Inner>,
}

/// The result of a pressure-requested, restartable idle unload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnloadOutcome {
    Unloaded,
    DeferredDemand,
    ExternalKept,
    NotRunning,
}

/// A held claim on one ready incarnation, from [`InferenceWorker::acquire`]
/// until it drops: hold it through the call's settlement or cancellation.
pub struct WorkerLease {
    inner: Arc<Inner>,
    incarnation: Option<u64>,
    observed: Option<WorkerDescriptor>,
}

impl WorkerLease {
    /// What the incarnation this lease was granted on answered its
    /// qualification with; `None` for an external worker.
    #[must_use]
    pub fn observed(&self) -> Option<&WorkerDescriptor> {
        self.observed.as_ref()
    }

    /// Whether the incarnation this lease was granted on has ended.
    #[must_use]
    pub fn revoked(&self) -> bool {
        self.incarnation
            .is_some_and(|incarnation| self.inner.lock().incarnation != incarnation)
    }

    /// Waits until the incarnation this lease was granted on has ended, for
    /// a lease held while that incarnation still charges a call it could not
    /// release; at once for an external worker's lease.
    pub async fn revocation(&self) {
        if self.incarnation.is_none() {
            return;
        }
        loop {
            let mut changes = self.inner.changed.subscribe();
            if self.revoked() {
                return;
            }
            let _ = changes.changed().await;
        }
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        let Some(incarnation) = self.incarnation else {
            return;
        };
        {
            let mut state = self.inner.lock();
            if state.incarnation == incarnation {
                state.leases = state.leases.saturating_sub(1);
            }
            state.used_at = Some(Instant::now());
        }
        self.inner.notify();
    }
}

/// A caller's registered wait for readiness; withdrawn if the caller goes.
struct Demand {
    inner: Arc<Inner>,
    armed: bool,
}

impl Drop for Demand {
    fn drop(&mut self) {
        if self.armed {
            let mut state = self.inner.lock();
            state.waiting = state.waiting.saturating_sub(1);
        }
    }
}

impl InferenceWorker {
    /// A managed worker's supervisor. Nothing starts until [`Self::start`]
    /// or the first demand. `device` is the ledger its declaration goes in.
    #[must_use]
    pub fn managed(
        spec: WorkerSpec,
        launcher: Arc<dyn WorkerLauncher>,
        probe: Arc<dyn WorkerProbe>,
        policy: WorkerPolicy,
        device: Option<(Arc<DeviceLedger>, DeclaredEnvelope)>,
    ) -> Self {
        Self::new(spec, Some(launcher), probe, policy, device)
    }

    /// Binds this managed worker to its device's admission queue. Existing
    /// constructors leave it `None`, which preserves their current path.
    pub fn with_admission(&self, admission: Arc<DeviceAdmission>) {
        if self.inner.launcher.is_some() {
            *self
                .inner
                .admission
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(admission);
        }
    }

    /// An external worker's supervisor: it probes, and does nothing else.
    #[must_use]
    pub fn external(spec: WorkerSpec, probe: Arc<dyn WorkerProbe>) -> Self {
        Self::new(spec, None, probe, WorkerPolicy::default(), None)
    }

    fn new(
        spec: WorkerSpec,
        launcher: Option<Arc<dyn WorkerLauncher>>,
        probe: Arc<dyn WorkerProbe>,
        policy: WorkerPolicy,
        device: Option<(Arc<DeviceLedger>, DeclaredEnvelope)>,
    ) -> Self {
        let state = State {
            phase: Phase::Stopped,
            driving: false,
            retiring: false,
            waiting: 0,
            incarnation: 0,
            leases: 0,
            used_at: None,
            activity: None,
            probed: WorkerReadiness::Unchecked,
            epoch: None,
            abort: None,
            unload_requested: false,
            last_receipt: None,
            failure_detail: None,
        };
        Self {
            inner: Arc::new(Inner {
                spec,
                launcher,
                probe,
                policy,
                device,
                admission: Mutex::new(None),
                state: Mutex::new(state),
                changed: watch::Sender::new(0),
            }),
        }
    }

    #[must_use]
    pub fn spec(&self) -> &WorkerSpec {
        &self.inner.spec
    }

    /// Starts a stopped managed worker now, as an always-on worker starts at
    /// boot. Nothing for an external worker, one already running, or outside
    /// a Tokio runtime.
    pub fn start(&self) {
        if self.inner.launcher.is_none() || tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let mut state = self.inner.lock();
        if !state.driving && !state.retiring && !matches!(state.phase, Phase::Failed { .. }) {
            state.driving = true;
            tokio::spawn(drive(Arc::clone(&self.inner)));
        }
    }

    /// An external worker's one probe, kept for its status. Nothing for a
    /// managed worker, which its own qualification probes.
    pub async fn probe_once(&self) {
        if self.inner.launcher.is_some() {
            return;
        }
        let readiness = self.inner.probe.probe(&self.inner.spec).await;
        self.inner.lock().probed = readiness;
        self.inner.notify();
    }

    /// Registers this caller's demand, waits for a ready incarnation (one a
    /// stopped worker starts for it), and holds it under the returned lease.
    /// An external worker's lease is granted at once and holds nothing.
    /// Errs only for a parked or retired worker, never for one starting.
    pub async fn acquire(&self) -> Result<WorkerLease, WorkerUnavailable> {
        self.admit(true).await.map(|lease| {
            lease.unwrap_or_else(|| WorkerLease {
                inner: Arc::clone(&self.inner),
                incarnation: None,
                observed: None,
            })
        })
    }

    /// Waits until a managed worker is ready, starting it if it is stopped;
    /// at once for an external one. Errs as [`Self::acquire`] does.
    pub async fn ensure_ready(&self) -> Result<(), WorkerUnavailable> {
        self.admit(false).await.map(drop)
    }

    async fn admit(&self, lease: bool) -> Result<Option<WorkerLease>, WorkerUnavailable> {
        let inner = &self.inner;
        if inner.launcher.is_none() {
            return Ok(None);
        }
        let mut demand: Option<Demand> = None;
        loop {
            let mut changes = inner.changed.subscribe();
            {
                let mut state = inner.lock();
                if state.retiring {
                    return Err(inner.unavailable(WorkerReadiness::Unchecked, "it was retired"));
                }
                let ready = match &state.phase {
                    Phase::Ready(observed) => Some(observed.clone()),
                    Phase::Failed { readiness, reason } => {
                        return Err(inner.unavailable(readiness.clone(), reason));
                    }
                    _ => None,
                };
                if let Some(observed) = ready {
                    if let Some(mut demand) = demand.take() {
                        demand.armed = false;
                        state.waiting = state.waiting.saturating_sub(1);
                    }
                    if !lease {
                        return Ok(None);
                    }
                    state.leases += 1;
                    state.used_at = Some(Instant::now());
                    return Ok(Some(WorkerLease {
                        inner: Arc::clone(inner),
                        incarnation: Some(state.incarnation),
                        observed: Some(observed),
                    }));
                }
                if demand.is_none() {
                    state.waiting += 1;
                    demand = Some(Demand {
                        inner: Arc::clone(inner),
                        armed: true,
                    });
                }
                if !state.driving {
                    state.driving = true;
                    tokio::spawn(drive(Arc::clone(inner)));
                }
            }
            let _ = changes.changed().await;
        }
    }

    /// The worker's status row. `machine` is the host's to fill; metrics no
    /// report gave and the last receipt stay `None`.
    #[must_use]
    pub fn status(&self) -> WorkerStatus {
        let state = self.inner.lock();
        let readiness = if self.inner.launcher.is_none() {
            state.probed.clone()
        } else {
            match &state.phase {
                Phase::Stopped | Phase::IdleStopped | Phase::Draining => WorkerReadiness::Unchecked,
                Phase::Installing | Phase::Starting | Phase::Qualifying | Phase::Backoff => {
                    WorkerReadiness::Starting
                }
                Phase::Ready(observed) => WorkerReadiness::Ready {
                    observed: observed.clone(),
                },
                Phase::Failed { readiness, .. } => readiness.clone(),
            }
        };
        let queue = self.inner.admission().and_then(|admission| {
            admission
                .snapshot()
                .workers
                .remove(&self.inner.spec.worker_id)
        });
        WorkerStatus {
            worker_id: self.inner.spec.worker_id.clone(),
            model: self.inner.spec.model.clone(),
            mode: self.inner.spec.mode,
            machine: None,
            readiness,
            resident_mib: state.activity.and_then(|activity| activity.resident_mib),
            queue_depth: state.activity.map(|activity| activity.queued),
            last_receipt: state
                .last_receipt
                .as_ref()
                .map(|(_, receipt)| receipt.clone()),
            failure_detail: state.failure_detail.clone(),
            host_queued: queue.as_ref().map(|queue| queue.queued),
            host_active: queue.as_ref().map(|queue| queue.active),
            paused: queue.as_ref().map(|queue| queue.paused),
        }
    }

    /// Records what the worker reported it holds, from a report the host
    /// read itself; the supervisor's own polls land here too.
    pub fn report(&self, activity: WorkerActivity) {
        self.inner.note_activity(Some(activity));
    }

    /// Retains one sanitized physical receipt and its epoch after the worker
    /// exits. No status read probes the worker to obtain it.
    pub fn record_receipt(&self, epoch: &str, receipt: InferenceCallReceipt) {
        self.inner.lock().last_receipt = Some((epoch.to_owned(), receipt));
        self.inner.notify();
    }

    /// Asks a ready managed worker to stop through the existing restartable
    /// idle path. Demand or queued/active/paused admission work defers it;
    /// an external worker is never touched.
    pub async fn unload_if_idle(&self) -> UnloadOutcome {
        if self.inner.launcher.is_none() {
            return UnloadOutcome::ExternalKept;
        }
        {
            let mut state = self.inner.lock();
            if !state.driving || !matches!(state.phase, Phase::Ready(_)) {
                return UnloadOutcome::NotRunning;
            }
            if state.leases > 0 || state.waiting > 0 || !self.inner.admission_idle() {
                return UnloadOutcome::DeferredDemand;
            }
            state.unload_requested = true;
        }
        self.inner.notify();
        loop {
            let mut changes = self.inner.changed.subscribe();
            {
                let mut state = self.inner.lock();
                if state.leases > 0 || state.waiting > 0 || !self.inner.admission_idle() {
                    state.unload_requested = false;
                    drop(state);
                    self.inner.notify();
                    return UnloadOutcome::DeferredDemand;
                }
                if matches!(state.phase, Phase::IdleStopped | Phase::Stopped) || !state.driving {
                    state.unload_requested = false;
                    return UnloadOutcome::Unloaded;
                }
            }
            let _ = changes.changed().await;
        }
    }

    /// Aborts the incarnation that qualified with `epoch`, if it is still
    /// the one running: admission closes, its process group is killed and
    /// reaped with no drain, its leases are revoked, and the supervisor
    /// launches the next one at once. Returns once that incarnation has
    /// ended: `true`, or `false` at once when `epoch` names no running
    /// incarnation (it already ended, or never qualified) or the worker is
    /// external. A call through a revoked lease fails as a cut, under its
    /// caller's own retry authority.
    pub async fn abort_incarnation(&self, epoch: &str) -> bool {
        let target = {
            let mut state = self.inner.lock();
            if self.inner.launcher.is_none()
                || !state.driving
                || state.epoch.as_deref() != Some(epoch)
            {
                return false;
            }
            state.abort = Some(state.incarnation);
            state.incarnation
        };
        self.inner.notify();
        loop {
            let mut changes = self.inner.changed.subscribe();
            {
                let state = self.inner.lock();
                if state.incarnation != target || !state.driving {
                    return true;
                }
            }
            let _ = changes.changed().await;
        }
    }

    /// Retires the worker: no lease is granted again, a running managed
    /// worker drains and stops, and this returns once it has.
    pub async fn retire(&self) {
        self.inner.lock().retiring = true;
        self.inner.notify();
        loop {
            let mut changes = self.inner.changed.subscribe();
            if !self.inner.lock().driving {
                return;
            }
            let _ = changes.changed().await;
        }
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn notify(&self) {
        self.changed
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    fn unavailable(&self, readiness: WorkerReadiness, reason: &str) -> WorkerUnavailable {
        WorkerUnavailable {
            worker_id: self.spec.worker_id.clone(),
            readiness,
            reason: Some(reason.to_owned()),
        }
    }

    fn admission(&self) -> Option<Arc<DeviceAdmission>> {
        self.admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn resource_class(&self) -> ResourceClass {
        match self.spec.kind {
            WorkerKind::Embedder => ResourceClass::Embedder,
            WorkerKind::Oneironer => ResourceClass::Encoder,
            WorkerKind::VoxCpm2 => ResourceClass::Tts,
            WorkerKind::Asr => ResourceClass::Asr,
            WorkerKind::LlamaCpp | WorkerKind::Exl3 | WorkerKind::Unknown => ResourceClass::Chat,
        }
    }

    fn admission_idle(&self) -> bool {
        self.admission()
            .is_none_or(|admission| admission.worker_idle(&self.spec.worker_id))
    }

    fn note_activity(&self, activity: Option<WorkerActivity>) {
        self.lock().activity = activity;
        if let (Some((ledger, _)), Some(mib)) = (
            &self.device,
            activity.and_then(|activity| activity.resident_mib),
        ) {
            ledger.report(
                &self.spec.worker_id,
                ResidentReport {
                    resident_mib: mib,
                    source: ResidentSource::WorkerReport,
                    observed_at: SystemTime::now(),
                },
            );
        }
    }
}
