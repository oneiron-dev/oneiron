//! Process readiness (L8-11; runtime `#provider-health`, decision
//! `scour:S25`): a state machine over this process's event loop, moved by a
//! watchdog, read by `/api/health`, the managed `Ping` and the intake gate.
//!
//! - **The machine** ([`ReadinessMachine`]): `ready`, `degraded`,
//!   `recovering`, `draining`. Lag at or over the threshold marks the
//!   process degraded; a sustained hang (no probe sample for the hang
//!   threshold) drains it; the first sample after the hang starts its
//!   recovery; and only a stabilization window of clean samples makes a
//!   degraded or recovering process ready again.
//! - **The watchdog** ([`ProcessWatchdog`]): a probe task on the serving
//!   runtime, whose scheduling delay at each tick is the event-loop lag, and
//!   one OS thread that sees the probe go silent. A hung runtime cannot run
//!   its own detector, so the hang check lives off it.
//! - **The intake gate** ([`refuse_new_work_while_not_ready`]): when the
//!   watchdog sheds intake (managed serve, canon's "Oneiron Cloud vault
//!   processes"), a draining or recovering process answers every new request
//!   but `GET /api/health` with a typed 503 and `Retry-After`. Requests it
//!   already admitted run to their end. Plain serve reports and sheds
//!   nothing; embedded serve starts no watchdog and stays ready.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use oneiron_vault_contract::{ProcessReadinessReport, ProcessState};

use crate::error::ApiError;

/// The one route a process that sheds intake still answers: it says why.
const HEALTH_PATH: &str = "/api/health";

// The Engine's shipped defaults (L8-11, figures A), not owner rulings: the
// runtime page's provider-health figures are the precedent.
/// How often the probe ticks on the serving runtime.
const PROBE_INTERVAL: Duration = Duration::from_millis(250);
/// A probe sample this late or later marks the process degraded.
const LAG_THRESHOLD: Duration = Duration::from_millis(500);
/// No probe sample for this long is a sustained hang: the process drains.
const HANG_THRESHOLD: Duration = Duration::from_secs(5);
/// Clean samples for this long make a degraded or recovering process ready.
/// The same 30 s a recovering provider offer needs before its recovery is
/// stable (`models::cooldown`).
const STABILIZATION_WINDOW: Duration = Duration::from_secs(30);

/// The watchdog's figures and whether a not-ready process refuses new work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessHealthSettings {
    /// How often the probe ticks on the serving runtime.
    pub probe_interval: Duration,
    /// A probe sample this late or later marks the process degraded.
    pub lag_threshold: Duration,
    /// No probe sample for this long drains the process.
    pub hang_threshold: Duration,
    /// Clean samples for this long make the process ready again.
    pub stabilization_window: Duration,
    /// Whether a draining or recovering process refuses new work. Only
    /// managed serve sheds; elsewhere the state is reported only.
    pub sheds_intake: bool,
}

impl Default for ProcessHealthSettings {
    /// The Engine's figures, reporting only: plain serve's watchdog.
    fn default() -> Self {
        Self {
            probe_interval: PROBE_INTERVAL,
            lag_threshold: LAG_THRESHOLD,
            hang_threshold: HANG_THRESHOLD,
            stabilization_window: STABILIZATION_WINDOW,
            sheds_intake: false,
        }
    }
}

impl ProcessHealthSettings {
    /// The Engine's figures, shedding intake: a managed vault's watchdog.
    #[must_use]
    pub fn managed() -> Self {
        Self {
            sheds_intake: true,
            ..Self::default()
        }
    }
}

/// The readiness rules over explicit instants, so they hold without timers.
#[derive(Clone, Debug)]
pub struct ReadinessMachine {
    probe_interval: Duration,
    lag_threshold: Duration,
    hang_threshold: Duration,
    stabilization_window: Duration,
    state: ProcessState,
    /// When the probe last reported, or when the watchdog last forgave a
    /// stop of the whole process.
    last_sample_at: Instant,
    last_lag: Duration,
    /// The first clean sample of the current run of clean samples, while the
    /// process is degraded or recovering.
    clean_since: Option<Instant>,
}

impl ReadinessMachine {
    /// A ready process whose silence counts from `now`.
    #[must_use]
    pub fn new(settings: &ProcessHealthSettings, now: Instant) -> Self {
        Self {
            probe_interval: settings.probe_interval,
            lag_threshold: settings.lag_threshold,
            hang_threshold: settings.hang_threshold,
            stabilization_window: settings.stabilization_window,
            state: ProcessState::Ready,
            last_sample_at: now,
            last_lag: Duration::ZERO,
            clean_since: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> ProcessState {
        self.state
    }

    /// The lag of the last probe sample.
    #[must_use]
    pub const fn last_lag(&self) -> Duration {
        self.last_lag
    }

    /// One probe sample at `now`, `lag` after its tick was due.
    ///
    /// Ready goes degraded on a lagging sample. Draining goes recovering on
    /// any sample: the hang ended. Degraded and recovering go ready once
    /// their clean samples span a stabilization window; a lagging sample
    /// restarts the window and keeps the state.
    pub fn observe_sample(&mut self, now: Instant, lag: Duration) {
        self.last_sample_at = now;
        self.last_lag = lag;
        let clean = lag < self.lag_threshold;
        self.state = match self.state {
            ProcessState::Ready if clean => ProcessState::Ready,
            ProcessState::Ready => {
                self.clean_since = None;
                ProcessState::Degraded
            }
            ProcessState::Draining => {
                self.clean_since = clean.then_some(now);
                ProcessState::Recovering
            }
            held @ (ProcessState::Degraded | ProcessState::Recovering) if !clean => {
                self.clean_since = None;
                held
            }
            held @ (ProcessState::Degraded | ProcessState::Recovering) => {
                let since = *self.clean_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= self.stabilization_window {
                    self.clean_since = None;
                    ProcessState::Ready
                } else {
                    held
                }
            }
        };
    }

    /// The watchdog thread's check at `now`, `since_last_check` after its
    /// previous one. No probe sample for the hang threshold drains the
    /// process, from any state.
    ///
    /// A check that itself comes a hang threshold past its own interval
    /// means the whole process was stopped (a frozen cgroup, a paused VM, a
    /// stop signal), not its event loop: the probe's silence then counts from
    /// `now`, and the process does not drain for it.
    pub fn observe_watchdog_check(&mut self, now: Instant, since_last_check: Duration) {
        if since_last_check.saturating_sub(self.probe_interval) >= self.hang_threshold {
            self.last_sample_at = now;
            return;
        }
        if self.state != ProcessState::Draining
            && now.saturating_duration_since(self.last_sample_at) >= self.hang_threshold
        {
            self.state = ProcessState::Draining;
            self.clean_since = None;
        }
    }

    /// How long a refused caller should wait at `now`: what is left of the
    /// stabilization window, the whole window while it has not started, and
    /// never under one second.
    #[must_use]
    pub fn retry_after(&self, now: Instant) -> Duration {
        let left = match (self.state, self.clean_since) {
            (ProcessState::Ready | ProcessState::Degraded, _) => Duration::ZERO,
            (ProcessState::Recovering, Some(since)) => self
                .stabilization_window
                .saturating_sub(now.saturating_duration_since(since)),
            (ProcessState::Recovering | ProcessState::Draining, _) => self.stabilization_window,
        };
        left.max(Duration::from_secs(1))
    }
}

/// This process's readiness: the machine, and its state mirrored for
/// lock-free reads by the health route and the intake gate.
#[derive(Debug)]
pub struct ProcessReadiness {
    machine: Mutex<ReadinessMachine>,
    state: AtomicU8,
    lag_ms: AtomicU64,
    sheds_intake: AtomicBool,
}

impl Default for ProcessReadiness {
    /// Ready, shedding nothing, with no watchdog moving it.
    fn default() -> Self {
        Self {
            machine: Mutex::new(ReadinessMachine::new(
                &ProcessHealthSettings::default(),
                Instant::now(),
            )),
            state: AtomicU8::new(state_code(ProcessState::Ready)),
            lag_ms: AtomicU64::new(0),
            sheds_intake: AtomicBool::new(false),
        }
    }
}

impl ProcessReadiness {
    /// The state as the watchdog last moved it.
    #[must_use]
    pub fn state(&self) -> ProcessState {
        state_from_code(self.state.load(Ordering::Acquire))
    }

    /// What the managed `Ping` reports: the state and the last sample's lag.
    #[must_use]
    pub fn report(&self) -> ProcessReadinessReport {
        ProcessReadinessReport {
            state: self.state(),
            lag_ms: self.lag_ms.load(Ordering::Relaxed),
        }
    }

    /// The refusal a new request gets now, as its state and the seconds to
    /// wait: only while the watchdog sheds intake and the process drains or
    /// recovers.
    fn intake_refusal(&self) -> Option<(ProcessState, u64)> {
        if !self.sheds_intake.load(Ordering::Acquire)
            || !matches!(
                self.state(),
                ProcessState::Draining | ProcessState::Recovering
            )
        {
            return None;
        }
        let machine = self.machine.lock().unwrap_or_else(PoisonError::into_inner);
        let state = machine.state();
        if !matches!(state, ProcessState::Draining | ProcessState::Recovering) {
            return None;
        }
        Some((state, whole_seconds_up(machine.retry_after(Instant::now()))))
    }

    /// A fresh machine on `settings`, ready, its silence counted from now.
    fn restart(&self, settings: &ProcessHealthSettings) {
        let mut machine = self.machine.lock().unwrap_or_else(PoisonError::into_inner);
        *machine = ReadinessMachine::new(settings, Instant::now());
        self.sheds_intake
            .store(settings.sheds_intake, Ordering::Release);
        self.publish(&machine, ProcessState::Ready);
    }

    fn observe_sample(&self, now: Instant, lag: Duration) {
        let mut machine = self.machine.lock().unwrap_or_else(PoisonError::into_inner);
        let before = machine.state();
        machine.observe_sample(now, lag);
        self.publish(&machine, before);
    }

    fn observe_watchdog_check(&self, now: Instant, since_last_check: Duration) {
        let mut machine = self.machine.lock().unwrap_or_else(PoisonError::into_inner);
        let before = machine.state();
        machine.observe_watchdog_check(now, since_last_check);
        self.publish(&machine, before);
    }

    /// Mirrors `machine` for lock-free readers, and logs a move from
    /// `before`.
    fn publish(&self, machine: &ReadinessMachine, before: ProcessState) {
        let lag_ms = u64::try_from(machine.last_lag().as_millis()).unwrap_or(u64::MAX);
        self.lag_ms.store(lag_ms, Ordering::Relaxed);
        let state = machine.state();
        self.state.store(state_code(state), Ordering::Release);
        if state == before {
            return;
        }
        let (from, to) = (before.as_str(), state.as_str());
        match state {
            ProcessState::Ready => tracing::info!(from, to, lag_ms, "process readiness moved"),
            ProcessState::Degraded | ProcessState::Recovering | ProcessState::Draining => {
                tracing::warn!(from, to, lag_ms, "process readiness moved");
            }
        }
    }
}

const fn state_code(state: ProcessState) -> u8 {
    match state {
        ProcessState::Ready => 0,
        ProcessState::Degraded => 1,
        ProcessState::Recovering => 2,
        ProcessState::Draining => 3,
    }
}

const fn state_from_code(code: u8) -> ProcessState {
    match code {
        0 => ProcessState::Ready,
        1 => ProcessState::Degraded,
        2 => ProcessState::Recovering,
        _ => ProcessState::Draining,
    }
}

/// `duration` in whole seconds, rounded up.
fn whole_seconds_up(duration: Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
}

/// The running watchdog: its probe task and its hang-check thread. Dropping
/// it stops both and joins the thread; the readiness then stays as they last
/// moved it.
#[must_use = "dropping the watchdog stops it"]
#[derive(Debug)]
pub struct ProcessWatchdog {
    probe: Option<tokio::task::JoinHandle<()>>,
    stop: Option<mpsc::Sender<()>>,
    checker: Option<std::thread::JoinHandle<()>>,
}

impl ProcessWatchdog {
    /// Starts the probe on the calling Tokio runtime, which must be the one
    /// that serves the app, and the hang check on a thread of its own,
    /// after a fresh machine on `settings`. A hang-check thread that does not
    /// start leaves no watchdog: the readiness stays ready, and the error is
    /// logged.
    pub(crate) fn start(
        readiness: &Arc<ProcessReadiness>,
        settings: ProcessHealthSettings,
    ) -> Self {
        readiness.restart(&settings);
        let (stop, stopped) = mpsc::channel::<()>();
        let checked = Arc::clone(readiness);
        let checker = std::thread::Builder::new()
            .name("oneiron-readiness-watchdog".to_owned())
            .spawn(move || check_for_hangs(&checked, settings.probe_interval, &stopped));
        let checker = match checker {
            Ok(checker) => checker,
            Err(error) => {
                tracing::error!(%error, "the process watchdog did not start; process readiness stays ready");
                return Self {
                    probe: None,
                    stop: None,
                    checker: None,
                };
            }
        };
        let probed = Arc::clone(readiness);
        let probe: tokio::task::JoinHandle<()> = tokio::spawn(async move {
            let mut ticks = tokio::time::interval(settings.probe_interval);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let due = ticks.tick().await;
                let lag = tokio::time::Instant::now().saturating_duration_since(due);
                probed.observe_sample(Instant::now(), lag);
            }
        });
        Self {
            probe: Some(probe),
            stop: Some(stop),
            checker: Some(checker),
        }
    }
}

impl Drop for ProcessWatchdog {
    fn drop(&mut self) {
        if let Some(probe) = self.probe.take() {
            probe.abort();
        }
        // A dropped sender wakes the thread at once.
        drop(self.stop.take());
        if let Some(checker) = self.checker.take()
            && checker.join().is_err()
        {
            tracing::warn!("the process watchdog's hang check panicked");
        }
    }
}

/// The hang check: every probe interval until `stopped` disconnects, tell
/// the machine how long since this thread's previous check.
fn check_for_hangs(readiness: &ProcessReadiness, interval: Duration, stopped: &mpsc::Receiver<()>) {
    let mut last_check = Instant::now();
    loop {
        match stopped.recv_timeout(interval) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
        }
        let now = Instant::now();
        readiness.observe_watchdog_check(now, now.saturating_duration_since(last_check));
        last_check = now;
    }
}

/// The intake gate: while the watchdog sheds intake and the process drains
/// or recovers, a new request gets a 503 `PROCESS_NOT_READY` with
/// `Retry-After`, a connection upgrade too. `GET /api/health` always passes,
/// and so does every request while the process is ready or degraded. It acts
/// at admission only and reads no vault, so it sits ahead of auth.
pub(crate) async fn refuse_new_work_while_not_ready(
    State(readiness): State<Arc<ProcessReadiness>>,
    request: Request,
    next: Next,
) -> Response {
    let health = request.method() == Method::GET && request.uri().path() == HEALTH_PATH;
    if !health && let Some((state, retry_after_secs)) = readiness.intake_refusal() {
        let mut reply = ApiError::process_not_ready(state, retry_after_secs).into_response();
        reply
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from(retry_after_secs));
        return reply;
    }
    next.run(request).await
}
