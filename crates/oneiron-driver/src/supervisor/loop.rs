//! Biased-select supervisor loop with panic containment and backoff.
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::wave_dispatch::{WaveDispatchLimits, WaveDispatchPass, WaveDispatchPump};
use oneiron::{
    AttemptQueue, Vault, WakeCancellation, WakePassReport, WakePassStop, WavePlanner, WriteActor,
};
use tokio::sync::{Semaphore, watch};

use super::budget_ids::{
    advance_past_occupied_pass_rows, durable_pass_budget_id, next_pass_budget_index,
};
use super::config::{NowSeconds, RestartBackoff, WakeSupervisorConfig, system_now_secs};
use super::factory::PassExecutorFactory;
use super::pass::{PassRunError, run_one_pass};
use super::shutdown::{ShutdownHandle, ShutdownListener};
use crate::tick::{Tick, TickSource};

/// Supervisor run tally.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WakeSupervisorReport {
    pub passes_completed: u64,
    pub passes_failed: u64,
    pub passes_panicked: u64,
    pub attempts_completed: u64,
    pub attempts_parked: u64,
    /// ONE-1896: attempts that answered a stop by LANDING. Never folded into
    /// `attempts_completed` — a landing delivered no result.
    pub attempts_landed: u64,
}

pub(super) enum PassOutcome {
    Completed(WakePassReport),
    /// Pass ran (or at least crossed admission setup) and returned Err.
    /// The consumed tick is re-driven after backoff (same family as
    /// pre-admission failure / panic / zero-progress).
    Failed(oneiron::Error),
    /// Factory/`run_one_pass` setup failed before any attempt could be admitted.
    /// Re-drives the consumed tick after backoff and **keeps** `pass_index`
    /// (no durable budget row was written). Orthogonal to redrive: only this
    /// arm preserves the index; Failed/Panicked/Completed still advance.
    PreAdmissionFailed(oneiron::Error),
    /// Panic anywhere in the pass (including factory). Re-drives after backoff.
    Panicked,
}

/// True when a completed pass made no durable progress and would otherwise
/// hot-loop under HybridTick deadline redelivery (or leave PushTick work
/// stranded after a consumed wake). Back off + redrive the consumed tick.
fn zero_progress_should_backoff(pass: &WakePassReport) -> bool {
    pass.admitted == 0
        && matches!(
            pass.stop,
            WakePassStop::BudgetExhausted | WakePassStop::DeadlineHardCut
        )
}

/// Resolve operational pump limits from a fresh vault policy snapshot. A
/// host-supplied selector can NARROW, never widen, the vault-owned ceilings.
fn resolved_wave_limits(
    vault: &Vault,
    holder: Option<WaveDispatchLimits>,
) -> oneiron::Result<(WaveDispatchLimits, [u8; 32])> {
    let policy = vault.wave_handoff_policy()?;
    let selected = match holder {
        Some(value) => {
            value.validate()?;
            let mut requested = policy;
            requested.scan_limit = value.page_size;
            requested.retry_floor_ms =
                u64::try_from(value.retry_initial.as_millis()).map_err(|_| {
                    oneiron::Error::InvalidConfig("wave retry floor exceeds u64".into())
                })?;
            requested.retry_cap_ms = u64::try_from(value.retry_max.as_millis())
                .map_err(|_| oneiron::Error::InvalidConfig("wave retry cap exceeds u64".into()))?;
            policy.with_holder(Some(requested))?;
            value
        }
        None => WaveDispatchLimits {
            page_size: policy.scan_limit,
            retry_quantum: policy.scan_limit,
            retry_initial: Duration::from_millis(policy.retry_floor_ms),
            retry_max: Duration::from_millis(policy.retry_cap_ms),
        },
    };
    selected.validate()?;
    Ok((selected, policy.policy_frontier))
}

struct WaveQuantum<'a, F> {
    vault: &'a Vault,
    pump: &'a mut WaveDispatchPump,
    factory: &'a mut F,
    planner: &'a Arc<dyn WavePlanner + Send + Sync>,
    actor: WriteActor,
    lease_owner: &'a str,
    now: u64,
    holder: Option<WaveDispatchLimits>,
    frontier: &'a mut Option<[u8; 32]>,
}

enum WaveQuantumError {
    Policy(oneiron::Error),
    Pump(oneiron::Error),
}

fn run_wave_quantum<F: PassExecutorFactory>(
    input: WaveQuantum<'_, F>,
) -> std::result::Result<WaveDispatchPass, WaveQuantumError> {
    let WaveQuantum {
        vault,
        pump,
        factory,
        planner,
        actor,
        lease_owner,
        now,
        holder,
        frontier,
    } = input;
    let (limits, resolved_frontier) =
        resolved_wave_limits(vault, holder).map_err(WaveQuantumError::Policy)?;
    if *frontier != Some(resolved_frontier) {
        pump.set_limits(limits).map_err(WaveQuantumError::Policy)?;
        *frontier = Some(resolved_frontier);
    }
    pump.work_one(vault, factory, planner, actor, lease_owner, now)
        .map_err(WaveQuantumError::Pump)
}

/// One arbitration decision; each wave pass, notification and ordinary tick
/// returns here rather than running another pre-select work loop.
#[derive(Debug)]
enum SupervisorWake {
    Shutdown,
    Wave,
    Notify,
    Due,
    Tick(Option<Tick>),
}

struct SupervisorEventInputs<'a, T> {
    shutdown: &'a mut ShutdownListener,
    ticks: &'a mut T,
    redrive_tick: Option<Tick>,
    wave_events: &'a mut tokio::sync::broadcast::Receiver<()>,
    wave_enabled: bool,
    wave_ready: bool,
    delay: Option<Duration>,
    prefer_tick: bool,
    ticks_exhausted: bool,
}

async fn next_supervisor_event<T: TickSource>(
    input: SupervisorEventInputs<'_, T>,
) -> SupervisorWake {
    let SupervisorEventInputs {
        shutdown,
        ticks,
        redrive_tick,
        wave_events,
        wave_enabled,
        wave_ready,
        delay,
        prefer_tick,
        ticks_exhausted,
    } = input;
    if prefer_tick {
        tokio::select! {
            biased;
            () = shutdown.triggered() => SupervisorWake::Shutdown,
            tick = async {
                if let Some(tick) = redrive_tick { Some(tick) }
                else { ticks.next_tick().await }
            }, if !ticks_exhausted => SupervisorWake::Tick(tick),
            () = std::future::ready(()), if wave_ready => SupervisorWake::Wave,
            _ = wave_events.recv(), if wave_enabled => SupervisorWake::Notify,
            () = async {
                if let Some(delay) = delay { tokio::time::sleep(delay).await; }
                else { std::future::pending::<()>().await; }
            }, if delay.is_some() => SupervisorWake::Due,
        }
    } else {
        tokio::select! {
            biased;
            () = shutdown.triggered() => SupervisorWake::Shutdown,
            () = std::future::ready(()), if wave_ready => SupervisorWake::Wave,
            tick = async {
                if let Some(tick) = redrive_tick { Some(tick) }
                else { ticks.next_tick().await }
            }, if !ticks_exhausted => SupervisorWake::Tick(tick),
            _ = wave_events.recv(), if wave_enabled => SupervisorWake::Notify,
            () = async {
                if let Some(delay) = delay { tokio::time::sleep(delay).await; }
                else { std::future::pending::<()>().await; }
            }, if delay.is_some() => SupervisorWake::Due,
        }
    }
}

struct PassAccounting<'a> {
    report: &'a mut WakeSupervisorReport,
    pass_index: &'a mut u64,
    backoff: &'a mut RestartBackoff,
    shutdown: &'a mut ShutdownListener,
    redrive_tick: &'a mut Option<Tick>,
}

async fn account_pass_outcome(
    outcome: PassOutcome,
    tick: Tick,
    accounting: PassAccounting<'_>,
) -> bool {
    let PassAccounting {
        report,
        pass_index,
        backoff,
        shutdown,
        redrive_tick,
    } = accounting;
    // RULE: after ANY backoff-taking outcome, re-drive the consumed
    // tick. Outcomes that take backoff: Failed, PreAdmissionFailed,
    // Panicked, and zero-progress Completed (admitted == 0 +
    // BudgetExhausted/DeadlineHardCut). Productive Completed consumes
    // the tick normally (no backoff, no redrive). pass_index: only
    // PreAdmissionFailed preserves it; all other arms advance.
    // Permanent failure = capped-backoff retry forever (same contract
    // as HybridTick redelivery); wait_backoff false → shutdown wins.
    match outcome {
        PassOutcome::Completed(pass) => {
            *pass_index = pass_index.saturating_add(1);
            report.passes_completed += 1;
            report.attempts_completed += u64::from(pass.completed);
            report.attempts_parked += u64::from(pass.parked);
            report.attempts_landed += u64::from(pass.landed);
            // Zero-progress BudgetExhausted / DeadlineHardCut
            // (admitted == 0): HybridTick re-surfaces the same due
            // deadline immediately; PushTick-only has already
            // consumed the wake. Back off + redrive so we never
            // hot-loop empty refusals and never strand due work.
            // Productive BudgetExhausted (admitted > 0) resets
            // backoff and lets the next source tick drain the rest.
            if zero_progress_should_backoff(&pass) {
                tracing::warn!(
                    ?pass.stop,
                    "wake pass stopped without admitting work; \
                     backing off then re-driving tick"
                );
                if !wait_backoff(shutdown, backoff.advance()).await {
                    return false;
                }
                *redrive_tick = Some(tick);
            } else {
                backoff.reset();
            }
        }
        PassOutcome::Failed(error) => {
            // In-pass failure may have admitted/parked some attempts;
            // the same consumed wake can still represent remaining
            // backlog → redrive after backoff (idempotent for Hybrid).
            *pass_index = pass_index.saturating_add(1);
            report.passes_failed += 1;
            tracing::error!(?error, "wake pass failed; backing off then re-driving tick");
            if !wait_backoff(shutdown, backoff.advance()).await {
                return false;
            }
            *redrive_tick = Some(tick);
        }
        PassOutcome::PreAdmissionFailed(error) => {
            // No attempt row mutated and no durable budget row written —
            // keep pass_index; redrive after backoff.
            report.passes_failed += 1;
            tracing::error!(
                ?error,
                "wake pass failed before admission; backing off then re-driving tick"
            );
            if !wait_backoff(shutdown, backoff.advance()).await {
                return false;
            }
            *redrive_tick = Some(tick);
        }
        PassOutcome::Panicked => {
            // Setup panic before admission (or any uncontained panic):
            // redrive after backoff so a PushTick-only host keeps work.
            *pass_index = pass_index.saturating_add(1);
            report.passes_panicked += 1;
            tracing::error!("wake pass panicked; backing off then re-driving tick");
            if !wait_backoff(shutdown, backoff.advance()).await {
                return false;
            }
            *redrive_tick = Some(tick);
        }
    }

    true
}

/// The in-process starter motor: waits on its [`TickSource`], runs at most
/// one wake pass at a time, survives pass panics, and shuts down
/// cooperatively.
pub struct WakeSupervisor<'v, T, F> {
    vault: &'v Vault,
    ticks: T,
    factory: F,
    config: WakeSupervisorConfig,
    shutdown_handle: ShutdownHandle,
    shutdown: ShutdownListener,
    pass_gate: Arc<Semaphore>,
    now_secs: NowSeconds,
    wave_limits: Option<WaveDispatchLimits>,
}

impl<'v, T, F> WakeSupervisor<'v, T, F>
where
    T: TickSource,
    F: PassExecutorFactory,
{
    #[must_use]
    pub fn new(vault: &'v Vault, ticks: T, factory: F, config: WakeSupervisorConfig) -> Self {
        let (tx, rx) = watch::channel(false);
        let linked = factory.linked_shutdown();
        Self {
            vault,
            ticks,
            factory,
            config,
            shutdown_handle: ShutdownHandle {
                tx,
                linked: linked.clone(),
            },
            shutdown: ShutdownListener { rx, linked },
            pass_gate: Arc::new(Semaphore::new(1)),
            now_secs: Arc::new(system_now_secs),
            wave_limits: None,
        }
    }

    /// The handle a host uses to request a graceful stop.
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.shutdown_handle.clone()
    }

    /// Shares a pass gate across supervisors over the same vault so at most
    /// one wake pass runs vault-wide.
    #[must_use]
    pub fn with_pass_gate(mut self, gate: Arc<Semaphore>) -> Self {
        self.pass_gate = gate;
        self
    }

    /// Injects the wall clock used for [`RunWakePass::now`](oneiron::RunWakePass::now) (tests).
    #[must_use]
    pub fn with_clock(mut self, now_secs: NowSeconds) -> Self {
        self.now_secs = now_secs;
        self
    }

    /// Injects resolved operational page/retry ceilings for the wave pump.
    #[must_use]
    pub fn with_wave_dispatch_limits(mut self, limits: WaveDispatchLimits) -> Self {
        self.wave_limits = Some(limits);
        self
    }

    /// Runs the supervisor loop until shutdown or tick-source exhaustion.
    pub async fn run(self) -> WakeSupervisorReport {
        let Self {
            vault,
            mut ticks,
            mut factory,
            config,
            shutdown_handle,
            mut shutdown,
            pass_gate,
            now_secs,
            wave_limits,
        } = self;
        // Keep the supervisor's own handle alive so a host-less run idles
        // on "not requested" instead of erroring the watch channel.
        let _shutdown_handle = shutdown_handle;

        let mut report = WakeSupervisorReport::default();
        // An over-long base id would make every derived per-pass id fail the
        // runner store's validation: the startup scan reads those errors as
        // "occupied" and admission fails every pass, redelivering due work
        // forever. No pass can ever succeed, so stop before ticking.
        if let Err(error) = config.validate() {
            tracing::error!(?error, "wake supervisor config invalid; refusing to run");
            return report;
        }
        let mut backoff = RestartBackoff::new(config.backoff);
        // Resume the per-pass durable budget sequence after the highest
        // occupied `{base}:p{n}` row (dense scan + gallop past the bound).
        // One full probe at run start only — not progress, not a rescan
        // per pass — so a process restart does not re-mint spent p0/p1/…
        // rows or advance into a later occupied suffix after filling an
        // earlier hole (empty passes leave no budget row).
        let mut pass_index = next_pass_budget_index(vault, &config.budget_id);
        // PushTick drains a wake before the pass runs. Any backoff-taking
        // outcome re-drives that same tick after wait_backoff so a
        // push-only host does not lose remaining backlog (or the only wake).
        // HybridTick deadline redelivery makes redrive idempotent there.
        let mut redrive_tick: Option<Tick> = None;
        // Subscribe before the startup scan: a concurrent enqueue can neither
        // disappear between snapshot and receiver nor need a polling timer.
        let mut wave_events = AttemptQueue::new(vault).subscribe();
        let wave_planner = factory.wave_planner();
        if wave_planner.is_some() && factory.actor().is_none() {
            tracing::error!("wave planner requires an authenticated factory actor");
            return report;
        }
        let mut wave_policy_frontier = None;
        let mut wave = if wave_planner.is_some() {
            match resolved_wave_limits(vault, wave_limits) {
                Ok((limits, frontier)) => {
                    wave_policy_frontier = Some(frontier);
                    Some(WaveDispatchPump::new(limits))
                }
                Err(error) => {
                    tracing::error!(
                        ?error,
                        "wave operational policy invalid; refusing supervisor"
                    );
                    return report;
                }
            }
        } else {
            None
        };
        let mut prefer_tick = false;
        let mut ticks_exhausted = false;

        loop {
            // A single arbiter for plans, bounded pages, retries, ordinary
            // passes, notifications and shutdown. Alternate ready wave work
            // and ready ticks; a hot notification stream cannot pin either.
            let wave_ready = wave.as_ref().is_some_and(WaveDispatchPump::ready);
            let delay = wave.as_ref().and_then(|pump| pump.next_delay(now_secs()));
            let wake = next_supervisor_event(SupervisorEventInputs {
                shutdown: &mut shutdown,
                ticks: &mut ticks,
                redrive_tick,
                wave_events: &mut wave_events,
                wave_enabled: wave_planner.is_some(),
                wave_ready,
                delay,
                prefer_tick,
                ticks_exhausted,
            })
            .await;
            let tick = match wake {
                SupervisorWake::Shutdown => break,
                SupervisorWake::Wave => {
                    prefer_tick = true;
                    if let (Some(planner), Some(actor), Some(pump)) =
                        (wave_planner.as_ref(), factory.actor(), wave.as_mut())
                    {
                        match run_wave_quantum(WaveQuantum {
                            vault,
                            pump,
                            factory: &mut factory,
                            planner,
                            actor,
                            lease_owner: &config.lease_owner,
                            now: now_secs(),
                            holder: wave_limits,
                            frontier: &mut wave_policy_frontier,
                        }) {
                            Ok(pass) => {
                                tracing::trace!(progressed = pass.progressed,
                                    cursor = ?pass.next_cursor, retry = ?pass.earliest_retry,
                                    "wave dispatch pass");
                                for failure in pass.item_failures {
                                    tracing::warn!(task = ?failure.candidate.task,
                                        reason = %failure.reason, "wave handoff deferred");
                                }
                            }
                            Err(WaveQuantumError::Policy(error)) => {
                                tracing::error!(?error, "wave operational policy invalid");
                                return report;
                            }
                            Err(WaveQuantumError::Pump(error)) => {
                                tracing::error!(?error, "wave pump pass failed");
                            }
                        }
                    }
                    tokio::task::yield_now().await;
                    continue;
                }
                SupervisorWake::Notify => {
                    if let Some(pump) = wave.as_mut() {
                        pump.notify();
                    }
                    continue;
                }
                SupervisorWake::Due => {
                    if let Some(pump) = wave.as_mut() {
                        pump.on_timer(now_secs());
                    }
                    continue;
                }
                SupervisorWake::Tick(None) => {
                    ticks_exhausted = true;
                    if wave_planner.is_none() {
                        break;
                    }
                    continue;
                }
                SupervisorWake::Tick(Some(tick)) => {
                    redrive_tick = None;
                    prefer_tick = false;
                    tick
                }
            };

            // At most ONE pass in flight, ever — even with a shared gate.
            let permit = tokio::select! {
                biased;
                () = shutdown.triggered() => break,
                permit = pass_gate.acquire() => match permit {
                    Ok(permit) => permit,
                    Err(_closed) => break,
                },
            };
            // One point-read per pass: the startup probe is an optimization,
            // not a guarantee — an empty-pass hole below a still-occupied
            // higher suffix (possible past the gallop window) must never be
            // filled and then advance onto a spent row the store would
            // silently reuse. Skipping occupied rows here kills that whole
            // class for the cost of a budget lookup.
            pass_index = advance_past_occupied_pass_rows(vault, &config.budget_id, pass_index);
            let pass_budget_id = durable_pass_budget_id(&config.budget_id, pass_index);
            let outcome = run_pass_supervised(
                vault,
                &config,
                &pass_budget_id,
                &now_secs,
                &mut factory,
                &mut shutdown,
                &tick,
            )
            .await;
            drop(permit);

            if !account_pass_outcome(
                outcome,
                tick,
                PassAccounting {
                    report: &mut report,
                    pass_index: &mut pass_index,
                    backoff: &mut backoff,
                    shutdown: &mut shutdown,
                    redrive_tick: &mut redrive_tick,
                },
            )
            .await
            {
                break;
            }

            if shutdown.requested() {
                break;
            }
        }

        report
    }
}

/// Runs one pass panic-caught and cooperatively cancellable: a shutdown
/// arriving mid-pass raises the pass's [`WakeCancellation`] flag and keeps
/// awaiting — the pass future is NEVER dropped mid-await (H-S5/R2), so a
/// gated write or off-record close in progress always runs to its boundary.
///
/// Factory/`Result` failures before `run_wake_pass` surface as
/// [`PassOutcome::PreAdmissionFailed`] so the supervisor can re-drive the
/// tick; panics anywhere in the pass still map to [`PassOutcome::Panicked`].
pub(super) async fn run_pass_supervised<F: PassExecutorFactory>(
    vault: &Vault,
    config: &WakeSupervisorConfig,
    pass_budget_id: &str,
    now_secs: &NowSeconds,
    factory: &mut F,
    shutdown: &mut ShutdownListener,
    tick: &Tick,
) -> PassOutcome {
    let cancel = WakeCancellation::new();
    let mut pass = CatchUnwind::new(run_one_pass(
        vault,
        config,
        pass_budget_id,
        now_secs,
        factory,
        tick,
        &cancel,
    ));
    loop {
        tokio::select! {
            biased;
            () = shutdown.triggered(), if !cancel.is_cancelled() => {
                // Cooperative preemption: flag only. The loop continues and
                // the next iteration awaits the pass to completion (this
                // branch disables itself once the flag is up).
                cancel.cancel();
            }
            result = &mut pass => {
                return match result {
                    Ok(Ok(pass_report)) => PassOutcome::Completed(pass_report),
                    Ok(Err(PassRunError::PreAdmission(error))) => {
                        PassOutcome::PreAdmissionFailed(error)
                    }
                    Ok(Err(PassRunError::Failed(error))) => PassOutcome::Failed(error),
                    Err(_panic) => PassOutcome::Panicked,
                };
            }
        }
    }
}

/// One-shot restart delay. NOT a heartbeat: it defers consuming the next
/// already-signalled tick after a failed pass; it never generates a wakeup
/// of its own. Returns false when shutdown fires during the wait.
async fn wait_backoff(shutdown: &mut ShutdownListener, delay: Duration) -> bool {
    tokio::select! {
        biased;
        () = shutdown.triggered() => false,
        () = tokio::time::sleep(delay) => true,
    }
}

/// Converts a panicking poll into a value so one exploding pass cannot take
/// the supervisor down. Boxes the inner future — no unsafe pin projection.
struct CatchUnwind<Fut> {
    inner: Pin<Box<Fut>>,
}

impl<Fut> CatchUnwind<Fut> {
    fn new(inner: Fut) -> Self {
        Self {
            inner: Box::pin(inner),
        }
    }
}

impl<Fut: Future> Future for CatchUnwind<Fut> {
    type Output = std::thread::Result<Fut::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // `Pin<Box<Fut>>` is Unpin, so plain mutable access is sound.
        let this = self.get_mut();
        let inner = this.inner.as_mut();
        match std::panic::catch_unwind(AssertUnwindSafe(|| inner.poll(cx))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(panic) => Poll::Ready(Err(panic)),
        }
    }
}
