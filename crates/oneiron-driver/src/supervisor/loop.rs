//! The supervisor loop: one arbiter over fresh ticks, owed retries and wave
//! quanta (see `arbiter`), at most one pass in flight, panic containment and
//! per-tick backoff (see `retry`).
use std::sync::Arc;

use crate::wave_dispatch::{WaveDispatchLimits, WaveDispatchPump};
use oneiron::{AttemptQueue, Vault};
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;

use super::arbiter::{
    Lane, LaneRotation, SupervisorEventInputs, SupervisorWake, next_supervisor_event,
};
use super::budget_ids::{
    advance_past_occupied_pass_rows, durable_pass_budget_id, next_pass_budget_index,
};
use super::config::{NowSeconds, WakeSupervisorConfig, system_now_secs};
use super::factory::PassExecutorFactory;
use super::pass::paused;
use super::retry::{FreshTick, PassAccounting, RetryDebt, account_pass_outcome};
use super::shutdown::{ShutdownHandle, ShutdownListener};
use super::supervised_pass::run_pass_supervised;
use super::wave_lane::{
    WaveQuantum, WaveQuantumError, report_wave_pass, resolved_wave_limits, run_wave_quantum,
};
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

    /// Runs the supervisor loop until shutdown, or until the tick source runs
    /// dry with no wave planner registered and no owed pass left.
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
        // Resume the per-pass durable budget sequence after the highest
        // occupied `{base}:p{n}` row (dense scan + gallop past the bound).
        // One full probe at run start only — not progress, not a rescan
        // per pass — so a process restart does not re-mint spent p0/p1/…
        // rows or advance into a later occupied suffix after filling an
        // earlier hole (empty passes leave no budget row).
        let mut pass_index = next_pass_budget_index(vault, &config.budget_id);
        // PushTick drains a wake before the pass runs. A tick a pass did not
        // settle is owed here on its own backoff (FIX 8601), so a push-only
        // host does not lose remaining backlog (or the only wake), and a
        // failing tick never stops the source, the other owed ticks or the
        // wave lane. HybridTick deadline redelivery makes the retry
        // idempotent there.
        let mut debt = RetryDebt::new(config.backoff);
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
        let mut rotation = LaneRotation::new();
        let mut ticks_exhausted = false;
        // While the source keeps redelivering a deadline whose owed retry is
        // not yet due, its deadline lane rests until that retry and its
        // pushes keep flowing (FIX 11403): reading the deadline sooner only
        // returns it again. A source that cannot rest that lane alone rests
        // whole here instead.
        let mut source_rests_until: Option<Instant> = None;

        loop {
            // While the host's pause holds (FIX 6909) the loop reads no
            // tick, so no deadline arms and no pass starts; an owed tick
            // waits for the pause to lift.
            if !wait_unpaused(&factory, &mut shutdown).await {
                break;
            }
            // The source running dry ends the run only once nothing is owed
            // and no wave planner can bring more work.
            if ticks_exhausted && wave_planner.is_none() && debt.is_empty() {
                break;
            }
            let now = Instant::now();
            if source_rests_until.is_some_and(|until| until <= now) {
                source_rests_until = None;
            }
            let wave_ready = wave.as_ref().is_some_and(WaveDispatchPump::ready);
            let delay = [
                wave.as_ref().and_then(|pump| pump.next_delay(now_secs())),
                debt.next_due()
                    .map(|due| due.saturating_duration_since(now)),
                source_rests_until.map(|until| until.saturating_duration_since(now)),
            ]
            .into_iter()
            .flatten()
            .min();
            let wake = next_supervisor_event(SupervisorEventInputs {
                shutdown: &mut shutdown,
                ticks: &mut ticks,
                wave_events: &mut wave_events,
                wave_enabled: wave_planner.is_some(),
                source_open: !ticks_exhausted && source_rests_until.is_none(),
                retry_ready: debt.ready(now),
                wave_ready,
                delay,
                rotation,
            })
            .await;
            let owed = match wake {
                SupervisorWake::Shutdown => break,
                SupervisorWake::Wave => {
                    rotation.served(Lane::Wave);
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
                            Ok(pass) => report_wave_pass(pass),
                            Err(WaveQuantumError::Policy(error)) => {
                                tracing::error!(?error, "wave operational policy invalid");
                                return report;
                            }
                            Err(WaveQuantumError::Pump(error)) => {
                                tracing::error!(kind = ?error.kind(), "wave pump pass failed");
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
                SupervisorWake::Retry => {
                    rotation.served(Lane::Retry);
                    let Some(owed) = debt.take_ready(Instant::now()) else {
                        continue;
                    };
                    owed
                }
                SupervisorWake::Tick(None) => {
                    ticks_exhausted = true;
                    continue;
                }
                SupervisorWake::Tick(Some(tick)) => {
                    rotation.served(Lane::Source);
                    match debt.fresh(tick, Instant::now()) {
                        FreshTick::Run(owed) => owed,
                        // The owed pass covers this tick. A push was consumed
                        // by its read and rests nothing; a deadline comes back
                        // on every read, so its lane rests until the retry.
                        FreshTick::Owed(due) => {
                            if matches!(tick, Tick::Deadline(_)) && !ticks.rest_deadlines(Some(due))
                            {
                                source_rests_until = Some(due);
                            }
                            continue;
                        }
                    }
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
            // A pause that began while the tick or the permit was awaited
            // holds the tick, owed, until it lifts (FIX 6909).
            if paused(factory.pass_pause().as_ref()) {
                drop(permit);
                debt.owe_now(owed);
                continue;
            }
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
                &owed.tick,
            )
            .await;
            drop(permit);

            account_pass_outcome(
                outcome,
                owed,
                PassAccounting {
                    report: &mut report,
                    pass_index: &mut pass_index,
                    debt: &mut debt,
                },
            );
            // The debt changed: the source reads again, and a deadline it
            // still redelivers rests behind its owed retry once more.
            source_rests_until = None;
            ticks.rest_deadlines(None);

            if shutdown.requested() {
                break;
            }
        }

        report
    }
}

/// Waits while the host's pause holds (FIX 6909), reading each epoch afresh:
/// lifting the pause closes the epoch it held. It sleeps on the watch alone,
/// with no timer. Returns false when shutdown fires first.
async fn wait_unpaused<F: PassExecutorFactory>(
    factory: &F,
    shutdown: &mut ShutdownListener,
) -> bool {
    loop {
        let Some(mut pause) = factory.pass_pause() else {
            return true;
        };
        if !*pause.borrow() {
            return true;
        }
        tokio::select! {
            biased;
            () = shutdown.triggered() => return false,
            _ = pause.wait_for(|held| !*held) => {}
        }
    }
}
