//! The wake-pass supervisor (ONE-1683): a plain `tokio::select!` loop that
//! pumps [`DreamerWakeDriver::run_wake_pass`] — the starter motor the engine
//! deliberately does not own.
//!
//! Shape (all acceptance-pinned):
//!
//! * ONE biased select composes the loop: shutdown beats a ready tick, and
//!   the tick source itself resolves deadline-vs-push priority (deadline
//!   wins — see [`HybridTick`](crate::HybridTick)).
//! * A `tokio::sync::Semaphore(1)` serializes passes: a second tick arriving
//!   mid-pass can never start a second pass (share the gate across
//!   supervisors over one vault via [`WakeSupervisor::with_pass_gate`]).
//! * Panic containment is layered: the ENGINE contains an `exec.execute`
//!   panic at the job boundary (the job is parked, its reservation
//!   refunded, and the pass fails cleanly), and a panic anywhere else in a
//!   pass is caught HERE as the backstop — either way the supervisor
//!   restarts with backoff, never crashes.
//! * Shutdown mid-pass is COOPERATIVE (H-S5/R2): the supervisor raises the
//!   pass's [`WakeCancellation`] flag and KEEPS AWAITING the pass future —
//!   it is never dropped mid-await, so an in-flight gated write or
//!   off-record close is never aborted. The pass stops itself at its
//!   job-boundary checkpoints, parking + refunding anything it had admitted.
//! * Budget admission stays entirely INSIDE `run_wake_pass`: this crate
//!   never calls `admit_next_consolidation` / `settle_budget` /
//!   `abort_budget_reservation`.
//! * No actor framework, no job-worker crate, no heartbeat: the loop only
//!   ever wakes for a [`Tick`] (a job-queue deadline read or an
//!   authenticated push) — plus a bounded one-shot delay after a FAILED
//!   pass, which defers consuming the next already-signalled tick rather
//!   than generating wakeups of its own.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, ConsolidationExecutor, ConsolidationSink,
    DEFAULT_DREAMER_CHILD_RESERVE_UNITS, DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS,
    DreamerClaimAuthoringStrategy, DreamerConsolidationScope, DreamerJobExecutor,
    DreamerWakeDriver, LlmBackend, ModelId, Result, RunWakePass, Vault, WakeCancellation,
    WakeMilestoneAuthor, WakePassDeadline, WakePassReport, WakePassStop, WakeTrigger, WriteActor,
};
use oneiron_llm_local::{LocalLlmBackend, LocalLlmRuntime};
use tokio::sync::{Semaphore, watch};

use crate::tick::{Tick, TickSource};

/// Second-resolution wall-clock read for [`RunWakePass::now`], injectable
/// for tests.
pub type NowSeconds = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Restart-backoff shape for failed/panicked passes: exponential from
/// `initial`, doubling to `max`. Reset by every completed pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartBackoffConfig {
    pub initial: Duration,
    pub max: Duration,
}

impl Default for RestartBackoffConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(60),
        }
    }
}

#[derive(Debug)]
struct RestartBackoff {
    config: RestartBackoffConfig,
    next: Option<Duration>,
}

impl RestartBackoff {
    fn new(config: RestartBackoffConfig) -> Self {
        Self { config, next: None }
    }

    fn advance(&mut self) -> Duration {
        let delay = self
            .next
            .unwrap_or(self.config.initial)
            .min(self.config.max);
        self.next = Some(delay.saturating_mul(2).min(self.config.max));
        delay
    }

    fn reset(&mut self) {
        self.next = None;
    }
}

/// Static supervisor configuration. One base wake budget id + lease owner
/// per supervisor; every pass gets a fresh wall-clock deadline, a fresh
/// in-memory wake-budget counter, and a **per-pass durable runner-store
/// budget row** derived from [`Self::budget_id`] (see
/// [`durable_pass_budget_id`]).
#[derive(Clone)]
pub struct WakeSupervisorConfig {
    /// Base durable runner-store budget id. Each pass appends a monotonic
    /// pass index (`{budget_id}:p{n}`) so a long-lived supervisor never
    /// reuses a spent budget row across passes. Note: each pass therefore
    /// leaves one budget row in the runner store; this crate does not GC
    /// them.
    pub budget_id: String,
    /// Lease owner stamped on admissions and parks.
    pub lease_owner: String,
    /// This node's id (macro-scope admission verifies it against the vault
    /// identity; must be nonzero).
    pub local_node_id: u64,
    /// Total budget units granted to each pass.
    pub budget_total_units: u64,
    /// Units reserved per admitted child job.
    pub reserve_units: u64,
    /// Per-pass wall-clock ceiling in milliseconds.
    pub pass_ceiling_ms: u64,
    /// Counter behavior at exhaustion. `Suspend` (fail-closed) by default.
    pub exhaustion_policy: BudgetExhaustionPolicy,
    /// Durable Started/Done milestone authorship, if the host wants it.
    pub milestones: Option<WakeMilestoneAuthor>,
    /// Restart-backoff shape for failed/panicked passes and for
    /// zero-progress [`WakePassStop::BudgetExhausted`] (admitted == 0),
    /// which would otherwise hot-loop under HybridTick deadline redelivery.
    pub backoff: RestartBackoffConfig,
}

impl WakeSupervisorConfig {
    #[must_use]
    pub fn new(
        budget_id: impl Into<String>,
        lease_owner: impl Into<String>,
        local_node_id: u64,
        budget_total_units: u64,
    ) -> Self {
        Self {
            budget_id: budget_id.into(),
            lease_owner: lease_owner.into(),
            local_node_id,
            budget_total_units,
            reserve_units: DEFAULT_DREAMER_CHILD_RESERVE_UNITS,
            pass_ceiling_ms: DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS,
            exhaustion_policy: BudgetExhaustionPolicy::Suspend,
            milestones: None,
            backoff: RestartBackoffConfig::default(),
        }
    }
}

/// Requests a graceful supervisor stop. Cooperative ONLY (H-S5/R2): between
/// passes the loop exits immediately; mid-pass the running pass's
/// [`WakeCancellation`] flag is raised and the pass is awaited to its own
/// job-boundary stop — never aborted.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

impl ShutdownHandle {
    /// Requests shutdown. Idempotent.
    pub fn shutdown(&self) {
        let _ = self.tx.send(true);
    }
}

#[derive(Debug)]
struct ShutdownListener {
    rx: watch::Receiver<bool>,
}

impl ShutdownListener {
    fn requested(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves once shutdown is requested. If every [`ShutdownHandle`] is
    /// dropped without a request, nothing can ever request one — this pends
    /// forever rather than reporting a spurious shutdown.
    async fn triggered(&mut self) {
        if self.rx.wait_for(|stopped| *stopped).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Builds the per-pass job executor. Generic-associated so executors may
/// borrow factory-owned state (the backend constructed at startup, the
/// promotion sink) and per-pass state (the fresh [`BudgetGuard`]).
pub trait PassExecutorFactory {
    type Exec<'p>: DreamerJobExecutor
    where
        Self: 'p;

    /// Builds the executor for one pass. `guard` is the pass's wake-budget
    /// counter — the same counter the driver reads for legibility, never a
    /// second one.
    fn executor<'p>(&'p mut self, guard: &'p BudgetGuard) -> Result<Self::Exec<'p>>;
}

/// [`PassExecutorFactory`] over the landed [`ConsolidationExecutor`]: owns
/// the [`LlmBackend`] the supervisor constructed at startup plus the
/// promotion sink, and lends both to each pass.
pub struct ConsolidationExecutorFactory {
    backend: Arc<dyn LlmBackend>,
    strategy: DreamerClaimAuthoringStrategy,
    actor: WriteActor,
    model: ModelId,
    sink: Box<dyn ConsolidationSink>,
}

impl ConsolidationExecutorFactory {
    /// Wraps a host-injected backend (any adapter).
    #[must_use]
    pub fn new(
        backend: Arc<dyn LlmBackend>,
        strategy: DreamerClaimAuthoringStrategy,
        actor: WriteActor,
        model: ModelId,
        sink: Box<dyn ConsolidationSink>,
    ) -> Self {
        Self {
            backend,
            strategy,
            actor,
            model,
            sink,
        }
    }

    /// Constructs the crate's DEFAULT backend: the LOCAL adapter over a
    /// host-supplied runtime. Local on purpose — the default driver wiring
    /// must not imply network egress; hosts pick a remote adapter only by
    /// explicitly injecting one via [`Self::new`].
    #[must_use]
    pub fn with_local_runtime<R>(
        runtime: R,
        strategy: DreamerClaimAuthoringStrategy,
        actor: WriteActor,
        model: ModelId,
        sink: Box<dyn ConsolidationSink>,
    ) -> Self
    where
        R: LocalLlmRuntime + 'static,
    {
        Self::new(
            Arc::new(LocalLlmBackend::new(runtime)),
            strategy,
            actor,
            model,
            sink,
        )
    }
}

impl PassExecutorFactory for ConsolidationExecutorFactory {
    type Exec<'p> = ConsolidationExecutor<'p>;

    fn executor<'p>(&'p mut self, guard: &'p BudgetGuard) -> Result<Self::Exec<'p>> {
        Ok(ConsolidationExecutor {
            backend: self.backend.as_ref(),
            guard,
            strategy: self.strategy,
            actor: self.actor,
            model: self.model.clone(),
            sink: self.sink.as_mut(),
        })
    }
}

/// Supervisor run tally.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WakeSupervisorReport {
    pub passes_completed: u64,
    pub passes_failed: u64,
    pub passes_panicked: u64,
    pub jobs_completed: u64,
    pub jobs_parked: u64,
}

enum PassOutcome {
    Completed(WakePassReport),
    Failed(oneiron::Error),
    Panicked,
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
}

impl<'v, T, F> WakeSupervisor<'v, T, F>
where
    T: TickSource,
    F: PassExecutorFactory,
{
    #[must_use]
    pub fn new(vault: &'v Vault, ticks: T, factory: F, config: WakeSupervisorConfig) -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            vault,
            ticks,
            factory,
            config,
            shutdown_handle: ShutdownHandle { tx },
            shutdown: ShutdownListener { rx },
            pass_gate: Arc::new(Semaphore::new(1)),
            now_secs: Arc::new(system_now_secs),
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

    /// Injects the wall clock used for [`RunWakePass::now`] (tests).
    #[must_use]
    pub fn with_clock(mut self, now_secs: NowSeconds) -> Self {
        self.now_secs = now_secs;
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
        } = self;
        // Keep the supervisor's own handle alive so a host-less run idles
        // on "not requested" instead of erroring the watch channel.
        let _shutdown_handle = shutdown_handle;

        let mut report = WakeSupervisorReport::default();
        let mut backoff = RestartBackoff::new(config.backoff);
        // Monotonic pass index used only to mint a fresh durable budget id
        // per pass. Deterministic (no clock/random) so restart bookkeeping
        // stays inspectable.
        let mut pass_index: u64 = 0;

        loop {
            // ONE biased select: shutdown always beats a ready tick.
            let tick = tokio::select! {
                biased;
                () = shutdown.triggered() => break,
                tick = ticks.next_tick() => match tick {
                    Some(tick) => tick,
                    // Source exhausted: nothing can ever wake us again.
                    None => break,
                },
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
            let pass_budget_id = durable_pass_budget_id(&config.budget_id, pass_index);
            pass_index = pass_index.saturating_add(1);
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

            match outcome {
                PassOutcome::Completed(pass) => {
                    report.passes_completed += 1;
                    report.jobs_completed += u64::from(pass.completed);
                    report.jobs_parked += u64::from(pass.parked);
                    // Zero-progress BudgetExhausted (e.g. total < reserve,
                    // or a still-shared spent row): HybridTick re-surfaces
                    // the same due deadline immediately. Back off so we
                    // never hot-loop when a pass cannot make durable
                    // progress. With per-pass budget ids a spent row is
                    // not reused, so a productive BudgetExhausted
                    // (admitted > 0) continues straight into the next
                    // pass and drains remaining work.
                    if pass.stop == WakePassStop::BudgetExhausted && pass.admitted == 0 {
                        tracing::warn!(
                            "wake pass stopped on BudgetExhausted without admitting work; \
                             backing off before the next tick"
                        );
                        if !wait_backoff(&mut shutdown, backoff.advance()).await {
                            break;
                        }
                    } else {
                        backoff.reset();
                    }
                }
                PassOutcome::Failed(error) => {
                    report.passes_failed += 1;
                    tracing::error!(?error, "wake pass failed; backing off before the next tick");
                    if !wait_backoff(&mut shutdown, backoff.advance()).await {
                        break;
                    }
                }
                PassOutcome::Panicked => {
                    report.passes_panicked += 1;
                    tracing::error!("wake pass panicked; restarting with backoff");
                    if !wait_backoff(&mut shutdown, backoff.advance()).await {
                        break;
                    }
                }
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
async fn run_pass_supervised<F: PassExecutorFactory>(
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
                    Ok(Err(error)) => PassOutcome::Failed(error),
                    Err(_panic) => PassOutcome::Panicked,
                };
            }
        }
    }
}

/// Derives the durable runner-store budget id for one pass from the
/// supervisor's static base id and a monotonic pass index.
///
/// DreamerRunnerStore only initializes a budget row when it is absent, so
/// reusing `config.budget_id` across passes would leave later ticks stuck
/// on `BudgetExhausted` against a spent row. A per-pass id gives each pass
/// a fresh row without requiring this crate to renew or otherwise write
/// runner-store budget state (admission/settle stay inside `run_wake_pass`).
///
/// Trade-off: one durable budget row leaks per pass for the life of the
/// vault (no GC here). That is intentional and cheaper than a shared-row
/// spin; hosts that care about row growth can GC by base-prefix if needed.
///
/// Single-supervisor assumption: concurrent supervisors over one vault
/// already share the pass gate when configured via
/// [`WakeSupervisor::with_pass_gate`]; independent supervisors minting
/// distinct pass sequences under the same base id would each get their own
/// rows and would not clobber each other (unlike an in-place renew).
#[must_use]
fn durable_pass_budget_id(base: &str, pass_index: u64) -> String {
    format!("{base}:p{pass_index}")
}

/// One wake pass: fresh deadline, fresh wake-budget counter, per-pass
/// durable budget id, per-pass executor, then `run_wake_pass`. Budget
/// admission/settle stays entirely inside the engine call — this function
/// never touches the runner store.
async fn run_one_pass<F: PassExecutorFactory>(
    vault: &Vault,
    config: &WakeSupervisorConfig,
    pass_budget_id: &str,
    now_secs: &NowSeconds,
    factory: &mut F,
    tick: &Tick,
    cancel: &WakeCancellation,
) -> Result<WakePassReport> {
    let (scope, trigger) = pass_shape(tick);
    let deadline = WakePassDeadline::new(config.pass_ceiling_ms);
    // ONE wake-budget counter per pass (the LLM-4 guard), shared between
    // the driver's legibility reads and the executor's admissions. The
    // durable store id matches so settle/reserve land on the pass's own
    // row.
    let guard = BudgetGuard::with_reserve_units(
        pass_budget_id.to_owned(),
        config.budget_total_units,
        config.reserve_units,
        config.exhaustion_policy,
    );
    let mut driver = DreamerWakeDriver::new(vault, pass_budget_id.to_owned(), deadline)
        .with_budget_guard(guard.clone());
    if let Some(author) = config.milestones.clone() {
        driver = driver.with_milestone_author(author);
    }
    let mut executor = factory.executor(&guard)?;
    let input = RunWakePass {
        trigger,
        scope,
        local_node_id: config.local_node_id,
        lease_owner: config.lease_owner.clone(),
        budget_total_units: config.budget_total_units,
        reserve_units: config.reserve_units,
        now: (*now_secs)(),
    };
    driver.run_wake_pass(input, &mut executor, cancel).await
}

/// Maps a tick to the pass it may drive. Deadline ticks drain the lane the
/// due commitment belongs to; wake pushes carry their own authority; hints
/// are pinned to the LEAST-privileged shape — a hint producer cannot
/// escalate scope or forge a trigger (H-S4).
fn pass_shape(tick: &Tick) -> (DreamerConsolidationScope, WakeTrigger) {
    match tick {
        Tick::Deadline(deadline) => (deadline.scope, WakeTrigger::Timer),
        Tick::Wake(wake) => (wake.scope, wake.trigger),
        Tick::Hint(_) => (DreamerConsolidationScope::Micro, WakeTrigger::Event),
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::tick::{PushTick, WakeSignal};
    use oneiron::job_queue::{JobId, JobState};
    use oneiron::{
        DREAMER_EXECUTOR_ERROR_PARK_REASON, DreamerAdmittedJob, DreamerJobExecution,
        DreamerRunnerStore, EnqueueDreamerConsolidationJob, EnqueueDreamerJobOutcome, VaultConfig,
        WakeJobContext,
    };

    fn open_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        (dir, vault)
    }

    fn enqueue_micro(vault: &Vault, tag: &str, now: u64) -> JobId {
        match DreamerRunnerStore::new(vault)
            .enqueue_consolidation(EnqueueDreamerConsolidationJob {
                scope: DreamerConsolidationScope::Micro,
                input: rmpv::Value::from(tag),
                parent_job: None,
                dedupe_key: Some(tag.to_owned()),
                run_id: None,
                now,
            })
            .expect("enqueue")
        {
            EnqueueDreamerJobOutcome::Enqueued(status)
            | EnqueueDreamerJobOutcome::Existing(status) => status.job.id,
            other => panic!("unexpected enqueue outcome: {other:?}"),
        }
    }

    fn test_config() -> WakeSupervisorConfig {
        let mut config = WakeSupervisorConfig::new("driver-budget", "driver-worker", 1, 10_000);
        config.reserve_units = 100;
        config
    }

    struct ScriptedTicks {
        ticks: Vec<Tick>,
    }

    impl TickSource for ScriptedTicks {
        async fn next_tick(&mut self) -> Option<Tick> {
            if self.ticks.is_empty() {
                None
            } else {
                Some(self.ticks.remove(0))
            }
        }
    }

    struct TestExec {
        panic_now: bool,
        completed_units: u64,
    }

    impl DreamerJobExecutor for TestExec {
        async fn execute(
            &mut self,
            _job: &DreamerAdmittedJob,
            _ctx: &mut WakeJobContext<'_>,
        ) -> Result<DreamerJobExecution> {
            assert!(!self.panic_now, "scripted executor panic");
            Ok(DreamerJobExecution::Completed {
                completed_units: self.completed_units,
            })
        }
    }

    struct TestExecFactory {
        panics_left: u32,
        factory_panics_left: u32,
        completed_units: u64,
    }

    impl PassExecutorFactory for TestExecFactory {
        type Exec<'p> = TestExec;

        fn executor<'p>(&'p mut self, _guard: &'p BudgetGuard) -> Result<TestExec> {
            if self.factory_panics_left > 0 {
                self.factory_panics_left -= 1;
                panic!("scripted factory panic");
            }
            let panic_now = self.panics_left > 0;
            if panic_now {
                self.panics_left -= 1;
            }
            Ok(TestExec {
                panic_now,
                completed_units: self.completed_units,
            })
        }
    }

    #[test]
    fn hint_ticks_map_to_least_privileged_pass_shape() {
        let (scope, trigger) = pass_shape(&Tick::Hint(crate::tick::HintSignal {}));
        assert_eq!(scope, DreamerConsolidationScope::Micro);
        assert_eq!(trigger, WakeTrigger::Event);
    }

    #[tokio::test]
    async fn supervisor_pumps_one_pass_per_wake_then_stops_when_exhausted() {
        let (_dir, vault) = open_vault();
        enqueue_micro(&vault, "driver-smoke", 10);

        let (push, wake, hint) = PushTick::channel();
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        drop(wake);
        drop(hint);

        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            completed_units: 40,
        };
        let supervisor = WakeSupervisor::new(&vault, push, factory, test_config());
        let report = supervisor.run().await;

        assert_eq!(report.passes_completed, 1);
        assert_eq!(report.jobs_completed, 1);
        assert_eq!(report.passes_panicked, 0);
        assert_eq!(report.passes_failed, 0);

        // The pass settled its budget through the engine, not this crate.
        // Pass index 0 → durable id `{base}:p0`.
        let budget = DreamerRunnerStore::new(&vault)
            .budget("driver-budget:p0")
            .expect("budget read")
            .expect("budget row");
        assert_eq!(budget.reserved_units, 0);
        assert_eq!(budget.remaining_units, 10_000 - 40);
    }

    #[tokio::test(start_paused = true)]
    async fn panicking_executor_parks_job_and_supervisor_continues() {
        // ONE-1683: an executor panic after admission used to unwind past
        // the driver's park/refund code — the supervisor's catch converted
        // it to Panicked by resolving before that bookkeeping ran, leaving
        // the job leased and the reservation held until external cleanup.
        // The engine now contains the panic at the job boundary: the job is
        // parked, the reservation refunded, and the pass surfaces as a
        // FAILED pass the supervisor backs off from and outlives.
        let (_dir, vault) = open_vault();
        let first = enqueue_micro(&vault, "panics", 10);
        let second = enqueue_micro(&vault, "completes", 11);

        let wake = Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        });
        let ticks = ScriptedTicks {
            ticks: vec![wake, wake],
        };
        let factory = TestExecFactory {
            panics_left: 1,
            factory_panics_left: 0,
            completed_units: 40,
        };
        let supervisor = WakeSupervisor::new(&vault, ticks, factory, test_config());
        let report = supervisor.run().await;

        assert_eq!(
            report.passes_failed, 1,
            "the contained panic surfaces as a failed pass"
        );
        assert_eq!(report.passes_panicked, 0, "nothing unwound past the driver");
        assert_eq!(
            report.passes_completed, 1,
            "the supervisor restarted after backoff and ran the next pass"
        );
        assert_eq!(report.jobs_completed, 1);

        // The panicked job is parked under the executor-error reason, its
        // reservation refunded; the second job settled normally.
        let store = DreamerRunnerStore::new(&vault);
        let parked = store
            .parked_job(first)
            .expect("parked read")
            .expect("parked row");
        assert!(
            parked
                .reason
                .starts_with(DREAMER_EXECUTOR_ERROR_PARK_REASON),
            "park reason carries the executor-error class: {}",
            parked.reason
        );
        assert!(
            parked.reason.contains("panicked"),
            "park reason names the panic: {}",
            parked.reason
        );
        // Completing pass was pass index 1 (`:p1`); the failed pass spent
        // nothing durable after the park+refund.
        let budget = store
            .budget("driver-budget:p1")
            .expect("budget read")
            .expect("budget row");
        assert_eq!(budget.reserved_units, 0, "no reservation leaked");
        assert_eq!(budget.remaining_units, 10_000 - 40);
        let status = store.status(second).expect("status read").expect("status");
        assert_eq!(status.job.state, JobState::Completed);
    }

    #[tokio::test(start_paused = true)]
    async fn pass_panic_outside_the_job_boundary_restarts_with_backoff() {
        // The supervisor-level catch stays as the backstop for panics the
        // engine cannot contain — anywhere outside exec.execute, here the
        // executor factory. Nothing is leased at that point, so
        // restart-with-backoff is leak-free.
        let (_dir, vault) = open_vault();
        enqueue_micro(&vault, "factory-panics-once", 10);

        let wake = Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        });
        let ticks = ScriptedTicks {
            ticks: vec![wake, wake],
        };
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 1,
            completed_units: 40,
        };
        let supervisor = WakeSupervisor::new(&vault, ticks, factory, test_config());
        let report = supervisor.run().await;

        assert_eq!(report.passes_panicked, 1, "the backstop caught the panic");
        assert_eq!(
            report.passes_completed, 1,
            "the supervisor restarted after backoff and ran the next pass"
        );
    }

    /// Completes jobs synchronously and requests supervisor shutdown from
    /// inside the first execution — without a job-boundary yield the whole
    /// backlog would drain in a single poll before the biased select! ever
    /// saw the request.
    struct ShutdownRequestingExec {
        handle: ShutdownHandle,
    }

    impl DreamerJobExecutor for ShutdownRequestingExec {
        async fn execute(
            &mut self,
            _job: &DreamerAdmittedJob,
            _ctx: &mut WakeJobContext<'_>,
        ) -> Result<DreamerJobExecution> {
            self.handle.shutdown();
            Ok(DreamerJobExecution::Completed {
                completed_units: 40,
            })
        }
    }

    struct ShutdownRequestingFactory {
        handle: Arc<Mutex<Option<ShutdownHandle>>>,
    }

    impl PassExecutorFactory for ShutdownRequestingFactory {
        type Exec<'p> = ShutdownRequestingExec;

        fn executor<'p>(&'p mut self, _guard: &'p BudgetGuard) -> Result<ShutdownRequestingExec> {
            let handle = self
                .handle
                .lock()
                .expect("handle slot")
                .clone()
                .expect("handle wired before run");
            Ok(ShutdownRequestingExec { handle })
        }
    }

    #[tokio::test]
    async fn shutdown_during_synchronous_pass_stops_at_the_next_job_boundary() {
        // ONE-1683: run_wake_pass yields once per job boundary, so a
        // shutdown requested while a synchronously-completing pass is
        // running raises the cancellation flag after the in-flight job —
        // the pass stops cooperatively instead of draining the whole queue.
        let (_dir, vault) = open_vault();
        enqueue_micro(&vault, "first", 10);
        let second = enqueue_micro(&vault, "second", 11);
        let third = enqueue_micro(&vault, "third", 12);

        let wake = Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        });
        let ticks = ScriptedTicks {
            ticks: vec![wake, wake],
        };
        let slot = Arc::new(Mutex::new(None));
        let factory = ShutdownRequestingFactory {
            handle: Arc::clone(&slot),
        };
        let supervisor = WakeSupervisor::new(&vault, ticks, factory, test_config());
        *slot.lock().expect("handle slot") = Some(supervisor.shutdown_handle());
        let report = supervisor.run().await;

        assert_eq!(report.passes_completed, 1);
        assert_eq!(
            report.jobs_completed, 1,
            "the pass stopped at the first job boundary after the request"
        );

        // The rest of the queue is untouched, ready for the next run.
        let store = DreamerRunnerStore::new(&vault);
        for id in [second, third] {
            let status = store.status(id).expect("status read").expect("status");
            assert_eq!(status.job.state, JobState::Queued, "never claimed");
        }
    }

    #[tokio::test]
    async fn shutdown_between_passes_stops_the_loop() {
        let (_dir, vault) = open_vault();
        let (push, _wake, _hint) = PushTick::channel();
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            completed_units: 0,
        };
        let supervisor = WakeSupervisor::new(&vault, push, factory, test_config());
        let handle = supervisor.shutdown_handle();
        handle.shutdown();
        let report = supervisor.run().await;
        assert_eq!(report, WakeSupervisorReport::default(), "no pass ran");
    }

    #[tokio::test]
    async fn second_pass_runs_jobs_after_first_pass_budget_exhausts() {
        // P1 (codex): a static config.budget_id was shared across passes, so
        // DreamerRunnerStore's init-if-absent left pass 2 stuck on a spent
        // row. Per-pass durable ids (`{base}:p{n}`) give each pass a fresh
        // budget so remaining work drains.
        let (_dir, vault) = open_vault();
        let first = enqueue_micro(&vault, "exhaust-first", 10);
        let second = enqueue_micro(&vault, "needs-fresh-budget", 11);

        let wake = Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        });
        let ticks = ScriptedTicks {
            // Two passes: first exhausts after one job; second must still
            // be able to admit the remaining job.
            ticks: vec![wake, wake],
        };
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            // Spend 100 of the 150-unit grant so the second reservation in
            // the same pass is denied (remaining 50 < reserve 100).
            completed_units: 100,
        };
        let mut config = test_config();
        config.budget_total_units = 150;
        config.reserve_units = 100;
        // Keep default backoff for any zero-progress path; this test expects
        // productive BudgetExhausted then a fresh second pass.
        let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
        let report = supervisor.run().await;

        assert_eq!(
            report.passes_completed, 2,
            "both passes complete (first BudgetExhausted, second drains)"
        );
        assert_eq!(
            report.jobs_completed, 2,
            "second pass must admit under a fresh durable budget row"
        );
        assert_eq!(report.passes_failed, 0);
        assert_eq!(report.passes_panicked, 0);

        let store = DreamerRunnerStore::new(&vault);
        for (id, pass_id, spent) in [
            (first, "driver-budget:p0", 100u64),
            (second, "driver-budget:p1", 100u64),
        ] {
            let status = store.status(id).expect("status read").expect("status");
            assert_eq!(status.job.state, JobState::Completed, "job under {pass_id}");
            let budget = store
                .budget(pass_id)
                .expect("budget read")
                .expect("per-pass budget row");
            assert_eq!(budget.reserved_units, 0);
            assert_eq!(budget.remaining_units, 150 - spent);
            assert_eq!(budget.total_units, 150);
        }
        // The static base id must NOT have been written as a shared row —
        // that was the spin root cause.
        assert!(
            store
                .budget("driver-budget")
                .expect("base budget read")
                .is_none(),
            "base budget_id is only a prefix; rows live at :p{{n}}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn budget_exhausted_with_due_deadline_does_not_busy_loop() {
        // Regression: HybridTick re-surfaces an already-due deadline on
        // every cycle. With a shared spent budget that spun forever (hot
        // BudgetExhausted passes, zero progress). Per-pass ids let work
        // drain; zero-progress BudgetExhausted backs off so a permanently
        // un-admittable grant cannot hot-loop either.
        let (_dir, vault) = open_vault();
        let job_a = enqueue_micro(&vault, "due-a", 10);
        let job_b = enqueue_micro(&vault, "due-b", 11);

        // Jobs are due at created_at * 1000 ms; clock is far past that so
        // HybridTick short-circuits to Deadline every cycle until empty.
        let now_ms: crate::tick::NowMillis = Arc::new(|| 1_000_000);
        let timer = crate::TimerTick::with_clock(
            crate::JobQueueDeadlines::new(&vault, 1),
            Arc::clone(&now_ms),
        );
        let (push, wake, hint) = PushTick::channel();
        // No push producers: once the queue is empty the hybrid source
        // exhausts and the supervisor must stop.
        drop(wake);
        drop(hint);
        let hybrid = crate::HybridTick::new(timer, push);

        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            completed_units: 100,
        };
        let mut config = test_config();
        config.budget_total_units = 150;
        config.reserve_units = 100;
        // Tiny backoff so the zero-progress arm (if hit) is still bounded
        // under the paused clock without making the happy path wait.
        config.backoff = RestartBackoffConfig {
            initial: Duration::from_millis(1),
            max: Duration::from_millis(1),
        };

        let supervisor = WakeSupervisor::new(&vault, hybrid, factory, config);
        // Under the pre-fix shared-budget spin this would never resolve.
        // Bound wall-polls via a generous virtual-time cap: productive
        // draining finishes in a handful of passes.
        let report = tokio::time::timeout(Duration::from_secs(5), supervisor.run())
            .await
            .expect("supervisor must not busy-loop on due HybridTick redelivery");

        assert_eq!(
            report.jobs_completed, 2,
            "due work must drain across per-pass budgets"
        );
        // Exactly two productive passes (one job each under the 150-unit
        // grant) — not an unbounded series of empty BudgetExhausted polls.
        assert_eq!(report.passes_completed, 2);
        assert_eq!(report.passes_failed, 0);
        assert_eq!(report.passes_panicked, 0);

        let store = DreamerRunnerStore::new(&vault);
        for id in [job_a, job_b] {
            let status = store.status(id).expect("status read").expect("status");
            assert_eq!(status.job.state, JobState::Completed, "queue fully drained");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn zero_progress_budget_exhausted_backs_off_instead_of_hot_looping() {
        // Permanently un-admittable grant (total < reserve): every pass
        // hits BudgetExhausted with admitted == 0. Without the zero-progress
        // backoff, a HybridTick due-deadline redelivery would hot-loop;
        // with it, each empty pass sleeps before the next tick is consumed.
        // Under start_paused the backoff sleeps auto-advance, so a fixed
        // tick count finishes in bounded virtual time with exact tallies.
        let (_dir, vault) = open_vault();
        let stuck = enqueue_micro(&vault, "stuck-due", 10);

        let wake = Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        });
        const EMPTY_PASSES: u64 = 5;
        let ticks = ScriptedTicks {
            ticks: vec![wake; EMPTY_PASSES as usize],
        };
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            completed_units: 0,
        };
        let mut config = test_config();
        config.budget_total_units = 50;
        config.reserve_units = 100;
        config.backoff = RestartBackoffConfig {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(10),
        };

        let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
        let report = supervisor.run().await;

        assert_eq!(
            report.passes_completed, EMPTY_PASSES,
            "exactly one completed empty pass per scripted tick"
        );
        assert_eq!(report.jobs_completed, 0, "nothing was admittable");
        assert_eq!(report.passes_failed, 0);
        assert_eq!(report.passes_panicked, 0);
        // Job remains queued — BudgetExhausted before reserve does not
        // claim or park, so the due work is still waiting for a usable grant.
        let status = DreamerRunnerStore::new(&vault)
            .status(stuck)
            .expect("status read")
            .expect("status");
        assert_eq!(status.job.state, JobState::Queued);
    }

    #[test]
    fn durable_pass_budget_id_is_deterministic_per_index() {
        assert_eq!(durable_pass_budget_id("wake", 0), "wake:p0");
        assert_eq!(durable_pass_budget_id("wake", 1), "wake:p1");
        assert_eq!(
            durable_pass_budget_id("driver-budget", 42),
            "driver-budget:p42"
        );
    }
}
