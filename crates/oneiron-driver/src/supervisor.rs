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
//!   panic at the attempt boundary (the attempt is parked, its reservation
//!   refunded, and the pass fails cleanly), and a panic anywhere else in a
//!   pass is caught HERE as the backstop — either way the supervisor
//!   restarts with backoff, never crashes.
//! * Shutdown mid-pass is COOPERATIVE (H-S5/R2): the supervisor raises the
//!   pass's [`WakeCancellation`] flag and KEEPS AWAITING the pass future —
//!   it is never dropped mid-await, so an in-flight gated write or
//!   off-record close is never aborted. The pass stops itself at its
//!   attempt-boundary checkpoints, parking + refunding anything it had admitted.
//! * Budget admission stays entirely INSIDE `run_wake_pass`: this crate
//!   never calls `admit_next_consolidation` / `settle_budget` /
//!   `abort_budget_reservation`.
//! * No actor framework, no attempt-worker crate, no heartbeat: the loop only
//!   ever wakes for a [`Tick`] (an attempt-queue deadline read or an
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
    DEFAULT_DREAMER_CHILD_RESERVE_UNITS, DREAMER_GRACEFUL_WRAP_WINDOW_MS,
    DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS, DreamerAttemptExecutor, DreamerClaimAuthoringStrategy,
    DreamerConsolidationScope, DreamerRunnerStore, DreamerWakeDriver, LlmBackend, ModelId, Result,
    RunWakePass, Vault, WakeCancellation, WakeMilestoneAuthor, WakePassDeadline, WakePassReport,
    WakePassStop, WakeTrigger, WriteActor,
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

/// Dense-scan window for the one-shot startup probe of the next free
/// per-pass budget index (see [`next_pass_budget_index`]). Every index in
/// `[0, bound)` is probed once (at most 65_536 point-reads via
/// [`DreamerRunnerStore::budget`]). When the window is full, a galloping
/// probe continues past the bound until a free suffix is found (binary
/// search between the last occupied and first free), so restart never
/// clamps onto an already-occupied `{base}:p{bound}`. Finite work, no
/// rescan per pass, no hot-loop; cost is paid once per [`WakeSupervisor::run`].
const PASS_BUDGET_INDEX_SCAN_BOUND: u64 = 65_536;

/// Mirror of the runner store's private budget-id ceiling
/// (`MAX_DREAMER_BUDGET_ID_LEN` in `oneiron::dreamer_runner`). Pinned by a
/// real-store validation test below, so drift breaks the build here.
const MAX_RUNNER_BUDGET_ID_LEN: usize = 128;

/// Mirror of `attempt_queue`'s private `MAX_LEASE_OWNER_LEN` (admission stamps
/// `lease_owner` through the runner into the attempt queue, which rejects empty
/// and over-long owners before mutating rows). Pinned by a real-queue
/// validation test below.
const MAX_RUNNER_LEASE_OWNER_LEN: usize = 128;

/// Bytes reserved for the derived per-pass suffix: `":p"` plus the widest
/// `u64` decimal rendering (20 digits).
const PASS_BUDGET_SUFFIX_RESERVE: usize = 22;

/// Longest base [`WakeSupervisorConfig::budget_id`] whose derived
/// `{base}:p{n}` id stays within the runner store's ceiling for every
/// possible pass index.
pub const MAX_PASS_BUDGET_BASE_LEN: usize = MAX_RUNNER_BUDGET_ID_LEN - PASS_BUDGET_SUFFIX_RESERVE;

/// Static supervisor configuration. One base wake budget id + lease owner
/// per supervisor; every pass gets a fresh wall-clock deadline, a fresh
/// in-memory wake-budget counter, and a **per-pass durable runner-store
/// budget row** derived from [`Self::budget_id`] (see
/// `durable_pass_budget_id`).
///
/// On each [`WakeSupervisor::run`] the supervisor probes the runner store
/// once for existing `{budget_id}:p{n}` rows and resumes at
/// highest-occupied + 1 (dense-scanning `[0, bound)` then galloping past
/// the bound when full) so process restarts do not re-mint spent rows or
/// land in a hole that later collides with a still-occupied higher
/// suffix. Concurrent supervisors sharing one base id remain out of
/// scope (single-supervisor model; share the pass gate when co-located).
#[derive(Clone)]
pub struct WakeSupervisorConfig {
    /// Base durable runner-store budget id. Each pass appends a monotonic
    /// pass index (`{budget_id}:p{n}`) so a long-lived supervisor never
    /// reuses a spent budget row across passes. Note: each pass therefore
    /// leaves one budget row in the runner store; this crate does not GC
    /// them. Restart-safe: [`WakeSupervisor::run`] skip-scans existing
    /// `:p{n}` rows before minting.
    pub budget_id: String,
    /// Lease owner stamped on admissions and parks.
    pub lease_owner: String,
    /// This node's id (macro-scope admission verifies it against the vault
    /// identity; must be nonzero — zero is rejected by [`Self::validate`]).
    pub local_node_id: u64,
    /// Total budget units granted to each pass.
    pub budget_total_units: u64,
    /// Units reserved per admitted child attempt.
    pub reserve_units: u64,
    /// Per-pass wall-clock ceiling in milliseconds. Must exceed
    /// [`DREAMER_GRACEFUL_WRAP_WINDOW_MS`] so a pass is not born already
    /// inside the finalize/hard-cut window (see [`Self::validate`]).
    pub pass_ceiling_ms: u64,
    /// Counter behavior at exhaustion. `Suspend` (fail-closed) by default.
    pub exhaustion_policy: BudgetExhaustionPolicy,
    /// Durable Started/Done milestone authorship, if the host wants it.
    pub milestones: Option<WakeMilestoneAuthor>,
    /// Restart-backoff shape for failed/panicked passes and for
    /// zero-progress [`WakePassStop::BudgetExhausted`] /
    /// [`WakePassStop::DeadlineHardCut`] (admitted == 0), which would
    /// otherwise hot-loop under HybridTick deadline redelivery.
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

    /// Rejects configs that would make every pass fail or hard-cut without
    /// durable progress (fail-fast before the tick loop):
    ///
    /// * a base [`Self::budget_id`] whose derived `{base}:p{n}` id could
    ///   exceed the runner store's budget-id ceiling (startup scan would
    ///   treat validation errors as "occupied" and spin);
    /// * `local_node_id == 0` (admission rejects zero before mutating any
    ///   attempt row, so every pass would empty-fail under HybridTick);
    /// * `pass_ceiling_ms <= DREAMER_GRACEFUL_WRAP_WINDOW_MS` (the pass is
    ///   born already in the finalize/hard-cut window and never admits);
    /// * `reserve_units == 0` (runner admission rejects zero reserve before
    ///   mutating rows — every pass would surface as Failed);
    /// * empty or over-long [`Self::lease_owner`] (attempt-queue lease-owner
    ///   ceiling is `MAX_RUNNER_LEASE_OWNER_LEN`; empty/over-long fails
    ///   admission the same way).
    pub fn validate(&self) -> Result<()> {
        if self.budget_id.len() > MAX_PASS_BUDGET_BASE_LEN {
            return Err(oneiron::Error::InvalidConfig(format!(
                "wake supervisor budget_id is {} bytes; max {} so derived \
                 per-pass ids fit the runner-store ceiling",
                self.budget_id.len(),
                MAX_PASS_BUDGET_BASE_LEN
            )));
        }
        if self.local_node_id == 0 {
            return Err(oneiron::Error::InvalidConfig(
                "wake supervisor local_node_id must be nonzero \
                 (admission rejects zero before mutating any attempt)"
                    .into(),
            ));
        }
        if self.pass_ceiling_ms <= DREAMER_GRACEFUL_WRAP_WINDOW_MS {
            return Err(oneiron::Error::InvalidConfig(format!(
                "wake supervisor pass_ceiling_ms is {}; must exceed the \
                 graceful wrap window ({DREAMER_GRACEFUL_WRAP_WINDOW_MS} ms) \
                 so a pass is not born already in the finalize window",
                self.pass_ceiling_ms,
            )));
        }
        if self.reserve_units == 0 {
            return Err(oneiron::Error::InvalidConfig(
                "wake supervisor reserve_units must be > 0 \
                 (admission rejects zero reserve before mutating any attempt)"
                    .into(),
            ));
        }
        if self.lease_owner.is_empty() {
            return Err(oneiron::Error::InvalidConfig(
                "wake supervisor lease_owner must be non-empty \
                 (admission rejects empty lease owners before mutating any attempt)"
                    .into(),
            ));
        }
        if self.lease_owner.len() > MAX_RUNNER_LEASE_OWNER_LEN {
            return Err(oneiron::Error::InvalidConfig(format!(
                "wake supervisor lease_owner is {} bytes; max {} \
                 (attempt-queue lease-owner ceiling)",
                self.lease_owner.len(),
                MAX_RUNNER_LEASE_OWNER_LEN
            )));
        }
        Ok(())
    }
}

/// Requests a graceful supervisor stop. Cooperative ONLY (H-S5/R2): between
/// passes the loop exits immediately; mid-pass the running pass's
/// [`WakeCancellation`] flag is raised and the pass is awaited to its own
/// attempt-boundary stop — never aborted.
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

/// Builds the per-pass attempt executor. Generic-associated so executors may
/// borrow factory-owned state (the backend constructed at startup, the
/// promotion sink) and per-pass state (the fresh [`BudgetGuard`]).
pub trait PassExecutorFactory {
    type Exec<'p>: DreamerAttemptExecutor
    where
        Self: 'p;

    /// Builds the executor for one pass. `guard` is the pass's wake-budget
    /// counter — the same counter the driver reads for legibility, never a
    /// second one.
    fn executor<'p>(&'p mut self, guard: &'p BudgetGuard) -> Result<Self::Exec<'p>>;

    /// The engine-stamped actor for policy-aware budget construction;
    /// `None` selects the legacy single-pool guard.
    fn actor(&self) -> Option<WriteActor> {
        None
    }
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

    fn actor(&self) -> Option<WriteActor> {
        Some(self.actor)
    }
}

/// Supervisor run tally.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WakeSupervisorReport {
    pub passes_completed: u64,
    pub passes_failed: u64,
    pub passes_panicked: u64,
    pub attempts_completed: u64,
    pub attempts_parked: u64,
}

enum PassOutcome {
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

        loop {
            // ONE biased select: shutdown always beats a ready tick.
            // A re-drive reuses the last tick without waiting on the source
            // (and without blocking shutdown — checked after backoff).
            let tick = if let Some(tick) = redrive_tick.take() {
                tick
            } else {
                tokio::select! {
                    biased;
                    () = shutdown.triggered() => break,
                    tick = ticks.next_tick() => match tick {
                        Some(tick) => tick,
                        // Source exhausted: nothing can ever wake us again.
                        None => break,
                    },
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
                    pass_index = pass_index.saturating_add(1);
                    report.passes_completed += 1;
                    report.attempts_completed += u64::from(pass.completed);
                    report.attempts_parked += u64::from(pass.parked);
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
                        if !wait_backoff(&mut shutdown, backoff.advance()).await {
                            break;
                        }
                        redrive_tick = Some(tick);
                    } else {
                        backoff.reset();
                    }
                }
                PassOutcome::Failed(error) => {
                    // In-pass failure may have admitted/parked some attempts;
                    // the same consumed wake can still represent remaining
                    // backlog → redrive after backoff (idempotent for Hybrid).
                    pass_index = pass_index.saturating_add(1);
                    report.passes_failed += 1;
                    tracing::error!(?error, "wake pass failed; backing off then re-driving tick");
                    if !wait_backoff(&mut shutdown, backoff.advance()).await {
                        break;
                    }
                    redrive_tick = Some(tick);
                }
                PassOutcome::PreAdmissionFailed(error) => {
                    // No attempt row mutated and no durable budget row written —
                    // keep pass_index; redrive after backoff.
                    report.passes_failed += 1;
                    tracing::error!(
                        ?error,
                        "wake pass failed before admission; backing off then re-driving tick"
                    );
                    if !wait_backoff(&mut shutdown, backoff.advance()).await {
                        break;
                    }
                    redrive_tick = Some(tick);
                }
                PassOutcome::Panicked => {
                    // Setup panic before admission (or any uncontained panic):
                    // redrive after backoff so a PushTick-only host keeps work.
                    pass_index = pass_index.saturating_add(1);
                    report.passes_panicked += 1;
                    tracing::error!("wake pass panicked; backing off then re-driving tick");
                    if !wait_backoff(&mut shutdown, backoff.advance()).await {
                        break;
                    }
                    redrive_tick = Some(tick);
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
///
/// Factory/`Result` failures before `run_wake_pass` surface as
/// [`PassOutcome::PreAdmissionFailed`] so the supervisor can re-drive the
/// tick; panics anywhere in the pass still map to [`PassOutcome::Panicked`].
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

/// Distinguishes setup failures (no attempt admitted) from in-pass failures so
/// the supervisor can re-drive a consumed push tick after backoff.
enum PassRunError {
    PreAdmission(oneiron::Error),
    Failed(oneiron::Error),
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
/// Restart: [`next_pass_budget_index`] scans existing `:p{n}` rows at
/// `run` start so a new process under the same base does not re-enter
/// spent rows. Single-supervisor model only — two supervisors concurrently
/// sharing one base are out of scope (use [`WakeSupervisor::with_pass_gate`]
/// when co-located; do not run independent sequences on the same base).
#[must_use]
fn durable_pass_budget_id(base: &str, pass_index: u64) -> String {
    format!("{base}:p{pass_index}")
}

/// Next free per-pass budget index under `base` for this vault:
/// **highest occupied suffix + 1**.
///
/// Dense-probes every `{base}:p{n}` for `n` in `[0, bound)` via
/// [`DreamerRunnerStore::budget`] and returns `max(occupied) + 1`, or `0`
/// when none are occupied. If the dense window is full (resume index would
/// be `bound`) and `{base}:p{bound}` (or later) is still occupied, a
/// galloping probe walks upward and binary-searches the first free suffix
/// so restart never clamps onto a spent row past the bound. Lookups stay
/// O(log n) past the dense window; the scan still runs once per `run`.
///
/// Highest-occupied (not first-absent) matters because empty passes leave
/// no runner-store budget row: a prior run may have written `:p1` after an
/// empty `:p0`, and first-absent would restart at `0`, fill `:p0`, then
/// advance into the still-occupied stale `:p1`. Scanning to the max
/// occupied suffix avoids that collision; holes below the max are skipped.
///
/// Unreadable probes count as occupied for the max (do not re-mint a row
/// we failed to confirm is free). Not progress for restart-backoff
/// purposes: pure read bookkeeping before any pass runs.
#[must_use]
fn next_pass_budget_index(vault: &Vault, base: &str) -> u64 {
    next_pass_budget_index_with_bound(vault, base, PASS_BUDGET_INDEX_SCAN_BOUND)
}

/// Same as [`next_pass_budget_index`] with an injectable dense-scan bound
/// (tests pin a small bound; production uses [`PASS_BUDGET_INDEX_SCAN_BOUND`]).
#[must_use]
fn next_pass_budget_index_with_bound(vault: &Vault, base: &str, bound: u64) -> u64 {
    let store = DreamerRunnerStore::new(vault);
    let mut highest_occupied: Option<u64> = None;
    // Full dense scan (not first-absent): holes below a later occupied
    // row must not become the resume index. Cost: one point-read per index
    // in [0, bound) once per supervisor run — production bound is 65_536.
    for n in 0..bound {
        if pass_budget_row_occupied(&store, base, n) {
            highest_occupied = Some(n);
        }
    }
    let start = match highest_occupied {
        None => return 0,
        Some(highest) => {
            let next = highest.saturating_add(1);
            // Free slot still inside the dense window (we scanned it).
            if next < bound {
                return next;
            }
            next
        }
    };
    // Dense window full (or highest was bound-1): find first free at/after
    // `start`, galloping upward then binary-searching so occupied rows past
    // the bound never clamp the resume index.
    first_free_pass_budget_index_from(&store, base, start)
}

/// First free suffix at or after `from`, probed per pass before minting.
/// The startup scan positions the sequence; this is the per-pass guarantee
/// that a spent row is never silently reused (the store reuses existing
/// rows rather than reinitializing them) — e.g. after resuming into an
/// empty-pass hole that sits below a still-occupied higher suffix. Cost:
/// one point-read on the free path; skips cost one read per stale row and
/// terminate because occupied rows are finite.
fn advance_past_occupied_pass_rows(vault: &Vault, base: &str, from: u64) -> u64 {
    let store = DreamerRunnerStore::new(vault);
    let mut index = from;
    while pass_budget_row_occupied(&store, base, index) {
        index = index.saturating_add(1);
    }
    index
}

/// True when `{base}:p{n}` exists or is unreadable (treat unreadable as
/// occupied so we never re-mint a row we failed to confirm is free).
fn pass_budget_row_occupied(store: &DreamerRunnerStore<'_>, base: &str, n: u64) -> bool {
    let id = durable_pass_budget_id(base, n);
    match store.budget(&id) {
        Ok(None) => false,
        Ok(Some(_)) => true,
        Err(error) => {
            tracing::warn!(
                ?error,
                budget_id = %id,
                "pass-budget index probe failed; treating as occupied"
            );
            true
        }
    }
}

/// First free suffix at or after `start`. Gallops (doubling) to find an
/// upper free bound, then binary-searches — O(log n) probes past a dense
/// occupied prefix. If the entire remaining `u64` domain is occupied,
/// returns `u64::MAX` (last possible suffix; no further free index exists).
fn first_free_pass_budget_index_from(
    store: &DreamerRunnerStore<'_>,
    base: &str,
    start: u64,
) -> u64 {
    if !pass_budget_row_occupied(store, base, start) {
        return start;
    }
    // `lo` is occupied. Gallop until `hi` is free (or the domain ends).
    let mut lo = start;
    let mut step = 1u64;
    loop {
        let Some(hi) = lo.checked_add(step) else {
            // No free index remains in the u64 domain.
            return u64::MAX;
        };
        if !pass_budget_row_occupied(store, base, hi) {
            return binary_search_first_free_pass_budget(store, base, lo, hi);
        }
        lo = hi;
        step = step.saturating_mul(2);
    }
}

/// Least free index in `(lo, hi]` given `lo` occupied and `hi` free.
fn binary_search_first_free_pass_budget(
    store: &DreamerRunnerStore<'_>,
    base: &str,
    mut lo: u64,
    mut hi: u64,
) -> u64 {
    while lo.saturating_add(1) < hi {
        let mid = lo + (hi - lo) / 2;
        if pass_budget_row_occupied(store, base, mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi
}

/// One wake pass: fresh deadline, fresh wake-budget counter, per-pass
/// durable budget id, per-pass executor, then `run_wake_pass`. Budget
/// admission/settle stays entirely inside the engine call — this function
/// never touches the runner store.
///
/// Factory errors surface as [`PassRunError::PreAdmission`] (no attempt row
/// mutated); errors from `run_wake_pass` as [`PassRunError::Failed`].
async fn run_one_pass<F: PassExecutorFactory>(
    vault: &Vault,
    config: &WakeSupervisorConfig,
    pass_budget_id: &str,
    now_secs: &NowSeconds,
    factory: &mut F,
    tick: &Tick,
    cancel: &WakeCancellation,
) -> std::result::Result<WakePassReport, PassRunError> {
    let (scope, trigger) = pass_shape(tick);
    let deadline = WakePassDeadline::new(config.pass_ceiling_ms);
    // ONE wake-budget counter per pass (the LLM-4 guard), shared between
    // the driver's legibility reads and the executor's admissions. The
    // durable store id matches so settle/reserve land on the pass's own
    // row.
    let guard = match factory.actor() {
        Some(actor) => vault
            .policy_budget_guard(
                pass_budget_id.to_owned(),
                config.budget_total_units,
                config.reserve_units,
                config.exhaustion_policy,
                actor,
            )
            .map_err(PassRunError::PreAdmission)?,
        None => BudgetGuard::with_reserve_units(
            pass_budget_id.to_owned(),
            config.budget_total_units,
            config.reserve_units,
            config.exhaustion_policy,
        ),
    };
    let mut driver = DreamerWakeDriver::new(vault, pass_budget_id.to_owned(), deadline)
        .with_budget_guard(guard.clone());
    if let Some(author) = config.milestones.clone() {
        driver = driver.with_milestone_author(author);
    }
    let mut executor = factory
        .executor(&guard)
        .map_err(PassRunError::PreAdmission)?;
    let input = RunWakePass {
        trigger,
        scope,
        local_node_id: config.local_node_id,
        lease_owner: config.lease_owner.clone(),
        budget_total_units: config.budget_total_units,
        reserve_units: config.reserve_units,
        now: (*now_secs)(),
    };
    driver
        .run_wake_pass(input, &mut executor, cancel)
        .await
        .map_err(PassRunError::Failed)
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
    use oneiron::attempt_queue::{AttemptId, AttemptState};
    use oneiron::{
        DREAMER_EXECUTOR_ERROR_PARK_REASON, DREAMER_GRACEFUL_WRAP_WINDOW_MS,
        DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerBudgetReserveOutcome,
        DreamerRunnerStore, EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
        ReserveDreamerBudget, VaultConfig, WakeAttemptContext,
    };

    /// Seeds a durable budget row at `budget_id` (init-if-absent via reserve).
    fn seed_budget_row(vault: &Vault, budget_id: &str) {
        let store = DreamerRunnerStore::new(vault);
        match store
            .reserve_budget(ReserveDreamerBudget {
                budget_id: budget_id.to_owned(),
                child_attempt: AttemptId::now(),
                budget_total_units: 1,
                reserve_units: 1,
                now: 1,
            })
            .expect("seed reserve")
        {
            // Only Reserved persists a new counter row; Exhausted on a
            // missing id is in-memory only and must not be treated as seed.
            DreamerBudgetReserveOutcome::Reserved(_) => {}
            other => panic!("expected Reserved seed outcome, got {other:?}"),
        }
        assert!(
            store.budget(budget_id).expect("budget read").is_some(),
            "seeded budget row must exist at {budget_id}"
        );
    }

    fn open_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        (dir, vault)
    }

    fn enqueue_micro(vault: &Vault, tag: &str, now: u64) -> AttemptId {
        match DreamerRunnerStore::new(vault)
            .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
                scope: DreamerConsolidationScope::Micro,
                input: rmpv::Value::from(tag),
                parent_attempt: None,
                dedupe_key: Some(tag.to_owned()),
                run_id: None,
                now,
            })
            .expect("enqueue")
        {
            EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
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

    impl DreamerAttemptExecutor for TestExec {
        async fn execute(
            &mut self,
            _attempt: &DreamerAdmittedAttempt,
            _ctx: &mut WakeAttemptContext<'_>,
        ) -> Result<DreamerAttemptExecution> {
            assert!(!self.panic_now, "scripted executor panic");
            Ok(DreamerAttemptExecution::Completed {
                completed_units: self.completed_units,
            })
        }
    }

    struct TestExecFactory {
        panics_left: u32,
        factory_panics_left: u32,
        /// Pre-admission `Err` count (not panic): surfaces as
        /// [`PassOutcome::PreAdmissionFailed`] so the supervisor re-drives.
        factory_errors_left: u32,
        completed_units: u64,
    }

    impl PassExecutorFactory for TestExecFactory {
        type Exec<'p> = TestExec;

        fn executor<'p>(&'p mut self, _guard: &'p BudgetGuard) -> Result<TestExec> {
            if self.factory_panics_left > 0 {
                self.factory_panics_left -= 1;
                panic!("scripted factory panic");
            }
            if self.factory_errors_left > 0 {
                self.factory_errors_left -= 1;
                return Err(oneiron::Error::InvalidConfig(
                    "scripted pre-admission factory error".into(),
                ));
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
        let (scope, trigger) = pass_shape(&Tick::Hint(crate::tick::HintSignal::default()));
        assert_eq!(scope, DreamerConsolidationScope::Micro);
        assert_eq!(trigger, WakeTrigger::Event);
    }

    #[test]
    fn session_hint_ticks_carry_no_pass_shaping_authority() {
        // H-S4 (ONE-1685): a lifecycle fact on a hint never escalates the
        // pass it provokes — even "explicit end" maps least-privileged
        // here; the Meso consolidation on close is driver policy (a
        // DURABLE queue attempt), not producer authority.
        for hint in [
            crate::SessionHint::AppOpen,
            crate::SessionHint::Activity,
            crate::SessionHint::ExplicitEnd,
        ] {
            let (scope, trigger) = pass_shape(&Tick::Hint(crate::tick::HintSignal {
                session: Some(hint),
            }));
            assert_eq!(scope, DreamerConsolidationScope::Micro);
            assert_eq!(trigger, WakeTrigger::Event);
        }
    }

    #[tokio::test]
    async fn supervisor_pumps_one_pass_per_wake_then_stops_when_exhausted() {
        let (_dir, vault) = open_vault();
        enqueue_micro(&vault, "driver-smoke", 10);

        let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        drop(wake);
        drop(hint);

        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            factory_errors_left: 0,
            completed_units: 40,
        };
        let supervisor = WakeSupervisor::new(&vault, push, factory, test_config());
        let report = supervisor.run().await;

        assert_eq!(report.passes_completed, 1);
        assert_eq!(report.attempts_completed, 1);
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
    async fn panicking_executor_parks_attempt_and_supervisor_continues() {
        // ONE-1683: an executor panic after admission used to unwind past
        // the driver's park/refund code — the supervisor's catch converted
        // it to Panicked by resolving before that bookkeeping ran, leaving
        // the attempt leased and the reservation held until external cleanup.
        // The engine now contains the panic at the attempt boundary: the attempt is
        // parked, the reservation refunded, and the pass surfaces as a
        // FAILED pass the supervisor backs off from and re-drives (same
        // consumed wake drains remaining backlog without a second push).
        let (_dir, vault) = open_vault();
        let first = enqueue_micro(&vault, "panics", 10);
        let second = enqueue_micro(&vault, "completes", 11);

        let wake = Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        });
        // Single wake: Failed redrives; attempt 2 completes on the redrive.
        let ticks = ScriptedTicks { ticks: vec![wake] };
        let factory = TestExecFactory {
            panics_left: 1,
            factory_panics_left: 0,
            factory_errors_left: 0,
            completed_units: 40,
        };
        let mut config = test_config();
        config.backoff = RestartBackoffConfig {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(10),
        };
        let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
        let report = supervisor.run().await;

        assert_eq!(
            report.passes_failed, 1,
            "the contained panic surfaces as a failed pass"
        );
        assert_eq!(report.passes_panicked, 0, "nothing unwound past the driver");
        assert_eq!(
            report.passes_completed, 1,
            "redrive after backoff ran the completing pass"
        );
        assert_eq!(report.attempts_completed, 1);

        // The panicked attempt is parked under the executor-error reason, its
        // reservation refunded; the second attempt settled normally.
        let store = DreamerRunnerStore::new(&vault);
        let parked = store
            .parked_attempt(first)
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
        assert_eq!(status.attempt.state, AttemptState::Completed);
    }

    #[tokio::test(start_paused = true)]
    async fn pass_panic_outside_the_attempt_boundary_restarts_with_backoff() {
        // The supervisor-level catch stays as the backstop for panics the
        // engine cannot contain — anywhere outside exec.execute, here the
        // executor factory. Nothing is leased at that point; Panicked
        // redrives the consumed tick after backoff.
        let (_dir, vault) = open_vault();
        enqueue_micro(&vault, "factory-panics-once", 10);

        let wake = Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        });
        let ticks = ScriptedTicks { ticks: vec![wake] };
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 1,
            factory_errors_left: 0,
            completed_units: 40,
        };
        let mut config = test_config();
        config.backoff = RestartBackoffConfig {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(10),
        };
        let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
        let report = supervisor.run().await;

        assert_eq!(report.passes_panicked, 1, "the backstop caught the panic");
        assert_eq!(
            report.passes_completed, 1,
            "redrive after backoff ran the completing pass"
        );
        assert_eq!(report.attempts_completed, 1);
    }

    /// Completes attempts synchronously and requests supervisor shutdown from
    /// inside the first execution — without an attempt-boundary yield the whole
    /// backlog would drain in a single poll before the biased select! ever
    /// saw the request.
    struct ShutdownRequestingExec {
        handle: ShutdownHandle,
    }

    impl DreamerAttemptExecutor for ShutdownRequestingExec {
        async fn execute(
            &mut self,
            _attempt: &DreamerAdmittedAttempt,
            _ctx: &mut WakeAttemptContext<'_>,
        ) -> Result<DreamerAttemptExecution> {
            self.handle.shutdown();
            Ok(DreamerAttemptExecution::Completed {
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
    async fn shutdown_during_synchronous_pass_stops_at_the_next_attempt_boundary() {
        // ONE-1683: run_wake_pass yields once per attempt boundary, so a
        // shutdown requested while a synchronously-completing pass is
        // running raises the cancellation flag after the in-flight attempt —
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
            report.attempts_completed, 1,
            "the pass stopped at the first attempt boundary after the request"
        );

        // The rest of the queue is untouched, ready for the next run.
        let store = DreamerRunnerStore::new(&vault);
        for id in [second, third] {
            let status = store.status(id).expect("status read").expect("status");
            assert_eq!(status.attempt.state, AttemptState::Queued, "never claimed");
        }
    }

    #[tokio::test]
    async fn shutdown_between_passes_stops_the_loop() {
        let (_dir, vault) = open_vault();
        let (push, _wake, _hint) =
            PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            factory_errors_left: 0,
            completed_units: 0,
        };
        let supervisor = WakeSupervisor::new(&vault, push, factory, test_config());
        let handle = supervisor.shutdown_handle();
        handle.shutdown();
        let report = supervisor.run().await;
        assert_eq!(report, WakeSupervisorReport::default(), "no pass ran");
    }

    #[tokio::test]
    async fn second_pass_runs_attempts_after_first_pass_budget_exhausts() {
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
            // Two passes: first exhausts after one attempt; second must still
            // be able to admit the remaining attempt.
            ticks: vec![wake, wake],
        };
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            factory_errors_left: 0,
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
            report.attempts_completed, 2,
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
            assert_eq!(
                status.attempt.state,
                AttemptState::Completed,
                "attempt under {pass_id}"
            );
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
        let attempt_a = enqueue_micro(&vault, "due-a", 10);
        let attempt_b = enqueue_micro(&vault, "due-b", 11);

        // Attempts are due at created_at * 1000 ms; clock is far past that so
        // HybridTick short-circuits to Deadline every cycle until empty.
        let now_ms: crate::tick::NowMillis = Arc::new(|| 1_000_000);
        let timer = crate::TimerTick::with_clock(
            crate::AttemptQueueDeadlines::new(&vault, 1),
            Arc::clone(&now_ms),
        );
        let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        // No push producers: once the queue is empty the hybrid source
        // exhausts and the supervisor must stop.
        drop(wake);
        drop(hint);
        let hybrid = crate::HybridTick::new(timer, push);

        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            factory_errors_left: 0,
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
            report.attempts_completed, 2,
            "due work must drain across per-pass budgets"
        );
        // Exactly two productive passes (one attempt each under the 150-unit
        // grant) — not an unbounded series of empty BudgetExhausted polls.
        assert_eq!(report.passes_completed, 2);
        assert_eq!(report.passes_failed, 0);
        assert_eq!(report.passes_panicked, 0);

        let store = DreamerRunnerStore::new(&vault);
        for id in [attempt_a, attempt_b] {
            let status = store.status(id).expect("status read").expect("status");
            assert_eq!(
                status.attempt.state,
                AttemptState::Completed,
                "queue fully drained"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn zero_progress_budget_exhausted_backs_off_instead_of_hot_looping() {
        // Permanently un-admittable grant (total < reserve): every pass
        // hits BudgetExhausted with admitted == 0. Zero-progress backs off
        // and redrives the same tick (permanent failure = capped-backoff
        // retry forever, same contract as HybridTick redelivery). Shutdown
        // during backoff ends the loop without a hot spin.
        let (_dir, vault) = open_vault();
        let stuck = enqueue_micro(&vault, "stuck-due", 10);

        let wake = Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        });
        let ticks = ScriptedTicks { ticks: vec![wake] };
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            factory_errors_left: 0,
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
        let handle = supervisor.shutdown_handle();
        // Enough virtual time for several empty redrive+backoff cycles.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(55)).await;
            handle.shutdown();
        });
        let report = supervisor.run().await;

        assert!(
            report.passes_completed >= 3,
            "multiple empty redrives before shutdown, got {}",
            report.passes_completed
        );
        assert_eq!(report.attempts_completed, 0, "nothing was admittable");
        assert_eq!(report.passes_failed, 0);
        assert_eq!(report.passes_panicked, 0);
        // Attempt remains queued — BudgetExhausted before reserve does not
        // claim or park, so the due work is still waiting for a usable grant.
        let status = DreamerRunnerStore::new(&vault)
            .status(stuck)
            .expect("status read")
            .expect("status");
        assert_eq!(status.attempt.state, AttemptState::Queued);
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

    #[test]
    fn config_validate_rejects_base_ids_that_overflow_derived_length() {
        let ok = WakeSupervisorConfig::new("b".repeat(MAX_PASS_BUDGET_BASE_LEN), "owner", 1, 100);
        assert!(ok.validate().is_ok());

        let over =
            WakeSupervisorConfig::new("b".repeat(MAX_PASS_BUDGET_BASE_LEN + 1), "owner", 1, 100);
        let error = over.validate().expect_err("over-long base must reject");
        assert!(matches!(error, oneiron::Error::InvalidConfig(_)));
    }

    /// Pins the mirrored `MAX_RUNNER_BUDGET_ID_LEN` against the real store:
    /// the widest derived id a valid base can produce must pass runner-store
    /// validation, and one byte more must fail. If oneiron's private ceiling
    /// drifts, this test breaks instead of the supervisor spinning at runtime.
    #[test]
    fn widest_derived_pass_budget_id_fits_the_runner_store_ceiling() {
        let (_dir, vault) = open_vault();

        let widest = durable_pass_budget_id(&"b".repeat(MAX_PASS_BUDGET_BASE_LEN), u64::MAX);
        assert_eq!(widest.len(), MAX_RUNNER_BUDGET_ID_LEN);
        seed_budget_row(&vault, &widest);
        assert!(
            DreamerRunnerStore::new(&vault)
                .budget(&widest)
                .expect("probe widest id")
                .is_some(),
            "widest derived id must be storable"
        );

        let over_long = format!("{widest}b");
        let outcome = DreamerRunnerStore::new(&vault).budget(&over_long);
        assert!(
            outcome.is_err(),
            "one byte past the ceiling must fail store validation"
        );
    }

    #[tokio::test]
    async fn over_long_budget_base_refuses_to_run_instead_of_spinning() {
        let (_dir, vault) = open_vault();
        let (push, _wake, _hint) =
            PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            factory_errors_left: 0,
            completed_units: 0,
        };
        let config =
            WakeSupervisorConfig::new("b".repeat(MAX_PASS_BUDGET_BASE_LEN + 1), "owner", 1, 100);
        let supervisor = WakeSupervisor::new(&vault, push, factory, config);
        let report = supervisor.run().await;
        assert_eq!(report, WakeSupervisorReport::default(), "no pass may run");
    }

    #[tokio::test]
    async fn restart_resumes_pass_budget_index_after_existing_rows() {
        // P1 (codex r3/r4): pass_index was in-memory only and reset to 0 on
        // every WakeSupervisor::run, so a process restart re-minted :p0
        // against a spent row (DreamerRunnerStore reuses existing budgets).
        // Startup scan must resume at highest-occupied + 1 (here :p2).
        let (_dir, vault) = open_vault();
        let first = enqueue_micro(&vault, "restart-p0", 10);
        let second = enqueue_micro(&vault, "restart-p1", 11);

        let wake = Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        });
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            factory_errors_left: 0,
            completed_units: 100,
        };
        let mut config = test_config();
        config.budget_total_units = 150;
        config.reserve_units = 100;

        // First supervisor "run" (pre-restart): exhausts :p0 and :p1.
        let ticks = ScriptedTicks {
            ticks: vec![wake, wake],
        };
        let report = WakeSupervisor::new(&vault, ticks, factory, config.clone())
            .run()
            .await;
        assert_eq!(report.passes_completed, 2);
        assert_eq!(report.attempts_completed, 2);

        let store = DreamerRunnerStore::new(&vault);
        assert!(
            store.budget("driver-budget:p0").expect("p0").is_some(),
            "first run wrote :p0"
        );
        assert!(
            store.budget("driver-budget:p1").expect("p1").is_some(),
            "first run wrote :p1"
        );
        assert!(
            store.budget("driver-budget:p2").expect("p2").is_none(),
            "first run must not have touched :p2"
        );
        for id in [first, second] {
            let status = store.status(id).expect("status").expect("row");
            assert_eq!(status.attempt.state, AttemptState::Completed);
        }

        // Simulated restart: new supervisor instance, same base budget_id,
        // one queued attempt — must mint :p2 (not walk :p0/:p1 spent rows).
        let third = enqueue_micro(&vault, "restart-p2", 12);
        let ticks = ScriptedTicks { ticks: vec![wake] };
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            factory_errors_left: 0,
            completed_units: 40,
        };
        // Fresh grant large enough for one attempt under the restarted pass.
        let mut restart_config = config;
        restart_config.budget_total_units = 10_000;
        let report = WakeSupervisor::new(&vault, ticks, factory, restart_config)
            .run()
            .await;

        assert_eq!(report.passes_completed, 1);
        assert_eq!(
            report.attempts_completed, 1,
            "restarted supervisor must drain under a fresh :p2 row"
        );
        assert_eq!(report.passes_failed, 0);
        assert_eq!(report.passes_panicked, 0);

        let status = store.status(third).expect("status").expect("row");
        assert_eq!(status.attempt.state, AttemptState::Completed);
        let budget = store
            .budget("driver-budget:p2")
            .expect("p2 read")
            .expect("restart must write driver-budget:p2");
        assert_eq!(budget.reserved_units, 0);
        assert_eq!(budget.remaining_units, 10_000 - 40);
        assert_eq!(budget.total_units, 10_000);
        // Spent pre-restart rows must not have been rewritten as the
        // restart pass's working counter (still the 150-unit grant).
        let p0 = store
            .budget("driver-budget:p0")
            .expect("p0")
            .expect("p0 still present");
        assert_eq!(p0.total_units, 150);
        assert_eq!(p0.remaining_units, 50);
    }

    #[test]
    fn pass_budget_index_scan_is_bounded_and_falls_back() {
        // Highest-occupied + 1: dense-scan [0, bound). When every index in
        // [0, bound) already has a durable row and :p{bound} is free, the
        // scan returns `bound` (first free past the dense window). Production
        // uses PASS_BUDGET_INDEX_SCAN_BOUND; tests pin a tiny bound.
        const BOUND: u64 = 4;

        let (_dir, vault) = open_vault();
        let base = "scan-bound-budget";

        assert_eq!(
            next_pass_budget_index_with_bound(&vault, base, BOUND),
            0,
            "empty vault starts at p0"
        );

        for n in 0..BOUND {
            seed_budget_row(&vault, &durable_pass_budget_id(base, n));
        }
        assert_eq!(
            next_pass_budget_index_with_bound(&vault, base, BOUND),
            BOUND,
            "full [0, bound) with free :p{{bound}} resumes at bound"
        );

        // Empty :p0 (hole) with only :p1 occupied — the r4 collision:
        // first-absent would return 0 and later collide with stale :p1;
        // highest-occupied + 1 resumes at p2.
        let (_dir_hole, vault_hole) = open_vault();
        seed_budget_row(&vault_hole, &durable_pass_budget_id(base, 1));
        assert_eq!(
            next_pass_budget_index_with_bound(&vault_hole, base, BOUND),
            2,
            "hole at p0 with occupied p1 → start at p2, not p0/p1"
        );

        // Hole at p1 while p0 and p2 exist: skip the hole, resume after max.
        let (_dir2, vault2) = open_vault();
        seed_budget_row(&vault2, &durable_pass_budget_id(base, 0));
        seed_budget_row(&vault2, &durable_pass_budget_id(base, 2));
        assert_eq!(
            next_pass_budget_index_with_bound(&vault2, base, BOUND),
            3,
            "hole at p1 with occupied p2 → start at p3 (highest+1), not p1"
        );

        // Production bound is the large fixed constant (inspectable).
        assert_eq!(PASS_BUDGET_INDEX_SCAN_BOUND, 65_536);
    }

    // --- r5 codex P2s -------------------------------------------------------

    #[test]
    fn config_validate_rejects_zero_local_node_id() {
        let mut config = WakeSupervisorConfig::new("budget", "owner", 0, 100);
        // Default ceiling is valid; only the node id is wrong.
        let error = config.validate().expect_err("local_node_id=0 must reject");
        assert!(matches!(error, oneiron::Error::InvalidConfig(_)));

        config.local_node_id = 1;
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn zero_local_node_id_refuses_to_run_instead_of_ticking() {
        let (_dir, vault) = open_vault();
        enqueue_micro(&vault, "never-touched", 10);
        let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        drop(wake);
        drop(hint);
        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            factory_errors_left: 0,
            completed_units: 40,
        };
        let config = WakeSupervisorConfig::new("driver-budget", "driver-worker", 0, 10_000);
        let supervisor = WakeSupervisor::new(&vault, push, factory, config);
        let report = supervisor.run().await;
        assert_eq!(
            report,
            WakeSupervisorReport::default(),
            "invalid local_node_id must fail-fast with no pass"
        );
    }

    #[test]
    fn config_validate_rejects_pass_ceiling_at_or_below_wrap_window() {
        let mut config = test_config();
        config.pass_ceiling_ms = DREAMER_GRACEFUL_WRAP_WINDOW_MS;
        let error = config
            .validate()
            .expect_err("ceiling == wrap window must reject");
        assert!(matches!(error, oneiron::Error::InvalidConfig(_)));

        config.pass_ceiling_ms = 0;
        assert!(config.validate().is_err());

        config.pass_ceiling_ms = DREAMER_GRACEFUL_WRAP_WINDOW_MS.saturating_sub(1);
        assert!(config.validate().is_err());

        config.pass_ceiling_ms = DREAMER_GRACEFUL_WRAP_WINDOW_MS + 1;
        assert!(config.validate().is_ok());
    }

    /// Factory that sleeps past the finalize threshold for a
    /// `pass_ceiling_ms = WRAP + 1` config, so Instant-elapsed hard-cuts
    /// before any admission (defense path for runtime-induced empty cuts).
    /// `delays_left` counts how many factory calls still sleep (then the
    /// redrive path can complete work without a second push).
    struct DelayedHardCutFactory {
        completed_units: u64,
        delay: Duration,
        delays_left: u32,
    }

    impl PassExecutorFactory for DelayedHardCutFactory {
        type Exec<'p> = TestExec;

        fn executor<'p>(&'p mut self, _guard: &'p BudgetGuard) -> Result<TestExec> {
            // Advances the real Instant behind WakePassDeadline::new so the
            // pass is already in the finalize window when run_wake_pass starts.
            if self.delays_left > 0 {
                self.delays_left -= 1;
                std::thread::sleep(self.delay);
            }
            Ok(TestExec {
                panic_now: false,
                completed_units: self.completed_units,
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn zero_progress_deadline_hard_cut_backs_off_instead_of_hot_looping() {
        // Valid ceiling (just above wrap window) + factory delay past the
        // 1ms finalize threshold → DeadlineHardCut with admitted == 0.
        // Zero-progress redrives forever under capped backoff until shutdown
        // (same permanent-failure contract as HybridTick redelivery).
        let (_dir, vault) = open_vault();
        let stuck = enqueue_micro(&vault, "hard-cut-stuck", 10);

        let wake = Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        });
        let ticks = ScriptedTicks { ticks: vec![wake] };
        let factory = DelayedHardCutFactory {
            completed_units: 40,
            delay: Duration::from_millis(5),
            delays_left: u32::MAX,
        };
        let mut config = test_config();
        config.pass_ceiling_ms = DREAMER_GRACEFUL_WRAP_WINDOW_MS + 1;
        config.backoff = RestartBackoffConfig {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(10),
        };

        let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
        let handle = supervisor.shutdown_handle();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(45)).await;
            handle.shutdown();
        });
        let report = supervisor.run().await;

        assert!(
            report.passes_completed >= 2,
            "multiple empty hard-cut redrives before shutdown, got {}",
            report.passes_completed
        );
        assert_eq!(report.attempts_completed, 0, "hard-cut before admission");
        assert_eq!(report.passes_failed, 0);
        assert_eq!(report.passes_panicked, 0);
        let status = DreamerRunnerStore::new(&vault)
            .status(stuck)
            .expect("status read")
            .expect("status");
        assert_eq!(status.attempt.state, AttemptState::Queued);
    }

    #[tokio::test(start_paused = true)]
    async fn pre_admission_factory_error_redrives_push_tick_after_backoff() {
        // PushTick-only: one wake is drained, factory returns Err before
        // admission, then succeeds. Without re-drive the wake is lost and
        // the attempt stays queued forever.
        let (_dir, vault) = open_vault();
        let attempt = enqueue_micro(&vault, "redrive-after-factory-err", 10);

        let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        // Drop producers so the source exhausts after the re-driven pass
        // completes (no second push).
        drop(wake);
        drop(hint);

        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            factory_errors_left: 1,
            completed_units: 40,
        };
        let mut config = test_config();
        config.backoff = RestartBackoffConfig {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(10),
        };
        let supervisor = WakeSupervisor::new(&vault, push, factory, config);
        let report = supervisor.run().await;

        assert_eq!(
            report.passes_failed, 1,
            "one pre-admission factory Err counted as failed"
        );
        assert_eq!(
            report.passes_completed, 1,
            "re-driven tick must run a successful pass"
        );
        assert_eq!(
            report.attempts_completed, 1,
            "attempt admitted on the re-driven tick"
        );
        assert_eq!(report.passes_panicked, 0);

        let status = DreamerRunnerStore::new(&vault)
            .status(attempt)
            .expect("status read")
            .expect("status");
        assert_eq!(status.attempt.state, AttemptState::Completed);
        // Pre-admission failure must not burn a durable budget row: success
        // lands on :p0 (pass_index kept across the re-drive).
        let budget = DreamerRunnerStore::new(&vault)
            .budget("driver-budget:p0")
            .expect("budget read")
            .expect("success pass writes :p0");
        assert_eq!(budget.remaining_units, 10_000 - 40);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_during_preadmission_redrive_exits_cleanly() {
        // Factory always fails pre-admission; shutdown during the re-drive
        // backoff must exit without hanging on the next push wait.
        let (_dir, vault) = open_vault();
        enqueue_micro(&vault, "shutdown-redrive", 10);

        let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        // Keep producers alive so next_tick would otherwise wait forever —
        // the only exit is shutdown during re-drive backoff.
        let _wake = wake;
        let _hint = hint;

        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 0,
            // Keep failing so every attempt is pre-admission + re-drive.
            factory_errors_left: u32::MAX,
            completed_units: 40,
        };
        let mut config = test_config();
        config.backoff = RestartBackoffConfig {
            initial: Duration::from_millis(50),
            max: Duration::from_millis(50),
        };
        let supervisor = WakeSupervisor::new(&vault, push, factory, config);
        let handle = supervisor.shutdown_handle();
        // Let at least one failed attempt start its backoff, then stop.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            handle.shutdown();
        });
        let report = tokio::time::timeout(Duration::from_secs(2), supervisor.run())
            .await
            .expect("shutdown during re-drive must not hang");
        assert!(
            report.passes_failed >= 1,
            "at least one pre-admission failure before shutdown"
        );
        assert_eq!(report.passes_completed, 0);
        assert_eq!(report.attempts_completed, 0);
    }

    #[test]
    fn restart_scan_gallops_past_occupied_bound() {
        // P2 (codex r5): when [0, bound) is full AND :p{bound}/later are
        // occupied, clamp-to-bound reused spent rows. Gallop + binary
        // search must resume at the first free suffix past the dense window.
        const BOUND: u64 = 4;

        let (_dir, vault) = open_vault();
        let base = "gallop-past-bound";

        // Occupy 0..BOUND+3 → first free is BOUND+3.
        for n in 0..(BOUND + 3) {
            seed_budget_row(&vault, &durable_pass_budget_id(base, n));
        }
        assert_eq!(
            next_pass_budget_index_with_bound(&vault, base, BOUND),
            BOUND + 3,
            "must skip occupied rows past the dense-scan bound"
        );

        // Sparse occupation past bound: dense full, free gap, then occupied.
        let (_dir2, vault2) = open_vault();
        for n in 0..BOUND {
            seed_budget_row(&vault2, &durable_pass_budget_id(base, n));
        }
        seed_budget_row(&vault2, &durable_pass_budget_id(base, BOUND));
        seed_budget_row(&vault2, &durable_pass_budget_id(base, BOUND + 2));
        // :p{BOUND+1} free — first free after dense+gallop.
        assert_eq!(
            next_pass_budget_index_with_bound(&vault2, base, BOUND),
            BOUND + 1,
            "binary search must land on the first free past bound"
        );

        // Only :p{bound} occupied after a full dense window.
        let (_dir3, vault3) = open_vault();
        for n in 0..=BOUND {
            seed_budget_row(&vault3, &durable_pass_budget_id(base, n));
        }
        assert_eq!(
            next_pass_budget_index_with_bound(&vault3, base, BOUND),
            BOUND + 1
        );
    }

    #[test]
    fn per_pass_probe_skips_stale_rows_instead_of_reusing_them() {
        // P2 (codex r6): a resume index landing in an empty-pass hole below
        // still-occupied higher suffixes must not advance onto a spent row
        // the store would silently reuse. The per-pass probe skips every
        // occupied row and passes a free index through untouched.
        let (_dir, vault) = open_vault();
        let base = "per-pass-skip";
        seed_budget_row(&vault, &durable_pass_budget_id(base, 5));
        seed_budget_row(&vault, &durable_pass_budget_id(base, 6));

        assert_eq!(advance_past_occupied_pass_rows(&vault, base, 5), 7);
        assert_eq!(advance_past_occupied_pass_rows(&vault, base, 6), 7);
        assert_eq!(advance_past_occupied_pass_rows(&vault, base, 3), 3);
        assert_eq!(advance_past_occupied_pass_rows(&vault, base, 7), 7);
    }

    // --- r6: validate admission fields + unified redrive family ---

    #[test]
    fn config_validate_rejects_zero_reserve_units_and_bad_lease_owner() {
        // P2 (codex r6): reserve_units==0 / empty / overlong lease_owner
        // passed validate but admission rejected before mutating rows,
        // surfacing as Failed (tick consumed). Fail-fast in validate.
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.reserve_units = 0;
        let error = config.validate().expect_err("reserve_units=0 must reject");
        assert!(matches!(error, oneiron::Error::InvalidConfig(_)));
        config.reserve_units = 100;
        assert!(config.validate().is_ok());

        config.lease_owner.clear();
        let error = config
            .validate()
            .expect_err("empty lease_owner must reject");
        assert!(matches!(error, oneiron::Error::InvalidConfig(_)));

        config.lease_owner = "x".repeat(MAX_RUNNER_LEASE_OWNER_LEN + 1);
        let error = config
            .validate()
            .expect_err("overlong lease_owner must reject");
        assert!(matches!(error, oneiron::Error::InvalidConfig(_)));

        config.lease_owner = "x".repeat(MAX_RUNNER_LEASE_OWNER_LEN);
        assert!(
            config.validate().is_ok(),
            "exactly MAX_RUNNER_LEASE_OWNER_LEN is allowed"
        );
    }

    /// Pins the mirrored lease-owner ceiling against the real attempt queue:
    /// a claim with an owner of `MAX_RUNNER_LEASE_OWNER_LEN` must be
    /// accepted at the validation boundary, and one byte more must fail.
    #[test]
    fn widest_lease_owner_fits_attempt_queue_ceiling() {
        use oneiron::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND;
        use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};

        let (_dir, vault) = open_vault();
        enqueue_micro(&vault, "lease-owner-ceiling", 10);
        let queue = AttemptQueue::new(&vault);

        let ok_owner = "o".repeat(MAX_RUNNER_LEASE_OWNER_LEN);
        let claimed = queue
            .claim_kind(
                DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: ok_owner,
                    now: 20,
                },
            )
            .expect("claim with max-length owner must validate");
        assert!(
            matches!(claimed, ClaimOutcome::Claimed(_)),
            "max-length lease_owner must be admissible"
        );

        // Overlong fails validation before scanning — no need for another attempt.
        let over = "o".repeat(MAX_RUNNER_LEASE_OWNER_LEN + 1);
        let err = queue
            .claim_kind(
                DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: over,
                    now: 21,
                },
            )
            .expect_err("overlong lease_owner must fail attempt-queue validation");
        assert!(
            matches!(err, oneiron::Error::InvalidAttemptQueueRecord(_)),
            "expected InvalidAttemptQueueRecord, got {err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn setup_panic_before_admission_redrives_push_tick() {
        // P2 (codex r6 / 3585850170): factory panic before admission on a
        // PushTick-only supervisor. Single wake, panics once → redrive after
        // backoff completes the attempt (no second push).
        let (_dir, vault) = open_vault();
        let attempt = enqueue_micro(&vault, "factory-panic-redrive", 10);

        let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        drop(wake);
        drop(hint);

        let factory = TestExecFactory {
            panics_left: 0,
            factory_panics_left: 1,
            factory_errors_left: 0,
            completed_units: 40,
        };
        let mut config = test_config();
        config.backoff = RestartBackoffConfig {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(10),
        };
        let supervisor = WakeSupervisor::new(&vault, push, factory, config);
        let report = supervisor.run().await;

        assert_eq!(report.passes_panicked, 1, "one setup panic counted");
        assert_eq!(
            report.passes_completed, 1,
            "redrive after backoff must complete a pass"
        );
        assert_eq!(report.attempts_completed, 1);
        assert_eq!(report.passes_failed, 0);

        let status = DreamerRunnerStore::new(&vault)
            .status(attempt)
            .expect("status read")
            .expect("status");
        assert_eq!(status.attempt.state, AttemptState::Completed);
    }

    #[tokio::test(start_paused = true)]
    async fn in_pass_failure_with_backlog_redrives_without_second_push() {
        // P2 (codex r6 / 3585850187): single wake, two queued attempts; first
        // pass fails after admitting attempt 1 (executor panic → park+Failed).
        // Redrive drains attempt 2 without a second push.
        let (_dir, vault) = open_vault();
        let first = enqueue_micro(&vault, "fail-after-admit-1", 10);
        let second = enqueue_micro(&vault, "fail-after-admit-2", 11);

        let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        drop(wake);
        drop(hint);

        let factory = TestExecFactory {
            panics_left: 1,
            factory_panics_left: 0,
            factory_errors_left: 0,
            completed_units: 40,
        };
        let mut config = test_config();
        config.backoff = RestartBackoffConfig {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(10),
        };
        let supervisor = WakeSupervisor::new(&vault, push, factory, config);
        let report = supervisor.run().await;

        assert_eq!(report.passes_failed, 1, "in-pass failure counted once");
        assert_eq!(
            report.passes_completed, 1,
            "redrive completes the backlog pass"
        );
        assert_eq!(
            report.attempts_completed, 1,
            "attempt 2 completed on redrive"
        );
        assert_eq!(report.passes_panicked, 0);

        let store = DreamerRunnerStore::new(&vault);
        let parked = store
            .parked_attempt(first)
            .expect("parked read")
            .expect("attempt 1 parked");
        assert!(
            parked
                .reason
                .starts_with(DREAMER_EXECUTOR_ERROR_PARK_REASON),
            "attempt 1 park reason: {}",
            parked.reason
        );
        let status = store
            .status(second)
            .expect("status read")
            .expect("attempt 2 status");
        assert_eq!(status.attempt.state, AttemptState::Completed);
    }

    #[tokio::test(start_paused = true)]
    async fn empty_completed_pass_redrives_then_completes_without_second_push() {
        // P2 (codex r6 / 3585850199): single wake, first pass zero-progress
        // DeadlineHardCut (admitted == 0) → backoff + redrive; second pass
        // admits and completes without a second push.
        //
        // Ceiling WRAP+50 → finalize opens at 50ms. First factory call sleeps
        // 60ms (past finalize); redrive call does not sleep so the pass has
        // ~50ms of wall budget — enough to admit one scripted attempt.
        let (_dir, vault) = open_vault();
        let attempt = enqueue_micro(&vault, "empty-then-complete", 10);

        let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        drop(wake);
        drop(hint);

        let factory = DelayedHardCutFactory {
            completed_units: 40,
            delay: Duration::from_millis(60),
            delays_left: 1,
        };
        let mut config = test_config();
        config.pass_ceiling_ms = DREAMER_GRACEFUL_WRAP_WINDOW_MS + 50;
        config.backoff = RestartBackoffConfig {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(10),
        };
        let supervisor = WakeSupervisor::new(&vault, push, factory, config);
        let report = supervisor.run().await;

        assert_eq!(
            report.passes_completed, 2,
            "one empty hard-cut + one productive redrive"
        );
        assert_eq!(report.attempts_completed, 1);
        assert_eq!(report.passes_failed, 0);
        assert_eq!(report.passes_panicked, 0);

        let status = DreamerRunnerStore::new(&vault)
            .status(attempt)
            .expect("status read")
            .expect("status");
        assert_eq!(status.attempt.state, AttemptState::Completed);
    }
}
