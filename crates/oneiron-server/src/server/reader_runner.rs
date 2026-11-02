//! The reader runner (ARCH-0079 #reader-forks): runs the reader children a
//! code run's `self.spawn` queues, each a run of its own on the code-run
//! pool, and keeps their clock.
//!
//! The vault wakes it when a child is queued, and it only notes the wake.
//! One worker thread first claims again what a stopped runner left active,
//! then ticks: the due sweep, which settles every wait set and child past its
//! cutoff and delivers each settled set to its parked parent, then claims of
//! queued children while the window has room. It ticks on each wake, at the
//! next due row, and once a second; a child whose source was not yet
//! committed, or whose parent had nothing left to spend, is tried again then.
//!
//! The window is the code-run pool's free permits, taken as the host's own
//! work behind every caller, and per parent its run-memory share over what
//! one child holds. Total work is never capped: the rest stays queued.
//!
//! Each child runs on its own thread with its own reactor, as `execute_code`
//! does: a fresh sandbox, a dispatcher bound to its job, a door that admits
//! only its report and its reads, and a backend that spends on its own child
//! scope, or on the host's code-mode meter when its run spends under no
//! scope. It stops at its cutoff and settles as its run ended. An off-record
//! session's children run in its overlay and are not restart-durable: the
//! overlay evaporates.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant};

use oneiron::agent_def::{birth_under_inherited_list, ensure_inherited_model_list};
use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::claim::CallerLocality;
use oneiron::code_run::{
    AgentVerbDoor, ClaimOutcome, DEFAULT_READER_WINDOW_TOKENS, HostSelfDispatcher, ReaderJob,
    ReaderJobKind, ReaderJobRunner, ReaderJobWake, ReaderJobs, ReaderRunEnd, ReaderSpend,
    RunDeadline, SCOPED_CHILD_PARENT_LEASE_LOST, SUMMARY_READ_BYTES_PER_TOKEN, ScopedChildPorts,
    ScopedChildProfile, SpawnHostSeat, SummarizeRecipe, SummaryRead, reader_task_brief,
    summarize_input, summarize_prompt, summary_exceeds_window, summary_token_budget,
};
use oneiron::engine_executor::{
    ENGINE_EXECUTOR_PURPOSE_NAME, EngineExecutorError, EngineExecutorStatus, EngineNativeExecutor,
    JsCodeModeRuntime,
};
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::BudgetDenied;
use oneiron::llm::seat::{ModelSeat, SeatKind, SeatTask};
use oneiron::off_record::OffRecordSession;
use oneiron::settings::ReadDestination;
use oneiron::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, EntityId, LlmBackend, LlmError,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence, Vault,
};

use crate::admission::Permit;
use crate::ai_host::payer_funding::scope_funding;
use crate::ai_host::scoped_child::{
    ReaderParentClock, ReaderParentHost, ScopedChildDoor, scoped_child_service,
};
use crate::mcp::{McpCodeExecutionHost, McpCodeModeProvider, run_seat};
use crate::runtime::wall_clock_ms as unix_millis_now;

mod child;
mod scoped;

/// The window a run with no decision clock gives its children: one, fixed
/// at its first spawn.
pub(crate) const DEFAULT_READER_WINDOW_MS: u64 = 600_000;

/// What one running child is taken to hold in memory: its 24 MiB guest heap
/// plus one context window's cache.
const READER_RESIDENT_BYTES: u64 = 32 << 20;

/// The longest the worker waits between two ticks.
const TICK: Duration = Duration::from_secs(1);

/// Queued children one tick looks at in one store.
const QUEUED_PER_TICK: usize = 64;

/// The purpose a summary job's model call is admitted under.
const SUMMARY_PURPOSE_NAME: &str = "code-reader-summary";

/// What a reader child's door answers every call but its report, its
/// `self.context` and `self.think`, and its reads: the engine's own word.
pub(crate) const READER_CHILD_READ_ONLY: &str = "reader_child_read_only";

/// The seats hosts lend their runs to spawn readers under, and where each
/// parent run's caller's rows go, as its host noted it at the run's last
/// entry: its locality, with the machine its connection proved (FIX 4937).
pub(crate) struct ReaderSeats {
    callers: Mutex<HashMap<EntityId, (ReadDestination, u64)>>,
    /// Each parent run's live clock, as its host last lent it (FIX 1839):
    /// it bounds the parent's children's work beside the clock its first
    /// spawn froze, and is forgotten with the parent's caller.
    clocks: Mutex<HashMap<EntityId, ReaderParentClock>>,
    /// The memory one running child may hold: its run's memory share over
    /// the children one parent runs at once.
    child_memory_bytes: u64,
}

impl ReaderSeats {
    fn new(child_memory_bytes: u64) -> Self {
        Self {
            callers: Mutex::default(),
            clocks: Mutex::default(),
            child_memory_bytes,
        }
    }

    /// The seat run `run` spawns its children under. `scope` is the scope
    /// the run's own model calls spend under, if any, and
    /// [`ReaderSpend::for_run_scope`] picks what its children spend on from
    /// it: under that scope, where one that is not open answers every spawn
    /// `reader_spawn_unmetered`, else on the host's meter. Their clock is
    /// one window from now, which the run's first spawn fixes. `caller` is
    /// where the run's caller sits, noted for its children's reads.
    /// `window_tokens` is the input window of the model its children and
    /// summaries run on, when its host knows it. A clockless, leaseless
    /// parent's: [`Self::seat_with_parent`] with none.
    pub(crate) fn seat(
        &self,
        run: EntityId,
        scope: Option<SpendScopeId>,
        caller: impl Into<ReadDestination>,
        window_tokens: Option<u64>,
    ) -> SpawnHostSeat {
        self.seat_with_parent(run, scope, caller, window_tokens, None)
    }

    /// [`Self::seat`] for a parent its host lends `parent` (FIX 1839, FIX
    /// 7507 PR3): the live clock it runs under, which the run's first spawn
    /// freezes into its parent row once (`reader_parent_deadline`) and which
    /// bounds its children's model and port work beside that row, and the
    /// lease of the attempt it runs as, which a scoped child queued under
    /// this seat borrows. With none, the run's clock is one window from now
    /// and its children outlive it, as before.
    pub(crate) fn seat_with_parent(
        &self,
        run: EntityId,
        scope: Option<SpendScopeId>,
        caller: impl Into<ReadDestination>,
        window_tokens: Option<u64>,
        parent: Option<&ReaderParentHost>,
    ) -> SpawnHostSeat {
        let now = unix_millis_now();
        lock(&self.callers).insert(run, (caller.into(), now));
        let clock = parent.and_then(ReaderParentHost::clock);
        if let Some(clock) = clock {
            lock(&self.clocks).insert(run, clock);
        }
        SpawnHostSeat {
            spend: ReaderSpend::for_run_scope(scope),
            deadline: reader_parent_deadline(clock, now),
            // A child holds nothing at its claim: it tops up from its
            // parent's chain as it spends, the cap enforced at each spend.
            hold_units: 0,
            window_tokens: window_tokens.unwrap_or(DEFAULT_READER_WINDOW_TOKENS),
            memory_bytes: self.child_memory_bytes,
            // Any eligible model: an agent's run lends its own list
            // (`run_bound`, and a session run's `parent_model_list`).
            listed: Vec::new(),
            parent_lease: parent.and_then(ReaderParentHost::lease).cloned(),
        }
    }

    /// The live clock `parent`'s host last lent it, if any.
    fn clock(&self, parent: EntityId) -> Option<ReaderParentClock> {
        lock(&self.clocks).get(&parent).copied()
    }

    /// Where `parent`'s caller's rows go: as its host last noted it, else a
    /// destination nobody proved, the rule that withholds the most. A child
    /// gets a copy of that destination, never its parent's credential.
    fn caller(&self, parent: EntityId) -> ReadDestination {
        lock(&self.callers).get(&parent).map_or_else(
            || CallerLocality::OffDevice.into(),
            |(caller, _)| caller.clone(),
        )
    }

    /// Forgets every parent last noted more than two windows before `now`,
    /// with its live clock.
    fn forget_before(&self, now: u64) {
        let horizon = now.saturating_sub(DEFAULT_READER_WINDOW_MS.saturating_mul(2));
        let mut callers = lock(&self.callers);
        callers.retain(|_, (_, noted)| *noted >= horizon);
        lock(&self.clocks).retain(|run, _| callers.contains_key(run));
    }
}

/// `reader_parent_deadline` (CALLS, open): the clock a parent's first spawn
/// freezes at `now_ms` from the live `clock` its host lends. With none, one
/// window from now (`DEFAULT_READER_WINDOW_MS`), unchanged. A present clock
/// is projected once to what is left of it, an expired one to now (it is
/// expired, never given the window), and its children stop at the existing
/// fold reserve before it (`RunDeadline::with_default_reserve`), taken once.
/// A parent under a wake and a decision clock at once lends the earlier
/// (`ReaderParentClock::earlier`).
fn reader_parent_deadline(clock: Option<ReaderParentClock>, now_ms: u64) -> RunDeadline {
    let window = clock.map_or(DEFAULT_READER_WINDOW_MS, ReaderParentClock::remaining_ms);
    RunDeadline::with_default_reserve(now_ms.saturating_add(window), now_ms)
}

/// What reaches the worker: a child queued, or a running one gone, which
/// frees its window.
enum Signal {
    Queued(ReaderJobWake),
    Freed,
}

/// The runner one vault's reader children are woken through.
pub(crate) struct ReaderRunner {
    signals: Sender<Signal>,
    shared: Arc<Shared>,
}

/// What the runner, its worker and its children share.
struct Shared {
    /// The vault, held weakly: the worker ends once it is gone.
    vault: Weak<Vault>,
    /// The code host whose provider and pool the children run on; none
    /// claims nothing, and the tick only settles what comes due.
    host: RwLock<Option<Arc<dyn McpCodeExecutionHost>>>,
    seats: Arc<ReaderSeats>,
    /// Children running, by parent run.
    running: Mutex<HashMap<EntityId, usize>>,
    /// Children one parent runs at once: a run's memory share over what one
    /// child holds.
    per_parent: usize,
}

impl Shared {
    fn running_of(&self, parent: EntityId) -> usize {
        lock(&self.running).get(&parent).copied().unwrap_or(0)
    }

    fn started(&self, parent: EntityId) {
        *lock(&self.running).entry(parent).or_insert(0) += 1;
    }

    fn ended(&self, parent: EntityId) {
        let mut running = lock(&self.running);
        if let Some(count) = running.get_mut(&parent) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                running.remove(&parent);
            }
        }
    }

    fn host(&self) -> Option<Arc<dyn McpCodeExecutionHost>> {
        self.host
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ReaderRunner {
    /// Starts the runner of `vault`'s reader children under `limits`. It
    /// claims nothing until a code host is bound.
    pub(crate) fn start(vault: &Arc<Vault>, limits: &crate::config::LimitsConfig) -> Arc<Self> {
        let (signals, wakes) = std::sync::mpsc::channel();
        let memory = limits
            .engine
            .bound(EngineLimit::CodeResultSessionMemoryBytes);
        let per_parent = (memory / READER_RESIDENT_BYTES).max(1);
        let shared = Arc::new(Shared {
            vault: Arc::downgrade(vault),
            host: RwLock::new(None),
            seats: Arc::new(ReaderSeats::new(child_memory_bytes(memory, per_parent))),
            running: Mutex::default(),
            per_parent: usize::try_from(per_parent).unwrap_or(usize::MAX),
        });
        let worker = Worker {
            shared: Arc::clone(&shared),
            signals: signals.clone(),
            wakes,
            sessions: BTreeSet::new(),
        };
        let started = std::thread::Builder::new()
            .name("oneiron-reader-runner".to_owned())
            .spawn(move || worker.run());
        if let Err(error) = started {
            tracing::error!(%error, "the reader runner did not start; reader children stay queued until their cutoff");
        }
        Arc::new(Self { signals, shared })
    }

    /// The seats this runner's hosts lend their runs.
    pub(crate) fn seats(&self) -> Arc<ReaderSeats> {
        Arc::clone(&self.shared.seats)
    }

    /// Runs children on `host`'s provider and pool from now on.
    pub(crate) fn bind_host(&self, host: Arc<dyn McpCodeExecutionHost>) {
        *self
            .shared
            .host
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(host);
        let _ = self.signals.send(Signal::Freed);
    }
}

impl ReaderJobRunner for ReaderRunner {
    fn wake(&self, wake: ReaderJobWake) {
        // A stopped worker leaves the child queued until its cutoff.
        let _ = self.signals.send(Signal::Queued(wake));
    }
}

/// One live session the worker drives, and the participant its parents ran
/// as, whom its children's rows are read as.
type SessionSeat = (String, EntityId);

/// The worker thread's state.
struct Worker {
    shared: Arc<Shared>,
    /// Handed to each child, which signals when it is gone.
    signals: Sender<Signal>,
    wakes: Receiver<Signal>,
    /// The live sessions the runner holds children for.
    sessions: BTreeSet<SessionSeat>,
}

impl Worker {
    fn run(mut self) {
        let Some(vault) = self.shared.vault.upgrade() else {
            return;
        };
        // One runner per vault process: what a stopped one left active is
        // claimed again at its next generation, or settled past its cutoff.
        if let Err(error) = ReaderJobs::canonical(&vault).recover(unix_millis_now()) {
            tracing::warn!(%error, "the reader runner could not recover its children; it ticks on");
        }
        drop(vault);
        loop {
            let Some(vault) = self.shared.vault.upgrade() else {
                return;
            };
            let next = self.tick(&vault);
            drop(vault);
            let wait = next.map_or(TICK, |due| {
                Duration::from_millis(due.saturating_sub(unix_millis_now())).min(TICK)
            });
            match self.wakes.recv_timeout(wait) {
                Ok(signal) => self.note(signal),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            while let Ok(signal) = self.wakes.try_recv() {
                self.note(signal);
            }
        }
    }

    fn note(&mut self, signal: Signal) {
        if let Signal::Queued(ReaderJobWake {
            session_ref: Some(session_ref),
            participant: Some(participant),
            ..
        }) = signal
        {
            self.sessions.insert((session_ref, participant));
        }
    }

    /// One tick: the canonical store, then each live session the runner
    /// holds children for. Answers when the due sweep next has work.
    fn tick(&mut self, vault: &Arc<Vault>) -> Option<u64> {
        let now = unix_millis_now();
        self.shared.seats.forget_before(now);
        let mut next = match self.drive(vault, &ReaderJobs::canonical(vault), None, now) {
            Ok((due, _)) => due,
            Err(error) => {
                tracing::warn!(%error, "the reader runner's tick failed; it tries again");
                None
            }
        };
        let mut done = Vec::new();
        for held in &self.sessions {
            // A session that is gone took its children's rows with its
            // overlay.
            let Ok(session) = vault.off_record_session_vault().bind(&held.0) else {
                done.push(held.clone());
                continue;
            };
            let Ok(jobs) = ReaderJobs::for_session(&session, held.1) else {
                done.push(held.clone());
                continue;
            };
            match self.drive(vault, &jobs, Some(held), now) {
                Ok((None, false)) => done.push(held.clone()),
                Ok((due, _)) => next = earliest(next, due),
                Err(error) => {
                    tracing::warn!(%error, "the reader runner's session tick failed; it tries again");
                }
            }
        }
        for held in done {
            self.sessions.remove(&held);
        }
        next
    }

    /// One store's pass: the due sweep, then claims of its queued children
    /// while the window has room. Answers when its sweep next has work, and
    /// whether a child is still queued.
    fn drive(
        &self,
        vault: &Arc<Vault>,
        jobs: &ReaderJobs<'_>,
        session: Option<&SessionSeat>,
        now: u64,
    ) -> oneiron::Result<(Option<u64>, bool)> {
        // The sweep writes, so it runs only once a row is due.
        if jobs.next_due()?.is_some_and(|due| due <= now) {
            jobs.settle_due(now)?;
        }
        // A child parked on its payer is queued again once the owners said
        // yes (FIX 3740); while one waits, its session stays held.
        let parked = crate::ai_host::payer_funding::resume_reader_payer_parks(vault, jobs, now);
        let queued = jobs.queued(QUEUED_PER_TICK)?;
        let waiting = !queued.is_empty() || parked > 0;
        let host = self.shared.host();
        if let Some(native) = host.as_ref().and_then(|host| host.engine_native()) {
            // Parents whose window is full, or whose scope has nothing left
            // to hold, wait for the next tick.
            let mut held_back = HashSet::new();
            for job in queued {
                let parent = job.binding.parent_run;
                if held_back.contains(&parent) {
                    continue;
                }
                if self.shared.running_of(parent) >= self.shared.per_parent {
                    held_back.insert(parent);
                    continue;
                }
                let Some(permit) = native.runs().try_admit_background() else {
                    break;
                };
                match jobs.claim(job.task, now) {
                    Ok(ClaimOutcome::Claimed(job)) => {
                        let child = Child {
                            clock: self.shared.seats.clock(job.binding.parent_run),
                            job: *job,
                            session: session.cloned(),
                            provider: Arc::clone(native.provider()),
                        };
                        self.spawn(vault, jobs, child, permit, now);
                    }
                    Ok(ClaimOutcome::WaitingForSpend) => {
                        held_back.insert(parent);
                    }
                    Ok(ClaimOutcome::SourceNotReady | ClaimOutcome::Settled) => {}
                    Err(error) => {
                        tracing::warn!(%error, task = %job.task.to_hex(), "a reader child was not claimed");
                    }
                }
            }
        }
        Ok((jobs.next_due()?, waiting))
    }

    /// Runs one claimed child on its own thread, holding `permit` until it
    /// settles.
    fn spawn(
        &self,
        vault: &Arc<Vault>,
        jobs: &ReaderJobs<'_>,
        child: Child,
        permit: Permit,
        now: u64,
    ) {
        let parent = child.job.binding.parent_run;
        let (task, generation) = (child.job.task, child.job.generation);
        self.shared.started(parent);
        let shared = Arc::clone(&self.shared);
        let signals = self.signals.clone();
        let vault = Arc::clone(vault);
        let spawned = std::thread::Builder::new()
            .name("oneiron-code-reader".to_owned())
            .spawn(move || {
                child.run_and_settle(&shared, &vault);
                drop(permit);
                shared.ended(parent);
                let _ = signals.send(Signal::Freed);
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, task = %task.to_hex(), "a reader child's thread did not start");
            self.shared.ended(parent);
            let failed = ReaderRunEnd::Failed("reader_thread_failed".to_owned());
            if let Err(error) = jobs.complete(task, generation, failed, now) {
                tracing::warn!(%error, task = %task.to_hex(), "a reader child that did not start was not settled");
            }
        }
    }
}

/// One claimed child, as its thread runs it, with its parent's live clock
/// when its host lent one.
struct Child {
    job: ReaderJob,
    session: Option<SessionSeat>,
    provider: Arc<dyn McpCodeModeProvider>,
    clock: Option<ReaderParentClock>,
}

/// Why a canonical job's seat was not born ([`Child::seat`]).
enum Unseated {
    /// Its parent's clock bound the pick, or is spent: the job ends at its
    /// cutoff, as its run would ([`Child::unseated`], FIX 8230).
    Cutoff,
    /// Any other birth error: the job fails `reader_seat_failed`, as before.
    Failed(String),
}

/// Default A (FIX 7507, Engine 10-21): a job in an off-record session whose
/// seat its room's route does not bear, its birth failed, runs its
/// configured model, as every session job did before it took a seat; that
/// model is still held to its inherited list ([`Child::held_to_list`]). No
/// call that runs today stops here.
fn session_seat_or_seatless(
    task: EntityId,
    born: Result<Option<ModelSeat>, String>,
) -> Option<ModelSeat> {
    born.unwrap_or_else(|error| {
        tracing::info!(%error, task = %task.to_hex(), "a session job's seat was not born; it runs its configured model");
        None
    })
}

/// The memory one running child may hold, which `can({read, child})`
/// answers as `memory_bytes`: its run's memory share over the children one
/// parent runs at once.
const fn child_memory_bytes(run_memory: u64, per_parent: u64) -> u64 {
    run_memory / per_parent
}

fn earliest(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Every lock here guards plain maps changed in one step each, so a holder
/// that panicked left them whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
