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
use std::time::Duration;

use oneiron::agent_def::{birth_under_inherited_list, ensure_inherited_model_list};
use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::claim::CallerLocality;
use oneiron::code_run::{
    AgentVerbDoor, ClaimOutcome, DEFAULT_READER_WINDOW_TOKENS, HostSelfDispatcher, ReaderJob,
    ReaderJobKind, ReaderJobRunner, ReaderJobWake, ReaderJobs, ReaderRunEnd, ReaderSpend,
    RunDeadline, SCOPED_CHILD_PARENT_LEASE_LOST, SUMMARY_READ_BYTES_PER_TOKEN, ScopedChildPorts,
    SpawnHostSeat, SummarizeRecipe, SummaryRead, reader_task_brief, summarize_input,
    summarize_prompt, summary_exceeds_window, summary_token_budget,
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
        let queued = jobs.queued(QUEUED_PER_TICK)?;
        let waiting = !queued.is_empty();
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

impl Child {
    /// What is left of this job's time at `now_ms`, in milliseconds: to the
    /// cutoff its first spawn fixed (`reader_job_cutoff`) and, while its
    /// parent's host lends a live clock, to that clock too, less the fold
    /// reserve fixed at that spawn for a read or a scoped child. A summary is
    /// the fold the reserve is kept for, so it runs to the whole clock. No
    /// reserve is taken twice and no time is added.
    fn left_ms(&self, now_ms: u64) -> u64 {
        let binding = &self.job.binding;
        let left = binding.child_cutoff_unix_ms.saturating_sub(now_ms);
        let Some(clock) = self.clock else {
            return left;
        };
        let reserve = match self.job.kind {
            ReaderJobKind::Summarize { .. } => 0,
            ReaderJobKind::Read | ReaderJobKind::ScopedAgent { .. } => {
                binding.deadline.fold_reserve_ms
            }
        };
        left.min(clock.remaining_ms().saturating_sub(reserve))
    }

    /// How a scoped child that borrowed its parent attempt's lease ends when
    /// that lease no longer holds (`ReaderJobs::scoped_parent_holds`),
    /// checked before its seat and each model entry, as its dispatcher
    /// checks it before each read and port; `None` while it holds, and for
    /// every job that borrowed none. Its settle checks the lease again.
    fn parent_lease_lost(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
    ) -> Option<ReaderRunEnd> {
        let job = &self.job;
        if job.scoped_parent_lease().is_none() {
            return None;
        }
        let holds = match (session, self.session.as_ref()) {
            (Some(session), Some((_, participant))) => {
                ReaderJobs::for_session(session, *participant)
                    .and_then(|jobs| jobs.scoped_parent_holds(job.task, job.generation))
            }
            (Some(_), None) => Ok(false),
            (None, _) => ReaderJobs::canonical(vault).scoped_parent_holds(job.task, job.generation),
        };
        match holds {
            Ok(true) => None,
            Ok(false) => Some(ReaderRunEnd::Failed(
                SCOPED_CHILD_PARENT_LEASE_LOST.to_owned(),
            )),
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a scoped child's parent lease was not read");
                Some(ReaderRunEnd::Failed("reader_binding_failed".to_owned()))
            }
        }
    }

    /// Runs the child and settles it as its run ended.
    fn run_and_settle(&self, shared: &Shared, vault: &Arc<Vault>) {
        let job = &self.job;
        // A scoped child's door is its loan, Grant-checked at each call
        // (FIX 7507); the read child's door never stands in for it.
        let door: Arc<dyn AgentVerbDoor> = match &job.kind {
            ReaderJobKind::ScopedAgent { .. } => {
                Arc::new(ScopedChildDoor::new(Arc::clone(vault), job.clone()))
            }
            ReaderJobKind::Read | ReaderJobKind::Summarize { .. } => {
                Arc::new(crate::api::ReaderChildDoor::new(
                    Arc::clone(vault),
                    shared.seats.caller(job.binding.parent_run),
                ))
            }
        };
        let settled = match &self.session {
            None => {
                let end = self.metered(vault, None, door);
                ReaderJobs::canonical(vault).complete(
                    job.task,
                    job.generation,
                    end,
                    unix_millis_now(),
                )
            }
            Some((session_ref, participant)) => {
                // A session that is gone took the child's rows with its
                // overlay: there is nothing left to settle.
                let Ok(session) = vault.off_record_session_vault().bind(session_ref) else {
                    return;
                };
                let end = self.metered(vault, Some(&session), door);
                ReaderJobs::for_session(&session, *participant).and_then(|jobs| {
                    jobs.complete(job.task, job.generation, end, unix_millis_now())
                })
            }
        };
        if let Err(error) = settled {
            tracing::warn!(%error, task = %job.task.to_hex(), "a reader child was not settled; its cutoff settles it");
        }
    }

    /// Runs the child, or a summary job's one model call, on its meter
    /// ([`Child::meter`]), and records what it used on its child scope once
    /// the run ends when it spends under one.
    fn metered(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
        door: Arc<dyn AgentVerbDoor>,
    ) -> ReaderRunEnd {
        let job = &self.job;
        let (guard, recorded) = match self.meter(vault) {
            Ok(meter) => meter,
            Err(end) => return end,
        };
        // A child under a room-paid scope bills its root's payer, bound
        // before its first call (OF-531). One with no payer it can bill ends
        // with that typed reason before any call, never on the vault owner's
        // account.
        let payer = match scope_funding(vault, recorded.as_ref(), false) {
            Ok(payer) => payer,
            Err(fault) => {
                tracing::info!(%fault, task = %job.task.to_hex(), "a reader child has no payer to bill");
                return ReaderRunEnd::Failed(fault.reason().to_owned());
            }
        };
        let Some(backend) = self.provider.reader_backend(guard.clone(), payer) else {
            return ReaderRunEnd::Failed("reader_meter_unbound".to_owned());
        };
        let end = match &job.kind {
            ReaderJobKind::Read => self.run(vault, session, backend.as_ref(), &guard, door, None),
            // A scoped child runs as a read child's run does, with its lent
            // ports bound; one whose authority or ports do not hold ends
            // before any call, never as a read child.
            ReaderJobKind::ScopedAgent { .. } => {
                match scoped_child_service(vault, self.provider.as_ref(), job) {
                    Ok(ports) => self.run(vault, session, backend.as_ref(), &guard, door, ports),
                    Err(end) => end,
                }
            }
            ReaderJobKind::Summarize {
                recipe,
                window_tokens,
                ..
            } => self.run_summarize_job(
                vault,
                session,
                backend.as_ref(),
                door.as_ref(),
                recipe,
                *window_tokens,
            ),
        };
        if let Some(scope) = recorded
            && let Err(error) =
                AgentDispatcher::new(vault).record_guard_spend(&scope, guard.read().used_units)
        {
            tracing::warn!(%error, task = %job.task.to_hex(), "a reader child's spend was not recorded");
        }
        end
    }

    /// The guard a child's model calls spend on, and the child scope what it
    /// used is recorded on afterwards. Under a scope: a guard of what its
    /// own child scope may still spend. On the host's meter: the host's
    /// shared guard, which settles each call itself as it does the parent's,
    /// so nothing is recorded after; a provider with none to lend fails the
    /// child `reader_meter_unbound`.
    fn meter(&self, vault: &Vault) -> Result<(BudgetGuard, Option<SpendScopeId>), ReaderRunEnd> {
        let job = &self.job;
        if job.binding.spend.scope().is_none() {
            return self
                .provider
                .host_meter()
                .map(|guard| (guard, None))
                .ok_or_else(|| ReaderRunEnd::Failed("reader_meter_unbound".to_owned()));
        }
        let scope = SpendScopeId::for_attempt(&job.attempt);
        match AgentDispatcher::new(vault).guard_for_scope(&scope) {
            Ok(guard) => Ok((guard, Some(scope))),
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a reader child's meter did not open");
                Err(ReaderRunEnd::Failed("reader_meter_failed".to_owned()))
            }
        }
    }

    /// The dispatcher bound to this job's run on its route, `session`'s room
    /// or base, at the generation its runner claimed the job at.
    fn bind<'s>(
        &self,
        vault: &'s Vault,
        session: Option<&'s OffRecordSession<'s>>,
    ) -> oneiron::Result<HostSelfDispatcher<'s>> {
        let job = &self.job;
        job.binding
            .actor
            .write_actor()
            .and_then(|actor| match session {
                Some(session) => {
                    HostSelfDispatcher::for_off_record_session(session, actor, job.run.to_hex())
                }
                None => HostSelfDispatcher::new(vault, actor, job.run.to_hex()),
            })
            .and_then(|dispatcher| dispatcher.with_reader_child(job.task, job.generation))
    }

    /// The seat a job's model calls are bound to, born under its own run on
    /// the route `bound`, its dispatcher, captured, as a run's is: on base
    /// for a canonical job (`run_seat`), where a manifest-backed vault
    /// refuses a seatless executor, and on its room's route for a job in an
    /// off-record session (`run_seat_on`, FIX 2594), never base. A session
    /// job whose seat is not born there runs its configured model, as before
    /// (`session_seat_or_seatless`). A read and a summary alike are held to
    /// the list their spawning run froze (`birth_under_inherited_list`, FIX
    /// 4539), and so is a seatless one's configured model
    /// ([`Child::held_to_list`]).
    fn seat(
        &self,
        vault: &Vault,
        bound: &HostSelfDispatcher<'_>,
        task: &str,
        purpose: CallPurpose,
        min_context_tokens: u64,
        locality: ModelLocality,
    ) -> Result<Option<ModelSeat>, String> {
        let job = &self.job;
        let born = || -> Result<Option<ModelSeat>, String> {
            let inherited = &job.binding.listed;
            let prior = if inherited.is_empty() {
                None
            } else {
                bound
                    .model_seat_receipt(job.run)
                    .map_err(|error| error.to_string())?
            };
            birth_under_inherited_list(
                job.run,
                inherited,
                prior.as_ref().map(|receipt| &receipt.model),
                |listed| {
                    let seat_task = |facet: &str| SeatTask {
                        kind: SeatKind::Child,
                        warm_scope: format!("reader-run:{}", job.run.to_hex()),
                        task: task.to_owned(),
                        purpose: purpose.clone(),
                        facet: facet.to_owned(),
                        required: Vec::new(),
                        min_context_tokens,
                        locality,
                        override_model: None,
                        override_effort: None,
                        listed,
                    };
                    match self.session {
                        None => run_seat(vault, self.provider.as_ref(), job.run, seat_task),
                        Some(_) => self.provider.run_seat_on(vault, bound, job.run, seat_task),
                    }
                },
            )
        };
        match self.session {
            None => born(),
            Some(_) => Ok(session_seat_or_seatless(job.task, born())),
        }
    }

    /// A seatless job runs its configured `model` only when the list its
    /// spawning run froze admits it (`ensure_inherited_model_list`, FIX 5070
    /// under FIX 6030's ruling that the engine enforces only the list): one
    /// off the list ends failed, its reason the refusal naming the list. An
    /// empty list admits any model, as before.
    fn held_to_list(&self, model: &ModelId) -> Result<(), ReaderRunEnd> {
        ensure_inherited_model_list(&self.job.binding.listed, model).map_err(|refused| {
            tracing::info!(%refused, task = %self.job.task.to_hex(), "a seatless job's configured model is off its inherited list");
            ReaderRunEnd::Failed(refused.to_string())
        })
    }

    /// The child's run: a fresh sandbox and a dispatcher bound to its job
    /// and door, and a scoped child's to its lent `ports`, entered again
    /// after each yielded slice until it ends or its cutoff comes. The
    /// cutoff stops the run at its next await; a running step is not cut.
    fn run(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
        backend: &dyn LlmBackend,
        guard: &BudgetGuard,
        door: Arc<dyn AgentVerbDoor>,
        ports: Option<Arc<dyn ScopedChildPorts>>,
    ) -> ReaderRunEnd {
        let job = &self.job;
        let provider = self.provider.as_ref();
        let failed = |reason: &str, error: &dyn std::fmt::Display| {
            tracing::warn!(%error, task = %job.task.to_hex(), reason, "a reader child did not run");
            ReaderRunEnd::Failed(reason.to_owned())
        };
        let bound = self
            .bind(vault, session)
            .and_then(|dispatcher| match ports {
                Some(ports) => dispatcher.with_scoped_child_ports(ports),
                None => Ok(dispatcher),
            });
        let dispatcher = match bound {
            Ok(dispatcher) => dispatcher.with_agent_verb_door(door),
            Err(error) => return failed("reader_binding_failed", &error),
        };
        // A scoped child whose borrowed parent lease is gone takes no seat.
        if let Some(end) = self.parent_lease_lost(vault, session) {
            return end;
        }
        // Read on the job's route: a session child's first start is its
        // room's record's.
        let brief = reader_task_brief(job);
        let mut config = match provider.executor_config_on(vault, &dispatcher, job.run, &brief) {
            Ok(config) => config,
            Err(error) => return failed("reader_config_failed", &error),
        };
        let purpose = CallPurpose::Other {
            name: ENGINE_EXECUTOR_PURPOSE_NAME.into(),
        };
        let seat = match self.seat(
            vault,
            &dispatcher,
            &config.task,
            purpose,
            1,
            config.model_locality,
        ) {
            Ok(seat) => seat,
            Err(error) => return failed("reader_seat_failed", &error),
        };
        // The seat binds its model and effort into the config and the
        // executor alike; a seatless child runs its configured model, held
        // to its inherited list.
        if let Some(seat) = &seat {
            config.model = seat.model().clone();
            config.model_locality = seat.locality();
            config.seat_effort = Some(seat.effort());
        } else if let Err(end) = self.held_to_list(&config.model) {
            return end;
        }
        let reactor = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(reactor) => reactor,
            Err(error) => return failed("reader_reactor_failed", &error),
        };
        let mut runtime = provider.reader_runtime();
        let runtime: &mut dyn JsCodeModeRuntime = &mut *runtime;
        let executor = match session {
            Some(session) => EngineNativeExecutor::for_off_record_session(
                session,
                backend,
                provider.lease(),
                runtime,
                &dispatcher,
            ),
            None => Ok(EngineNativeExecutor::new(
                vault,
                backend,
                provider.lease(),
                runtime,
                &dispatcher,
            )),
        };
        // An executor error's text can quote what the vault holds.
        let Ok(mut executor) = executor else {
            return failed("reader_binding_failed", &"the run's executor did not bind");
        };
        if let Some(seat) = &seat {
            executor = executor.with_model_seat(seat);
        }
        loop {
            // Its cutoff and its parent's live clock bound each entry, and a
            // lost parent lease admits none.
            let left = self.left_ms(unix_millis_now());
            if left == 0 {
                return ReaderRunEnd::Cutoff;
            }
            if let Some(end) = self.parent_lease_lost(vault, session) {
                return end;
            }
            let ran = reactor.block_on(async {
                tokio::time::timeout(Duration::from_millis(left), executor.run(&config)).await
            });
            let error = match ran {
                Err(_) => return ReaderRunEnd::Cutoff,
                Ok(Ok(outcome)) => match outcome.status {
                    EngineExecutorStatus::Complete => return ReaderRunEnd::Completed,
                    EngineExecutorStatus::Yielded { .. } => continue,
                    EngineExecutorStatus::Waiting(_) => {
                        return ReaderRunEnd::Failed("reader_child_waited".to_owned());
                    }
                    EngineExecutorStatus::WindowFull { .. } => {
                        return ReaderRunEnd::Failed("window_full".to_owned());
                    }
                },
                Ok(Err(error)) => error,
            };
            return match error {
                // The run's last step committed; the trailing bubble it may
                // not say is refused after that.
                EngineExecutorError::HostRefused { code } if code == READER_CHILD_READ_ONLY => {
                    ReaderRunEnd::Completed
                }
                EngineExecutorError::Llm(LlmError::BudgetDenied(BudgetDenied::Exhausted)) => {
                    ReaderRunEnd::SpendExhausted
                }
                _ if guard.read().remaining_units == 0 => ReaderRunEnd::SpendExhausted,
                _ => {
                    tracing::warn!(task = %job.task.to_hex(), "a reader child's run failed");
                    ReaderRunEnd::Failed("reader_run_failed".to_owned())
                }
            };
        }
    }
}

impl Child {
    /// A summary job's one model call (code-mode-summary-sdk-v1), never
    /// inside a parent's step: each member read with the checks a child's
    /// `src` read makes (the job live, the door's rows, the member's taint
    /// now), counted with the executor's tokenizer against half the model's
    /// window, then one generate on the job's own meter, its text stored as
    /// the job's finding. A group past the window fails
    /// `group_exceeds_window`, and the helper splits it.
    fn run_summarize_job(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
        backend: &dyn LlmBackend,
        door: &dyn AgentVerbDoor,
        recipe: &SummarizeRecipe,
        window_tokens: u64,
    ) -> ReaderRunEnd {
        let job = &self.job;
        let failed = |reason: &str| ReaderRunEnd::Failed(reason.to_owned());
        let jobs = match session {
            Some(session) => match self.session.as_ref() {
                Some((_, participant)) => match ReaderJobs::for_session(session, *participant) {
                    Ok(jobs) => jobs,
                    Err(_) => return failed("reader_binding_failed"),
                },
                None => return failed("reader_binding_failed"),
            },
            None => ReaderJobs::canonical(vault),
        };
        let budget = summary_token_budget(window_tokens);
        let members = match jobs.summary_members(
            job.task,
            job.generation,
            budget.saturating_mul(SUMMARY_READ_BYTES_PER_TOKEN),
        ) {
            Ok(SummaryRead::Members(members)) => members,
            Ok(SummaryRead::Refused(reason)) => return ReaderRunEnd::Failed(reason),
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary's members were not read");
                return failed("summary_read_failed");
            }
        };
        for member in &members {
            if !matches!(door.withholds_retained(member.rows.as_deref()), Ok(false)) {
                return failed("result_withheld");
            }
        }
        let prompt = summarize_prompt(recipe);
        let input = summarize_input(
            members
                .iter()
                .map(|member| (member.handle.as_str(), member.text.as_str())),
        );
        let tokens = (oneiron::count_context_pack_tokens(&prompt)
            + oneiron::count_context_pack_tokens(&input)) as u64;
        if tokens > budget {
            return ReaderRunEnd::Failed(summary_exceeds_window(tokens, window_tokens));
        }
        // Its config and seat are read on its own route, through a
        // dispatcher bound to the job as a child's run is.
        let bound = match self.bind(vault, session) {
            Ok(bound) => bound,
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary's dispatcher did not bind");
                return failed("reader_binding_failed");
            }
        };
        let config = match self
            .provider
            .executor_config_on(vault, &bound, job.run, "summarize")
        {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary's config did not bind");
                return failed("reader_config_failed");
            }
        };
        // Its seat sees only models whose window holds the window the group
        // was sized against.
        let seat = match self.seat(
            vault,
            &bound,
            &config.task,
            CallPurpose::Other {
                name: SUMMARY_PURPOSE_NAME.to_owned(),
            },
            window_tokens,
            config.model_locality,
        ) {
            Ok(seat) => seat,
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary's seat was not born");
                return failed("reader_seat_failed");
            }
        };
        // A seatless summary calls its configured model, held to its
        // inherited list.
        if seat.is_none()
            && let Err(end) = self.held_to_list(&config.model)
        {
            return end;
        }
        let purpose = CallPurpose::Other {
            name: SUMMARY_PURPOSE_NAME.to_owned(),
        };
        let mut request = LlmRequest {
            model: config.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: oneiron::llm::Scope::default(),
                tier: TierPrecedence::for_purpose(
                    &purpose,
                    ModelTierRef(SUMMARY_PURPOSE_NAME.to_owned()),
                ),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: config.model_locality,
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text { text: prompt }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text { text: input }],
                },
            ],
            tools: Vec::new(),
            params: std::collections::BTreeMap::new(),
            provider_options: std::collections::BTreeMap::new(),
        };
        if let Some(seat) = &seat {
            seat.bind(&mut request);
        }
        let reactor = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(reactor) => reactor,
            Err(_) => return failed("reader_reactor_failed"),
        };
        // A summary runs to its parent's outer cutoff, into the fold
        // reserve, and to its live clock when its host lent one.
        let left = self.left_ms(unix_millis_now());
        if left == 0 {
            return ReaderRunEnd::Cutoff;
        }
        let lease = self.provider.lease();
        let generated = reactor.block_on(async {
            tokio::time::timeout(
                Duration::from_millis(left),
                backend.generate(request, lease),
            )
            .await
        });
        let response = match generated {
            Err(_) => return ReaderRunEnd::Cutoff,
            Ok(Err(LlmError::BudgetDenied(BudgetDenied::Exhausted))) => {
                return ReaderRunEnd::SpendExhausted;
            }
            Ok(Err(_)) => {
                tracing::warn!(task = %job.task.to_hex(), "a summary's model call failed");
                return failed("summary_call_failed");
            }
            Ok(Ok(response)) => response,
        };
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        if text.trim().is_empty() {
            return failed("summary_empty");
        }
        match jobs.store_summary(job.task, job.generation, &text) {
            Ok(Ok(())) => ReaderRunEnd::Completed,
            Ok(Err(reason)) => ReaderRunEnd::Failed(reason),
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary was not stored");
                failed("summary_store_failed")
            }
        }
    }
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

fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
