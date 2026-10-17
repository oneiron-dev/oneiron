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
//! scope. It stops at its cutoff and settles as its run ended. An off-record
//! session's children run in its overlay and are not restart-durable: the
//! overlay evaporates.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, Weak};
use std::time::Duration;

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::claim::CallerLocality;
use oneiron::code_run::{
    AgentVerbDoor, ClaimOutcome, DEFAULT_READER_WINDOW_TOKENS, HostSelfDispatcher, ReaderJob,
    ReaderJobKind, ReaderJobRunner, ReaderJobWake, ReaderJobs, ReaderRunEnd, RunDeadline,
    SUMMARY_READ_BYTES_PER_TOKEN, SpawnHostSeat, SummarizeRecipe, SummaryRead, reader_task_brief,
    summarize_input, summarize_prompt, summary_exceeds_window, summary_token_budget,
};
use oneiron::engine_executor::{
    EngineExecutorError, EngineExecutorStatus, EngineNativeExecutor, JsCodeModeRuntime,
};
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::BudgetDenied;
use oneiron::off_record::OffRecordSession;
use oneiron::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, EntityId, LlmBackend,
    LlmError, LlmMessage, LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat,
    TierPrecedence, Vault,
};

use crate::admission::Permit;
use crate::mcp::{McpCodeExecutionHost, McpCodeModeProvider};

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

/// The root scope a code run's launch opens under the run's own id.
/// `execute_code` carries no shown maximum and opens none, so its spawns
/// answer `reader_spawn_unmetered` until a host opens one.
pub(crate) fn run_launch_scope(run: EntityId) -> Option<SpendScopeId> {
    SpendScopeId::launch(format!("code-run:{}", run.to_hex())).ok()
}

/// The seats hosts lend their runs to spawn readers under, and where each
/// parent run's caller sits, as its host noted it at the run's last entry.
pub(crate) struct ReaderSeats {
    callers: Mutex<HashMap<EntityId, (CallerLocality, u64)>>,
    /// The memory one running child may hold: its run's memory share over
    /// the children one parent runs at once.
    child_memory_bytes: u64,
}

impl ReaderSeats {
    fn new(child_memory_bytes: u64) -> Self {
        Self {
            callers: Mutex::default(),
            child_memory_bytes,
        }
    }

    /// The seat run `run` spawns its children under. `spend` is the scope
    /// they spend under; one that is not open answers every spawn
    /// `reader_spawn_unmetered`. Their clock is one window from now, which
    /// the run's first spawn fixes. `caller` is where the run's caller sits,
    /// noted for its children's reads. `window_tokens` is the input window
    /// of the model its children and summaries run on, when its host knows
    /// it.
    pub(crate) fn seat(
        &self,
        run: EntityId,
        spend: SpendScopeId,
        caller: CallerLocality,
        window_tokens: Option<u64>,
    ) -> SpawnHostSeat {
        let now = unix_millis_now();
        lock(&self.callers).insert(run, (caller, now));
        SpawnHostSeat {
            spend,
            deadline: RunDeadline::with_default_reserve(
                now.saturating_add(DEFAULT_READER_WINDOW_MS),
                now,
            ),
            // A child holds nothing at its claim: it tops up from its
            // parent's chain as it spends, the cap enforced at each spend.
            hold_units: 0,
            window_tokens: window_tokens.unwrap_or(DEFAULT_READER_WINDOW_TOKENS),
            memory_bytes: self.child_memory_bytes,
        }
    }

    /// Where `parent`'s caller sits: as its host last noted it, else off
    /// this device, the rule that withholds the most.
    fn caller(&self, parent: EntityId) -> CallerLocality {
        lock(&self.callers)
            .get(&parent)
            .map_or(CallerLocality::OffDevice, |(caller, _)| *caller)
    }

    /// Forgets every parent last noted more than two windows before `now`.
    fn forget_before(&self, now: u64) {
        let horizon = now.saturating_sub(DEFAULT_READER_WINDOW_MS.saturating_mul(2));
        lock(&self.callers).retain(|_, (_, noted)| *noted >= horizon);
    }
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

/// One claimed child, as its thread runs it.
struct Child {
    job: ReaderJob,
    session: Option<SessionSeat>,
    provider: Arc<dyn McpCodeModeProvider>,
}

impl Child {
    /// Runs the child and settles it as its run ended.
    fn run_and_settle(&self, shared: &Shared, vault: &Arc<Vault>) {
        let job = &self.job;
        let door: Arc<dyn AgentVerbDoor> = Arc::new(crate::api::ReaderChildDoor::new(
            Arc::clone(vault),
            shared.seats.caller(job.binding.parent_run),
        ));
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

    /// Runs the child on its own child scope's meter: its backend spends on
    /// a guard of what the scope may still spend, and what the guard used is
    /// recorded on the scope once the run ends. A summary job makes its one
    /// model call instead of a run.
    fn metered(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
        door: Arc<dyn AgentVerbDoor>,
    ) -> ReaderRunEnd {
        let job = &self.job;
        let scope = SpendScopeId::for_attempt(&job.attempt);
        let spend = AgentDispatcher::new(vault);
        let guard = match spend.guard_for_scope(&scope) {
            Ok(guard) => guard,
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a reader child's meter did not open");
                return ReaderRunEnd::Failed("reader_meter_failed".to_owned());
            }
        };
        let Some(backend) = self.provider.reader_backend(guard.clone()) else {
            return ReaderRunEnd::Failed("reader_meter_unbound".to_owned());
        };
        let end = match &job.kind {
            ReaderJobKind::Read => self.run(vault, session, backend.as_ref(), &guard, door),
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
        if let Err(error) = spend.record_guard_spend(&scope, guard.read().used_units) {
            tracing::warn!(%error, task = %job.task.to_hex(), "a reader child's spend was not recorded");
        }
        end
    }

    /// The child's run: a fresh sandbox and a dispatcher bound to its job
    /// and door, entered again after each yielded slice until it ends or its
    /// cutoff comes. The cutoff stops the run at its next await; a running
    /// step is not cut.
    fn run(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
        backend: &dyn LlmBackend,
        guard: &BudgetGuard,
        door: Arc<dyn AgentVerbDoor>,
    ) -> ReaderRunEnd {
        let job = &self.job;
        let provider = self.provider.as_ref();
        let failed = |reason: &str, error: &dyn std::fmt::Display| {
            tracing::warn!(%error, task = %job.task.to_hex(), reason, "a reader child did not run");
            ReaderRunEnd::Failed(reason.to_owned())
        };
        let bound = job
            .binding
            .actor
            .write_actor()
            .and_then(|actor| match session {
                Some(session) => {
                    HostSelfDispatcher::for_off_record_session(session, actor, job.run.to_hex())
                }
                None => HostSelfDispatcher::new(vault, actor, job.run.to_hex()),
            })
            .and_then(|dispatcher| dispatcher.with_reader_child(job.task, job.generation));
        let dispatcher = match bound {
            Ok(dispatcher) => dispatcher.with_agent_verb_door(door),
            Err(error) => return failed("reader_binding_failed", &error),
        };
        let config = match provider.executor_config(vault, job.run, &reader_task_brief(job)) {
            Ok(config) => config,
            Err(error) => return failed("reader_config_failed", &error),
        };
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
        let cutoff = job.binding.child_cutoff_unix_ms;
        loop {
            let left = cutoff.saturating_sub(unix_millis_now());
            if left == 0 {
                return ReaderRunEnd::Cutoff;
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
                    EngineExecutorStatus::HardStepLimitReached => {
                        return ReaderRunEnd::Failed("step_limit".to_owned());
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
        let config = match self
            .provider
            .executor_config(vault, job.run, "summarize")
        {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary's config did not bind");
                return failed("reader_config_failed");
            }
        };
        let purpose = CallPurpose::Other {
            name: SUMMARY_PURPOSE_NAME.to_owned(),
        };
        let request = LlmRequest {
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
        let reactor = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(reactor) => reactor,
            Err(_) => return failed("reader_reactor_failed"),
        };
        let left = job
            .binding
            .child_cutoff_unix_ms
            .saturating_sub(unix_millis_now());
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
