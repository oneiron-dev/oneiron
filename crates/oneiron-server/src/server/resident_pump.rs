//! The agent run pump (OF-533): runs each agent-def dispatch bound to its
//! own leased attempt, so a run's `tasks.refuse` and decline latch reach the
//! TASK it realizes.
//!
//! A pass wakes every settled resident from its inbox, then reads each ready
//! run: a resident's inbox wake or TASK, and every other agent run, which is
//! a child a run spawned or a top-level dispatch of an agent that is no
//! resident. A saved workflow's leaves are its own pump's. Each run waits its
//! turn for a code-run permit, under its agent's key in the pool
//! `execute_code` draws from, before it takes its lease (rule 5): past the
//! bound it waits and is never refused. It then claims its attempt by id,
//! runs on its own thread bound to that lease, and settles through the
//! runner's completion door or the typed failure ladder. A TASK's Done is
//! judged through the host's decisions before the completion reports it, so
//! a TASK with a brief completes without asking up when a model answers.
//! The pump wakes on the vault's attempt signal, and on a slow timer for a
//! run whose backoff or schedule ends with no signal of its own.
//!
//! A run holds no MCP credential. Its host door serves every host row under
//! the run's own agent ([`super::run_host_door`]), with the run's lease as
//! the creator of a TASK it starts (OF-532), and its run verbs are its own.
//! It calls the vault's callable skills (OF-353). Its model calls spend under
//! its attempt's spend scope (OF-533), and it may spawn reader children
//! under that scope.
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oneiron::agent_dispatch::{
    AgentDispatchStatus, AgentDispatcher, AgentRun, HealerSlot, LeaderStarterSkills, PlannerSeat,
    PlannerSkills, ProjectConversationSkills, ResidentAgentSpec, SpendScopeId,
    agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptResultRef, SetAttemptResult};
use oneiron::claim::CallerLocality;
use oneiron::code_run::{
    AgentVerbDoor, HostPlannerBinding, HostPlannerDecisions, HostSelfDispatcher, SpawnHostSeat,
    park_and_bind_wait_trap,
};
use oneiron::compaction::output::OutputContextEntry;
use oneiron::dreamer_runner::{CompleteDreamerAttempt, DreamerParkCause, ParkDreamerAttempt};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorOutcome, EngineExecutorStatus, RunCompaction,
};
use oneiron::failure_ladder::{
    DetectorTier, FailureEscalationMode, FailureLadderOutcome, FailureScope, FailureScopePolicy,
    HandleAttemptFailure, TypedFailureEvidence, TypedFailureVerdict,
};
use oneiron::llm::SpentKind;
use oneiron::llm::seat::ModelSeat;
use oneiron::llm::{
    DurableStepContext, open_trap, register_wait, trap_for_durable_wait, trap_park_owner,
};
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::{DreamerRunnerStore, EntityId, LlmError, RetryableLlmError, Vault, WriteActor};
use tokio::sync::broadcast;

use super::run_host_door::RunHostDoor;
use super::{ReaderSeats, SyncServer};
use crate::config::models::PlannerSettings;
use crate::decision_host::DecisionHost;
use crate::mcp::{EngineRunError, McpCodeModeProvider, engine_run_seat, enter_engine_native_run};

const LEASE_OWNER: &str = "oneiron-server-agent-runs";
/// The park a run waiting on a durable signal holds its lease under, owned
/// by the trap its wait's reply wakes; a restart is not that signal, so
/// recovery keeps the lease.
const WAITING_PARK_REASON: &str = "agent_run_waiting";
/// How often the pump looks again with no signal: a run's backoff or
/// schedule ends without one.
const RECHECK: Duration = Duration::from_secs(30);
/// The shortest wait between two passes, so a burst of commits costs one.
const PASS_SPACING: Duration = Duration::from_secs(1);
/// Inbox messages one resident is woken for in one pass.
const WAKES_PER_PASS: usize = 16;
/// How long a run whose window is full waits for its compaction before it
/// enters again, and how many such waits in a row it takes before it ends.
const WINDOW_FULL_WAIT: Duration = Duration::from_secs(2);
const WINDOW_FULL_TRIES: u32 = 30;
/// How many tries in a row a run gets whose model call failed for a reason
/// that passes (an outage, a rate limit, a spent window): the failure
/// ladder's default bound. Each retry is a fresh attempt, so a fresh run.
const RUN_MAX_TRIES: NonZeroU16 = NonZeroU16::new(3).expect("three is nonzero");
/// How long such a retry waits per try when its provider named no reset.
const RUN_RETRY_BACKOFF_SECS: u64 = 30;

/// What one pass found: the ready runs, and what it could not serve, keyed
/// by what it was for.
#[derive(Default)]
struct Pass {
    ready: Vec<(AttemptId, RunOf)>,
    faults: BTreeMap<String, String>,
}

/// Whose run a ready row is: a settled resident's, or another agent's.
#[derive(Debug, Clone, Copy)]
enum RunOf {
    Resident(EntityId),
    Agent(EntityId),
}

impl RunOf {
    /// The run's key in the code-run permit pool.
    fn key(self) -> String {
        match self {
            Self::Resident(agent) => format!("resident:{}", agent.to_hex()),
            Self::Agent(agent) => format!("agent:{}", agent.to_hex()),
        }
    }
}

/// A claimed run: its leased attempt and input, the agent it runs as, what
/// its task says, and the MESSAGE thread its failure asks on.
struct Claimed {
    status: AgentDispatchStatus,
    agent: EntityId,
    task: String,
    qa_thread_ref: EntityId,
}

impl SyncServer {
    /// Starts the pump, or returns `None` when no engine-native code host
    /// serves this vault.
    pub(crate) fn spawn_resident_pump(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        self.code_execution_host()?.engine_native()?;
        let server = Arc::clone(self);
        Some(tokio::spawn(async move {
            server.pump_residents_forever().await
        }))
    }

    async fn pump_residents_forever(self: Arc<Self>) {
        // Subscribed before the first pass, so a commit between that pass
        // and the first wait still wakes the loop.
        let mut wake = AttemptQueue::new(self.vault()).subscribe();
        // Runs this pump holds, from their permit wait to their settlement.
        let running: Arc<Mutex<HashSet<AttemptId>>> = Arc::default();
        let mut failing: BTreeMap<String, String> = BTreeMap::new();
        loop {
            let server = Arc::clone(&self);
            let pass = tokio::task::spawn_blocking(move || server.resident_pass(unix_now()))
                .await
                .unwrap_or_else(|error| Pass {
                    ready: Vec::new(),
                    faults: BTreeMap::from([("pass".to_owned(), error.to_string())]),
                });
            for (what, reason) in &pass.faults {
                if failing.get(what) != Some(reason) {
                    tracing::warn!(%what, %reason, "the resident pump cannot serve this; it retries");
                }
            }
            for what in failing
                .keys()
                .filter(|what| !pass.faults.contains_key(*what))
            {
                tracing::info!(%what, "the resident pump serves this again");
            }
            failing = pass.faults;
            for (id, of) in pass.ready {
                if !held(&running).insert(id) {
                    continue;
                }
                let server = Arc::clone(&self);
                let running = Arc::clone(&running);
                tokio::spawn(async move {
                    if !server.run_agent(id, of).await {
                        held(&running).remove(&id);
                    }
                });
            }
            let woke = tokio::select! {
                signal = wake.recv() => !matches!(signal, Err(broadcast::error::RecvError::Closed)),
                () = tokio::time::sleep(RECHECK) => true,
            };
            if !woke {
                return;
            }
            tokio::time::sleep(PASS_SPACING).await;
            // One pass serves the burst of commits that woke it.
            while let Ok(()) | Err(broadcast::error::TryRecvError::Lagged(_)) = wake.try_recv() {}
        }
    }

    /// Wakes every settled resident from its inbox and reads every ready
    /// run. Blocking.
    fn resident_pass(&self, now: u64) -> Pass {
        let mut pass = Pass::default();
        let vault = self.vault();
        // OF-533: the waits a pumped run parks on are swept on this recheck,
        // so a parked ask's deadline lands with no Dreamer enabled.
        if let Err(error) = vault.settle_code_run_waits() {
            pass.faults
                .insert("task waits".to_owned(), error.to_string());
        }
        let agents = match vault.entities_by_type(ENTITY_TYPE_AGENT_DEF) {
            Ok(agents) => agents,
            Err(error) => {
                pass.faults.insert("agents".to_owned(), error.to_string());
                return pass;
            }
        };
        let mut residents = Vec::new();
        for agent in agents {
            match vault.settled_resident_agent(agent) {
                Ok(Some(_)) => residents.push(agent),
                Ok(None) => {}
                Err(error) => {
                    pass.faults
                        .insert(format!("resident {}", agent.to_hex()), error.to_string());
                }
            }
        }
        let dispatcher = AgentDispatcher::new(vault);
        if !residents.is_empty() {
            for agent in &residents {
                if let Err(error) = dispatcher.dispatch_resident_inbox(*agent, WAKES_PER_PASS, now)
                {
                    pass.faults
                        .insert(format!("inbox {}", agent.to_hex()), error.to_string());
                }
            }
            match dispatcher.ready_resident_runs(&residents, now) {
                Ok(ready) => pass.ready.extend(
                    ready
                        .into_iter()
                        .map(|(id, agent)| (id, RunOf::Resident(agent))),
                ),
                Err(error) => {
                    pass.faults.insert("runs".to_owned(), error.to_string());
                }
            }
        }
        match dispatcher.ready_agent_runs(&residents, now) {
            Ok(ready) => pass.ready.extend(
                ready
                    .into_iter()
                    .map(|(id, agent)| (id, RunOf::Agent(agent))),
            ),
            Err(error) => {
                pass.faults
                    .insert("agent runs".to_owned(), error.to_string());
            }
        }
        pass
    }

    /// Waits its agent's turn for a permit, then claims, runs and settles
    /// one run on its own thread. Returns whether later passes must leave the
    /// run alone: a claim that failed fails again on every pass.
    async fn run_agent(self: Arc<Self>, id: AttemptId, of: RunOf) -> bool {
        let key = of.key();
        let permit = loop {
            let wait = match self
                .code_execution_host()
                .and_then(|host| host.engine_native())
            {
                Some(host) => host.runs().admit_in_line(key.clone()),
                None => return false,
            };
            // A wait that reached its deadline refuses nothing: the run
            // waits its turn again.
            if let Ok(permit) = wait.await {
                break permit;
            }
        };
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let server = Arc::clone(&self);
        // The run's host door runs its rows on this runtime.
        let runtime = tokio::runtime::Handle::current();
        // The engine REPL driver's future is not `Send`: each run drives it
        // on its own thread with its own reactor, as `execute_code` does.
        let spawned = std::thread::Builder::new()
            .name("oneiron-agent-run".to_owned())
            .spawn(move || {
                let leave = server.run_agent_blocking(id, of, &key, runtime);
                drop(permit);
                let _ = sender.send(leave);
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, attempt = ?id, "an agent run thread did not start");
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    fn run_agent_blocking(
        self: &Arc<Self>,
        id: AttemptId,
        of: RunOf,
        key: &str,
        runtime: tokio::runtime::Handle,
    ) -> bool {
        let Some(host) = self
            .code_execution_host()
            .and_then(|host| host.engine_native())
        else {
            return false;
        };
        let vault = self.vault();
        let claimed = match claim(vault, id, of) {
            Ok(Some(claimed)) => claimed,
            Ok(None) => return false,
            Err(error) => {
                tracing::warn!(%error, attempt = ?id, "an agent run cannot be claimed; it waits for a restart");
                return true;
            }
        };
        let ran = run_bound(
            self,
            host.provider().as_ref(),
            &claimed,
            key,
            &self.reader_runner.seats(),
            runtime,
        );
        // OF-181: the run settles under its live-run guard, and leaves the
        // host's live runs unless it parked on a durable wait.
        let waits = ran
            .as_ref()
            .is_ok_and(|outcome| matches!(outcome.status, EngineExecutorStatus::Waiting(_)));
        let run = EntityId::from_bytes(*id.as_bytes()).ok();
        if let Err(error) = self.live_runs.settle(run, waits, || {
            settle(vault, self.decision_host(), &claimed, ran)
        }) {
            tracing::warn!(%error, attempt = ?id, "an agent run did not settle; its lease waits for recovery");
        }
        false
    }
}

/// Claims the run by id through its pump's door, with the task it runs.
fn claim(vault: &Vault, id: AttemptId, of: RunOf) -> oneiron::Result<Option<Claimed>> {
    let dispatcher = AgentDispatcher::new(vault);
    match of {
        RunOf::Resident(agent) => Ok(dispatcher
            .claim_resident_run(id, LEASE_OWNER, unix_now())?
            .map(|(status, resident)| Claimed {
                task: resident_task(&dispatcher, &status, &resident),
                agent,
                qa_thread_ref: resident.home_message_ref,
                status,
            })),
        RunOf::Agent(agent) => Ok(dispatcher
            .claim_agent_run(id, LEASE_OWNER, unix_now())?
            .map(
                |AgentRun {
                     status,
                     qa_thread_ref,
                 }| Claimed {
                    task: agent_task(&dispatcher, &status),
                    agent,
                    qa_thread_ref,
                    status,
                },
            )),
    }
}

/// Runs the leased attempt until it ends, waits, or fails: a yielded slice
/// enters again at once, a full window once its compaction can land.
fn run_bound(
    server: &Arc<SyncServer>,
    provider: &dyn McpCodeModeProvider,
    claimed: &Claimed,
    key: &str,
    seats: &ReaderSeats,
    runtime: tokio::runtime::Handle,
) -> Result<EngineExecutorOutcome, EngineRunError> {
    let vault = server.vault();
    let status = &claimed.status;
    let actor = agent_dispatch_actor(&status.input).map_err(text)?;
    // The run is the attempt's own: a retry is a fresh attempt, and so a
    // fresh run.
    let run_id = EntityId::from_bytes(*status.attempt.id.as_bytes()).map_err(text)?;
    let mut config = provider
        .executor_config(vault, run_id, &claimed.task)
        .map_err(text)?;
    // OF-541: the run is born on its seat once, from its own task, before
    // its skill adds to it, and each entry runs on that seat. A run its
    // parent planned is born on the model its plan picked. The attempt is
    // stamped with what runs it: the seat's model, beside the template seat
    // its host configured, and its pack loads and planner take that model.
    // A vault with no manifest bears no seat, so the template stays the
    // stamp its pack loads write.
    let model_seat = engine_run_seat(
        vault,
        provider,
        &config,
        format!("agent-run:{}", run_id.to_hex()),
        status.input.plan.as_ref(),
    )?;
    if let Some(seat) = &model_seat {
        let lease_owner = status
            .attempt
            .lease_owner
            .as_deref()
            .ok_or_else(|| "a claimed agent run holds no lease".to_owned())?;
        AttemptQueue::new(vault)
            .set_executor_stamp(
                status.attempt.id,
                lease_owner,
                status.attempt.attempt_count,
                seat.model().as_str(),
                config.model.as_str(),
            )
            .map_err(text)?;
        config.model = seat.model().clone();
    }
    // A project conversation run runs with its skill's SKILL.md (OF-501); a
    // run whose skill does not load is refused, never run unskilled.
    let skills = ProjectConversationSkills::shipped(None).map_err(text)?;
    if let Some(skill) = AgentDispatcher::new(vault)
        .prepare_project_conversation_run(
            &status.attempt,
            &skills,
            config.model.as_str(),
            unix_now(),
        )
        .map_err(text)?
        && let Some(body) = skill
            .source_files
            .iter()
            .flatten()
            .find(|file| file.path == "SKILL.md")
            .and_then(|file| std::str::from_utf8(&file.content).ok())
    {
        config.task = format!("{}\n\n{}", config.task, body.trim());
    }
    // Its model calls and its reader children spend under the attempt's
    // scope. An unmetered attempt's calls stay on the provider's meter, and
    // so do its children's. Its door withholds nothing, so its children's
    // reads withhold nothing, as its own do.
    let metered = AgentDispatcher::new(vault)
        .spend_scope_for_attempt(status.attempt.id)
        .map_err(text)?;
    let seat = seats.seat(
        run_id,
        metered.clone(),
        CallerLocality::OnDevice,
        provider.reader_window_tokens(),
    );
    // One door for the whole run, so its browser lives as long as the run.
    let door: Arc<dyn AgentVerbDoor> = Arc::new(RunHostDoor::new(server, actor, runtime, run_id));
    let reactor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(text)?;
    // Its compaction passes spend under the attempt's scope too.
    let mut compaction = provider.compaction(actor, key, metered.as_ref());
    let mut full = 0;
    loop {
        let outcome = enter_run(
            vault,
            provider,
            status,
            actor,
            &config,
            &door,
            &seat,
            model_seat.as_ref(),
            metered.as_ref(),
            compaction.as_mut(),
            &reactor,
            server.decision_host(),
            &server.live_runs,
        )?;
        match outcome.status {
            EngineExecutorStatus::Yielded { .. } => full = 0,
            EngineExecutorStatus::WindowFull { .. }
                if compaction.is_some() && full < WINDOW_FULL_TRIES =>
            {
                full += 1;
                std::thread::sleep(WINDOW_FULL_WAIT);
            }
            _ => return Ok(outcome),
        }
    }
}

/// One entry of the run, as `execute_code` enters its runs, but bound to the
/// leased attempt: its dispatcher carries the attempt, so `tasks.refuse`
/// reaches the TASK it realizes, a TASK it creates runs under it, its
/// program calls the vault's callable skills, its host rows take `door`,
/// its model calls spend under `spend`, and `seat`, which its reader
/// children spawn under. It runs on `model_seat`, the one `run_bound` bore
/// it on. With the host's `[models.planner]` seats, its spawns are planned
/// on `decisions`' ladder and its leader calls answer.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one axis of the run's host binding"
)]
fn enter_run(
    vault: &Arc<Vault>,
    provider: &dyn McpCodeModeProvider,
    status: &AgentDispatchStatus,
    actor: WriteActor,
    config: &EngineExecutorConfig,
    door: &Arc<dyn AgentVerbDoor>,
    seat: &SpawnHostSeat,
    model_seat: Option<&ModelSeat>,
    spend: Option<&SpendScopeId>,
    compaction: Option<&mut RunCompaction>,
    reactor: &tokio::runtime::Runtime,
    decisions: &DecisionHost,
    live_runs: &super::LiveRuns,
) -> Result<EngineExecutorOutcome, EngineRunError> {
    let mut bound = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, &status.attempt)
        .map_err(text)?
        .with_callable_skills(Arc::clone(vault))
        .map_err(text)?
        .with_agent_verb_door(Arc::clone(door))
        .with_reader_spawn(seat.clone());
    let planner = decisions.host_planner_decisions(actor.entity_ref());
    if let Some(planner) = planner_binding(vault, provider, config, planner)? {
        bound = bound.with_planner(planner);
    }
    // OF-181: the run's lease proof, registered for the handle a harness
    // attaches, and its guard, held through the whole entry: an action
    // through that handle runs only between entries.
    let proof = bound.live_run_host_binding(config.run_id).map_err(text)?;
    let _serial = live_runs
        .register(
            vault,
            config.run_id,
            actor,
            &status.attempt,
            proof,
            provider.planner().cloned(),
            config.model.as_str().to_owned(),
        )
        .map_err(text)?
        .enter();
    enter_engine_native_run(
        vault, provider, &bound, config, compaction, reactor, spend, model_seat,
    )
}

/// The host's planner for one entry of a leased agent run (OF-541, OF-389):
/// the `[models.planner]` seats whose AGENT_DEF this vault holds, the shipped
/// planner and leader skills, the model the run is stamped with (its seat's
/// once born, else its template) as the executor, and the host's ladder.
/// `None` when no seat resolves.
fn planner_binding<'a>(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    config: &EngineExecutorConfig,
    decisions: HostPlannerDecisions<'a>,
) -> Result<Option<HostPlannerBinding<'a>>, String> {
    let Some(settings) = provider.planner() else {
        return Ok(None);
    };
    seated_planner(vault, settings, config.model.as_str(), decisions)
}

/// The host's planner under `settings` for a run executing on `executor`:
/// [`planner_binding`]'s for one entry, and an action's on a live run
/// (OF-181), from what the run registered with. `None` when no seat
/// resolves.
pub(crate) fn seated_planner<'a>(
    vault: &Vault,
    settings: &PlannerSettings,
    executor: &str,
    decisions: HostPlannerDecisions<'a>,
) -> Result<Option<HostPlannerBinding<'a>>, String> {
    let mut seats = Vec::with_capacity(settings.seats.len());
    for seat in &settings.seats {
        match planner_seat_agent(vault, &seat.agent).map_err(text)? {
            Some(agent_def) => seats.push(PlannerSeat {
                model: seat.model.clone(),
                agent_def,
            }),
            None => tracing::warn!(
                agent = %seat.agent,
                model = seat.model.as_str(),
                "a models.planner seat names no AGENT_DEF in this vault; the planner skips it"
            ),
        }
    }
    if seats.is_empty() {
        return Ok(None);
    }
    Ok(Some(HostPlannerBinding {
        skills: PlannerSkills::seeded().map_err(text)?,
        seats,
        executor: executor.to_owned(),
        decisions: Some(decisions),
        leader: LeaderStarterSkills::seeded().map_err(text)?,
        top: settings.top,
    }))
}

/// A planner seat's AGENT_DEF: a hex ID this vault holds, or a seeded
/// definition's logical ID.
fn planner_seat_agent(vault: &Vault, agent: &str) -> oneiron::Result<Option<EntityId>> {
    if let Ok(id) = EntityId::from_hex(agent) {
        return Ok(vault.get_agent_definition(&id)?.map(|_| id));
    }
    Ok(vault
        .get_seeded_agent_definition_by_logical_id(agent)?
        .map(|(id, _)| id))
}

/// A resident run's task: its frozen definition's instructions, then what
/// woke it, then the briefing its wake carries: an inbox wake's message as
/// its sender wrote it (OF-519). It reads only the attempt and its binding,
/// so each entry of the run binds the same text to the run's record.
fn resident_task(
    dispatcher: &AgentDispatcher<'_>,
    status: &AgentDispatchStatus,
    resident: &ResidentAgentSpec,
) -> String {
    let cause = match &status.attempt.task_ref {
        Some(task) => task_cause(task),
        None => format!(
            "A message reached your inbox (identity {}). Your home conversation is {}.",
            resident.inbox_identity_ref.to_hex(),
            resident.home_conversation_ref.to_hex()
        ),
    };
    task_text(
        status,
        std::iter::once(cause).chain(briefing(dispatcher, status)),
    )
}

/// Another agent's run task: its frozen definition's instructions, then the
/// briefing its spawn gave it and the TASK it realizes.
fn agent_task(dispatcher: &AgentDispatcher<'_>, status: &AgentDispatchStatus) -> String {
    task_text(
        status,
        briefing(dispatcher, status)
            .into_iter()
            .chain(status.attempt.task_ref.as_deref().map(task_cause)),
    )
}

/// The briefing the run's dispatch gave it. A briefing the run's context
/// cannot resolve is left out, and the run reads its own context.
fn briefing(dispatcher: &AgentDispatcher<'_>, status: &AgentDispatchStatus) -> Option<String> {
    match dispatcher.resolve_attempt_context(status.attempt.id) {
        Ok(context) => context.briefing.filter(|text| !text.trim().is_empty()),
        Err(error) => {
            tracing::warn!(%error, attempt = ?status.attempt.id, "an agent run's briefing does not resolve");
            None
        }
    }
}

fn task_cause(task: &str) -> String {
    format!("This run realizes TASK {task}, assigned to you; tasks.refuse declines it.")
}

/// The definition's instructions, else its description, then each part.
fn task_text(status: &AgentDispatchStatus, parts: impl Iterator<Item = String>) -> String {
    let definition = &status.input.definition;
    let brief = definition
        .instructions
        .as_deref()
        .filter(|text| !text.trim().is_empty())
        .unwrap_or(&definition.desc)
        .trim();
    (!brief.is_empty())
        .then(|| brief.to_owned())
        .into_iter()
        .chain(parts)
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Settles the run's attempt: complete, parked on its wait, or failed; a
/// run whose model call failed for a reason that passes is tried again.
fn settle(
    vault: &Vault,
    decisions: &DecisionHost,
    claimed: &Claimed,
    ran: Result<EngineExecutorOutcome, EngineRunError>,
) -> oneiron::Result<()> {
    let status = &claimed.status;
    let attempt = &status.attempt;
    let now = unix_now();
    // OF-540: the run's execution context, bound while its lease holds; one
    // that cannot bind leaves the run to close unattributed.
    if let Err(error) = oneiron::skill_attribution::bind_agent_run_attribution(
        vault,
        attempt.id,
        LEASE_OWNER,
        decisions.ladder(),
    ) {
        tracing::warn!(%error, attempt = ?attempt.id, "an agent run's pack attribution did not bind");
    }
    let mut evidence = TypedFailureEvidence {
        evidence_ref: None,
        verdict: TypedFailureVerdict::Indeterminate,
        tier: None,
        stable_reason: String::new(),
    };
    let mut retry_at = now;
    let reason = match ran {
        Ok(outcome) => match outcome.status {
            EngineExecutorStatus::Complete => {
                return complete(vault, decisions, status, &outcome, now);
            }
            // The run waits on a durable signal; its lease waits with it.
            EngineExecutorStatus::Waiting(_) => return park_on_wait(vault, status, &outcome, now),
            EngineExecutorStatus::HardStepLimitReached => "agent_run_step_limit",
            EngineExecutorStatus::Yielded { .. } | EngineExecutorStatus::WindowFull { .. } => {
                "agent_run_unfinished"
            }
        },
        Err(error) => {
            tracing::warn!(%error, attempt = ?attempt.id, "an agent run failed");
            match error.llm().and_then(|error| passing(error, now)) {
                // A model call that failed for a reason that passes is a
                // tripwire's typed verdict, its evidence the attempt: the
                // run is tried again, fresh, once the reason has passed.
                Some((reason, reset)) => {
                    let tries = AttemptQueue::new(vault)
                        .retry_chain_depth(attempt.id)?
                        .saturating_add(1);
                    evidence.evidence_ref =
                        Some(EntityId::from_bytes(*attempt.id.as_bytes())?.to_hex());
                    evidence.verdict = TypedFailureVerdict::Retryable;
                    evidence.tier = Some(DetectorTier::T1Tripwire);
                    retry_at = reset.unwrap_or_else(|| {
                        now.saturating_add(RUN_RETRY_BACKOFF_SECS.saturating_mul(u64::from(tries)))
                    });
                    reason
                }
                None => "agent_run_failed",
            }
        }
    };
    evidence.stable_reason = reason.to_owned();
    // Any other failure has no detector verdict, and the ladder never infers
    // one from prose: the run ends for a person to look at. Its checkpoint is
    // the run's own replay record, which the run id addresses; its Q&A
    // thread is the claim's: a resident's home, its TASK, or its tree's root.
    let ended = DreamerRunnerStore::new(vault).fail_agent_dispatch_with_evidence(
        HandleAttemptFailure {
            attempt_id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            evidence,
            blocked_reports: vault
                .blocked_reports_of_run(EntityId::from_bytes(*attempt.id.as_bytes())?)?,
            pre_fail_checkpoint_ref: EntityId::from_bytes(*attempt.id.as_bytes())?,
            qa_thread_ref: claimed.qa_thread_ref,
            retry_at,
            now,
        },
        FailureScopePolicy {
            scope: FailureScope {
                agent_ref: claimed.agent.to_hex(),
                skill_ref: None,
            },
            max_consecutive_transients: RUN_MAX_TRIES,
            escalation_mode: FailureEscalationMode::Human,
            healer_slot: HealerSlot::Reserved,
        },
    )?;
    // A retry shares the run's spend scope; only an end closes it.
    if !matches!(ended, FailureLadderOutcome::Retried { .. }) {
        AgentDispatcher::new(vault).settle_child(&attempt.id, now)?;
    }
    Ok(())
}

/// Whether a run's model call failed for a reason that passes, with its
/// stable reason and the reset its provider named, if one is still ahead:
/// an outage, a rate limit, a spent usage window, or no on-device offer
/// until a resting one is back. Spent credit waits for the owner, and any
/// other failure is not one a retry answers.
fn passing(error: &LlmError, now: u64) -> Option<(&'static str, Option<u64>)> {
    if error.is_provider_unavailable() {
        return Some(("agent_run_model_unavailable", None));
    }
    let (reason, retry_after, resets_at) = match error {
        LlmError::Retryable(RetryableLlmError::RateLimited {
            retry_after,
            resets_at,
        }) => ("agent_run_rate_limited", retry_after, resets_at),
        LlmError::Retryable(RetryableLlmError::QuotaSpent {
            kind: SpentKind::Window,
            retry_after,
            resets_at,
        }) => ("agent_run_window_spent", retry_after, resets_at),
        LlmError::Retryable(RetryableLlmError::KeptOnDevice {
            retry_after,
            resets_at,
        }) if retry_after.is_some() || !resets_at.is_empty() => {
            ("agent_run_kept_on_device", retry_after, resets_at)
        }
        _ => return None,
    };
    let reset = resets_at
        .iter()
        .copied()
        .find(|reset| *reset > now)
        .or_else(|| {
            retry_after
                .filter(|after| *after > 0)
                .map(|after| now.saturating_add(after))
        });
    Some((reason, reset))
}

/// Completes the attempt through the runner's one completion door, its
/// result the run's result TURN, and closes its spend. The TASK's "Done
/// means met?" is asked first, on this thread, so the completion carries
/// its answer.
fn complete(
    vault: &Vault,
    decisions: &DecisionHost,
    status: &AgentDispatchStatus,
    outcome: &EngineExecutorOutcome,
    now: u64,
) -> oneiron::Result<()> {
    let attempt = &status.attempt;
    // A run that settled its TASK itself (tasks.refuse; tasks.update once a
    // run may report) is owed no Done from its result.
    let settled_itself = outcome
        .replay_record
        .bridge_calls
        .iter()
        .any(|call| matches!(call.effect.as_str(), "tasks.refuse" | "tasks.update"));
    if settled_itself {
        let body =
            serde_json::json!({ "run_id": outcome.replay_record.run_id.to_hex() }).to_string();
        let entry = OutputContextEntry::capture(vault, body.as_bytes(), now, String::new())?;
        AttemptQueue::new(vault).set_result(SetAttemptResult {
            id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            result_ref: AttemptResultRef::new(entry.source.handle())?,
            now,
        })?;
    } else {
        // The run's durable result: the TASK's Done names it.
        let output = AgentDispatcher::new(vault).attach_resident_run_result(
            attempt,
            LEASE_OWNER,
            &outcome.replay_record,
            now,
        )?;
        // OF-540: the result derives from what the run derived, witnessed
        // while the lease holds; a run that cannot witness closes as bound.
        if let Err(error) =
            oneiron::skill_attribution::witness_agent_run_close(vault, attempt, LEASE_OWNER, output)
        {
            tracing::warn!(%error, attempt = ?attempt.id, "an agent run's close was not witnessed");
        }
    }
    let judged = oneiron::task_verb::runner_done_question(vault, attempt.id)?.and_then(
        |question| match decisions.task_decisions() {
            Ok(decisions) => Some(question.decide(&decisions)),
            Err(error) => {
                tracing::warn!(%error, "the task surface's questions are invalid; Done asks up");
                None
            }
        },
    );
    DreamerRunnerStore::new(vault).complete_judged(
        CompleteDreamerAttempt {
            id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            now,
        },
        judged,
    )?;
    AgentDispatcher::new(vault).settle_child(&attempt.id, now)?;
    Ok(())
}

/// Parks a Waiting run's attempt on a C9 trap its wait's reply wakes: the
/// trap opens and waits, then the attempt parks under the trap's owner and
/// the trap is bound to the wait in one commit, so a wake always finds the
/// park and no park is left unbound. The woken attempt is ready again, and
/// the next pass enters the run, which goes on from the reply.
fn park_on_wait(
    vault: &Vault,
    status: &AgentDispatchStatus,
    outcome: &EngineExecutorOutcome,
    now: u64,
) -> oneiron::Result<()> {
    let attempt = &status.attempt;
    let parked = outcome
        .parked_wait()
        .ok_or(oneiron::Error::InvariantViolation(
            "a waiting run parked on no wait",
        ))?;
    let now_ms = now.saturating_mul(1000);
    let trap = open_trap(
        vault,
        &DurableStepContext {
            vault,
            attempt_id: attempt.id,
            run_id: attempt.run_id.clone(),
            envelope_actor: agent_dispatch_actor(&status.input)?,
            subject: parked.wait.wait_id,
            deadline: None,
            now_ms,
        },
        trap_for_durable_wait(&parked.wait, parked.step_hash),
        parked.step_hash,
        "code-run wait",
    )?;
    register_wait(vault, &trap, now_ms)?;
    // The park and its wake binding commit together: a stop between them
    // would leave a park no delivery wakes.
    park_and_bind_wait_trap(
        vault,
        ParkDreamerAttempt {
            attempt_id: attempt.id,
            reason: WAITING_PARK_REASON.to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: trap_park_owner(&trap.trap_claim_id),
            now,
        },
        &parked.key,
        &trap,
        now_ms,
    )?;
    Ok(())
}

fn held(running: &Mutex<HashSet<AttemptId>>) -> MutexGuard<'_, HashSet<AttemptId>> {
    running.lock().unwrap_or_else(PoisonError::into_inner)
}

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
