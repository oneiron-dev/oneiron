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
//!
//! A successor that carries the owner's approved prompt continuation of its
//! failed predecessor (FIX 3694) runs as the fork of that run, from its cut.
//!
//! A leased run's planned team writes its start on the run's own seat and
//! line, and a planned team's leader runs with the exact pattern pack its
//! launch froze (DOOR-111 S4c, `pattern_launch`).
mod browser_workflow;
mod child_pin;
mod craft;
mod execution;
pub(super) mod pattern_launch;
mod settlement;

use self::execution::run_bound;
pub(crate) use self::execution::seated_planner;
use self::settlement::settle;

use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oneiron::agent_def::{
    AgentDefinition, AgentModel, UNBOUND_LIST_KEEPS_ROUTE, ensure_listed, note_stale_listed_models,
    note_unbound_listed_run,
};
use oneiron::agent_dispatch::{
    AgentDispatchStatus, AgentDispatcher, AgentRun, HealerSlot, LeaderStarterSkills, PlannerSeat,
    PlannerSkills, ProjectConversationSkills, ResidentAgentSpec, SpendScopeId,
    agent_dispatch_actor,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, ReadSetProducer, SetAttemptResult,
};
use oneiron::claim::CallerLocality;
use oneiron::code_run::{
    AgentVerbDoor, CodeRunReplayRecord, CompactionHostBinding, HostPlannerBinding,
    HostPlannerDecisions, HostSelfDispatcher, SpawnHostSeat, TaskExposure, bind_compaction_caller,
    finalize_step_captures, park_and_bind_wait_trap,
};
use oneiron::compaction::output::{OutputContextEntry, restore_output};
use oneiron::dreamer_consolidation::confession::{confession_ask, parse_confession};
use oneiron::dreamer_runner::{CompleteDreamerAttempt, DreamerParkCause, ParkDreamerAttempt};
use oneiron::engine_executor::continuation::{fork_executor_run, run_continuation};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorOutcome, EngineExecutorStatus, RunCompaction,
};
use oneiron::failure_ladder::{
    DetectorTier, FailureEscalationMode, FailureLadderOutcome, FailureScope, FailureScopePolicy,
    HandleAttemptFailure, TypedFailureEvidence, TypedFailureVerdict,
};
use oneiron::learning::TypeRef;
use oneiron::llm::SpentKind;
use oneiron::llm::seat::{ModelSeat, SeatKind, SeatTask};
use oneiron::llm::{
    DurableStepContext, open_trap, register_wait, trap_for_durable_wait, trap_park_owner,
};
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::self_heal::audit::AttemptConfession;
use oneiron::task_type::TaskTypeRef;
use oneiron::{
    DreamerRunnerStore, EntityId, LlmError, ModelId, RetryableLlmError, Vault, WriteActor,
};
use tokio::sync::broadcast;

use super::run_host_door::RunHostDoor;
use super::{HousekeepingAdmission, LiveRuns, ReaderSeats, SyncServer, admit_every_pass};
use crate::ai_host::payer_funding::{
    PayerFault, park_for_payer, resume_payer_parks, scope_funding,
};
use crate::config::models::PlannerSettings;
use crate::decision_host::DecisionHost;
use crate::mcp::{
    EngineRunError, McpCodeModeProvider, PlannedModel, ScopeMeter, enter_engine_native_run,
    task_engine_run_seat, task_run_seat,
};

/// The pump's lease owner, and the owner of the park a run stopped by a
/// provider outage holds (FIX 3194), which a provider's recovery resumes.
pub(crate) const LEASE_OWNER: &str = "oneiron-server-agent-runs";
/// The reason a run stopped by a provider outage parks under.
const OUTAGE_PARK_REASON: &str = "agent_run_provider_unavailable";
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
/// that passes (a rate limit, a spent window): the failure ladder's default
/// bound. Each retry is a fresh attempt, so a fresh run. An outage parks the
/// run instead (FIX 3194).
const RUN_MAX_TRIES: NonZeroU16 = NonZeroU16::new(3).expect("three is nonzero");
/// How long such a retry waits per try when its provider named no reset.
const RUN_RETRY_BACKOFF_SECS: u64 = 30;
/// The codes a continuation's fork refuses with at lease time (FIX 3694),
/// each the stable reason its successor fails under.
const FORK_REFUSALS: [&str; 5] = [
    "continuation_no_checkpoint",
    "continuation_effect_tail",
    "continuation_source_missing",
    "continuation_occupied",
    "continuation_storage",
];

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
/// its task says, the MESSAGE thread its failure asks on, and the objectives
/// it confesses against (OF-544).
struct Claimed {
    status: AgentDispatchStatus,
    agent: EntityId,
    task: String,
    qa_thread_ref: EntityId,
    objectives: Vec<String>,
}

impl Claimed {
    /// The run asked for its confession: its objectives are chosen once, at
    /// its first claim, and kept with its attempt, so its ask and the parse
    /// of its answer name the same rows at every claim, and a continued run
    /// confesses against its source's (OF-544). The ask is in the host's
    /// `confession` wording (FIX 8696).
    fn asked(mut self, vault: &Vault, briefing: Option<&str>, confession: &str) -> Self {
        let attempt = self.status.attempt.id;
        let choose = || run_objectives(vault, &self.status, briefing);
        self.objectives = match AgentDispatcher::new(vault).claimed_run_objectives(attempt, choose)
        {
            Ok(objectives) => objectives,
            Err(error) => {
                tracing::warn!(%error, attempt = ?attempt, "an agent run's kept objectives do not read; it is asked them afresh");
                run_objectives(vault, &self.status, briefing)
            }
        };
        if !self.objectives.is_empty() {
            self.task = format!(
                "{}\n\n{}",
                self.task,
                confession_ask(&self.objectives, confession)
            );
        }
        self
    }
}

impl SyncServer {
    /// Starts the pump, or returns `None` when no engine-native code host
    /// serves this vault.
    pub(crate) fn spawn_resident_pump(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        self.spawn_resident_pump_admitted(admit_every_pass(), admit_every_pass())
    }

    /// Starts the pump on a host with a write freeze: each pass is admitted
    /// through `admit` and each run through `admit_run`, and holds that
    /// admission on its blocking thread until its last write, so an aborted
    /// pump's work still counts until its writes do. A run is admitted after
    /// its permit wait and before its claim. Nothing is admitted while the
    /// pump waits.
    pub(crate) fn spawn_resident_pump_admitted(
        self: &Arc<Self>,
        admit: HousekeepingAdmission,
        admit_run: HousekeepingAdmission,
    ) -> Option<tokio::task::JoinHandle<()>> {
        self.code_execution_host()?.engine_native()?;
        let server = Arc::clone(self);
        Some(tokio::spawn(async move {
            server.pump_residents_forever(admit, admit_run).await
        }))
    }

    async fn pump_residents_forever(
        self: Arc<Self>,
        admit: HousekeepingAdmission,
        admit_run: HousekeepingAdmission,
    ) {
        // Subscribed before the first pass, so a commit between that pass
        // and the first wait still wakes the loop.
        let mut wake = AttemptQueue::new(self.vault()).subscribe();
        // Runs this pump holds, from their permit wait to their settlement.
        let running: Arc<Mutex<HashSet<AttemptId>>> = Arc::default();
        let mut failing: BTreeMap<String, String> = BTreeMap::new();
        loop {
            // A refused pass (a vault frozen for reap) wakes and resumes
            // nothing, and asks again.
            let Some(admission) = admit() else {
                tokio::time::sleep(PASS_SPACING).await;
                continue;
            };
            let server = Arc::clone(&self);
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                server.resident_pass(unix_now())
            })
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
                let admit = Arc::clone(&admit_run);
                tokio::spawn(async move {
                    if !server.run_agent(id, of, &admit).await {
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
        // A run parked on its payer goes on once the owners said yes (FIX 805).
        resume_payer_parks(vault, LEASE_OWNER, now);
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
    async fn run_agent(
        self: Arc<Self>,
        id: AttemptId,
        of: RunOf,
        admit: &HousekeepingAdmission,
    ) -> bool {
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
        // Admitted with its permit in hand and before its claim. A refused
        // run (a vault frozen for reap) stays unclaimed, and a later pass
        // reads it again.
        let Some(admission) = admit() else {
            return false;
        };
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let server = Arc::clone(&self);
        // The run's host door runs its rows on this runtime.
        let runtime = tokio::runtime::Handle::current();
        // The engine REPL driver's future is not `Send`: each run drives it
        // on its own thread with its own reactor, as `execute_code` does.
        // The admission goes with it, held through its claim, its run and
        // its settlement.
        let spawned = std::thread::Builder::new()
            .name("oneiron-agent-run".to_owned())
            .spawn(move || {
                let leave = server.run_agent_blocking(id, of, &key, runtime);
                drop(admission);
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
        let claimed = match claim(vault, id, of, self.ai.confession_instruction()) {
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
        // host's live runs unless it parked on a durable wait or a provider
        // outage (FIX 3194).
        let waits = match &ran {
            Ok(BoundRun::Agent(outcome)) => {
                matches!(outcome.status, EngineExecutorStatus::Waiting(_))
            }
            Ok(BoundRun::Library(_)) => false,
            Err(error) => parks_on_outage(error),
        };
        let run = EntityId::from_bytes(*id.as_bytes()).ok();
        if let Err(error) = self.live_runs.settle(run, waits, || {
            settle(vault, self.decision_host(), &claimed, ran)
        }) {
            tracing::warn!(%error, attempt = ?id, "an agent run did not settle; its lease waits for recovery");
        }
        self.desktop_seats.run_settled(run, waits);
        self.browser_seats.run_settled(run, waits);
        false
    }
}

/// Claims the run by id through its pump's door, with the task it runs,
/// asked for its confession in the host's `confession` wording.
fn claim(
    vault: &Vault,
    id: AttemptId,
    of: RunOf,
    confession: &str,
) -> oneiron::Result<Option<Claimed>> {
    let dispatcher = AgentDispatcher::new(vault);
    let claimed = match of {
        RunOf::Resident(agent) => dispatcher
            .claim_resident_run(id, LEASE_OWNER, unix_now())?
            .map(|(status, resident)| {
                let briefing = briefing(&dispatcher, &status);
                let claimed = Claimed {
                    task: resident_task(&status, &resident, briefing.clone()),
                    agent,
                    qa_thread_ref: resident.home_message_ref,
                    status,
                    objectives: Vec::new(),
                };
                (claimed, briefing)
            }),
        RunOf::Agent(agent) => dispatcher
            .claim_agent_run(id, LEASE_OWNER, unix_now())?
            .map(
                |AgentRun {
                     status,
                     qa_thread_ref,
                 }| {
                    let briefing = briefing(&dispatcher, &status);
                    let claimed = Claimed {
                        task: agent_task(&status, briefing.clone()),
                        agent,
                        qa_thread_ref,
                        status,
                        objectives: Vec::new(),
                    };
                    (claimed, briefing)
                },
            ),
    };
    Ok(claimed.map(|(claimed, briefing)| claimed.asked(vault, briefing.as_deref(), confession)))
}

/// What a leased run came to: its executor's outcome, or the receipt NOTE
/// of a try whose bound library program met its TASK's goal before any
/// seat was born (CUA E4).
enum BoundRun {
    Agent(EngineExecutorOutcome),
    Library(EntityId),
}

/// What a project conversation run's task puts before its skill's body.
const SKILL_SEPARATOR: &str = "\n\n";

/// A resident run's task: its frozen definition's instructions, then what
/// woke it, then the briefing its wake carries: an inbox wake's message as
/// its sender wrote it (OF-519). It reads only the attempt and its binding,
/// so each entry of the run binds the same text to the run's record.
fn resident_task(
    status: &AgentDispatchStatus,
    resident: &ResidentAgentSpec,
    briefing: Option<String>,
) -> String {
    let cause = match &status.attempt.task_ref {
        Some(task) => task_cause(task),
        None => format!(
            "A message reached your inbox (identity {}). Your home conversation is {}.",
            resident.inbox_identity_ref.to_hex(),
            resident.home_conversation_ref.to_hex()
        ),
    };
    task_text(status, std::iter::once(cause).chain(briefing))
}

/// Another agent's run task: its frozen definition's instructions, then the
/// briefing its spawn gave it and the TASK it realizes.
fn agent_task(status: &AgentDispatchStatus, briefing: Option<String>) -> String {
    task_text(
        status,
        briefing
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

/// The definition's instructions, else its description, then each part,
/// then the comm block its frozen slip generates (ARCH-0028 :611).
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
        .chain(std::iter::once(oneiron::agent_dispatch::comm_prompt_block(
            status.input.comm,
        )))
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Whether a run stopped on a model call no provider answered (FIX 3194):
/// its own step's, which the run makes again once it resumes, or a host
/// door's, after which it goes on from its next step. Either parks it.
fn parks_on_outage(error: &EngineRunError) -> bool {
    error.provider_outage().is_some() || error.llm().is_some_and(LlmError::is_provider_unavailable)
}

/// The objectives a run confesses against (OF-544): the caller's, verbatim,
/// when its dispatch carries them; else its TASK brief's done-means; else,
/// as a workflow step's, the one its spawn's planned need, its briefing or
/// its definition's `desc` names, whitespace folded and whole. A TASK brief
/// that does not read leaves the run unasked, and its claim stands.
fn run_objectives(
    vault: &Vault,
    status: &AgentDispatchStatus,
    briefing: Option<&str>,
) -> Vec<String> {
    if let Some(objectives) = &status.input.objectives {
        return objectives.clone();
    }
    let brief = status.attempt.task_ref.as_deref().map(|task| {
        oneiron::task_verb::task_confession_objectives(vault, EntityId::from_hex(task)?)
    });
    match brief.transpose() {
        Ok(Some(Some(objectives))) => return objectives,
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(%error, attempt = ?status.attempt.id, "an agent run's TASK brief does not read; it is asked no confession");
            return Vec::new();
        }
    }
    status
        .input
        .plan
        .as_ref()
        .map(|plan| plan.asked.need.as_str())
        .into_iter()
        .chain(briefing)
        .chain(std::iter::once(status.input.definition.desc.as_str()))
        .map(|text| text.split_whitespace().collect::<Vec<_>>().join(" "))
        .find(|text| !text.is_empty())
        .into_iter()
        .collect()
}

/// Where a pumped run's caller sits, as its provenance gives it (FIX 4465):
/// the attempt was leased by this host's own pump and runs here under the
/// agent's own Grant, so its caller is this host, on this device. It is the
/// read ceiling the run's reader children and its compaction home read
/// under, as every run's reads take their caller's place; it gates no
/// capability, and an agent is served the same wherever it lives.
fn pump_caller(actor: WriteActor) -> CompactionHostBinding {
    bind_compaction_caller(actor, CallerLocality::OnDevice, None)
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
