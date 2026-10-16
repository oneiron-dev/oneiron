//! The resident run pump (OF-533): runs each resident agent's dispatches
//! bound to their own leased attempts, so a run's `tasks.refuse` and decline
//! latch reach the TASK it realizes.
//!
//! A pass wakes every settled resident from its inbox, then reads each ready
//! run: an inbox wake, or a TASK assigned to the resident. Each run waits its
//! turn for a code-run permit, under its resident's key in the pool
//! `execute_code` draws from, before it takes its lease (rule 5): past the
//! bound it waits and is never refused. It then claims its attempt by id,
//! runs on its own thread bound to that lease, and settles through the
//! runner's completion door or the typed failure ladder. The pump wakes on
//! the vault's attempt signal, and on a slow timer for a run whose backoff
//! or schedule ends with no signal of its own.
//!
//! A run binds no agent verb door: a resident holds no MCP credential, so a
//! host-row verb answers `agent_verb_door_unbound` and its run verbs are its
//! own.
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oneiron::agent_dispatch::{
    AgentDispatchStatus, AgentDispatcher, HealerSlot, ResidentAgentSpec, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptResultRef, SetAttemptResult};
use oneiron::code_run::HostSelfDispatcher;
use oneiron::compaction::output::OutputContextEntry;
use oneiron::dreamer_runner::{CompleteDreamerAttempt, ParkDreamerAttempt};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorOutcome, EngineExecutorStatus, EngineNativeExecutor,
    JsCodeModeRuntime, RunCompaction,
};
use oneiron::failure_ladder::{
    FailureEscalationMode, FailureLadderOutcome, FailureScope, FailureScopePolicy,
    HandleAttemptFailure, TypedFailureEvidence, TypedFailureVerdict,
};
use oneiron::llm::seat::{SeatKind, SeatTask};
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::{DreamerRunnerStore, EntityId, Vault, WriteActor};
use tokio::sync::broadcast;

use super::SyncServer;
use crate::mcp::McpCodeModeProvider;

const LEASE_OWNER: &str = "oneiron-server-residents";
/// The park a run waiting on a durable signal holds its lease under; a
/// restart is not that signal, so recovery keeps the lease.
const WAITING_PARK_REASON: &str = "resident_run_waiting";
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

/// What one pass found: the ready runs, and what it could not serve, keyed
/// by what it was for.
#[derive(Default)]
struct Pass {
    ready: Vec<(AttemptId, EntityId)>,
    faults: BTreeMap<String, String>,
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
            for (id, agent) in pass.ready {
                if !held(&running).insert(id) {
                    continue;
                }
                let server = Arc::clone(&self);
                let running = Arc::clone(&running);
                tokio::spawn(async move {
                    if !server.run_resident(id, agent).await {
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

    /// Wakes every settled resident from its inbox and reads their ready
    /// runs. Blocking.
    fn resident_pass(&self, now: u64) -> Pass {
        let mut pass = Pass::default();
        let vault = self.vault();
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
        if residents.is_empty() {
            return pass;
        }
        let dispatcher = AgentDispatcher::new(vault);
        for agent in &residents {
            if let Err(error) = dispatcher.dispatch_resident_inbox(*agent, WAKES_PER_PASS, now) {
                pass.faults
                    .insert(format!("inbox {}", agent.to_hex()), error.to_string());
            }
        }
        match dispatcher.ready_resident_runs(&residents, now) {
            Ok(ready) => pass.ready = ready,
            Err(error) => {
                pass.faults.insert("runs".to_owned(), error.to_string());
            }
        }
        pass
    }

    /// Waits its resident's turn for a permit, then claims, runs and settles
    /// one run on its own thread. Returns whether later passes must leave the
    /// run alone: a claim that failed fails again on every pass.
    async fn run_resident(self: Arc<Self>, id: AttemptId, agent: EntityId) -> bool {
        let key = format!("resident:{}", agent.to_hex());
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
        // The engine REPL driver's future is not `Send`: each run drives it
        // on its own thread with its own reactor, as `execute_code` does.
        let spawned = std::thread::Builder::new()
            .name("oneiron-resident-run".to_owned())
            .spawn(move || {
                let leave = server.run_resident_blocking(id, &key);
                drop(permit);
                let _ = sender.send(leave);
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, attempt = ?id, "a resident run thread did not start");
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    fn run_resident_blocking(&self, id: AttemptId, key: &str) -> bool {
        let Some(host) = self
            .code_execution_host()
            .and_then(|host| host.engine_native())
        else {
            return false;
        };
        let vault = self.vault();
        let claimed = AgentDispatcher::new(vault).claim_resident_run(id, LEASE_OWNER, unix_now());
        let (status, resident) = match claimed {
            Ok(Some(claimed)) => claimed,
            Ok(None) => return false,
            Err(error) => {
                tracing::warn!(%error, attempt = ?id, "a resident run cannot be claimed; it waits for a restart");
                return true;
            }
        };
        let ran = run_bound(vault, host.provider().as_ref(), &status, &resident, key);
        if let Err(error) = settle(vault, &status, &resident, ran) {
            tracing::warn!(%error, attempt = ?id, "a resident run did not settle; its lease waits for recovery");
        }
        false
    }
}

/// Runs the leased attempt until it ends, waits, or fails: a yielded slice
/// enters again at once, a full window once its compaction can land.
fn run_bound(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    status: &AgentDispatchStatus,
    resident: &ResidentAgentSpec,
    key: &str,
) -> Result<EngineExecutorOutcome, String> {
    let actor = agent_dispatch_actor(&status.input).map_err(text)?;
    // The run is the attempt's own: a retry is a fresh attempt, and so a
    // fresh run.
    let run_id = EntityId::from_bytes(*status.attempt.id.as_bytes()).map_err(text)?;
    let config = provider
        .executor_config(vault, run_id, &resident_task(status, resident))
        .map_err(text)?;
    let reactor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(text)?;
    let mut compaction = provider.compaction(actor, key);
    let mut full = 0;
    loop {
        let outcome = enter_run(
            vault,
            provider,
            status,
            actor,
            &config,
            compaction.as_mut(),
            &reactor,
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
/// reaches the TASK it realizes.
fn enter_run(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    status: &AgentDispatchStatus,
    actor: WriteActor,
    config: &EngineExecutorConfig,
    compaction: Option<&mut RunCompaction>,
    reactor: &tokio::runtime::Runtime,
) -> Result<EngineExecutorOutcome, String> {
    let bound = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, &status.attempt)
        .map_err(text)?;
    let mut runtime = provider.runtime();
    let runtime: &mut dyn JsCodeModeRuntime = &mut *runtime;
    let has_seat = vault.model_manifest().map_err(text)?.is_some()
        || vault
            .model_seat_receipt(config.run_id)
            .map_err(text)?
            .is_some();
    let seat = if has_seat {
        let decisions = provider
            .seat_decisions()
            .ok_or("manifest-backed run requires seat decisions")?;
        let facet = provider
            .seat_facet()
            .ok_or("manifest-backed run requires a capability profile")?;
        let task = SeatTask {
            kind: SeatKind::Attempt,
            warm_scope: format!("resident-run:{}", config.run_id.to_hex()),
            task: config.task.clone(),
            purpose: oneiron::CallPurpose::Other {
                name: oneiron::engine_executor::ENGINE_EXECUTOR_PURPOSE_NAME.into(),
            },
            facet: facet.to_owned(),
            required: Vec::new(),
            min_context_tokens: 1,
            locality: config.model_locality,
            override_model: None,
            override_effort: None,
        };
        Some(
            vault
                .birth_model_seat(config.run_id, &task, decisions)
                .map_err(text)?,
        )
    } else {
        None
    };
    let mut routed_config = config.clone();
    let mut executor =
        EngineNativeExecutor::new(vault, provider.backend(), provider.lease(), runtime, &bound);
    if let Some(seat) = &seat {
        routed_config.model = seat.model().clone();
        routed_config.model_locality = seat.locality();
        routed_config.seat_effort = Some(seat.effort());
        executor = executor.with_model_seat(seat);
    }
    if let Some(seat) = compaction {
        executor = executor.with_compaction(seat);
    }
    if let Some(shadow) = provider.code_check() {
        executor = executor.with_code_check(shadow);
    }
    reactor.block_on(executor.run(&routed_config)).map_err(text)
}

/// The run's task: its frozen definition's instructions, then what woke it.
/// It reads only the attempt and its binding, so each entry of the run binds
/// the same text to the run's record.
fn resident_task(status: &AgentDispatchStatus, resident: &ResidentAgentSpec) -> String {
    let definition = &status.input.definition;
    let brief = definition
        .instructions
        .as_deref()
        .filter(|text| !text.trim().is_empty())
        .unwrap_or(&definition.desc)
        .trim();
    let cause = match &status.attempt.task_ref {
        Some(task) => {
            format!("This run realizes TASK {task}, assigned to you; tasks.refuse declines it.")
        }
        None => format!(
            "A message reached your inbox (identity {}). Your home conversation is {}.",
            resident.inbox_identity_ref.to_hex(),
            resident.home_conversation_ref.to_hex()
        ),
    };
    if brief.is_empty() {
        cause
    } else {
        format!("{brief}\n\n{cause}")
    }
}

/// Settles the run's attempt: complete, parked on its wait, or failed.
fn settle(
    vault: &Vault,
    status: &AgentDispatchStatus,
    resident: &ResidentAgentSpec,
    ran: Result<EngineExecutorOutcome, String>,
) -> oneiron::Result<()> {
    let attempt = &status.attempt;
    let now = unix_now();
    let reason = match ran {
        Ok(outcome) => match outcome.status {
            EngineExecutorStatus::Complete => return complete(vault, status, &outcome, now),
            // The run waits on a durable signal; its lease waits with it.
            EngineExecutorStatus::Waiting(_) => {
                DreamerRunnerStore::new(vault).park_attempt(ParkDreamerAttempt {
                    attempt_id: attempt.id,
                    reason: WAITING_PARK_REASON.to_owned(),
                    park_owner: LEASE_OWNER.to_owned(),
                    now,
                })?;
                return Ok(());
            }
            EngineExecutorStatus::HardStepLimitReached => "resident_run_step_limit",
            EngineExecutorStatus::Yielded { .. } | EngineExecutorStatus::WindowFull { .. } => {
                "resident_run_unfinished"
            }
        },
        Err(error) => {
            tracing::warn!(%error, attempt = ?attempt.id, "a resident run failed");
            "resident_run_failed"
        }
    };
    // The host has no detector verdict for the failure, and the ladder never
    // infers one from prose: the run ends for a person to look at. Its
    // checkpoint is the run's own replay record, which the run id addresses;
    // its Q&A thread is the resident's home.
    let ended = DreamerRunnerStore::new(vault).fail_agent_dispatch_with_evidence(
        HandleAttemptFailure {
            attempt_id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            evidence: TypedFailureEvidence {
                evidence_ref: None,
                verdict: TypedFailureVerdict::Indeterminate,
                tier: None,
                stable_reason: reason.to_owned(),
            },
            blocked_reports: Vec::new(),
            pre_fail_checkpoint_ref: EntityId::from_bytes(*attempt.id.as_bytes())?,
            qa_thread_ref: resident.home_message_ref,
            retry_at: now,
            now,
        },
        FailureScopePolicy {
            scope: FailureScope {
                agent_ref: resident.agent_def_ref.to_hex(),
                skill_ref: None,
            },
            max_consecutive_transients: NonZeroU16::MIN,
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

/// Completes the attempt through the runner's one completion door, its
/// result the run's result TURN, and closes its spend.
fn complete(
    vault: &Vault,
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
        AgentDispatcher::new(vault).attach_resident_run_result(
            attempt,
            LEASE_OWNER,
            &outcome.replay_record,
            now,
        )?;
    }
    DreamerRunnerStore::new(vault).complete(CompleteDreamerAttempt {
        id: attempt.id,
        lease_owner: LEASE_OWNER.to_owned(),
        attempt_count: attempt.attempt_count,
        now,
    })?;
    AgentDispatcher::new(vault).settle_child(&attempt.id, now)?;
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
