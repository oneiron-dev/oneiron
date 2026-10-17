//! The server's Dreamer: one wake supervisor for its one vault (ARCH-0026:
//! one Dreamer per vault, on the primary node — for a single local server,
//! this server).
//!
//! The supervisor runs on its own thread with its own current-thread runtime:
//! a wake pass does LMDB work inline and must not stall request handlers.
//! Triggers are the driver's: the attempt-queue deadline lane (never a poll),
//! the wake policy's one quiet timer and pushed session hints. A sitting
//! ends on the idle floor, the hard ceiling or an explicit end, and its turns
//! are enqueued for consolidation atomically with the end.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::ModelId;
use oneiron::agent_def::DreamingMode;
use oneiron::dreamer_consolidation::{
    CONFLICT_SETTLE_DIAL, ConflictSettleDecisions, DREAMER_EXTRACTION_ROLE, DREAMER_NARRATIVE_ROLE,
    DREAMER_ROLES, ResidentDreamModel, RoleBackend, RoleBackends, TASK_REALIZE_UNLENT_PARK_REASON,
    TaskRealizeModel, WEAVE_LENS_UNLENT_PARK_REASON, WeaveLensModel, resident_of_dream_input,
    run_resident_dream, run_task_realize, run_weave_lens, settle_parked_conflicts,
};
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::task_verb::{RunnerDoneAnswer, RunnerDoneQuestion};
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerClaimAuthoringStrategy, DreamerRunnerStore, Vault, WakeAttemptContext, WriteActor,
};
use oneiron_driver::{
    AttachedPassFuture, AttemptQueueDeadlines, ConsolidationExecutorFactory, HintPusher,
    HybridTick, IdleSample, PassAttachment, PassExecutorFactory, PushTick, SessionLifecycleConfig,
    SessionLifecycleDriver, SessionTicks, ShutdownHandle, SkillOptimizerLoan, TimerTick,
    WakePassFuture, WakePolicyTicks, WakeSupervisor, WakeSupervisorConfig, WakeSupervisorReport,
};

use super::policy::extraction_egress;
use super::skill_author::CoachSkillAuthor;
use super::status::{StatusCell, WorkState, WorkStatus};
use crate::config::models::{DreamerSettings, ModelsConfig, role_key};
use crate::decision_host::DecisionHost;
use crate::models::{ModelRuntime, RoleRefusal, RoleRoute, RunBackend, Seat};

/// Stamped on every admission and park this server makes.
pub(super) const LEASE_OWNER: &str = "oneiron-server-dreamer";
/// Base id of the per-pass durable budget rows (`dreamer:p<n>`).
const BUDGET_ID: &str = "dreamer";
/// The most parked conflicts one home-timer pass asks the ladder to settle.
const CONFLICT_SETTLE_LIMIT: usize = 8;
/// What one pass's settlement asks may spend between them.
const CONFLICT_SETTLE_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
/// How the host words a settlement ask.
const CONFLICT_SETTLE_WORDING: &str = "These claims about one subject contradict each other. \
Keep the one member that is true and let it supersede the rest, hold both if both can stand, \
dismiss if they do not really conflict, or escalate if you cannot tell.";

/// A running Dreamer: its stop handle, its hint producer and its thread.
pub(super) struct DreamerHost {
    shutdown: ShutdownHandle,
    hints: Arc<HintPusher>,
    thread: std::thread::JoinHandle<WakeSupervisorReport>,
}

/// The server the standing-question pump runs on, bound once the server is
/// built: the Dreamer's Deadline passes drive the pump through it (OF-506).
pub(super) type QuestionTimer =
    Arc<std::sync::OnceLock<std::sync::Weak<crate::server::SyncServer>>>;

/// The host's gate on each Dreamer pass, its home-timer pump and its
/// stewardship drafts, bound once serve has it: managed serve's reap freeze.
/// Unbound, everything is admitted.
pub(super) type PassAdmission = Arc<std::sync::OnceLock<crate::server::HousekeepingAdmission>>;

/// What the gate returns for one pass, held until that pass ends; `None`
/// when the gate refuses.
pub(super) fn admit(admission: &PassAdmission) -> Option<Box<dyn Send>> {
    match admission.get() {
        Some(admit) => admit(),
        None => Some(Box::new(())),
    }
}

pub(super) struct DreamerStart {
    pub(super) vault: Arc<Vault>,
    pub(super) runtime: Arc<ModelRuntime>,
    pub(super) seat: Seat,
    pub(super) settings: DreamerSettings,
    /// The owner lets extraction leave the device.
    pub(super) egress: bool,
    pub(super) status: Arc<StatusCell>,
    /// The host's liveness for the wake policy's idle recipes.
    pub(super) idle: IdleSample,
    /// The input each served model's window holds, for residents' dreaming.
    pub(super) windows: BTreeMap<ModelId, u64>,
    /// The server's decision host, once it is staffed.
    pub(super) decisions: Arc<std::sync::OnceLock<DecisionHost>>,
    pub(super) question_timer: QuestionTimer,
    pub(super) admission: PassAdmission,
    /// The host syncs as a device of another home (`[device_sync]`): the
    /// Dreamer defers to the elected home and never claims it.
    pub(super) device: bool,
}

/// The input each model a role's rungs name may fill: its provider's context
/// less the output it reserves, the smallest where several rungs name it.
pub(super) fn dream_windows(models: &ModelsConfig) -> BTreeMap<ModelId, u64> {
    let mut windows = BTreeMap::new();
    for rungs in models.roles.values() {
        for rung in rungs {
            let Some(provider) = models.providers.get(&rung.model.provider) else {
                continue;
            };
            let Ok(model) = rung.model.engine_id(&provider.revision) else {
                continue;
            };
            let output = provider
                .max_output_tokens
                .filter(|output| *output < provider.context_tokens)
                .unwrap_or(0);
            let room = provider.context_tokens - output;
            windows
                .entry(model)
                .and_modify(|held: &mut u64| *held = (*held).min(room))
                .or_insert(room);
        }
    }
    windows
}

impl DreamerHost {
    /// Starts the supervisor thread and waits until it is ticking.
    pub(super) async fn spawn(start: DreamerStart) -> anyhow::Result<Self> {
        let (ready, started) = tokio::sync::oneshot::channel();
        // The Coach's drafts block on the server's runtime, off the Dreamer's.
        let serve = tokio::runtime::Handle::current();
        let thread = std::thread::Builder::new()
            .name("oneiron-dreamer".into())
            .spawn(move || run(start, serve, ready))?;
        match started.await {
            Ok(Ok((shutdown, hints))) => Ok(Self {
                shutdown,
                hints: Arc::new(hints),
                thread,
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                anyhow::bail!("dreamer thread exited before it started")
            }
        }
    }

    pub(super) fn hints(&self) -> Arc<HintPusher> {
        Arc::clone(&self.hints)
    }

    /// Asks the supervisor to stop at its next boundary, without waiting.
    pub(super) fn signal_stop(&self) {
        self.shutdown.shutdown();
    }

    /// Cooperative stop: a pass in flight reaches its attempt boundary,
    /// parks and refunds what it admitted, and only then does the thread end.
    pub(super) async fn stop(self) -> Option<WakeSupervisorReport> {
        self.signal_stop();
        tokio::task::spawn_blocking(move || self.thread.join().ok())
            .await
            .ok()
            .flatten()
    }
}

type Ready = tokio::sync::oneshot::Sender<anyhow::Result<(ShutdownHandle, HintPusher)>>;

fn run(start: DreamerStart, serve: tokio::runtime::Handle, ready: Ready) -> WakeSupervisorReport {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(error.into()));
            return WakeSupervisorReport::default();
        }
    };
    runtime.block_on(supervise(start, serve, ready))
}

async fn supervise(
    start: DreamerStart,
    serve: tokio::runtime::Handle,
    ready: Ready,
) -> WakeSupervisorReport {
    let DreamerStart {
        vault,
        runtime,
        seat,
        settings,
        egress,
        status,
        idle,
        windows,
        decisions,
        question_timer,
        admission,
        device,
    } = start;
    // Stewardship follow-up drafts ride this thread and stop with it.
    tokio::spawn(super::stewardship::draft_loop(
        Arc::clone(&vault),
        Arc::clone(&runtime),
        settings.pass_budget_units,
        Arc::clone(&admission),
    ));
    let built = (|| -> anyhow::Result<_> {
        let node_id = claim_home_node(&vault, device)?;
        // The nightly harness audit reads this; a failed record never stops
        // the Dreamer.
        if let Err(error) = super::harness::record_tuning_config(
            &vault,
            &runtime,
            &seat,
            &settings,
            now_ms() / 1_000,
        ) {
            tracing::warn!(%error, "dreamer tuning config not recorded");
        }
        let factory = ObservedFactory {
            vault: Arc::clone(&vault),
            runtime,
            seat,
            actor: vault.dreamer_authority()?,
            egress,
            summary_instruction: settings.summary_instruction.clone(),
            resident_instruction: settings.resident_instruction.clone(),
            person_about_instruction: settings.person_about_instruction.clone(),
            task_instruction: settings.task_instruction.clone().unwrap_or_else(|| {
                oneiron::llm::decision::catalogue::TASK_REALIZE_INSTRUCTION.to_owned()
            }),
            windows,
            weaver: None,
            task_route: None,
            inner: None,
            status: Arc::clone(&status),
            decisions,
            question_timer,
            serve,
            admission,
            settle_after: None,
        };
        let lifecycle = SessionLifecycleDriver::new(
            &vault,
            SessionLifecycleConfig::new(settings.idle_floor_secs, settings.session_ceiling_secs),
            Arc::new(now_ms),
        )?;
        let (push, _wake, hints) =
            PushTick::channel(settings.idle_floor_secs.saturating_mul(1_000));
        // The wake policy (ARCH-0026 #wake) reads its rows on each tick and
        // arms one quiet timer; a due recipe lands as a durable receipt the
        // deadline lane then drives.
        let ticks = SessionTicks::new(
            WakePolicyTicks::new(
                HybridTick::new(
                    TimerTick::new(
                        AttemptQueueDeadlines::new(&vault, node_id).for_worker(LEASE_OWNER),
                    ),
                    push,
                ),
                &vault,
                idle,
                Arc::new(now_ms),
            )?,
            lifecycle,
        );
        let config =
            WakeSupervisorConfig::new(BUDGET_ID, LEASE_OWNER, node_id, settings.pass_budget_units);
        config.validate()?;
        Ok((ticks, factory, config, hints))
    })();
    let (ticks, factory, config, hints) = match built {
        Ok(parts) => parts,
        Err(error) => {
            let _ = ready.send(Err(error));
            return WakeSupervisorReport::default();
        }
    };
    let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
    // Waiting before the starter returns, so its first status read is live.
    status.update(|status| status.dreamer = WorkStatus::waiting());
    if ready
        .send(Ok((supervisor.shutdown_handle(), hints)))
        .is_err()
    {
        return WakeSupervisorReport::default();
    }
    let report = supervisor.run().await;
    tracing::info!(?report, "dreamer supervisor stopped");
    report
}

/// One Dreamer per vault: this server is the vault's always-on local node
/// and designates itself home, so macro rounds admit here too. A device of
/// another home (`device`) claims nothing and leaves macro rounds there.
fn claim_home_node(vault: &Vault, device: bool) -> oneiron::Result<u64> {
    let store = DreamerRunnerStore::new(vault);
    let candidate = store.local_home_node_candidate(true, true, false)?;
    let node_id = candidate.node_id;
    // A device defers to the elected home its sync section names; claiming
    // it here would make this install the home, and a home dials no one.
    if !device {
        store.elect_home_node(&[candidate], now_ms() / 1_000)?;
    }
    Ok(node_id)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The run a Dreamer pass's model calls are admitted under.
const DREAMER_PASS_RUN: &str = "dreamer-pass";

/// Each Dreamer role's route: the vault manifest's binding for it, else the
/// role's own `[models]` seat, else the Dreamer's seat (a one-model setup).
pub(super) fn role_routes(
    runtime: &ModelRuntime,
    vault: &Vault,
    seat: &Seat,
) -> Result<Vec<(ModelRole, RoleRoute)>, (ModelRole, RoleRefusal)> {
    DREAMER_ROLES
        .into_iter()
        .map(|role| {
            runtime
                .route_role(vault, role, runtime.seat(role).unwrap_or(seat))
                .map(|route| (role, route))
                .map_err(|refusal| (role, refusal))
        })
        .collect()
}

/// The consolidation factory, rebuilt for each pass on the models that
/// pass's roles are admitted as, with each pass and attempt reported to
/// status.
struct ObservedFactory {
    vault: Arc<Vault>,
    runtime: Arc<ModelRuntime>,
    /// The binding of a role with no manifest row and no seat of its own.
    seat: Seat,
    actor: WriteActor,
    egress: bool,
    /// Declared scope summaries are written with this (ARCH-0006a).
    summary_instruction: Option<String>,
    /// Each resident's own dreaming is written with this (OF-490).
    resident_instruction: Option<String>,
    /// PERSON `about` lines are written with this: the host's wording, else
    /// the engine's own.
    person_about_instruction: Option<String>,
    /// A Dreamer-lane TASK realizes with this: the host's wording, else the
    /// catalogue's own.
    task_instruction: String,
    windows: BTreeMap<ModelId, u64>,
    /// The weaver's narrative route: the model and window a resident that
    /// inherits dreams on, never its diary.
    weaver: Option<RoleBackend>,
    /// The route a TASK realizes on: narrative, else extraction.
    task_route: Option<(ModelRole, RoleBackend)>,
    inner: Option<ConsolidationExecutorFactory>,
    status: Arc<StatusCell>,
    /// The server's decision host: a pass asks its typed questions on its
    /// ladder and promotes through its auto check. Until the server staffs
    /// it, a pass runs on the shipped, unstaffed ladder.
    decisions: Arc<std::sync::OnceLock<DecisionHost>>,
    /// The bound server: the standing-question pump's, and the connector
    /// responder's chat budget and LINE plan.
    question_timer: QuestionTimer,
    /// The server's runtime, which the Coach's drafts and the connector
    /// responder's model calls block on.
    serve: tokio::runtime::Handle,
    admission: PassAdmission,
    /// The last parked conflict a settlement pass asked about: the next
    /// starts after it.
    settle_after: Option<oneiron::EntityId>,
}

/// A pass's admission, held while the pass runs.
struct AdmittedPass(Box<dyn Send>);

impl PassAttachment for AdmittedPass {
    fn serve<'p>(self: Box<Self>, pass: WakePassFuture<'p>) -> AttachedPassFuture<'p> {
        Box::pin(async move {
            let Self(_held) = *self;
            (pass.await, Ok(()))
        })
    }
}

impl ObservedFactory {
    fn prepare(&mut self, guard: &oneiron::BudgetGuard) -> oneiron::Result<()> {
        let routes = match role_routes(&self.runtime, &self.vault, &self.seat) {
            Ok(routes) => routes,
            Err((role, refusal)) => {
                let error = oneiron::Error::InvalidConfig(format!(
                    "dreamer {} refused: {refusal}",
                    role_key(role)
                ));
                self.status
                    .update(|status| status.dreamer.last_error = Some(error.to_string()));
                return Err(error);
            }
        };
        // The pass's calls go out as one run per role, all on one line that
        // mirrors the pass's own: its limit, and the vault's budget policy
        // for the Dreamer's actor, so each rung's permit meets the same caps
        // whichever role it serves. Each rung takes its own permit through
        // its role's run, and the line charges what the engine's step layer
        // does not see (a failed rung, an answer with no usage). The step
        // layer still meters the pass on `guard` with its own lease; a line
        // spent first traps the step on budget as the pass's own admission
        // would.
        let line = self.vault.policy_budget_guard(
            DREAMER_PASS_RUN,
            guard.read().limit_units,
            guard.reserve_units(),
            oneiron::BudgetExhaustionPolicy::Suspend,
            self.actor,
        )?;
        let mut roles = RoleBackends::default();
        for (role, route) in &routes {
            let run = self.runtime.undeclared_run(
                format!("{DREAMER_PASS_RUN}/{}", role_key(*role)),
                line.clone(),
            );
            roles = roles.with(
                *role,
                RoleBackend {
                    backend: Arc::new(RunBackend::new(Arc::clone(&route.ladder), run)),
                    model: route.model.clone(),
                    binding: HostInferenceBinding::Advertised {
                        model: route.model.clone(),
                        locality: route.locality,
                    },
                },
            );
        }
        self.weaver = roles.get(DREAMER_NARRATIVE_ROLE).cloned();
        self.task_route = [DREAMER_NARRATIVE_ROLE, DREAMER_EXTRACTION_ROLE]
            .into_iter()
            .find_map(|role| roles.get(role).cloned().map(|route| (role, route)));
        let extraction = roles
            .get(DREAMER_EXTRACTION_ROLE)
            .cloned()
            .ok_or_else(|| oneiron::Error::InvalidConfig("dreamer extraction unrouted".into()))?;
        let selected = routes.iter().map(|(_, route)| route.model.clone());
        let host = self.decisions.get();
        let sink = AttemptPromotionSink::new(Arc::clone(&self.vault))
            .with_checker(host.and_then(DecisionHost::auto_checker).cloned());
        let mut factory = ConsolidationExecutorFactory::new(
            extraction.backend,
            DreamerClaimAuthoringStrategy::SinglePass,
            self.actor,
            extraction.model,
            extraction.binding,
            self.egress.then(|| extraction_egress(selected.collect())),
            Box::new(sink),
        )
        .with_role_backends(roles)
        // A fired commitment proposes its reminder where the vault already
        // reaches the obligor; the owner approves it in run review (OF-187).
        .with_commitment_wake_planner(Box::new(
            oneiron::commitment_wake::CommitmentReminderPlanner,
        ))?;
        if let Some(instruction) = &self.summary_instruction {
            factory = factory.with_scope_summary_instruction(instruction.clone());
        }
        if let Some(instruction) = &self.person_about_instruction {
            factory = factory.with_person_about_instruction(instruction.clone());
        }
        if let Some(host) = host {
            factory = factory.with_decisions(host.consolidation_decisions()?);
        }
        // A subscribed Slack or LINE message wakes the agent it addressed,
        // which answers on the chat seat through the served sink (OF-519).
        // With no chat seat the wake is delivered and nothing answers.
        if self.runtime.seat(super::CHAT_ROLE).is_some() {
            factory = factory.with_connector_event_responder(Box::new(
                super::connector_event::ServedConnectorResponder::new(
                    Arc::clone(&self.vault),
                    Arc::clone(&self.runtime),
                    self.serve.clone(),
                    Arc::clone(&self.question_timer),
                ),
            ));
        }
        self.inner = Some(factory);
        Ok(())
    }
}

impl PassExecutorFactory for ObservedFactory {
    type Exec<'p> =
        ObservedExecutor<'p, <ConsolidationExecutorFactory as PassExecutorFactory>::Exec<'p>>;

    /// Resolves each of the Dreamer's roles (extraction, the conflict
    /// verdict, narrative) against the vault's live manifest and route, as a
    /// chat turn does, so each role's backend attests the model the engine's
    /// admission selects for it. A route this server does not serve stops
    /// the pass before any attempt is admitted.
    fn executor<'p>(
        &'p mut self,
        guard: &'p oneiron::BudgetGuard,
    ) -> oneiron::Result<Self::Exec<'p>> {
        self.prepare(guard)?;
        let resident = match (&self.weaver, self.resident_instruction.as_deref()) {
            (Some(weaver), Some(instruction)) => Some(ResidentLend {
                vault: &self.vault,
                runtime: &self.runtime,
                weaver,
                guard,
                egress: self.egress,
                instruction,
                windows: &self.windows,
            }),
            _ => None,
        };
        let task = self.task_route.as_ref().map(|(role, route)| TaskLend {
            role: *role,
            route,
            guard,
            egress: self.egress,
            actor: self.actor,
            instruction: &self.task_instruction,
        });
        Ok(ObservedExecutor {
            inner: self
                .inner
                .as_mut()
                .expect("prepared factory")
                .executor(guard)?,
            status: &self.status,
            resident,
            task,
            decisions: &self.decisions,
        })
    }

    fn macro_executors<'p>(
        &'p mut self,
        guard: &'p oneiron::BudgetGuard,
        buckets: usize,
    ) -> oneiron::Result<Vec<Self::Exec<'p>>> {
        self.prepare(guard)?;
        let status = self.status.as_ref();
        let decisions = &self.decisions;
        let resident = match (&self.weaver, self.resident_instruction.as_deref()) {
            (Some(weaver), Some(instruction)) => Some(ResidentLend {
                vault: &self.vault,
                runtime: &self.runtime,
                weaver,
                guard,
                egress: self.egress,
                instruction,
                windows: &self.windows,
            }),
            _ => None,
        };
        let task = self.task_route.as_ref().map(|(role, route)| TaskLend {
            role: *role,
            route,
            guard,
            egress: self.egress,
            actor: self.actor,
            instruction: &self.task_instruction,
        });
        self.inner
            .as_mut()
            .expect("prepared factory")
            .macro_executors(guard, buckets)
            .map(|executors| {
                executors
                    .into_iter()
                    .map(|inner| ObservedExecutor {
                        inner,
                        status,
                        resident,
                        task,
                        decisions,
                    })
                    .collect()
            })
    }

    fn actor(&self) -> Option<WriteActor> {
        Some(self.actor)
    }

    /// The Coach's skill optimizer (OF-214), once serve has bound the server
    /// and registered its replay judge: the Coach drafts on its own seat,
    /// each draft paid up to the pass's allowance, and that judge scores
    /// what it drafts on its live slice.
    fn skill_optimizer(
        &self,
        _vault: &Vault,
        guard: &oneiron::BudgetGuard,
    ) -> oneiron::Result<Option<SkillOptimizerLoan>> {
        let (Some(server), Some(judge)) =
            (self.question_timer.get(), crate::replay_judge::registered())
        else {
            return Ok(None);
        };
        Ok(Some(SkillOptimizerLoan {
            author: Box::new(CoachSkillAuthor::new(
                server.clone(),
                self.serve.clone(),
                guard.read().limit_units,
            )),
            scorer: judge,
            live: judge.coach_live_slice(),
        }))
    }

    /// The host's gate, asked as each pass starts and held until it ends. A
    /// refusal (a vault frozen for reap) stops the pass before any attempt
    /// is admitted; the supervisor backs off and re-drives its tick.
    fn pass_attachment(
        &self,
        _vault: &Vault,
        _guard: &oneiron::BudgetGuard,
    ) -> oneiron::Result<Option<Box<dyn PassAttachment>>> {
        match admit(&self.admission) {
            Some(held) => Ok(Some(Box::new(AdmittedPass(held)))),
            None => Err(oneiron::Error::InvalidConfig(
                "dreamer pass not admitted: the vault is frozen or not yet served".into(),
            )),
        }
    }

    /// The standing-question pump and the parked-conflict settlement, once
    /// serve has bound the server, under the host's gate. Their model rungs
    /// block on the server's runtime, so they run on a thread of their own,
    /// off this pass's runtime; the pass waits for them.
    fn run_home_timer(
        &mut self,
        _vault: &Vault,
        now_secs: u64,
        _local_node_id: u64,
    ) -> oneiron::Result<()> {
        let Some(server) = self.question_timer.get().and_then(std::sync::Weak::upgrade) else {
            return Ok(());
        };
        let Some(_pass) = admit(&self.admission) else {
            return Ok(());
        };
        let dreamer = self.actor;
        let after = self.settle_after;
        let joined = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let pumped = crate::decision_graph::pump_due(&server, now_secs);
                    (pumped, settle_parked(&server, dreamer, after, now_secs))
                })
                .join()
        });
        let Ok((pumped, settled_to)) = joined else {
            return Err(oneiron::Error::InvalidConfig(
                "standing question pump panicked".into(),
            ));
        };
        self.settle_after = settled_to;
        pumped
    }
}

/// Asks the ladder to settle the parked conflicts (OF-023), on the home node
/// only: `pump_due`'s home gate is its own. The Dreamer's review stands from
/// birth; each settlement applies at once and the owner reverts it, and a
/// conflict the owner holds or reverted is left out. A conflict the ladder
/// leaves stays for the owner, and the next pass starts after the last one
/// asked: the cursor this returns. A failure logs by kind only, since its
/// text can quote the vault.
fn settle_parked(
    server: &crate::server::SyncServer,
    dreamer: WriteActor,
    after: Option<oneiron::EntityId>,
    now_secs: u64,
) -> Option<oneiron::EntityId> {
    let vault = server.vault();
    match crate::decision_graph::at_home(server, now_secs) {
        Ok(true) => {}
        Ok(false) => return after,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "parked conflicts wait: the home check failed");
            return after;
        }
    }
    let host = server.decision_host();
    let deadline = oneiron::retrieval_depth::RetrievalDeadline::hard(
        std::time::Instant::now(),
        CONFLICT_SETTLE_BUDGET,
    );
    let decisions = ConflictSettleDecisions {
        ladder: host.ladder().ladder(),
        principal: dreamer.entity_ref(),
        dial: CONFLICT_SETTLE_DIAL,
        bands: host.bands(),
        wording: CONFLICT_SETTLE_WORDING.to_owned(),
        deadline: &deadline,
    };
    match settle_parked_conflicts(
        &vault.memory(dreamer.entity_ref(), dreamer.actor_class()),
        &decisions,
        after,
        CONFLICT_SETTLE_LIMIT,
        now_secs.saturating_mul(1000),
    ) {
        Ok(pass) => pass.last.or(after),
        Err(error) => {
            tracing::warn!(code = %error.code, "parked conflicts wait for the next pass");
            after
        }
    }
}

struct ObservedExecutor<'p, E> {
    inner: E,
    status: &'p StatusCell,
    /// What a resident's own dreaming borrows; none without an instruction.
    resident: Option<ResidentLend<'p>>,
    /// What a Dreamer-lane TASK's realization borrows; none without a route.
    /// A weave lens render borrows the same route.
    task: Option<TaskLend<'p>>,
    /// The server's decision host, which judges a completed TASK try's Done.
    decisions: &'p Arc<std::sync::OnceLock<DecisionHost>>,
}

/// The host's loan to a Dreamer-lane TASK's realization: the pass's route
/// and line, the Dreamer's stamp and the wording.
#[derive(Clone, Copy)]
struct TaskLend<'p> {
    role: ModelRole,
    route: &'p RoleBackend,
    guard: &'p oneiron::BudgetGuard,
    egress: bool,
    actor: WriteActor,
    instruction: &'p str,
}

impl TaskLend<'_> {
    async fn realize(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([self.route.model.clone()])));
        run_task_realize(
            attempt,
            ctx,
            TaskRealizeModel {
                backend: self.route.backend.as_ref(),
                guard: self.guard,
                model: self.route.model.clone(),
                inference: HostInferenceContext {
                    binding: self.route.binding.clone(),
                    extraction_egress: egress.as_deref(),
                },
                role: self.role,
                actor: self.actor,
                instruction: self.instruction,
            },
        )
        .await
    }

    /// The weave lens's generate step on the same route; the shipped
    /// weave-report skill is its instruction.
    async fn render_lens(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([self.route.model.clone()])));
        run_weave_lens(
            attempt,
            ctx,
            WeaveLensModel {
                backend: self.route.backend.as_ref(),
                guard: self.guard,
                model: self.route.model.clone(),
                inference: HostInferenceContext {
                    binding: self.route.binding.clone(),
                    extraction_egress: egress.as_deref(),
                },
                role: self.role,
                actor: self.actor,
            },
        )
        .await
    }
}

/// A resident's own dreaming model as this server serves it.
pub(super) type OwnModel = (
    ModelId,
    oneiron::ModelLocality,
    Arc<crate::models::OfferLadder>,
);

/// The host's loan to one resident's dreaming (OF-490): its own model when
/// it dreams on its own and this server serves that model, on a line of its
/// own, else the weaver's narrative route and window. The diary stays its own.
#[derive(Clone, Copy)]
struct ResidentLend<'p> {
    vault: &'p Vault,
    runtime: &'p ModelRuntime,
    weaver: &'p RoleBackend,
    guard: &'p oneiron::BudgetGuard,
    egress: bool,
    instruction: &'p str,
    windows: &'p BTreeMap<ModelId, u64>,
}

impl ResidentLend<'_> {
    async fn dream(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let resident = resident_of_dream_input(&attempt.status.payload.input)?;
        let slot = own_dreaming_slot(self.vault, resident)?;
        let own = match &slot {
            Some(slot) => served_slot_model(self.vault, self.runtime, slot)?,
            None => None,
        };
        if let Some((model, locality, ladder)) = own {
            // The resident pays for its own model: a run line under its own
            // budget policy rows, at the pass's limit, beside the pass's lease.
            let line = self.vault.policy_budget_guard(
                format!("{DREAMER_PASS_RUN}/resident/{}", resident.to_hex()),
                self.guard.read().limit_units,
                self.guard.reserve_units(),
                oneiron::BudgetExhaustionPolicy::Suspend,
                WriteActor::new(resident, oneiron::EdgeActorClass::Agent),
            )?;
            let backend = RunBackend::new(
                ladder,
                self.runtime.undeclared_run(
                    format!("{DREAMER_PASS_RUN}/resident/{}", resident.to_hex()),
                    line,
                ),
            );
            let egress = self
                .egress
                .then(|| extraction_egress(BTreeSet::from([model.clone()])));
            let window_tokens = self.windows.get(&model).copied();
            // Its durable step is metered on a line of its own too, so step
            // admission charges the resident, not the pass. A separate meter
            // from the backend's: one meter on both layers would charge twice.
            let step = self.vault.policy_budget_guard(
                resident_step_line(resident),
                self.guard.read().limit_units,
                self.guard.reserve_units(),
                oneiron::BudgetExhaustionPolicy::Suspend,
                WriteActor::new(resident, oneiron::EdgeActorClass::Agent),
            )?;
            return run_resident_dream(
                attempt,
                ctx,
                ResidentDreamModel {
                    backend: &backend,
                    guard: &step,
                    model: model.clone(),
                    inference: HostInferenceContext {
                        binding: HostInferenceBinding::Advertised { model, locality },
                        extraction_egress: egress.as_deref(),
                    },
                    role: None,
                    instruction: self.instruction,
                    window_tokens,
                },
            )
            .await;
        }
        if let Some(slot) = &slot {
            tracing::warn!(
                resident = %resident.to_hex(),
                slot = %slot.0,
                "a resident's own dreaming model is not served here; it dreams on the weaver's route"
            );
        }
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([self.weaver.model.clone()])));
        run_resident_dream(
            attempt,
            ctx,
            ResidentDreamModel {
                backend: self.weaver.backend.as_ref(),
                guard: self.guard,
                model: self.weaver.model.clone(),
                inference: HostInferenceContext {
                    binding: self.weaver.binding.clone(),
                    extraction_egress: egress.as_deref(),
                },
                role: Some(DREAMER_NARRATIVE_ROLE),
                instruction: self.instruction,
                window_tokens: self.windows.get(&self.weaver.model).copied(),
            },
        )
        .await
    }
}

/// The runner and step line a resident dreaming on its own model debits.
fn resident_step_line(resident: oneiron::EntityId) -> String {
    format!("{DREAMER_PASS_RUN}/resident/{}/step", resident.to_hex())
}

/// A resident's own dreaming slot (OF-490): its dreaming model, else its
/// talking model's tier, when it dreams on its own; None otherwise.
pub(super) fn own_dreaming_slot(
    vault: &Vault,
    resident: oneiron::EntityId,
) -> oneiron::Result<Option<oneiron::ModelTierRef>> {
    Ok(vault
        .get_agent_definition(&resident)?
        .filter(|definition| definition.dreaming_mode() == DreamingMode::Own)
        .and_then(|definition| definition.dreaming_model.or(definition.model_tier)))
}

/// The model a resident's slot names, as this server serves it: a model id
/// as it stands, a role on its live route, else a tier the vault's manifest
/// binds a chat-wire role to,
/// on the vault's live route for that slot (the first such role this server
/// serves). None when the slot names nothing served here.
pub(super) fn served_slot_model(
    vault: &Vault,
    runtime: &ModelRuntime,
    slot: &oneiron::ModelTierRef,
) -> oneiron::Result<Option<OwnModel>> {
    let Some(router) = runtime.router() else {
        return Ok(None);
    };
    let served = |model: ModelId| {
        router
            .served(&model)
            .map(|(locality, ladder)| (model, locality, ladder))
    };
    if let Some(own) = ModelId::new(slot.0.clone()).ok().and_then(served) {
        return Ok(Some(own));
    }
    // A slot that spells a role (`dreamer_current`) takes that role's live
    // route, as the role's own work does: None when it has no seat here or
    // its route refuses.
    if let Ok(role) = serde_json::from_value::<ModelRole>(serde_json::Value::String(slot.0.clone()))
    {
        return Ok(runtime
            .seat(role)
            .and_then(|seat| runtime.route_role(vault, role, seat).ok())
            .map(|route| (route.model, route.locality, route.ladder)));
    }
    let Some(manifest) = vault.model_manifest()? else {
        return Ok(None);
    };
    let slot_kind = oneiron::llm::manifest::ModelSlot::Llm;
    let Some(widest) = manifest.routes.get(&slot_kind).copied() else {
        return Ok(None);
    };
    let route = vault.model_route(slot_kind)?.unwrap_or(widest);
    Ok(manifest
        .roles
        .values()
        .filter(|binding| binding.slot == slot_kind && binding.tier == *slot)
        .filter_map(|binding| {
            if route == widest {
                Some(binding.model.clone())
            } else {
                binding.route_models.get(&route).cloned()
            }
        })
        .find_map(served))
}

impl<E: DreamerAttemptExecutor> DreamerAttemptExecutor for ObservedExecutor<'_, E> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        self.status.update(|status| {
            status.dreamer.state = WorkState::Working;
            status.dreamer.started += 1;
        });
        let outcome = if attempt.status.payload.attempt_type
            == oneiron::dreamer_runner::DREAMER_RESIDENT_DREAM_ATTEMPT_KIND
        {
            match self.resident {
                Some(lend) => lend.dream(attempt, ctx).await,
                // Without the host's instruction no resident dreams tonight.
                None => Ok(DreamerAttemptExecution::Completed { completed_units: 0 }),
            }
        } else if attempt.status.payload.attempt_type
            == oneiron::dreamer_runner::DREAMER_TASK_REALIZE_ATTEMPT_KIND
        {
            match self.task {
                Some(lend) => lend.realize(attempt, ctx).await,
                None => Ok(DreamerAttemptExecution::Park {
                    reason: TASK_REALIZE_UNLENT_PARK_REASON.to_owned(),
                    cause: oneiron::dreamer_runner::DreamerParkCause::Other,
                }),
            }
        } else if attempt.status.payload.attempt_type
            == oneiron::dreamer_runner::DREAMER_WEAVE_LENS_ATTEMPT_KIND
        {
            match self.task {
                Some(lend) => lend.render_lens(attempt, ctx).await,
                None => Ok(DreamerAttemptExecution::Park {
                    reason: WEAVE_LENS_UNLENT_PARK_REASON.to_owned(),
                    cause: oneiron::dreamer_runner::DreamerParkCause::Other,
                }),
            }
        } else {
            self.inner.execute(attempt, ctx).await
        };
        self.status.update(|status| {
            status.dreamer.state = WorkState::Waiting;
            match &outcome {
                Ok(DreamerAttemptExecution::Completed { .. }) => status.dreamer.completed += 1,
                Ok(other) => {
                    status.dreamer.last_error = Some(format!("{other:?}"));
                }
                Err(error) => {
                    status.dreamer.failed += 1;
                    status.dreamer.last_error = Some(error.to_string());
                }
            }
        });
        outcome
    }

    /// A resident dreaming on its own served model reserves and settles on
    /// its own runner line, the one its durable step meters (FIX 1152). An
    /// unresolved slot, a slot that fails to read and every other attempt
    /// keep the pass's line; execution meets any such error as before.
    fn runner_budget_id(
        &mut self,
        candidate: &oneiron::attempt_queue::AttemptRecord,
    ) -> Option<String> {
        let resident = self.resident.and_then(|lend| {
            let payload =
                oneiron::dreamer_runner::decode_dreamer_attempt_payload(&candidate.payload).ok()?;
            if payload.attempt_type != oneiron::dreamer_runner::DREAMER_RESIDENT_DREAM_ATTEMPT_KIND
            {
                return None;
            }
            let resident = resident_of_dream_input(&payload.input).ok()?;
            let slot = own_dreaming_slot(lend.vault, resident).ok()??;
            served_slot_model(lend.vault, lend.runtime, &slot)
                .ok()?
                .map(|_| resident_step_line(resident))
        });
        resident.or_else(|| self.inner.runner_budget_id(candidate))
    }

    /// Asks the Done question on the server's task ladder, as the resident
    /// pump does. Its rungs block on the server's runtime, so it runs on a
    /// blocking thread, off this pass's; unstaffed, invalid or panicked, the
    /// Done asks up.
    async fn judge_done(&self, question: RunnerDoneQuestion) -> Option<RunnerDoneAnswer> {
        let decisions = Arc::clone(self.decisions);
        tokio::task::spawn_blocking(move || match decisions.get()?.task_decisions() {
            Ok(decisions) => Some(question.decide(&decisions)),
            Err(error) => {
                tracing::warn!(%error, "the task surface's questions are invalid; Done asks up");
                None
            }
        })
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "the Done judge panicked; Done asks up");
            None
        })
    }
}
