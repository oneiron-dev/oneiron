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
    DREAMER_EXTRACTION_ROLE, DREAMER_NARRATIVE_ROLE, DREAMER_ROLES, ResidentDreamModel,
    RoleBackend, RoleBackends, TASK_REALIZE_UNLENT_PARK_REASON, TaskRealizeModel,
    WEAVE_LENS_UNLENT_PARK_REASON, WeaveLensModel, resident_of_dream_input, run_resident_dream,
    run_task_realize, run_weave_lens,
};
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerClaimAuthoringStrategy, DreamerRunnerStore, Vault, WakeAttemptContext, WriteActor,
};
use oneiron_driver::{
    AttemptQueueDeadlines, ConsolidationExecutorFactory, HintPusher, HybridTick, IdleSample,
    PassExecutorFactory, PushTick, SessionLifecycleConfig, SessionLifecycleDriver, SessionTicks,
    ShutdownHandle, TimerTick, WakePolicyTicks, WakeSupervisor, WakeSupervisorConfig,
    WakeSupervisorReport,
};

use super::policy::extraction_egress;
use super::status::{StatusCell, WorkState, WorkStatus};
use crate::config::models::{DreamerSettings, ModelsConfig, role_key};
use crate::models::{ModelRuntime, RoleRefusal, RoleRoute, RunBackend, Seat};

/// Stamped on every admission and park this server makes.
pub(super) const LEASE_OWNER: &str = "oneiron-server-dreamer";
/// Base id of the per-pass durable budget rows (`dreamer:p<n>`).
const BUDGET_ID: &str = "dreamer";

/// A running Dreamer: its stop handle, its hint producer and its thread.
pub(super) struct DreamerHost {
    shutdown: ShutdownHandle,
    hints: Arc<HintPusher>,
    thread: std::thread::JoinHandle<WakeSupervisorReport>,
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
        let thread = std::thread::Builder::new()
            .name("oneiron-dreamer".into())
            .spawn(move || run(start, ready))?;
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

fn run(start: DreamerStart, ready: Ready) -> WakeSupervisorReport {
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
    runtime.block_on(supervise(start, ready))
}

async fn supervise(start: DreamerStart, ready: Ready) -> WakeSupervisorReport {
    let DreamerStart {
        vault,
        runtime,
        seat,
        settings,
        egress,
        status,
        idle,
        windows,
    } = start;
    // Stewardship follow-up drafts ride this thread and stop with it.
    tokio::spawn(super::stewardship::draft_loop(
        Arc::clone(&vault),
        Arc::clone(&runtime),
        settings.pass_budget_units,
    ));
    let built = (|| -> anyhow::Result<_> {
        let node_id = claim_home_node(&vault)?;
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
            task_instruction: settings.task_instruction.clone().unwrap_or_else(|| {
                oneiron::llm::decision::catalogue::TASK_REALIZE_INSTRUCTION.to_owned()
            }),
            windows,
            weaver: None,
            task_route: None,
            line: None,
            inner: None,
            status: Arc::clone(&status),
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
/// and designates itself home, so macro rounds admit here too.
fn claim_home_node(vault: &Vault) -> oneiron::Result<u64> {
    let store = DreamerRunnerStore::new(vault);
    let candidate = store.local_home_node_candidate(true, true, false)?;
    let node_id = candidate.node_id;
    store.elect_home_node(&[candidate], now_ms() / 1_000)?;
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
    /// A Dreamer-lane TASK realizes with this: the host's wording, else the
    /// catalogue's own.
    task_instruction: String,
    windows: BTreeMap<ModelId, u64>,
    /// The weaver's narrative route: the model and window a resident that
    /// inherits dreams on, never its diary.
    weaver: Option<RoleBackend>,
    /// The route a TASK realizes on: narrative, else extraction.
    task_route: Option<(ModelRole, RoleBackend)>,
    /// The pass's budget line, which a resident's own model also runs on.
    line: Option<oneiron::BudgetGuard>,
    inner: Option<ConsolidationExecutorFactory>,
    status: Arc<StatusCell>,
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
        self.line = Some(line.clone());
        let extraction = roles
            .get(DREAMER_EXTRACTION_ROLE)
            .cloned()
            .ok_or_else(|| oneiron::Error::InvalidConfig("dreamer extraction unrouted".into()))?;
        let selected = routes.iter().map(|(_, route)| route.model.clone());
        let mut factory = ConsolidationExecutorFactory::new(
            extraction.backend,
            DreamerClaimAuthoringStrategy::SinglePass,
            self.actor,
            extraction.model,
            extraction.binding,
            self.egress.then(|| extraction_egress(selected.collect())),
            Box::new(AttemptPromotionSink::new(Arc::clone(&self.vault))),
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
        let resident = match (
            &self.weaver,
            &self.line,
            self.resident_instruction.as_deref(),
        ) {
            (Some(weaver), Some(line), Some(instruction)) => Some(ResidentLend {
                vault: &self.vault,
                runtime: &self.runtime,
                weaver,
                line,
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
        })
    }

    fn macro_executors<'p>(
        &'p mut self,
        guard: &'p oneiron::BudgetGuard,
        buckets: usize,
    ) -> oneiron::Result<Vec<Self::Exec<'p>>> {
        self.prepare(guard)?;
        let status = self.status.as_ref();
        let resident = match (
            &self.weaver,
            &self.line,
            self.resident_instruction.as_deref(),
        ) {
            (Some(weaver), Some(line), Some(instruction)) => Some(ResidentLend {
                vault: &self.vault,
                runtime: &self.runtime,
                weaver,
                line,
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
                    })
                    .collect()
            })
    }

    fn actor(&self) -> Option<WriteActor> {
        Some(self.actor)
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

/// The host's loan to one resident's dreaming (OF-490): its own model when
/// it dreams on its own and this server serves that model, else the
/// weaver's narrative route and window. The diary stays its own.
#[derive(Clone, Copy)]
struct ResidentLend<'p> {
    vault: &'p Vault,
    runtime: &'p ModelRuntime,
    weaver: &'p RoleBackend,
    line: &'p oneiron::BudgetGuard,
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
        let own = self
            .vault
            .get_agent_definition(&resident)?
            .filter(|definition| definition.dreaming_mode() == DreamingMode::Own)
            .and_then(|definition| definition.dreaming_model.or(definition.model_tier))
            .and_then(|slot| ModelId::new(slot.0).ok())
            .and_then(|model| {
                let (locality, ladder) = self.runtime.router()?.served(&model)?;
                Some((model, locality, ladder))
            });
        if let Some((model, locality, ladder)) = own {
            let backend = RunBackend::new(
                ladder,
                self.runtime
                    .undeclared_run(format!("{DREAMER_PASS_RUN}/resident"), self.line.clone()),
            );
            let egress = self
                .egress
                .then(|| extraction_egress(BTreeSet::from([model.clone()])));
            let window_tokens = self.windows.get(&model).copied();
            return run_resident_dream(
                attempt,
                ctx,
                ResidentDreamModel {
                    backend: &backend,
                    guard: self.guard,
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
                }),
            }
        } else if attempt.status.payload.attempt_type
            == oneiron::dreamer_runner::DREAMER_WEAVE_LENS_ATTEMPT_KIND
        {
            match self.task {
                Some(lend) => lend.render_lens(attempt, ctx).await,
                None => Ok(DreamerAttemptExecution::Park {
                    reason: WEAVE_LENS_UNLENT_PARK_REASON.to_owned(),
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
}
