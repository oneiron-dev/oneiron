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
use std::sync::Arc;

use oneiron::dreamer_consolidation::{
    DREAMER_EXTRACTION_ROLE, DREAMER_ROLES, RoleBackend, RoleBackends,
};
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::llm::HostInferenceBinding;
use oneiron::llm::manifest::ModelRole;
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerClaimAuthoringStrategy, DreamerRunnerStore, Vault, WakeAttemptContext, WriteActor,
};
use oneiron_driver::{
    AttemptQueueDeadlines, ConsolidationExecutorFactory, HintPusher, HybridTick,
    IdleSample, PassExecutorFactory, PushTick, SessionLifecycleConfig, SessionLifecycleDriver,
    SessionTicks, ShutdownHandle, TimerTick, WakePolicyTicks, WakeSupervisor, WakeSupervisorConfig,
    WakeSupervisorReport,
};

use super::policy::extraction_egress;
use super::status::{StatusCell, WorkState, WorkStatus};
use crate::config::models::{DreamerSettings, role_key};
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
    } = start;
    let built = (|| -> anyhow::Result<_> {
        let node_id = claim_home_node(&vault)?;
        // The nightly harness audit reads this; a failed record never stops
        // the Dreamer.
        if let Err(error) =
            super::harness::record_tuning_config(&vault, &runtime, &seat, &settings, now_ms() / 1_000)
        {
            tracing::warn!(%error, "dreamer tuning config not recorded");
        }
        let factory = ObservedFactory {
            vault: Arc::clone(&vault),
            runtime,
            seat,
            actor: vault.dreamer_authority()?,
            egress,
            summary_instruction: settings.summary_instruction.clone(),
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
    inner: Option<ConsolidationExecutorFactory>,
    status: Arc<StatusCell>,
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
        .with_role_backends(roles);
        if let Some(instruction) = &self.summary_instruction {
            factory = factory.with_scope_summary_instruction(instruction.clone());
        }
        let inner = self.inner.insert(factory);
        Ok(ObservedExecutor {
            inner: inner.executor(guard)?,
            status: &self.status,
        })
    }

    fn actor(&self) -> Option<WriteActor> {
        Some(self.actor)
    }
}

struct ObservedExecutor<'p, E> {
    inner: E,
    status: &'p StatusCell,
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
        let outcome = self.inner.execute(attempt, ctx).await;
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
