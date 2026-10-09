//! The server's Dreamer: one wake supervisor for its one vault (ARCH-0026:
//! one Dreamer per vault, on the primary node — for a single local server,
//! this server).
//!
//! The supervisor runs on its own thread with its own current-thread runtime:
//! a wake pass does LMDB work inline and must not stall request handlers.
//! Triggers are the driver's: the attempt-queue deadline lane (never a poll)
//! plus pushed session hints. A sitting ends on the idle floor, the hard
//! ceiling or an explicit end, and its turns are enqueued for consolidation
//! atomically with the end.
use std::sync::Arc;

use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::llm::HostInferenceBinding;
use oneiron::llm::manifest::ModelRole;
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerClaimAuthoringStrategy, DreamerRunnerStore, Vault, WakeAttemptContext, WriteActor,
};
use oneiron_driver::{
    AttemptQueueDeadlines, ConsolidationExecutorFactory, HintPusher, HybridTick,
    PassExecutorFactory, PushTick, SessionLifecycleConfig, SessionLifecycleDriver, SessionTicks,
    ShutdownHandle, TimerTick, WakeSupervisor, WakeSupervisorConfig, WakeSupervisorReport,
};

use super::policy::extraction_egress;
use super::status::{StatusCell, WorkState, WorkStatus};
use crate::config::models::DreamerSettings;
use crate::models::{ModelRuntime, Seat};

/// Stamped on every admission and park this server makes.
pub(super) const LEASE_OWNER: &str = "oneiron-server-dreamer";
/// Base id of the per-pass durable budget rows (`dreamer:p<n>`).
const BUDGET_ID: &str = "dreamer";
/// The role a pass's extraction is admitted as; a vault's manifest binds it.
const EXTRACTION_ROLE: ModelRole = ModelRole::ExtractionTeacher;

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
    } = start;
    let built = (|| -> anyhow::Result<_> {
        let node_id = claim_home_node(&vault)?;
        let factory = ObservedFactory {
            vault: Arc::clone(&vault),
            runtime,
            seat,
            actor: vault.dreamer_authority()?,
            egress,
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
        let ticks = SessionTicks::new(
            HybridTick::new(
                TimerTick::new(AttemptQueueDeadlines::new(&vault, node_id)),
                push,
            ),
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

/// The consolidation factory, rebuilt for each pass on the model that pass's
/// extraction is admitted as, with each pass and attempt reported to status.
struct ObservedFactory {
    vault: Arc<Vault>,
    runtime: Arc<ModelRuntime>,
    /// The binding when the vault has no model manifest.
    seat: Seat,
    actor: WriteActor,
    egress: bool,
    inner: Option<ConsolidationExecutorFactory>,
    status: Arc<StatusCell>,
}

impl PassExecutorFactory for ObservedFactory {
    type Exec<'p> =
        ObservedExecutor<'p, <ConsolidationExecutorFactory as PassExecutorFactory>::Exec<'p>>;

    /// Resolves the extraction role against the vault's live manifest and
    /// route, as a chat turn does, so the backend attests the model the
    /// engine's admission selects. A route this server does not serve stops
    /// the pass before any attempt is admitted.
    fn executor<'p>(
        &'p mut self,
        guard: &'p oneiron::BudgetGuard,
    ) -> oneiron::Result<Self::Exec<'p>> {
        let route = match self
            .runtime
            .route_role(&self.vault, EXTRACTION_ROLE, &self.seat)
        {
            Ok(route) => route,
            Err(refusal) => {
                let error =
                    oneiron::Error::InvalidConfig(format!("dreamer extraction refused: {refusal}"));
                self.status
                    .update(|status| status.dreamer.last_error = Some(error.to_string()));
                return Err(error);
            }
        };
        let inner = self.inner.insert(ConsolidationExecutorFactory::new(
            route.backend,
            DreamerClaimAuthoringStrategy::SinglePass,
            self.actor,
            route.model.clone(),
            HostInferenceBinding::Advertised {
                model: route.model.clone(),
                locality: route.locality,
            },
            self.egress.then(|| extraction_egress(route.model)),
            Box::new(AttemptPromotionSink::new(Arc::clone(&self.vault))),
        ));
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
