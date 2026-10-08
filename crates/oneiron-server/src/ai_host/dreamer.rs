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
use oneiron::llm::{ExtractionEgressPredicate, HostInferenceBinding};
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerClaimAuthoringStrategy, DreamerRunnerStore, Vault, WakeAttemptContext, WriteActor,
};
use oneiron_driver::{
    AttemptQueueDeadlines, ConsolidationExecutorFactory, HintPusher, HybridTick,
    PassExecutorFactory, PushTick, SessionLifecycleConfig, SessionLifecycleDriver, SessionTicks,
    ShutdownHandle, TimerTick, WakeSupervisor, WakeSupervisorConfig, WakeSupervisorReport,
};

use super::status::{StatusCell, WorkState};
use crate::config::models::DreamerSettings;
use crate::models::Seat;

/// Stamped on every admission and park this server makes.
const LEASE_OWNER: &str = "oneiron-server-dreamer";
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
    pub(super) seat: Seat,
    pub(super) settings: DreamerSettings,
    pub(super) egress: Option<Arc<dyn ExtractionEgressPredicate>>,
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

    /// Cooperative stop: a pass in flight reaches its attempt boundary,
    /// parks and refunds what it admitted, and only then does the thread end.
    pub(super) async fn stop(self) -> Option<WakeSupervisorReport> {
        self.shutdown.shutdown();
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
        seat,
        settings,
        egress,
        status,
    } = start;
    let built = (|| -> anyhow::Result<_> {
        let node_id = claim_home_node(&vault)?;
        let actor = vault.dreamer_authority()?;
        let factory = ConsolidationExecutorFactory::new(
            seat.backend.clone(),
            DreamerClaimAuthoringStrategy::SinglePass,
            actor,
            seat.model.clone(),
            HostInferenceBinding::Advertised {
                model: seat.model.clone(),
                locality: seat.locality,
            },
            egress,
            Box::new(AttemptPromotionSink::new(Arc::clone(&vault))),
        );
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
    let supervisor = WakeSupervisor::new(
        &vault,
        ticks,
        ObservedFactory {
            inner: factory,
            status: Arc::clone(&status),
        },
        config,
    );
    if ready
        .send(Ok((supervisor.shutdown_handle(), hints)))
        .is_err()
    {
        return WakeSupervisorReport::default();
    }
    status.update(|status| status.dreamer.state = WorkState::Waiting);
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

/// The consolidation factory, with each pass and attempt reported to status.
struct ObservedFactory {
    inner: ConsolidationExecutorFactory,
    status: Arc<StatusCell>,
}

impl PassExecutorFactory for ObservedFactory {
    type Exec<'p> =
        ObservedExecutor<'p, <ConsolidationExecutorFactory as PassExecutorFactory>::Exec<'p>>;

    fn executor<'p>(
        &'p mut self,
        guard: &'p oneiron::BudgetGuard,
    ) -> oneiron::Result<Self::Exec<'p>> {
        Ok(ObservedExecutor {
            inner: self.inner.executor(guard)?,
            status: &self.status,
        })
    }

    fn actor(&self) -> Option<WriteActor> {
        self.inner.actor()
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
