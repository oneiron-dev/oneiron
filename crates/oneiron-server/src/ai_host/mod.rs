//! The server's background AI work, built from `[models]`: the Dreamer, the
//! saved-workflow pump, and the seats chat turns run on.
//!
//! Nothing here is required. Without a model every model-free path works,
//! and each piece reports why it is idle (`no_model_configured`, say) on
//! `/api/health` and `GET /v1/ai/status`. Writes never wait on a model.
use std::collections::HashSet;
use std::sync::Arc;

use oneiron::attempt_queue::{AttemptQueue, AttemptState, CleanupAttemptLeases};
use oneiron::llm::manifest::ModelRole;
use oneiron::{DreamerRunnerStore, ModelId, ModelLocality, Vault};
use oneiron_driver::{HintPusher, SessionHint};

use crate::config::models::{ChatSettings, ModelsConfig};
use crate::models::{ModelRuntime, ModelsStatus, RoleCall, RoleRefusal, Seat};
use crate::server::SyncServer;

mod dreamer;
mod policy;
mod status;
mod step;
mod step_failure;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
mod turns;
mod workflows;

pub(crate) use policy::route_dreamer_extraction;
pub use status::{AiHealth, AiStatus, IdleReason, WorkState, WorkStatus};

use dreamer::{DreamerHost, DreamerStart};
use policy::DreamerRoute;
use status::StatusCell;
use step::StepRunner;
pub(crate) use turns::TurnGuard;
use turns::TurnTracker;
use workflows::WorkflowPump;

/// The seat each piece of AI work runs on.
const DREAMER_ROLE: ModelRole = ModelRole::DreamerCurrent;
pub(crate) const CHAT_ROLE: ModelRole = ModelRole::GenerativeReasoner;
/// How long shutdown lets running chat turns finish before stopping them.
const TURN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// What request handlers need: seats, status and the session-hint producer.
/// Cheap to clone; inert when nothing is configured.
#[derive(Clone)]
pub struct AiHandle {
    runtime: Arc<ModelRuntime>,
    status: Arc<StatusCell>,
    hints: Option<Arc<HintPusher>>,
    chat: ChatSettings,
    raw_budget_units: Option<u64>,
    turns: TurnTracker,
}

impl AiHandle {
    /// No `[models]`: every seat empty, every worker idle for want of one.
    #[must_use]
    pub fn inert() -> Self {
        Self::unstarted(Arc::new(ModelRuntime::unconfigured()), None)
    }

    fn unstarted(runtime: Arc<ModelRuntime>, models: Option<&ModelsConfig>) -> Self {
        let idle = || WorkStatus::idle(IdleReason::NoModelConfigured);
        let chat = if runtime.seat(CHAT_ROLE).is_some() {
            WorkStatus::waiting()
        } else {
            idle()
        };
        Self {
            runtime,
            status: Arc::new(StatusCell::new(AiStatus {
                dreamer: idle(),
                workflows: idle(),
                chat,
            })),
            hints: None,
            chat: models.map_or(
                ChatSettings {
                    history_turns: 0,
                    turn_budget_units: 0,
                },
                |models| models.chat,
            ),
            raw_budget_units: models.map(|models| models.raw_budget_units),
            turns: TurnTracker::new(),
        }
    }

    #[must_use]
    pub fn seat(&self, role: ModelRole) -> Option<&Seat> {
        self.runtime.seat(role)
    }

    /// The seat chat turns run on.
    #[must_use]
    pub fn chat_seat(&self) -> Option<&Seat> {
        self.runtime.seat(CHAT_ROLE)
    }

    #[must_use]
    pub fn chat_settings(&self) -> ChatSettings {
        self.chat
    }

    /// Admits a call of `role` against the vault's live model policy: its
    /// manifest and route when it has one, the role's seat otherwise.
    pub fn admit_role(
        &self,
        vault: &Vault,
        role: ModelRole,
        request: oneiron::LlmRequest,
    ) -> Result<RoleCall, RoleRefusal> {
        self.runtime.admit_role(vault, role, request)
    }

    /// Registers a running chat turn with shutdown.
    pub(crate) fn enter_turn(&self) -> TurnGuard {
        self.turns.enter()
    }

    /// Where a configured model runs: the host's attestation for raw calls.
    #[must_use]
    pub fn model_locality(&self, model: &ModelId) -> Option<ModelLocality> {
        self.runtime
            .router()
            .and_then(|router| router.locality(model))
    }

    #[must_use]
    pub fn status(&self) -> AiStatus {
        self.status.snapshot()
    }

    #[must_use]
    pub fn models_status(&self) -> &ModelsStatus {
        self.runtime.status()
    }

    /// Tells the Dreamer's session policy what the app saw. A no-op without
    /// a running Dreamer: no session is opened that nothing would close.
    pub fn session_hint(&self, hint: SessionHint) {
        let Some(hints) = &self.hints else {
            return;
        };
        if let Err(error) = hints.push_session_hint(hint, None) {
            tracing::warn!(?error, ?hint, "dreamer session hint dropped");
        }
    }
}

/// The running workers, owned by the serve path until shutdown.
pub struct AiHost {
    handle: AiHandle,
    dreamer: Option<DreamerHost>,
    workflows: Option<WorkflowPump>,
}

impl AiHost {
    /// Builds every seat from `models`, starts the workers those seats can
    /// serve, and hands the server its handle (and the raw `/v1/llm` routes
    /// their router).
    pub async fn attach(server: SyncServer, models: Option<&ModelsConfig>) -> (SyncServer, Self) {
        let host = Self::start(
            Arc::clone(server.vault()),
            models,
            server.host_root_provisioned(),
        )
        .await;
        (server.with_ai(host.handle.clone()), host)
    }

    pub async fn start(vault: Arc<Vault>, models: Option<&ModelsConfig>, host_root: bool) -> Self {
        recover_dead_leases(&vault);
        let runtime = Arc::new(ModelRuntime::build(models));
        let mut handle = AiHandle::unstarted(Arc::clone(&runtime), models);
        let mut host = Self {
            handle: handle.clone(),
            dreamer: None,
            workflows: None,
        };
        let Some(models) = models else {
            return host;
        };
        let status = Arc::clone(&handle.status);
        match start_dreamer(&vault, &runtime, models, host_root, &status).await {
            Ok(dreamer) => {
                handle.hints = Some(dreamer.hints());
                host.dreamer = Some(dreamer);
            }
            Err(reason) => status.update(|status| status.dreamer = WorkStatus::idle(reason)),
        }
        match start_workflows(&vault, &runtime, models, &status) {
            Ok(pump) => host.workflows = Some(pump),
            Err(reason) => status.update(|status| status.workflows = WorkStatus::idle(reason)),
        }
        host.handle = handle;
        host
    }

    #[must_use]
    pub fn handle(&self) -> AiHandle {
        self.handle.clone()
    }

    /// Lets running chat turns end, then stops both workers cooperatively
    /// and waits for them.
    pub async fn shutdown(mut self) {
        self.handle.turns.shutdown(TURN_GRACE).await;
        if let Some(pump) = self.workflows.take() {
            pump.stop().await;
        }
        if let Some(dreamer) = self.dreamer.take() {
            dreamer.stop().await;
        }
        self.handle.status.update(|status| {
            for work in [&mut status.dreamer, &mut status.workflows] {
                if work.state != WorkState::Idle {
                    work.state = WorkState::Idle;
                    work.reason = Some(IdleReason::Stopped);
                }
            }
        });
    }
}

/// A host dropped without [`AiHost::shutdown`] (an embedding process whose
/// startup failed after attach, say) still tells every worker to stop; it
/// cannot wait for them here.
impl Drop for AiHost {
    fn drop(&mut self) {
        self.handle.turns.stop_now();
        if let Some(pump) = &self.workflows {
            pump.signal_stop();
        }
        if let Some(dreamer) = &self.dreamer {
            dreamer.signal_stop();
        }
    }
}

/// This process owns the vault exclusively, so every attempt lease at boot
/// was held by a process that is gone. Requeue them: an interrupted pass or
/// step runs again exactly once, from its durable checkpoints.
///
/// A parked attempt is requeued only when this server's Dreamer parked it
/// itself (a pass cut at its deadline, an executor error): that park is its
/// own checkpoint, cleared here. One parked on a signal (a budget or consent
/// trap, a wait) stays leased: a restart is not its resume signal (runtime.md),
/// and it resumes only when its signal is consumed. Expiry is by age, so "now"
/// is the later of the wall clock and one second past the youngest lease:
/// every dead lease expires, even after the clock stepped back, and none
/// waits.
fn recover_dead_leases(vault: &Vault) {
    let queue = AttemptQueue::new(vault);
    let rows = match queue.list() {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "boot lease recovery could not list attempts");
            return;
        }
    };
    let runner = DreamerRunnerStore::new(vault);
    let mut held = HashSet::new();
    let mut youngest = None;
    for row in rows
        .iter()
        .filter(|row| matches!(row.state, AttemptState::Leased | AttemptState::Landing))
    {
        let parked = match runner.parked_attempt(row.id) {
            Ok(parked) => parked,
            Err(error) => {
                tracing::warn!(%error, attempt = ?row.id, "a parked attempt could not be read; its lease is kept");
                held.insert(row.id);
                continue;
            }
        };
        match parked {
            Some(park) if park.park_owner == dreamer::LEASE_OWNER => {
                if let Err(error) = runner.resume_parked(row.id, &park.park_owner, unix_now()) {
                    tracing::warn!(%error, attempt = ?row.id, "a checkpoint park was not cleared; its lease is kept");
                    held.insert(row.id);
                    continue;
                }
            }
            Some(_) => {
                held.insert(row.id);
                continue;
            }
            None => {}
        }
        youngest = youngest.max(Some(row.updated_at));
    }
    if !held.is_empty() {
        tracing::info!(
            attempts = held.len(),
            "attempts parked on a signal keep their leases"
        );
    }
    let Some(youngest) = youngest else {
        return;
    };
    match queue.cleanup_leases_except(
        CleanupAttemptLeases {
            now: unix_now().max(youngest.saturating_add(1)),
            lease_timeout_secs: 1,
        },
        &held,
    ) {
        Ok(report) => tracing::info!(?report, "requeued attempt leases a stopped process held"),
        Err(error) => tracing::warn!(%error, "boot lease recovery failed"),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

async fn start_dreamer(
    vault: &Arc<Vault>,
    runtime: &Arc<ModelRuntime>,
    models: &ModelsConfig,
    host_root: bool,
    status: &Arc<StatusCell>,
) -> Result<DreamerHost, IdleReason> {
    if !models.dreamer.enabled {
        return Err(IdleReason::Disabled);
    }
    let seat = runtime
        .seat(DREAMER_ROLE)
        .ok_or(IdleReason::NoModelConfigured)?
        .clone();
    if !host_root {
        return Err(IdleReason::NoHostAuthority);
    }
    // A pass the policy cannot serve would park its attempts for good; leave
    // them queued until the policy carries the Dreamer's rows again.
    match vault.dreamer_weave_reach() {
        Ok(reach) if reach.ready() => {}
        Ok(_) => return Err(IdleReason::NeedsOwnerGrant),
        Err(error) => {
            tracing::error!(%error, "dreamer policy reach could not be read");
            return Err(IdleReason::StartFailed);
        }
    }
    // Each pass extracts on the teacher the vault's live manifest pins (the
    // seat without one), so the route the owner's defaults must allow is that
    // model's, not the seat's.
    let teacher = match runtime.route_role(vault, dreamer::EXTRACTION_ROLE, &seat) {
        Ok(route) => route,
        Err(RoleRefusal::RouteNotServed { .. }) => {
            return Err(IdleReason::ExtractionModelNotServed);
        }
        Err(refusal) => {
            tracing::error!(%refusal, "dreamer extraction route could not be resolved");
            return Err(IdleReason::StartFailed);
        }
    };
    let egress = match policy::dreamer_route(vault, teacher.locality, models.extraction_egress) {
        Ok(DreamerRoute::Ready { egress }) => egress,
        Ok(DreamerRoute::Blocked(reason)) => return Err(reason),
        Err(error) => {
            tracing::error!(%error, "dreamer route policy could not be read");
            return Err(IdleReason::StartFailed);
        }
    };
    DreamerHost::spawn(DreamerStart {
        vault: Arc::clone(vault),
        runtime: Arc::clone(runtime),
        seat,
        settings: models.dreamer,
        egress,
        status: Arc::clone(status),
    })
    .await
    .map_err(|error| {
        tracing::error!(%error, "dreamer failed to start");
        IdleReason::StartFailed
    })
}

fn start_workflows(
    vault: &Arc<Vault>,
    runtime: &Arc<ModelRuntime>,
    models: &ModelsConfig,
    status: &Arc<StatusCell>,
) -> Result<WorkflowPump, IdleReason> {
    if !models.workflows.enabled {
        return Err(IdleReason::Disabled);
    }
    if runtime.seat(CHAT_ROLE).is_none() {
        return Err(IdleReason::NoModelConfigured);
    }
    WorkflowPump::spawn(
        Arc::clone(vault),
        StepRunner {
            models: Arc::clone(runtime),
            budget_units: models.workflows.step_budget_units,
            retry_backoff_secs: models.workflows.retry_backoff_secs,
        },
        Arc::clone(status),
    )
    .map_err(|error| {
        tracing::error!(%error, "workflow pump failed to start");
        IdleReason::StartFailed
    })
}

impl AiHandle {
    /// The router the raw `/v1/llm` routes call, with its own meter.
    pub(crate) fn raw_inference(
        &self,
    ) -> Option<(Arc<dyn oneiron::LlmBackend>, oneiron::BudgetGuard)> {
        let router: Arc<dyn oneiron::LlmBackend> = self.runtime.router()?;
        let units = self.raw_budget_units?;
        Some((
            router,
            oneiron::BudgetGuard::new(
                "raw-inference",
                units,
                oneiron::BudgetExhaustionPolicy::Suspend,
            ),
        ))
    }
}
