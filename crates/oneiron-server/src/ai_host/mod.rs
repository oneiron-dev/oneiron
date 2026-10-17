//! The server's background AI work, built from `[models]`: the Dreamer, the
//! saved-workflow pump, and the seats chat turns run on.
//!
//! Nothing here is required. Without a model every model-free path works,
//! and each piece reports why it is idle (`no_model_configured`, say) on
//! `/api/health` and `GET /v1/ai/status`. Writes never wait on a model.
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use oneiron::attempt_queue::{AttemptQueue, AttemptState, CleanupAttemptLeases};
use oneiron::dreamer_consolidation::DREAMER_EXTRACTION_ROLE;
use oneiron::dreamer_wake::{AgentWakeSignals, WakeIdleState, WakeTurnSubject};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::RunReceiptSink;
use oneiron::{DreamerRunnerStore, EdgeActorClass, EntityId, ModelId, ModelLocality, Vault};
use oneiron_driver::{HintPusher, IdleSample, SessionHint};

use crate::config::models::{ChatSettings, ModelsConfig};
use crate::models::{
    KeyDoor, LoggedReceipts, ModelRuntime, ModelsStatus, OfferCooldowns, RawInference, RoleCall,
    RoleRefusal, Seat, VaultKeyDoor,
};
use crate::server::SyncServer;

#[cfg(feature = "code-sandbox-wasmtime")]
mod code_mode;
#[cfg(feature = "code-sandbox-wasmtime")]
mod compaction;
#[cfg(all(test, feature = "code-sandbox-wasmtime"))]
pub(crate) use compaction::tests::cross_the_passes;
pub(crate) mod coach_heal;
mod code_fix;
mod dreamer;
mod harness;
pub(crate) mod identity;
mod local_vision;
mod policy;
mod status;
mod step;
mod step_failure;
mod stewardship;
mod sync_wake;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
mod turn_actions;
mod turns;
pub(crate) mod waves;
mod weave_lens;
mod workflows;

pub(crate) use local_vision::LocalVisionModel;
pub(crate) use policy::route_dreamer_extraction;
pub(crate) use weave_lens::{WeaveLensCaller, render_live_weave_lens};
pub use status::{
    AiHealth, AiStatus, CompactionState, CompactionStatus, IdleReason, WorkState, WorkStatus,
};

use dreamer::{DreamerHost, DreamerStart};
use policy::{DreamerRoute, dreamer_role_purpose};
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
    /// Each paid recall's line for its rerank calls (`[models.recall]`).
    rerank_budget_units: u64,
    turns: TurnTracker,
    /// When the last turn landed, in seconds: the inbound silence the
    /// Dreamer's wake policy waits out before an idle recipe.
    inbound: Arc<AtomicU64>,
    /// The running Dreamer has a summary instruction to write bodies with.
    summaries: bool,
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
                compaction: CompactionStatus::off(match models {
                    None => oneiron::compaction::CompactionOff::NoModels.as_str(),
                    Some(_) => status::CODE_MODE_OFF,
                }),
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
            rerank_budget_units: models.map_or(0, |models| models.recall.rerank_budget_units),
            turns: TurnTracker::new(),
            inbound: Arc::new(AtomicU64::new(unix_now())),
            summaries: false,
        }
    }

    /// What the Dreamer's wake policy samples before each decision (ARCH-0026
    /// #wake): running chat turns, live workflow work and the last landed
    /// turn. The Dreamer runs only on a seat, so compute is there.
    fn idle_sample(&self) -> IdleSample {
        let turns = self.turns.clone();
        let status = Arc::clone(&self.status);
        let inbound = Arc::clone(&self.inbound);
        Arc::new(move || WakeIdleState {
            running_turns: turns.running(),
            live_background_work: status.snapshot().workflows.state == WorkState::Working,
            compute_available: true,
            last_inbound_at: inbound.load(Ordering::Acquire),
        })
    }

    /// Whether a declared scope summary will be written: only the Dreamer
    /// writes a summary body (ARCH-0006a), so without a running Dreamer and
    /// its summary instruction a declaration is refused, never parked.
    pub fn summary_writer(&self) -> Result<(), String> {
        if self.summaries {
            return Ok(());
        }
        Err(match self.status().dreamer.reason {
            Some(reason) if self.hints.is_none() => {
                let reason = serde_json::to_value(reason)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default();
                format!("the Dreamer is idle: {reason}")
            }
            _ => "the Dreamer has no summary instruction ([models.dreamer] summary_prompt)"
                .to_owned(),
        })
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

    /// The line each recall at high, xhigh or max spends its rerank calls
    /// on.
    #[must_use]
    pub fn rerank_budget_units(&self) -> u64 {
        self.rerank_budget_units
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

    /// A run that declares nothing on `meter` (a chat turn's line), with this
    /// server's run receipts.
    pub(crate) fn undeclared_run(
        &self,
        run: impl Into<String>,
        meter: oneiron::BudgetGuard,
    ) -> oneiron::llm::run_admission::RunAdmission {
        self.runtime.undeclared_run(run, meter)
    }

    /// A declared run on this server's models, for the host that states a
    /// run's teachers and budget (a training loop). Nothing on the server
    /// declares a run yet.
    #[must_use]
    pub fn declared_run(
        &self,
        run: impl Into<String>,
        declaration: oneiron::llm::run_admission::RunDeclaration,
        host: Option<Arc<oneiron::llm::run_admission::HostAccount>>,
    ) -> crate::models::DeclaredRun {
        self.runtime.declared_run(run, declaration, host)
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

    /// The models this server serves, for the `ai.*` verbs.
    #[must_use]
    pub(crate) fn model_runtime(&self) -> &ModelRuntime {
        &self.runtime
    }

    /// Tells the Dreamer's session policy what the app saw. A no-op without
    /// a running Dreamer: no session is opened that nothing would close.
    pub fn session_hint(&self, key: oneiron::session_lifecycle::SessionKey, hint: SessionHint) {
        let Some(hints) = &self.hints else {
            return;
        };
        if let Err(error) = hints.push_session_hint(key, hint, None) {
            tracing::warn!(?error, ?hint, "dreamer session hint dropped");
        }
    }

    /// A turn landed: a due turn queues the running Dreamer's Micro wake
    /// (ARCH-0026 RD-26), off the request path. A no-op without a running
    /// Dreamer, so a model-free vault queues nothing that never runs.
    pub fn turn_landed(&self, vault: &Arc<Vault>, subject: WakeTurnSubject) {
        self.inbound.fetch_max(unix_now(), Ordering::AcqRel);
        drop(self.wake_on_turn(vault, subject));
    }

    /// [`Self::turn_landed`]'s wake and the task it runs on, for a caller
    /// that waits for it. `None` without a running Dreamer.
    fn wake_on_turn(
        &self,
        vault: &Arc<Vault>,
        subject: WakeTurnSubject,
    ) -> Option<tokio::task::JoinHandle<()>> {
        self.hints.as_ref()?;
        let (vault, handle) = (Arc::clone(vault), self.clone());
        Some(tokio::task::spawn_blocking(move || {
            // An agent waking under a dial its owner moved notes the move in
            // its own diary before it acts again (OF-533).
            if let WakeTurnSubject::Agent { id, .. } = subject
                && let Err(error) = vault.note_refusal_dial_change(id)
            {
                tracing::warn!(%error, agent = %id.to_hex(), "refusal dial note not written");
            }
            // Queued or not, the turn is news to the wake policy: the pass
            // the hint takes re-reads its rows and re-arms its quiet timer.
            match vault.wake_dreamer_on_turn(subject, vault.now_recorded_at()) {
                Ok(_) => handle.attempt_queued(),
                Err(error) => tracing::warn!(%error, ?subject, "turn wake not queued"),
            }
        }))
    }

    /// The sieve reads a bounded batch with each turn wake; history it has
    /// not read yet (a vault the Dreamer starts on for the first time) is
    /// read here, a pass at a time, off the request path, until it is read
    /// or shutdown raises the drain's stop. A pass in flight then commits
    /// its own transaction, and the drain stops before the next. `None`
    /// without a running Dreamer.
    fn drain_sieve(&self, vault: &Arc<Vault>) -> Option<SieveDrain> {
        self.hints.as_ref()?;
        let vault = Arc::clone(vault);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let task = tokio::task::spawn_blocking(move || {
            while !stopped.load(Ordering::Acquire) {
                match vault.sieve_pass(vault.now_recorded_at()) {
                    Ok(pass) if pass.more => {}
                    Ok(_) => break,
                    Err(error) => {
                        tracing::warn!(kind = ?error.kind(), "sieve backlog pass failed");
                        break;
                    }
                }
            }
        });
        Some(SieveDrain { stop, task })
    }

    /// A Dreamer attempt was queued outside the driver: the running Dreamer
    /// takes a pass for it now instead of at its next deadline.
    pub fn attempt_queued(&self) {
        let Some(hints) = &self.hints else {
            return;
        };
        if let Err(error) = hints.push_hint() {
            tracing::warn!(?error, "dreamer pass hint dropped");
        }
    }

    /// [`Self::turn_landed`] for a turn `actor` wrote: an agent with a stored
    /// definition counts it on its own cadence dial, anyone else on the
    /// vault's grain.
    pub fn turn_landed_by(&self, vault: &Arc<Vault>, actor: EntityId, class: EdgeActorClass) {
        let agent = class == EdgeActorClass::Agent
            && vault
                .get_agent_definition(&actor)
                .is_ok_and(|found| found.is_some());
        self.turn_landed(
            vault,
            if agent {
                WakeTurnSubject::Agent {
                    id: actor,
                    signals: AgentWakeSignals::default(),
                }
            } else {
                WakeTurnSubject::Vault
            },
        );
    }
}

/// The running workers, owned by the serve path until shutdown.
pub struct AiHost {
    handle: AiHandle,
    dreamer: Option<DreamerHost>,
    workflows: Option<WorkflowPump>,
    sieve: Option<SieveDrain>,
    /// A peer's sync apply wakes the running Dreamer.
    sync_wake: Option<sync_wake::SyncWake>,
}

/// The sieve's backlog drain and the stop it checks between passes.
struct SieveDrain {
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl AiHost {
    /// Builds every seat from `models`, starts the workers those seats can
    /// serve, and hands the server its handle (and the raw `/v1/llm` routes
    /// their router, and MCP `execute_code` its executor).
    pub async fn attach(server: SyncServer, models: Option<&ModelsConfig>) -> (SyncServer, Self) {
        let mut host = Self::start_receipted(
            Arc::clone(server.vault()),
            models,
            server.host_root_provisioned(),
            server.run_receipts(),
            Some(server.host_account()),
        )
        .await;
        if host.handle.hints.is_some() {
            host.sync_wake = Some(sync_wake::SyncWake::spawn(
                host.handle.clone(),
                Arc::clone(server.vault()),
                &server.reassert_manager,
            ));
        }
        let server = server
            .with_ai(host.handle.clone())
            .with_decision_config(models);
        #[cfg(feature = "code-sandbox-wasmtime")]
        let server =
            code_mode::bind(server, &host.handle.runtime, models, &host.handle.status).await;
        (server, host)
    }

    /// Builds every seat from `models` and starts the workers those seats can
    /// serve. Every model call they make is admitted as a run whose receipts
    /// are written to the log.
    pub async fn start(vault: Arc<Vault>, models: Option<&ModelsConfig>, host_root: bool) -> Self {
        Self::start_receipted(vault, models, host_root, Arc::new(LoggedReceipts), None).await
    }

    /// `start`, with the run receipts going to `receipts`.
    pub(crate) async fn start_receipted(
        vault: Arc<Vault>,
        models: Option<&ModelsConfig>,
        host_root: bool,
        receipts: Arc<dyn RunReceiptSink>,
        account: Option<Arc<oneiron::llm::run_admission::HostAccount>>,
    ) -> Self {
        recover_dead_leases(&vault);
        let keys: Arc<dyn KeyDoor> = Arc::new(VaultKeyDoor::new(Arc::clone(&vault)));
        let rests = OfferCooldowns::in_vault(Arc::clone(&vault));
        let mut runtime =
            ModelRuntime::build_hosted(models, Some(keys), rests).with_receipts(receipts);
        if let Some(account) = account {
            runtime = runtime.with_host_account(account);
        }
        let runtime = Arc::new(runtime);
        let mut handle = AiHandle::unstarted(Arc::clone(&runtime), models);
        let mut host = Self {
            handle: handle.clone(),
            dreamer: None,
            workflows: None,
            sieve: None,
            sync_wake: None,
        };
        let Some(models) = models else {
            return host;
        };
        let status = Arc::clone(&handle.status);
        let idle = handle.idle_sample();
        match start_dreamer(&vault, &runtime, models, host_root, &status, idle).await {
            Ok(dreamer) => {
                handle.hints = Some(dreamer.hints());
                handle.summaries = models.dreamer.summary_instruction.is_some();
                host.dreamer = Some(dreamer);
            }
            Err(reason) => status.update(|status| status.dreamer = WorkStatus::idle(reason)),
        }
        match start_workflows(&vault, &runtime, models, &status) {
            Ok(pump) => host.workflows = Some(pump),
            Err(reason) => status.update(|status| status.workflows = WorkStatus::idle(reason)),
        }
        host.handle = handle;
        turn_actions::spawn(&vault, &host.handle);
        if host.dreamer.is_some() {
            resume_on_recovery(&vault, &runtime);
        }
        // Turns that landed while no Dreamer ran, or just before a crash,
        // get their due wake now rather than waiting for the next turn. It
        // settles before start returns, so it reads only those turns: one
        // that lands later is woken by its own door, never by this one.
        if let Some(wake) = host.handle.wake_on_turn(&vault, WakeTurnSubject::Vault)
            && let Err(error) = wake.await
        {
            tracing::warn!(panicked = error.is_panic(), "boot turn wake did not finish");
        }
        host.sieve = host.handle.drain_sieve(&vault);
        host
    }

    #[must_use]
    pub fn handle(&self) -> AiHandle {
        self.handle.clone()
    }

    /// Lets running chat turns end, then stops both workers and the sieve's
    /// backlog drain cooperatively and waits for them.
    pub async fn shutdown(mut self) {
        if let Some(wake) = self.sync_wake.take() {
            wake.stop();
        }
        let sieve = self.sieve.take();
        if let Some(drain) = &sieve {
            drain.stop.store(true, Ordering::Release);
        }
        self.handle.turns.shutdown(TURN_GRACE).await;
        if let Some(pump) = self.workflows.take() {
            pump.stop().await;
        }
        if let Some(dreamer) = self.dreamer.take() {
            dreamer.stop().await;
        }
        if let Some(drain) = sieve
            && let Err(error) = drain.task.await
        {
            tracing::warn!(
                panicked = error.is_panic(),
                "sieve backlog drain did not stop cleanly"
            );
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
        if let Some(wake) = &self.sync_wake {
            wake.stop();
        }
        if let Some(pump) = &self.workflows {
            pump.signal_stop();
        }
        if let Some(dreamer) = &self.dreamer {
            dreamer.signal_stop();
        }
        if let Some(drain) = &self.sieve {
            drain.stop.store(true, Ordering::Release);
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

/// After each stable recovery of a provider that was down (OF-305), the
/// attempts this server's Dreamer parked on an executor error are requeued,
/// as a restart requeues them: the outage that failed their step is over.
/// One parked on a signal (a budget or consent trap, a wait) or by a hard
/// cut is not this resume's. The task holds the vault weakly and ends with
/// the runtime.
fn resume_on_recovery(vault: &Arc<Vault>, runtime: &ModelRuntime) {
    let vault = Arc::downgrade(vault);
    let mut recoveries = runtime.recoveries();
    tokio::spawn(async move {
        while recoveries.changed().await.is_ok() {
            let Some(vault) = vault.upgrade() else {
                return;
            };
            let resumed = tokio::task::spawn_blocking(move || resume_outage_parks(&vault)).await;
            if let Err(error) = resumed {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "recovery resume did not finish"
                );
            }
        }
    });
}

/// Requeues every attempt this server's Dreamer parked on an executor error.
fn resume_outage_parks(vault: &Vault) {
    let rows = match AttemptQueue::new(vault).list() {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "recovery resume could not list attempts");
            return;
        }
    };
    let runner = DreamerRunnerStore::new(vault);
    let mut resumed = 0usize;
    for row in rows
        .iter()
        .filter(|row| matches!(row.state, AttemptState::Leased))
    {
        let Ok(Some(park)) = runner.parked_attempt(row.id) else {
            continue;
        };
        if park.park_owner != dreamer::LEASE_OWNER
            || !park
                .reason
                .starts_with(oneiron::DREAMER_EXECUTOR_ERROR_PARK_REASON)
        {
            continue;
        }
        match runner.resume_parked(row.id, &park.park_owner, unix_now()) {
            Ok(Some(_)) => resumed += 1,
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, attempt = ?row.id, "an outage park was not resumed");
            }
        }
    }
    if resumed > 0 {
        tracing::info!(
            resumed,
            "a provider recovered; attempts its outage parked resume"
        );
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
    idle: IdleSample,
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
    // Each pass calls every role on the model the vault's live manifest pins
    // for it (else the role's seat, else the Dreamer's), so the routes the
    // owner's defaults must allow are those models', not the seat's.
    let routes = match dreamer::role_routes(runtime, vault, &seat) {
        Ok(routes) => routes,
        Err((role, RoleRefusal::RouteNotServed { .. })) => {
            return Err(if role == DREAMER_EXTRACTION_ROLE {
                IdleReason::ExtractionModelNotServed
            } else {
                IdleReason::RoleModelNotServed
            });
        }
        Err((role, refusal)) => {
            // An engine refusal logs by kind: its text can quote the vault.
            let kind = match &refusal {
                RoleRefusal::Refused(error) => Some(error.kind()),
                RoleRefusal::NoSeat | RoleRefusal::RouteNotServed { .. } => None,
            };
            tracing::error!(?kind, role = ?role, "a dreamer role's route could not be resolved");
            return Err(IdleReason::StartFailed);
        }
    };
    let localities = routes
        .iter()
        .map(|(role, route)| (dreamer_role_purpose(*role), route.locality))
        .collect::<Vec<_>>();
    let egress = match policy::dreamer_route(vault, &localities, models.extraction_egress) {
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
        settings: models.dreamer.clone(),
        egress,
        status: Arc::clone(status),
        idle,
        windows: dreamer::dream_windows(models),
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
            spent: Default::default(),
        },
        Arc::clone(status),
    )
    .map_err(|error| {
        tracing::error!(%error, "workflow pump failed to start");
        IdleReason::StartFailed
    })
}

impl AiHandle {
    /// The model seats this host built: inert ones when `[models]` is unset.
    pub(crate) fn models(&self) -> &Arc<ModelRuntime> {
        &self.runtime
    }

    /// The router the raw `/v1/llm` routes call, with its own meter.
    pub(crate) fn decision_read(&self) -> Option<crate::models::DecisionReadDoor> {
        self.runtime.decision_read().cloned()
    }

    pub(crate) fn raw_inference(&self) -> Option<RawInference> {
        let router = self.runtime.router()?;
        let units = self.raw_budget_units?;
        Some(RawInference::configured(
            router,
            oneiron::BudgetGuard::new(
                "raw-inference",
                units,
                oneiron::BudgetExhaustionPolicy::Suspend,
            ),
            self.runtime.host_account(),
        ))
    }
}
