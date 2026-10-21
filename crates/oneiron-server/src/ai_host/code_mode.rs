//! MCP `execute_code` on the served vault: the checked-in QuickJS component,
//! run by the engine executor on the generative seat.
//!
//! Bound when `[models]` fills that seat and `[models.code_mode]` names the
//! prompt package the executor's wire prompt resolves from. Otherwise
//! `execute_code` stays unlisted, as on a server with no model.
//!
//! A browser subgoal's step after a batch or library run of it ended
//! `NEEDS_AGENT` runs on `[models.roles.browser_planner]` instead, as its
//! own role-bound call, until the subgoal's second miss hands it back to
//! the generative seat, and each miss's answer reaches the next step's call
//! as host data (`browser_planner.rs`). A run's durable seat keeps its
//! model and effort; a pinned planned child keeps every step on its pick.
use std::sync::Arc;

use oneiron::agent_dispatch::SpendScopeId;
use oneiron::code_run::{CODE_RUN_RNG_SEED_LEN, CodeRunDeterminism, CompactionHostBinding};
use oneiron::compaction::EpochEmbedder;
use oneiron::engine_executor::{
    ENGINE_EXECUTOR_PURPOSE_NAME, EngineExecutorConfig, EngineExecutorLimits,
};
use oneiron::llm::BudgetDenied;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::PayerPerson;
use oneiron::{
    BudgetGuard, BudgetLease, EntityId, LlmBackend, LlmError, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, ModelId, ModelLocality, ModelTierRef, Vault,
};
use oneiron_code_check::{
    BackendKind, CheckFailure, CheckMode, CodeCheck, Fallback, MicrosoftTsc, ShadowCheck,
    TscRsBudget, TscRsWasm,
};

use super::CHAT_ROLE;
use super::browser_planner::{self, BrowserPlannerRuns};
use super::compaction::{CodeModeCompaction, LiveAdmission};
use super::status::StatusCell;
use crate::config::models::{CodeCheckSettings, ModelsConfig};
use crate::embedder::EmbedderSlot;
use crate::mcp::{McpQuickJsProvider, PlannedMeter, PlannedModel, PlannedRoute, RunCompactionSeat};
use crate::models::{ModelRuntime, RoleCall, RoleRefusal};
use crate::server::SyncServer;

/// Binds `execute_code` on `server` when `models` asks for it and the
/// checked-in component passes its pin and readiness probe. Any failure
/// leaves the server as it was, with `execute_code` unlisted. `shared` is
/// the compaction writer factory the host settled and the code-mode meter
/// it spends on (FIX 4465 D).
pub(super) async fn bind(
    server: SyncServer,
    runtime: &Arc<ModelRuntime>,
    models: Option<&ModelsConfig>,
    status: &StatusCell,
    shared: Option<(CodeModeCompaction, BudgetGuard)>,
) -> SyncServer {
    let (Some(models), Some((compaction, guard))) = (models, shared) else {
        return server;
    };
    let Some(prompt_package) = models.code_mode.prompt_package.clone() else {
        return server;
    };
    let Some(seat) = runtime.seat(CHAT_ROLE) else {
        tracing::warn!("models.code_mode is set, but no rung serves the generative seat");
        return server;
    };
    if let Err(error) = oneiron::prompt::resolve_engine_executor_wire_prompt(&prompt_package) {
        tracing::error!(
            %error,
            prompt_package = %prompt_package.display(),
            "models.code_mode.prompt_package holds no executor wire prompt"
        );
        return server;
    }
    let component = match tokio::task::spawn_blocking(crate::mcp::checked_in_quickjs_runtime).await
    {
        Ok(Ok(component)) => component,
        Ok(Err(error)) => {
            tracing::error!(%error, "the checked-in QuickJS component did not load");
            return server;
        }
        Err(error) => {
            tracing::error!(
                panicked = error.is_panic(),
                "the QuickJS component load stopped"
            );
            return server;
        }
    };
    // The executor hands this lease to every call; the backend below admits
    // and settles each call on the meter instead, so the lease carries no
    // spend and its reservation is released at once.
    let lease = match guard
        .admit()
        .and_then(|admission| guard.abort(&admission.lease).map(|_| admission.lease))
    {
        Ok(lease) => lease,
        Err(denied) => {
            tracing::error!(?denied, "code mode's meter admits nothing");
            return server;
        }
    };
    // Each run's browser planner state (CUA E5): its guest door finds it
    // through the provider, and every backend and live admission below
    // routes the run's step calls by it.
    let browser = Arc::new(BrowserPlannerRuns::default());
    let backend = Arc::new(CodeModeBackend {
        vault: Arc::clone(server.vault()),
        models: Arc::clone(runtime),
        guard: guard.clone(),
        payer: None,
        planned: None,
        browser: Arc::clone(&browser),
    });
    // Each run's compaction seat reads the rung its step's call is admitted
    // on, at the breakpoint, through this same admission (FIX 4465 C).
    let live_admission = Arc::new(LiveStepAdmission {
        vault: Arc::clone(server.vault()),
        models: Arc::clone(runtime),
        pinned: false,
        browser: Arc::clone(&browser),
    });
    // A reader child's calls take the same admission: on its own child
    // scope's guard when its run spends under a scope, else on code mode's
    // own, lent below as the host's meter. A room-paid scope's calls bill
    // the payer its host bound before the run began (OF-531).
    let reader_meter: crate::mcp::ReaderMeter = {
        let vault = Arc::clone(server.vault());
        let models = Arc::clone(runtime);
        let browser = Arc::clone(&browser);
        Arc::new(move |guard: BudgetGuard, payer: Option<PayerPerson>| {
            Arc::new(CodeModeBackend {
                vault: Arc::clone(&vault),
                models: Arc::clone(&models),
                guard,
                payer,
                planned: None,
                browser: Arc::clone(&browser),
            }) as Arc<dyn LlmBackend>
        })
    };
    // FIX 2310: a planned child no seat binds runs its pick exactly where
    // this host routes it so (Engine C1/C2), else on the route it takes
    // today; either way its calls take the same admission, bound to its
    // plan, on the meter and payer a reader child's would.
    let planned_route: PlannedRoute = {
        let models = Arc::clone(runtime);
        Arc::new(move |vault: &Vault, pick: &ModelId| exact_route(&models, vault, pick))
    };
    let planned_meter: PlannedMeter = {
        let vault = Arc::clone(server.vault());
        let models = Arc::clone(runtime);
        let browser = Arc::clone(&browser);
        Arc::new(
            move |guard: BudgetGuard, payer: Option<PayerPerson>, planned: &PlannedModel| {
                Arc::new(CodeModeBackend {
                    vault: Arc::clone(&vault),
                    models: Arc::clone(&models),
                    guard,
                    payer,
                    planned: Some(planned.clone()),
                    browser: Arc::clone(&browser),
                }) as Arc<dyn LlmBackend>
            },
        )
    };
    let config = EngineExecutorConfig {
        // Each run's id and task replace these.
        run_id: EntityId::now(),
        task: ENGINE_EXECUTOR_PURPOSE_NAME.to_owned(),
        prompt_package_root: prompt_package,
        model: seat.model.clone(),
        model_locality: seat.locality,
        seat_effort: None,
        global_tier: ModelTierRef(ENGINE_EXECUTOR_PURPOSE_NAME.to_owned()),
        determinism: CodeRunDeterminism::new(0, [0; CODE_RUN_RNG_SEED_LEN]),
        limits: EngineExecutorLimits::default(),
    };
    let provider = match McpQuickJsProvider::gated(Arc::new(component), backend, lease, config) {
        Ok(provider) => provider
            .with_clock_from_first_start()
            .with_reader_meter(reader_meter)
            .with_planned_models(planned_route, planned_meter)
            .with_browser_planner(Arc::clone(&browser))
            .with_host_meter(guard)
            .with_reader_window_tokens(
                super::dreamer::dream_windows(models)
                    .get(&seat.model)
                    .copied()
                    .unwrap_or(0),
            ),
        Err(error) => {
            tracing::error!(%error, "code mode's executor config is invalid");
            return server;
        }
    };
    let provider = match shadow_check(&models.code_mode.check).await {
        Some(shadow) => provider.with_code_check(shadow),
        None => provider,
    };
    // A manifest-backed run picks its seat through the host's decision ladder.
    let provider = match server.seat_router(models) {
        Some((decisions, facet)) => provider.with_model_seat_router(decisions, facet),
        None => provider,
    };
    // Leased agent runs plan their spawns over the host's seats, if any.
    let provider = if models.planner.seats.is_empty() {
        provider
    } else {
        provider.with_planner(models.planner.clone())
    };
    let runs = crate::mcp::CodeRunLimits {
        total: models.code_mode.max_runs,
        wait: server.config.limits.queue_wait(),
    };
    if let Some(backend) = compaction.host_backend() {
        let _ = server.ai.host_compaction.set(backend);
    }
    let embedder = server.embedder.clone();
    // Engine C5: a pinned child's compaction reads its live rung through
    // the admission its calls take, on its pick.
    let pinned = Arc::new(LiveStepAdmission {
        vault: Arc::clone(server.vault()),
        models: Arc::clone(runtime),
        pinned: true,
        browser,
    });
    let provider =
        provider.with_pinned_compaction(pinned_compaction(&compaction, embedder.clone(), pinned));
    server.with_mcp_quickjs_provider(
        compaction.attach(provider, status, embedder, live_admission),
        runs,
    )
}

/// Each pinned child's compaction seat (FIX 2310, Engine C5), as
/// [`CodeModeCompaction::attach`] hands every other run one, its live rung
/// read through `live`, the admission its calls take on its pick.
fn pinned_compaction(
    compaction: &CodeModeCompaction,
    embedder: Option<Arc<EmbedderSlot>>,
    live: Arc<LiveStepAdmission>,
) -> RunCompactionSeat {
    let compaction = compaction.clone();
    let live: Arc<dyn LiveAdmission> = live;
    let vectors = embedder.map(|slot| slot as Arc<dyn EpochEmbedder>);
    Arc::new(
        move |host: CompactionHostBinding, credential: &str, spend: Option<&SpendScopeId>| {
            let seat = compaction.for_run(host, credential, spend, &live);
            match &vectors {
                Some(vectors) => seat.with_room_vectors(Arc::clone(vectors)),
                None => seat,
            }
        },
    )
}

/// Where this host serves `pick`, a planned child's model, exactly (FIX
/// 2310, Engine C1/C2): its router serves it, on a configured or discovered
/// route, as one picked model, at a route no wider than the chat role's
/// live route, so a seat-bound admission takes it and its one model answers.
/// `None` otherwise, and the child runs as it would today.
fn exact_route(models: &ModelRuntime, vault: &Vault, pick: &ModelId) -> Option<ModelLocality> {
    let seat = models.seat(CHAT_ROLE)?;
    let route = models.route_role(vault, CHAT_ROLE, seat).ok()?.locality;
    let (served, ladder) = models.router()?.served(pick)?;
    (served <= route && ladder.exact_prompt().is_some()).then_some(served)
}

/// Shadow mode's checker, per `[models.code_mode.check]`; none when the mode
/// is `off`. A check never gates code mode: when no checker loads,
/// `execute_code` is served unchecked.
async fn shadow_check(settings: &CodeCheckSettings) -> Option<Arc<ShadowCheck>> {
    if settings.mode != CheckMode::Shadow {
        return None;
    }
    let settings = settings.clone();
    // Compiling the tsc-rs module takes seconds.
    match tokio::task::spawn_blocking(move || code_checker(&settings)).await {
        Ok(Ok(checker)) => {
            let backend = checker.backend();
            tracing::info!(backend = backend.name, pin = %backend.pin, "code mode checks each program in shadow mode");
            Some(Arc::new(ShadowCheck::new(checker)))
        }
        Ok(Err(failure)) => {
            tracing::error!(%failure, "no code checker loaded; code mode runs unchecked");
            None
        }
        Err(error) => {
            tracing::error!(panicked = error.is_panic(), "the code checker load stopped");
            None
        }
    }
}

/// The configured backend. tsc-rs falls back to Microsoft's `tsc` when it is
/// set: for a check tsc-rs cannot finish, or for every check when tsc-rs
/// does not load.
fn code_checker(settings: &CodeCheckSettings) -> Result<Arc<dyn CodeCheck>, CheckFailure> {
    let microsoft = settings
        .microsoft_tsc
        .as_ref()
        .map(MicrosoftTsc::new)
        .transpose();
    if let Err(failure) = &microsoft {
        tracing::warn!(%failure, "models.code_mode.check.microsoft_tsc is not the pinned tsc");
    }
    let microsoft = microsoft.ok().flatten();
    let checker: Arc<dyn CodeCheck> = match (settings.backend, microsoft) {
        (BackendKind::Microsoft, microsoft) => {
            Arc::new(microsoft.ok_or(CheckFailure::Unavailable)?)
        }
        (BackendKind::TscRs, microsoft) => {
            match (TscRsWasm::load(TscRsBudget::default()), microsoft) {
                (Ok(tsc_rs), Some(microsoft)) => {
                    Arc::new(Fallback::new(Box::new(tsc_rs), Box::new(microsoft)))
                }
                (Ok(tsc_rs), None) => Arc::new(tsc_rs),
                (Err(_), Some(microsoft)) => Arc::new(microsoft),
                (Err(failure), None) => return Err(failure),
            }
        }
    };
    Ok(checker)
}

/// Each executor step's model call, admitted like a chat turn against the
/// vault's live model policy (its manifest and route, else the seat), or,
/// when a durable seat bound its model (a run's, a planned child's, a reader
/// job's), on that model alone with no fallback; then sent as a run on code
/// mode's own budget: each provider call takes its own
/// permit and settles itself (its usage, or its reservation when it reports
/// none or fails after it went out). A browser subgoal's step takes the
/// role its run's browser planner state picks, on the same budget, with
/// the evidence that state holds (CUA E5).
struct CodeModeBackend {
    vault: Arc<Vault>,
    models: Arc<ModelRuntime>,
    guard: BudgetGuard,
    /// Who funds each call when a room's root spend scope pays for the run.
    payer: Option<PayerPerson>,
    /// The planned child no seat binds whose calls these are (FIX 2310):
    /// pinned, each runs its pick alone; else the role's live route, and
    /// one another model answers is marked on its receipts.
    planned: Option<PlannedModel>,
    /// The runs' browser planner states each call is routed by (CUA E5).
    browser: Arc<BrowserPlannerRuns>,
}

/// The run each code-mode call is admitted under, one run per call so the
/// server keeps no per-call state.
const CODE_MODE_RUN: &str = "code-mode";

/// A code-mode call's admission on the chat role, as every step's call is
/// admitted: the model a durable seat bound when its envelope carries the
/// seat's effort, else the role's live route. Says which. A browser
/// subgoal's step its run's browser planner state sent to `role` (CUA E5)
/// is its own call of that role, the seat untouched; with no rung for
/// `role` it is admitted here as any other step. A planned child its host
/// pinned to its pick (`pinned`, FIX 2310) is admitted on that one model as
/// a seat-bound call is; when that admission refuses now, the call takes
/// the role's live route as any other does, so nothing new refuses.
fn admit_code_mode_call(
    models: &ModelRuntime,
    vault: &Vault,
    request: LlmRequest,
    pinned: bool,
    role: ModelRole,
) -> Result<(RoleCall, bool), RoleRefusal> {
    let seat_bound = request.envelope.seat_effort.is_some();
    if pinned
        && !seat_bound
        && let Some(call) = pinned_call(models, vault, &request)
    {
        return Ok((call, true));
    }
    if let Some(admitted) = browser_planner::admit_browser_step(models, vault, role, &request) {
        return admitted.map(|call| (call, false));
    }
    let call = if seat_bound {
        models.admit_seat_bound(vault, CHAT_ROLE, request)
    } else {
        models.admit_role(vault, CHAT_ROLE, request)
    }?;
    Ok((call, seat_bound))
}

/// A pinned child's call on its pick alone, as [`ModelRuntime::admit_seat_bound`]
/// admits a seat's: `None` when that admission refuses now, or its route is
/// no longer one picked model.
fn pinned_call(models: &ModelRuntime, vault: &Vault, request: &LlmRequest) -> Option<RoleCall> {
    match models.admit_seat_bound(vault, CHAT_ROLE, request.clone()) {
        Ok(call) if call.ladder.exact_prompt().is_some() => Some(call),
        Ok(_) => None,
        Err(refusal) => {
            tracing::info!(%refusal, "a pinned planned child's call takes the role's route");
            None
        }
    }
}

/// The live admission a run's compaction seat reads at a breakpoint (FIX
/// 4465 C): the step's request admitted exactly as [`CodeModeBackend`]
/// admits it, on the same role and with the same browser evidence, before
/// the call is sent. It sends nothing, spends nothing, counts nothing and
/// keeps no request: the seat's capture holds the one copy, on its flight,
/// under the run's own actor and meter.
struct LiveStepAdmission {
    vault: Arc<Vault>,
    models: Arc<ModelRuntime>,
    /// A pinned planned child's, admitted on its pick (Engine C5).
    pinned: bool,
    /// The runs' browser planner states, read as the backend reads them.
    browser: Arc<BrowserPlannerRuns>,
}

impl LiveAdmission for LiveStepAdmission {
    fn admit_live(&self, request: LlmRequest) -> Result<RoleCall, RoleRefusal> {
        let (role, request, _) = self.browser.route(request, self.pinned);
        admit_code_mode_call(&self.models, &self.vault, request, self.pinned, role)
            .map(|(call, _)| call)
    }
}

impl LlmBackend for CodeModeBackend {
    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let pinned = self.planned.as_ref().is_some_and(|planned| planned.exact);
            // CUA E5: the role the run's browser planner state picks, and
            // the evidence it holds, handed on once this call answers.
            let (role, request, handoff) = self.browser.route(request, pinned);
            let (call, seat_bound) =
                admit_code_mode_call(&self.models, &self.vault, request, pinned, role).map_err(
                    |refusal| {
                        tracing::warn!(%refusal, "a code-mode model call was refused");
                        LlmError::BudgetDenied(BudgetDenied::AdmissionDenied)
                    },
                )?;
            let run = self
                .models
                .funded_run(CODE_MODE_RUN, self.guard.clone(), self.payer.clone());
            let answered = if seat_bound {
                call.ladder.generate_exact(&run, call.request, None).await
            } else if let Some(planned) = &self.planned {
                // FIX 2310: the model that answered, marked when it is not
                // the child's pick.
                let (response, ran) = call
                    .ladder
                    .generate_served(&run, call.request, None)
                    .await?;
                planned.answered(&run, ran);
                Ok(response)
            } else {
                call.ladder.generate(&run, call.request, None).await
            };
            if answered.is_ok() {
                handoff.answered();
            }
            answered
        })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::FatalLlmError::InvalidRequest.into())
    }
}
