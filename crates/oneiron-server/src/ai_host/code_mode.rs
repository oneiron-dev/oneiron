//! MCP `execute_code` on the served vault: the checked-in QuickJS component,
//! run by the engine executor on the generative seat.
//!
//! Bound when `[models]` fills that seat and `[models.code_mode]` names the
//! prompt package the executor's wire prompt resolves from. Otherwise
//! `execute_code` stays unlisted, as on a server with no model.
use std::sync::Arc;

use oneiron::code_run::{CODE_RUN_RNG_SEED_LEN, CodeRunDeterminism};
use oneiron::engine_executor::{
    ENGINE_EXECUTOR_PURPOSE_NAME, EngineExecutorConfig, EngineExecutorLimits,
};
use oneiron::llm::BudgetDenied;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, EntityId, LlmBackend, LlmError,
    LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelTierRef, Vault,
};
use oneiron_code_check::{
    BackendKind, CheckFailure, CheckMode, CodeCheck, Fallback, MicrosoftTsc, ShadowCheck,
    TscRsBudget, TscRsWasm,
};

use super::CHAT_ROLE;
use super::compaction::CodeModeCompaction;
use super::status::StatusCell;
use crate::config::models::{CodeCheckSettings, ModelsConfig};
use crate::mcp::McpQuickJsProvider;
use crate::models::ModelRuntime;
use crate::server::SyncServer;

/// Binds `execute_code` on `server` when `models` asks for it and the
/// checked-in component passes its pin and readiness probe. Any failure
/// leaves the server as it was, with `execute_code` unlisted.
pub(super) async fn bind(
    server: SyncServer,
    runtime: &Arc<ModelRuntime>,
    models: Option<&ModelsConfig>,
    status: &StatusCell,
) -> SyncServer {
    let Some(models) = models else {
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
    let guard = BudgetGuard::new(
        "code-mode",
        models.code_mode.budget_units,
        BudgetExhaustionPolicy::Suspend,
    );
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
    let compaction = CodeModeCompaction::resolve(
        server.vault(),
        runtime,
        models,
        &prompt_package,
        guard.clone(),
        Arc::clone(server.wire_telemetry.limit_questions()),
        server.config.limits.queue_wait(),
    );
    let backend = Arc::new(CodeModeBackend {
        vault: Arc::clone(server.vault()),
        models: Arc::clone(runtime),
        guard: guard.clone(),
    });
    // A reader child's calls take the same admission: on its own child
    // scope's guard when its run spends under a scope, else on code mode's
    // own, lent below as the host's meter.
    let reader_meter: crate::mcp::ReaderMeter = {
        let vault = Arc::clone(server.vault());
        let models = Arc::clone(runtime);
        Arc::new(move |guard: BudgetGuard| {
            Arc::new(CodeModeBackend {
                vault: Arc::clone(&vault),
                models: Arc::clone(&models),
                guard,
            }) as Arc<dyn LlmBackend>
        })
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
    server.with_mcp_quickjs_provider(compaction.attach(provider, status), runs)
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
/// vault's live model policy (its manifest and route, else the seat), then
/// sent as a run on code mode's own budget: each provider call takes its own
/// permit and settles itself (its usage, or its reservation when it reports
/// none or fails after it went out).
struct CodeModeBackend {
    vault: Arc<Vault>,
    models: Arc<ModelRuntime>,
    guard: BudgetGuard,
}

/// The run each code-mode call is admitted under, one run per call so the
/// server keeps no per-call state.
const CODE_MODE_RUN: &str = "code-mode";

impl LlmBackend for CodeModeBackend {
    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let call = self
                .models
                .admit_role(&self.vault, CHAT_ROLE, request)
                .map_err(|refusal| {
                    tracing::warn!(%refusal, "a code-mode model call was refused");
                    LlmError::BudgetDenied(BudgetDenied::AdmissionDenied)
                })?;
            let run = self
                .models
                .undeclared_run(CODE_MODE_RUN, self.guard.clone());
            call.ladder.generate(&run, call.request, None).await
        })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::FatalLlmError::InvalidRequest.into())
    }
}
