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
    LlmGenerateFuture, LlmRequest, LlmStreamResult, LlmUsage, ModelTierRef, Vault,
};

use super::CHAT_ROLE;
use crate::config::models::ModelsConfig;
use crate::mcp::McpQuickJsProvider;
use crate::models::{FAILED_RUNGS_KEY, ModelRuntime};
use crate::server::SyncServer;

/// Binds `execute_code` on `server` when `models` asks for it and the
/// checked-in component passes its pin and readiness probe. Any failure
/// leaves the server as it was, with `execute_code` unlisted.
pub(super) async fn bind(
    server: SyncServer,
    runtime: &Arc<ModelRuntime>,
    models: Option<&ModelsConfig>,
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
            tracing::error!(%error, "the QuickJS component load stopped");
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
    let backend = Arc::new(CodeModeBackend {
        vault: Arc::clone(server.vault()),
        models: Arc::clone(runtime),
        guard,
    });
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
    match McpQuickJsProvider::new(Arc::new(component), backend, lease, config) {
        Ok(provider) => server.with_mcp_quickjs_provider(provider.with_clock_from_first_start()),
        Err(error) => {
            tracing::error!(%error, "code mode's executor config is invalid");
            server
        }
    }
}

/// Each executor step's model call, admitted like a chat turn against the
/// vault's live model policy (its manifest and route, else the seat), then
/// metered on code mode's own budget.
struct CodeModeBackend {
    vault: Arc<Vault>,
    models: Arc<ModelRuntime>,
    guard: BudgetGuard,
}

/// What one provider call costs on the meter when it reports no usage: the
/// reservation every call is admitted against.
const CALL_FLOOR_UNITS: u64 = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;

/// An answer's charge: its tokens, or the call floor when it reports none,
/// plus the call floor for each rung that failed before it.
fn answered_units(usage: &LlmUsage) -> u64 {
    let tokens = usage.input.total.saturating_add(usage.output.total);
    let failed = usage
        .raw_provider
        .get(FAILED_RUNGS_KEY)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let answer = if tokens == 0 {
        CALL_FLOOR_UNITS
    } else {
        tokens
    };
    answer.saturating_add(failed.saturating_mul(CALL_FLOOR_UNITS))
}

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
            let lease = self.guard.admit_for_request(&call.request)?.lease;
            // A call that failed made every attempt its backend makes.
            let every_attempt = (call.attempts as u64).saturating_mul(CALL_FLOOR_UNITS);
            match call.backend.generate(call.request, &lease).await {
                Ok(response) => {
                    self.guard
                        .settle_usage(&lease, answered_units(&response.usage))?;
                    Ok(response)
                }
                Err(error) => {
                    let _ = self.guard.settle_usage(&lease, every_attempt);
                    Err(error)
                }
            }
        })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::FatalLlmError::InvalidRequest.into())
    }
}
