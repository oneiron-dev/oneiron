//! The native `execute` entry: one durable run entered on the engine's
//! own sandbox/REPL substrate through the run's credential-gated write door.

use std::sync::Arc;

use oneiron::code_run::{GatedActorWrite, SpawnHostSeat};
use oneiron::engine_executor::{
    CallerRunInput, EngineExecutorConfig, EngineExecutorOutcome, EngineNativeExecutor,
    JsCodeModeRuntime, RunCompaction, SelfBriefPort, caller_run_input,
};
use oneiron::{EntityId, Vault, WriteActor};

use super::{
    EngineRunError, McpCodeExecutionError, McpCodeModeProvider, engine_run_seat,
    enter_engine_native_run, enter_on,
};

/// Enters the EXISTING sandbox/REPL substrate for one durable run.
///
/// This is the whole of what `execute` means now: bind the gated write at
/// the host boundary, hand the engine its own runtime, and let
/// `EngineNativeExecutor` own every step, replay row, and terminal marker. The
/// server evaluates nothing and opens no second vault-write path. A run with
/// a seat may spawn reader children under it. A run its caller's credential
/// admitted binds that slip's lineage as its own (FIX 4705). A run its host
/// lends a self-brief port (`brief`, FIX 17594) carries the brief it
/// prepares on either backend.
///
/// FIX 7087: the door declares the caller's task text its own, and only
/// that text. `config.task` is exactly the request's task, as `execute`
/// checked against the provider's config before the call. Provider config,
/// seat grading, the home's persona words, the run's prior record and any
/// text a host adds later declare nothing, and keep their own row causes.
///
/// FIX 4606: the run carries `consent_origin`, the admitted caller the
/// gateway bound, so a code consent wait it mints keeps that caller.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one axis of the run's host binding"
)]
pub(super) fn run_engine_native_code_mode(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    write_actor: WriteActor,
    model_call_context: Option<(EntityId, Option<String>)>,
    run_ref: &str,
    config: &EngineExecutorConfig,
    verbs: Arc<dyn oneiron::code_run::AgentVerbDoor>,
    opener: Option<&oneiron::authority::VerifiedSlip>,
    worlds: Vec<EntityId>,
    birth_position: oneiron::federation::record_scope::BirthPosition,
    reader_seat: Option<SpawnHostSeat>,
    compaction: Option<&mut RunCompaction>,
    git_door_base: Option<String>,
    consent_origin: Option<oneiron::code_run::CodeConsentRunOrigin>,
    brief: Option<&dyn SelfBriefPort>,
) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
    // P2-1: reuse is explicit input comparison under the run's single flight, not the
    // engine's general config-changed string (which also covers non-input drift).
    if task_run_input_reused(vault, config.run_id, &config.task) {
        return Err(McpCodeExecutionError::RunRefReused);
    }
    let mut gated_write = GatedActorWrite::new(vault, write_actor, run_ref)
        .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?
        .with_agent_verb_door(verbs)
        .with_birth_position(birth_position)
        .with_bound_run(config.run_id)
        .with_git_door_base(git_door_base)
        // The caller's own task text, verbatim (FIX 7087).
        .with_caller_task(config.run_id, &config.task)
        // The admitted caller a code consent wait keeps (FIX 4606).
        .with_code_consent_origin(consent_origin);
    if let Some(opener) = opener {
        gated_write = gated_write.with_opener_credential(opener);
    }
    if let Some(seat) = reader_seat {
        gated_write = gated_write.with_reader_spawn(seat);
    }
    let reactor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| McpCodeExecutionError::Run(error.to_string()))?;
    let seat = engine_run_seat(
        vault,
        provider,
        config,
        format!("mcp-execute-code:{}", config.run_id.to_hex()),
        None,
        Vec::new(),
        worlds,
    )
    .map_err(McpCodeExecutionError::RunBinding)?;
    let model_call_backend = model_call_context.and_then(|(principal, session)| {
        provider.backend_with_model_call_context(principal, session)
    });
    match model_call_backend.as_ref() {
        Some(backend) => enter_on(
            vault,
            provider,
            backend.as_ref(),
            &gated_write,
            config,
            compaction,
            &reactor,
            seat.as_ref(),
            brief,
            // Each `execute` call is its own entry.
            None,
        ),
        None => enter_engine_native_run(
            vault,
            provider,
            &gated_write,
            config,
            compaction,
            &reactor,
            None,
            seat.as_ref(),
            // An `execute` run is no planned child.
            None,
            // Keep this caller's existing unconstrained routing.
            Vec::new(),
            brief,
            None,
        ),
    }
    .map_err(|error| match error.provider_outage() {
        Some(retry_after) => McpCodeExecutionError::ProviderUnavailable { retry_after },
        None => match error {
            EngineRunError::Binding(error) => McpCodeExecutionError::RunBinding(error),
            EngineRunError::Run(
                oneiron::engine_executor::EngineExecutorError::ResumeDivergence(report),
            ) => McpCodeExecutionError::ResumeDivergence(report.to_string()),
            EngineRunError::Run(error) if is_config_drift(&error) => {
                McpCodeExecutionError::RunBinding(error.to_string())
            }
            EngineRunError::Run(error) => McpCodeExecutionError::Run(error.to_string()),
            EngineRunError::Payer(fault) => McpCodeExecutionError::RunBinding(fault.to_string()),
        },
    })
}

/// The engine's config-changed refusal for an existing run id (FIX EXECUTE-CALLER-CODE): other
/// input, or non-input drift (model, limits, prompt). Reuse is decided by explicit input
/// comparison before entry (P2-1); this string only maps leftover drift to a binding error, and
/// its text is kept as is.
const CONFIG_CHANGED: &str = "engine executor config changed for existing run";

/// Whether `error` is the engine's config-changed refusal for an existing run id. Without
/// proof that the submitted input changed, keep this as a binding error (P2-1).
fn is_config_drift(error: &oneiron::engine_executor::EngineExecutorError) -> bool {
    matches!(
        error,
        oneiron::engine_executor::EngineExecutorError::Engine(oneiron::Error::InvalidConfig(
            msg
        )) if msg.as_str() == CONFIG_CHANGED
    )
}

/// Whether a task entry reuses `run_id` with other input (P2-1): the submitted task against
/// the run's kept caller input, read under the run's single flight. Unknown — no record yet,
/// no kept task, or an unreadable body after erasure — is not reuse; the engine entry below
/// decides.
fn task_run_input_reused(vault: &Vault, run_id: EntityId, task: &str) -> bool {
    match caller_run_input(vault, run_id) {
        Ok(Some(CallerRunInput::Task(kept))) => kept != task,
        Ok(Some(CallerRunInput::Source(_))) => true,
        Ok(None) | Err(_) => false,
    }
}

/// Whether a caller-source entry reuses `run_id` with other input (P2-1): the submitted code
/// against the run's kept caller input, read under the run's single flight. Unknown — no
/// record yet, or an unreadable body after erasure — is not reuse; the engine entry below
/// decides.
fn caller_source_input_reused(vault: &Vault, run_id: EntityId, code: &str) -> bool {
    match caller_run_input(vault, run_id) {
        Ok(Some(CallerRunInput::Source(kept))) => kept != code,
        Ok(Some(CallerRunInput::Task(_))) => true,
        Ok(None) | Err(_) => false,
    }
}

/// Enters the existing substrate for one caller-source run (FIX EXECUTE-CALLER-CODE): the gated
/// write at the host boundary, the engine's own runtime, and the model-free source entry. No
/// model seat, no prompt, no compaction seat, no skill-executor model, no model receipt, no
/// reader seat. Determinism, limits and the runtime factory are the task run's non-model ones.
/// The run carries `consent_origin` as a task run does (FIX 4606).
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one axis of the run's host binding"
)]
pub(super) fn run_engine_native_caller_source(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    write_actor: WriteActor,
    run_ref: &str,
    config: &EngineExecutorConfig,
    code: &str,
    verbs: Arc<dyn oneiron::code_run::AgentVerbDoor>,
    opener: Option<&oneiron::authority::VerifiedSlip>,
    birth_position: oneiron::federation::record_scope::BirthPosition,
    git_door_base: Option<String>,
    consent_origin: Option<oneiron::code_run::CodeConsentRunOrigin>,
) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
    // P2-1: as in the task path, reuse is explicit input comparison under single flight.
    if caller_source_input_reused(vault, config.run_id, code) {
        return Err(McpCodeExecutionError::RunRefReused);
    }
    let mut gated_write = GatedActorWrite::new(vault, write_actor, run_ref)
        .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?
        .with_agent_verb_door(verbs)
        .with_birth_position(birth_position)
        .with_bound_run(config.run_id)
        .with_git_door_base(git_door_base)
        .with_code_consent_origin(consent_origin);
    if let Some(opener) = opener {
        gated_write = gated_write.with_opener_credential(opener);
    }
    let mut runtime = provider.runtime();
    let runtime: &mut dyn JsCodeModeRuntime = &mut *runtime;
    let mut executor = EngineNativeExecutor::for_caller_source(vault, runtime, &gated_write);
    if let Some(feedback) = provider.code_check() {
        executor = executor.with_code_check(feedback);
    }
    executor.run_caller_source(config, code).map_err(|error| {
        if is_config_drift(&error) {
            return McpCodeExecutionError::RunBinding(error.to_string());
        }
        match error {
            oneiron::engine_executor::EngineExecutorError::ResumeDivergence(report) => {
                McpCodeExecutionError::ResumeDivergence(report.to_string())
            }
            error => McpCodeExecutionError::Run(error.to_string()),
        }
    })
}
