//! The native `execute_code` entry: one durable run entered on the engine's
//! own sandbox/REPL substrate through the run's credential-gated write door.

use std::sync::Arc;

use oneiron::code_run::{GatedActorWrite, SpawnHostSeat};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorOutcome, RunCompaction, SelfBriefPort,
};
use oneiron::{EntityId, Vault, WriteActor};

use super::{
    EngineRunError, McpCodeExecutionError, McpCodeModeProvider, engine_run_seat,
    enter_engine_native_run, enter_on,
};

/// Enters the EXISTING sandbox/REPL substrate for one durable run.
///
/// This is the whole of what `execute_code` means now: bind the gated write at
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
    reader_seat: Option<SpawnHostSeat>,
    compaction: Option<&mut RunCompaction>,
    git_door_base: Option<String>,
    brief: Option<&dyn SelfBriefPort>,
) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
    let mut gated_write = GatedActorWrite::new(vault, write_actor, run_ref)
        .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?
        .with_agent_verb_door(verbs)
        .with_bound_run(config.run_id)
        .with_git_door_base(git_door_base)
        // The caller's own task text, verbatim (FIX 7087).
        .with_caller_task(config.run_id, &config.task);
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
            // An `execute_code` run is no planned child.
            None,
            // Keep this caller's existing unconstrained routing.
            Vec::new(),
            brief,
        ),
    }
    .map_err(|error| match error.provider_outage() {
        Some(retry_after) => McpCodeExecutionError::ProviderUnavailable { retry_after },
        None => match error {
            EngineRunError::Binding(error) => McpCodeExecutionError::RunBinding(error),
            EngineRunError::Run(error) => McpCodeExecutionError::Run(error.to_string()),
            EngineRunError::Payer(fault) => McpCodeExecutionError::RunBinding(fault.to_string()),
        },
    })
}
