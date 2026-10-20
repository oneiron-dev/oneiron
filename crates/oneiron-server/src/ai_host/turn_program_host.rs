//! What this server lends one entry of a Dreamer turn program (DOOR-141 PR2):
//! the engine-native code host's own runtime, backend, config and seat, on
//! the program's code run, and the door a pumped agent run binds, under the
//! program's waking actor: an agent, or a person through a host surface
//! (FIX 5717), the exact actor its turn sealed and under its own class. Its
//! rows answer that actor alone, on this device, with the engine's own actor
//! and Gate checks; nothing here is the operator's or the Dreamer's, and no
//! owner, root or Dreamer proof is made up for it.
//!
//! A program this host cannot bind (its actor is a System actor, serve has
//! not bound the server, the host runs no engine-native code mode, or its run
//! cannot be configured or seated) is lent nothing: that program parks, and
//! nothing else changes. Once serve binds the server, each program held for
//! want of this host whose waking agent it now lends to resumes as the same
//! try (FIX 5874), and binds again at its entry.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use oneiron::dreamer_wake::{
    TurnProgramHost, TurnProgramReactor, TurnProgramRequest, TurnProgramRuntime,
};
use oneiron::llm::seat::{SeatKind, SeatTask};
use oneiron::{
    BudgetLease, DreamerRunnerStore, EdgeActorClass, LlmBackend, LlmCapability, LlmGenerateFuture,
    LlmRequest, LlmStreamResult, ModelId, Vault, WriteActor,
};

use super::dreamer::QuestionTimer;
use crate::mcp::{McpCodeModeProvider, run_seat};
use crate::server::{RunHostDoor, SyncServer};

/// The server's binding of its Dreamer's turn programs.
pub(super) struct ServerTurnPrograms {
    /// The bound server, once serve has it.
    server: QuestionTimer,
    /// The server's runtime: a program's door runs its rows there.
    serve: tokio::runtime::Handle,
}

impl ServerTurnPrograms {
    pub(super) fn new(server: QuestionTimer, serve: tokio::runtime::Handle) -> Self {
        Self { server, serve }
    }
}

/// Whether `server` lends `actor`'s turn programs on `vault` at all, before
/// any run is configured or seated: the host's run door serves the waking
/// actor's own rows under its own class, an agent's or a person's (FIX 5717),
/// on the server's own vault, through its engine-native code mode. A program
/// a System actor wakes is lent nothing here.
fn lends_programs(server: &SyncServer, vault: &Vault, actor: WriteActor) -> bool {
    matches!(
        actor.actor_class(),
        EdgeActorClass::Agent | EdgeActorClass::Human
    ) && std::ptr::eq(vault, server.vault().as_ref())
        && server
            .code_execution_host()
            .is_some_and(|host| host.engine_native().is_some())
}

/// Resumes, each as the same try, every turn program held for want of this
/// host whose waking agent `server` now lends to (FIX 5874), once serve binds
/// it: off the caller's thread, best-effort and logged. Each binds its
/// authority, its pin and this host again at its entry, and is held again
/// for whatever still holds it. Outside a runtime nothing is resumed here;
/// those programs keep their holds.
pub(super) fn resume_held_for_host(server: &Arc<SyncServer>) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!("no runtime resumes the turn programs held for want of this host");
        return;
    };
    let server = Arc::downgrade(server);
    drop(runtime.spawn_blocking(move || {
        let Some(server) = server.upgrade() else {
            return;
        };
        let vault = server.vault();
        let lends: &dyn Fn(WriteActor) -> bool =
            &|actor: WriteActor| lends_programs(&server, vault, actor);
        match DreamerRunnerStore::new(vault)
            .resume_returned_program_holds(Some(lends), vault.now_recorded_at())
        {
            Ok(0) => {}
            Ok(resumed) => tracing::info!(resumed, "held turn programs resumed on this host"),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "the turn programs held for want of this host were not resumed; they hold"
            ),
        }
    }));
}

impl TurnProgramRuntime for ServerTurnPrograms {
    fn bind(&mut self, vault: &Vault, request: &TurnProgramRequest<'_>) -> Option<TurnProgramHost> {
        let server = self.server.get().and_then(std::sync::Weak::upgrade)?;
        if !lends_programs(&server, vault, request.actor) {
            return None;
        }
        let provider = Arc::clone(server.code_execution_host()?.engine_native()?.provider());
        let code_run = request.code_run;
        let config = match provider.executor_config(vault, code_run, request.task) {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), code_run = %code_run.to_hex(), "a turn program's run is not configured; it parks");
                return None;
            }
        };
        // Born once on the program's code run, as an engine-native run's
        // seat is, from the program's own task.
        let seat = run_seat(vault, provider.as_ref(), code_run, |facet| SeatTask {
            kind: SeatKind::Attempt,
            warm_scope: format!("turn-program:{}", code_run.to_hex()),
            task: config.task.clone(),
            purpose: oneiron::CallPurpose::Other {
                name: oneiron::engine_executor::ENGINE_EXECUTOR_PURPOSE_NAME.into(),
            },
            facet: facet.to_owned(),
            required: Vec::new(),
            min_context_tokens: 1,
            locality: config.model_locality,
            override_model: None,
            override_effort: None,
            listed: Vec::new(),
        });
        // Its refusal's text can quote the vault: it is not logged.
        let Ok(seat) = seat else {
            tracing::warn!(code_run = %code_run.to_hex(), "a turn program's run is not seated; it parks");
            return None;
        };
        let reactor = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(reactor) => reactor,
            Err(error) => {
                tracing::warn!(%error, "a turn program's reactor did not start; it parks");
                return None;
            }
        };
        // The door's `ai.speech` spends on the line its model calls do, as an
        // unmetered agent run's does.
        let door = RunHostDoor::new(&server, request.actor, self.serve.clone(), code_run);
        door.bind_meter(provider.host_meter().map(|guard| (guard, None)));
        Some(TurnProgramHost {
            runtime: provider.runtime(),
            backend: Arc::new(ProviderBackend(provider)),
            door: Arc::new(door),
            vault: Arc::clone(server.vault()),
            config,
            seat,
            reactor: Arc::new(ProgramReactor(Some(reactor))),
        })
    }
}

/// The code host's own backend, as an engine-native run's calls take it: it
/// spends on the provider's line, a meter apart from the program's step
/// meter, so neither charges a call twice.
struct ProviderBackend(Arc<dyn McpCodeModeProvider>);

impl LlmBackend for ProviderBackend {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.0.backend().supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.0.backend().generate(request, lease)
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.0.backend().stream(request, lease)
    }
}

/// One entry's own current-thread runtime, which its model steps block on
/// from a thread of their own. It is shut down in the background when the
/// entry drops it, which may be on the Dreamer's runtime.
struct ProgramReactor(Option<tokio::runtime::Runtime>);

impl TurnProgramReactor for ProgramReactor {
    fn block_on(&self, step: Pin<Box<dyn Future<Output = ()> + '_>>) {
        if let Some(runtime) = &self.0 {
            runtime.block_on(step);
        }
    }
}

impl Drop for ProgramReactor {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}
