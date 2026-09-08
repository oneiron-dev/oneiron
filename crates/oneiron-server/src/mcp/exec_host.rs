//! MCP code-execution host seam and the engine-native host binding.

use super::actors::McpResolvedActor;
use oneiron::code_run::GatedActorWrite;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorOutcome, EngineNativeExecutor, JsCodeModeRuntime,
};
use oneiron::{BudgetLease, EntityId, LlmBackend, Vault, WriteActor};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;

/// The ONE place an MCP-derived durable id is minted (ONE-1704 M3).
///
/// Every axis of the IMMUTABLE connector-scope identity is mixed in — the
/// credential-fingerprint-derived STREAM connection, the actor, its gate
/// identity, and the registered world/facet ceiling — so two credentials for
/// the SAME actor with disjoint scopes can never map one reused key onto one
/// row. Nothing a caller sends reaches this: the key is a caller-chosen label,
/// the identity is not.
///
/// Both callers route through here: the `execute_code` durable run handle and
/// the retained edit adapter's idempotency row. There is no second derivation.
#[must_use]
pub fn mcp_scoped_identity_id(namespace: &str, key: &str, actor: &McpResolvedActor) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.mcp.scoped-identity.v2");
    hasher.update(&(namespace.len() as u64).to_be_bytes());
    hasher.update(namespace.as_bytes());
    // Credential identity: the stream connection id IS the registered
    // credential's fingerprint, never an actor field or a tool argument.
    hasher.update(&(actor.stream_connection.0.len() as u64).to_be_bytes());
    hasher.update(actor.stream_connection.0.as_bytes());
    hasher.update(actor.actor_ref.as_bytes());
    hasher.update(&(actor.gate_actor_class.len() as u64).to_be_bytes());
    hasher.update(actor.gate_actor_class.as_bytes());
    hasher.update(&(actor.gate_actor_ref.len() as u64).to_be_bytes());
    hasher.update(actor.gate_actor_ref.as_bytes());
    // The immutable registered scope ceiling.
    if let Some(world_ref) = actor.scope.world_ref {
        hasher.update(b"w1");
        hasher.update(world_ref.as_bytes());
    } else {
        hasher.update(b"w0");
    }
    if let Some(facet_ref) = actor.scope.facet_ref {
        hasher.update(b"f1");
        hasher.update(facet_ref.as_bytes());
    } else {
        hasher.update(b"f0");
    }
    hasher.update(&(key.len() as u64).to_be_bytes());
    hasher.update(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    loop {
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
        bytes[0] ^= 0x42;
    }
}

/// The DURABLE run id one `execute_code` handle resolves to.
///
/// Deterministic, so re-calling with the same `run_ref` under the same
/// credential scope re-enters the SAME persisted replay record — that is the
/// resume door. A second credential's identical handle is a different run.
#[must_use]
pub fn mcp_code_run_id(run_ref: &str, actor: &McpResolvedActor) -> EntityId {
    mcp_scoped_identity_id("execute_code.run", run_ref, actor)
}

/// One `execute_code` call as the injected host receives it.
///
/// The actor is the RESOLVED connector actor; nothing here is caller-shaped
/// except the task text and the run handle label.
pub struct McpCodeExecutionRequest<'a> {
    /// The vault this connector's durable run lives in. Supplied by the door
    /// the call arrived at, so the host binds no vault of its own.
    pub vault: Arc<Vault>,
    pub actor: &'a McpResolvedActor,
    /// The caller's handle onto the durable run.
    pub run_ref: &'a str,
    /// The REPL task the durable run carries out.
    pub task: &'a str,
    /// The durable run id [`mcp_code_run_id`] derived for this handle.
    pub run_id: EntityId,
}

impl fmt::Debug for McpCodeExecutionRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpCodeExecutionRequest")
            .field("actor", &self.actor)
            .field("run_ref", &self.run_ref)
            .field("run_id", &self.run_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpCodeExecutionError {
    #[error("no execute_code host is bound on this server")]
    HostUnbound,
    #[error("execute_code run binding failed: {0}")]
    RunBinding(String),
    #[error("execute_code run failed: {0}")]
    Run(String),
}

impl McpCodeExecutionError {
    /// The stable wire code this refusal carries.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::HostUnbound => "code_host_unbound",
            Self::RunBinding(_) => "code_run_binding_failed",
            Self::Run(_) => "code_run_failed",
        }
    }
}

/// The server-local, INJECTED `execute_code` seam.
///
/// ONE-1704 owns the MCP bridge, not a new engine runtime: the host is bound
/// once by route/provider wiring and this crate never evaluates anything of its
/// own. With no host bound, `execute_code` fails CLOSED — it does not fall back
/// to a gateway-local loop.
pub trait McpCodeExecutionHost: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: McpCodeExecutionRequest<'a>,
    ) -> Pin<
        Box<dyn Future<Output = Result<EngineExecutorOutcome, McpCodeExecutionError>> + Send + 'a>,
    >;
}

/// The engine-native pieces one durable run needs, bound by the HOST.
///
/// The core crate ships no production `JsCodeModeRuntime` and this server owns
/// no LLM backend or budget lease, so all three are injected. The ADAPTER below
/// — not the provider — is what constructs `HostSelfDispatcher`/`GatedActorWrite`
/// and enters the sandbox/REPL through `EngineNativeExecutor`.
pub trait McpCodeModeProvider: Send + Sync {
    /// The backend the durable REPL generates each step against.
    fn backend(&self) -> &dyn LlmBackend;
    /// The admission lease every generated step is charged to.
    fn lease(&self) -> &BudgetLease;
    /// A FRESH sandbox/REPL runtime for one run.
    fn runtime(&self) -> Box<dyn JsCodeModeRuntime + Send>;
    /// The executor configuration for this run.
    fn executor_config(&self, run_id: EntityId, task: &str) -> EngineExecutorConfig;
}

/// The PRODUCTION adapter: the injected provider, entered through the engine's
/// own durable executor.
pub struct McpEngineNativeCodeHost {
    provider: Arc<dyn McpCodeModeProvider>,
}

impl fmt::Debug for McpEngineNativeCodeHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpEngineNativeCodeHost").finish()
    }
}

impl McpEngineNativeCodeHost {
    #[must_use]
    pub fn new(provider: Arc<dyn McpCodeModeProvider>) -> Self {
        Self { provider }
    }
}

impl McpCodeExecutionHost for McpEngineNativeCodeHost {
    fn execute<'a>(
        &'a self,
        request: McpCodeExecutionRequest<'a>,
    ) -> Pin<
        Box<dyn Future<Output = Result<EngineExecutorOutcome, McpCodeExecutionError>> + Send + 'a>,
    > {
        let vault = Arc::clone(&request.vault);
        let provider = Arc::clone(&self.provider);
        let write_actor = request.actor.write_actor();
        // The gated run source is HOST-derived: the caller's handle is a label
        // inside it, never the WHO.
        let run_ref = format!("mcp.execute_code:{}", request.run_ref);
        let config = provider.executor_config(request.run_id, request.task);
        Box::pin(async move {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            // The engine REPL driver holds `&mut dyn JsCodeModeRuntime` across
            // its own awaits, so its future is deliberately not `Send`. It runs
            // on its OWN thread with its OWN current-thread reactor; the
            // gateway task holds no lock and only awaits the answer, so a
            // durable wait never becomes a held connection.
            let worker = std::thread::Builder::new()
                .name("mcp-execute-code".to_owned())
                .spawn(move || {
                    let outcome = run_engine_native_code_mode(
                        &vault,
                        provider.as_ref(),
                        write_actor,
                        &run_ref,
                        &config,
                    );
                    let _ = sender.send(outcome);
                })
                .map_err(|error| McpCodeExecutionError::Run(error.to_string()))?;
            // Detached on purpose: the caller awaits the answer instead of
            // blocking a runtime worker to join it.
            drop(worker);
            receiver.await.map_err(|_| {
                McpCodeExecutionError::Run("execute_code worker ended without a result".to_owned())
            })?
        })
    }
}

/// Enters the EXISTING sandbox/REPL substrate for one durable run.
///
/// This is the whole of what `execute_code` means now: bind the gated write at
/// the host boundary, hand the engine its own runtime, and let
/// `EngineNativeExecutor` own every step, replay row, and terminal marker. The
/// server evaluates nothing and opens no second vault-write path.
fn run_engine_native_code_mode(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    write_actor: WriteActor,
    run_ref: &str,
    config: &EngineExecutorConfig,
) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
    let gated_write = GatedActorWrite::new(vault, write_actor, run_ref)
        .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?;
    let mut runtime = provider.runtime();
    let runtime: &mut dyn JsCodeModeRuntime = &mut *runtime;
    let reactor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| McpCodeExecutionError::Run(error.to_string()))?;
    let mut executor = EngineNativeExecutor::new(
        vault,
        provider.backend(),
        provider.lease(),
        runtime,
        &gated_write,
    );
    reactor
        .block_on(executor.run(config))
        .map_err(|error| McpCodeExecutionError::Run(error.to_string()))
}

static MCP_CODE_EXECUTION_HOST: OnceLock<Arc<dyn McpCodeExecutionHost>> = OnceLock::new();

/// Binds the process's `execute_code` host. Route/provider wiring only.
///
/// Returns `false` when a host is already bound: the seam is set once, so no
/// request-time input can swap the substrate under a live connector.
pub fn bind_mcp_code_execution_host(host: Arc<dyn McpCodeExecutionHost>) -> bool {
    MCP_CODE_EXECUTION_HOST.set(host).is_ok()
}

/// The bound `execute_code` host, or `None` when this process bound none.
#[must_use]
pub fn mcp_code_execution_host() -> Option<&'static Arc<dyn McpCodeExecutionHost>> {
    MCP_CODE_EXECUTION_HOST.get()
}
