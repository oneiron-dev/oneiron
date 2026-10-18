//! Durable code-mode runs bound to an off-record session (DOOR-127): one
//! entry of a run whose every row stays in the session's room.

use std::sync::Arc;

use oneiron::code_run::GatedActorWrite;
use oneiron::engine_executor::{EngineExecutorOutcome, EngineNativeExecutor, JsCodeModeRuntime};
use oneiron::{EntityId, Vault, WriteActor};

use super::{ActiveRun, McpCodeExecutionError, McpCodeModeProvider, McpEngineNativeCodeHost};

/// The durable run id `run_ref` names in the off-record session
/// `session_ref` for `actor` (DOOR-127): the same handle in the same live
/// session enters the same run again. Its rows live in that session's room,
/// so a name reused after close names a run with no record yet.
#[must_use]
pub(crate) fn off_record_run_id(session_ref: &str, actor: EntityId, run_ref: &str) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.off-record.execute.run.v1");
    for part in [
        session_ref.as_bytes(),
        &actor.as_bytes()[..],
        run_ref.as_bytes(),
    ] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    loop {
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
        bytes[0] ^= 0x42;
    }
}

impl McpEngineNativeCodeHost {
    /// One entry of the durable code-mode run `run_id`, bound to the live
    /// off-record session `session_ref` and written by `actor` (DOOR-127).
    /// The session's route takes every row the run makes (its replay
    /// record, scripts, observations and raw outputs) and its spilled
    /// outputs land in the session's own body directory, so close drops them
    /// all. It waits its turn with `execute_code`'s runs, under `actor`'s
    /// own key, and never enters one run twice at once. It takes no seat (a
    /// seat row is the base vault's) and runs its configured model, as a
    /// session's reader child does.
    pub(crate) async fn execute_in_off_record_session(
        &self,
        vault: Arc<Vault>,
        session_ref: String,
        actor: WriteActor,
        run_ref: String,
        task: String,
        run_id: EntityId,
    ) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
        let provider = Arc::clone(&self.provider);
        let guard = ActiveRun::acquire(Arc::clone(&self.active), run_id)?;
        let permit = self
            .runs
            .admit(format!("off-record:{}", actor.entity_ref().to_hex()))
            .await
            .map_err(|_| McpCodeExecutionError::RunWaitedOut)?;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        // The executor's future is not `Send`, so it runs on a thread of its
        // own with its own reactor, as an `execute_code` run does.
        let worker = std::thread::Builder::new()
            .name("off-record-execute".to_owned())
            .spawn(move || {
                let outcome = run_in_off_record_session(
                    &vault,
                    provider.as_ref(),
                    &session_ref,
                    actor,
                    &run_ref,
                    run_id,
                    &task,
                );
                drop(guard);
                drop(permit);
                let _ = sender.send(outcome);
            })
            .map_err(|error| McpCodeExecutionError::Run(error.to_string()))?;
        drop(worker);
        receiver.await.map_err(|_| {
            McpCodeExecutionError::Run(
                "the off-record run's worker ended without a result".to_owned(),
            )
        })?
    }
}

/// [`McpEngineNativeCodeHost::execute_in_off_record_session`]'s worker: the
/// session bound for `actor`, then the paired session constructors, the
/// gated write and the executor, as a session's reader child pairs them.
fn run_in_off_record_session(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    session_ref: &str,
    actor: WriteActor,
    run_ref: &str,
    run_id: EntityId,
    task: &str,
) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
    let binding = |error: oneiron::Error| McpCodeExecutionError::RunBinding(error.to_string());
    let session = vault
        .off_record_session_vault()
        .bind_for(session_ref, actor.entity_ref())
        .map_err(binding)?;
    let config = provider
        .executor_config(vault, run_id, task)
        .map_err(binding)?;
    if config.run_id != run_id {
        return Err(McpCodeExecutionError::RunBinding(
            "provider changed the session run's identity".into(),
        ));
    }
    let gated_write = GatedActorWrite::for_off_record_session(
        &session,
        actor,
        format!("off_record.execute:{run_ref}"),
    )
    .map_err(binding)?;
    let reactor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| McpCodeExecutionError::Run(error.to_string()))?;
    let mut runtime = provider.runtime();
    let runtime: &mut dyn JsCodeModeRuntime = &mut *runtime;
    let mut executor = EngineNativeExecutor::for_off_record_session(
        &session,
        provider.backend(),
        provider.lease(),
        runtime,
        &gated_write,
    )
    .map_err(|error| McpCodeExecutionError::RunBinding(error.to_string()))?;
    reactor
        .block_on(executor.run(&config))
        .map_err(|error| McpCodeExecutionError::Run(error.to_string()))
}
