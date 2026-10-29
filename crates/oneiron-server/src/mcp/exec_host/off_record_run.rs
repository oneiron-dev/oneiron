//! Durable code-mode runs bound to an off-record session (DOOR-127): one
//! entry of a run whose every row stays in the session's room.

use std::sync::Arc;

use oneiron::agent_def::AgentModel;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AGENT_VERB_SESSION_BOUND, AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, GatedActorWrite,
    RunCall, SelfAgentVerbCall, SelfEffect, SessionWriteAdmission, SessionWriteCeiling,
};
use oneiron::engine_executor::{EngineExecutorOutcome, EngineNativeExecutor, JsCodeModeRuntime};
use oneiron::memory::HostWriteOrigin;
use oneiron::off_record::OffRecordCreator;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::{EdgeActorClass, EntityId, Vault, WriteActor};

use super::{McpCodeExecutionError, McpCodeModeProvider, McpEngineNativeCodeHost};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::ApiError;
use crate::server::ReaderSeats;

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

/// The live session a run enters, by name, and the creator that instance
/// must name when its caller manages it as its creator (WILL-PLAN L13 row
/// 03); `None` for the vault's owner, who manages every stretch entered
/// alone. The run binds it again on its own thread, so a name taken again
/// since its door's check never lends the run another creator's stretch.
/// `caller` is the request the run was admitted on: the run's reads in the
/// room read under that caller's own key (WILL L11-01).
pub(crate) struct OffRecordRunSession {
    pub(crate) session_ref: String,
    pub(crate) creator: Option<OffRecordCreator>,
    pub(crate) caller: CoreAuth,
}

/// The door a run bound to an off-record session binds (WILL L11-01): the
/// caller its request was admitted for, with that request's credential and
/// the place its connection sits. A read the run serves through the room
/// reads under the key this caller's own handle builds again at each read,
/// so its Grant and ceiling bind it as they bind the caller's other reads,
/// wherever the caller or the vault runs. A write the run stages in the room
/// is admitted the same way, under the room's own write gate, and its
/// credential is checked again where the write lands (S01-2a). It forwards
/// no verb (a run's verbs stage in the room or are refused there), keys the
/// run's own search on its caller (FIX 5976), and admits every other call
/// the run serves itself as a host that binds no door does.
struct OffRecordRunDoor {
    vault: Arc<Vault>,
    caller: CoreAuth,
    actor: WriteActor,
}

impl OffRecordRunDoor {
    /// The key this door's caller reads under, built again now by the
    /// caller's own handle at the place its connection sits.
    fn caller_key(&self) -> Result<ScopedReadActorKey, AgentVerbRefusal> {
        let actor = self.actor;
        crate::api::credential_memory(
            &self.vault,
            Some(&self.caller),
            actor.entity_ref(),
            actor.actor_class(),
        )
        .at(self.caller.locality())
        .read_key()
        .map_err(|refused| AgentVerbRefusal { code: refused.code })
    }
}

/// The ceiling a room write of an [`OffRecordRunDoor`]'s run lands under:
/// the caller's credential, live in the write's own transaction.
struct LiveCaller {
    vault: Arc<Vault>,
    caller: CoreAuth,
}

impl SessionWriteCeiling for LiveCaller {
    fn holds_in(&self, txn: &heed::RwTxn<'_>) -> Result<(), AgentVerbRefusal> {
        if self
            .caller
            .credential_is_live_in_write_txn(&self.vault, txn)
        {
            return Ok(());
        }
        Err(api_refusal(&ApiError::unauthorized()))
    }
}

/// An API refusal as the run's guest reads it: its stable code.
fn api_refusal(refused: &ApiError) -> AgentVerbRefusal {
    AgentVerbRefusal {
        code: refused.code().as_str().to_owned(),
    }
}

impl AgentVerbDoor for OffRecordRunDoor {
    fn call(
        &self,
        _: &SelfAgentVerbCall,
        _: &HostWriteOrigin,
        _: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(AgentVerbRefusal {
            code: AGENT_VERB_SESSION_BOUND.to_owned(),
        }))
    }

    /// The run's own `vault.search` reads on the caller's key, in the room,
    /// each posting admitted on that key's lane (FIX 5976). Every other call
    /// the run serves itself is admitted as a host that binds no door does,
    /// while the caller's credential is live (FIX 9504): a revoked
    /// credential's run serves no call of its own, and none of them asks
    /// for a read or search scope it never needed.
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        if !self.caller.credential_is_live(&self.vault) {
            return Err(api_refusal(&ApiError::unauthorized()));
        }
        match call {
            RunCall::Bridge(SelfEffect::MemorySearch) => self.caller_key().map(Some),
            _ => Ok(None),
        }
    }

    /// The keyed search drops only rows the caller may not read.
    fn keyed_search_surfaceable_only(&self) -> bool {
        false
    }

    fn admit_session_read(&self, _: AgentVerb) -> Result<ScopedReadActorKey, AgentVerbRefusal> {
        self.caller_key()
    }

    /// A room write meets the room's own write gate, as the session's
    /// direct write doors run it: a credential live now, holding Write over
    /// the whole record scope, checked again in the write's own transaction.
    /// The caller's key opens the room's view a claim's subject resolves
    /// in; a credential that grants no read still writes, as those doors
    /// let it, its subjects resolved as the vault resolves them.
    fn admit_session_write(&self, _: AgentVerb) -> Result<SessionWriteAdmission, AgentVerbRefusal> {
        if !self.caller.credential_is_live(&self.vault) {
            return Err(api_refusal(&ApiError::unauthorized()));
        }
        self.caller
            .require(CoreScope::Write)
            .map_err(|refused| api_refusal(&refused))?;
        Ok(SessionWriteAdmission::new(
            self.caller_key().ok(),
            Arc::new(LiveCaller {
                vault: Arc::clone(&self.vault),
                caller: self.caller.clone(),
            }),
        ))
    }
}

impl McpEngineNativeCodeHost {
    /// One entry of the durable code-mode run `run_id`, bound to the live
    /// off-record session `session` names and written by `actor` (DOOR-127).
    /// The session's route takes every row the run makes (its replay
    /// record, scripts, observations and raw outputs) and its spilled
    /// outputs land in the session's own body directory, so close drops them
    /// all. It waits behind an earlier entry of the same run still running,
    /// in arrival order, then its turn with `execute_code`'s runs, under
    /// `actor`'s own key, so it never enters one run twice at once (FIX
    /// 9505). It takes no model seat and runs its configured model. Its
    /// `self.spawn` queues reader children in the room, under the seat this
    /// host's reader seats lend it, as an `execute_code` run's does (FIX
    /// 7507).
    pub(crate) async fn execute_in_off_record_session(
        &self,
        vault: Arc<Vault>,
        session: OffRecordRunSession,
        actor: WriteActor,
        run_ref: String,
        task: String,
        run_id: EntityId,
    ) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
        let provider = Arc::clone(&self.provider);
        let reader_seats = self.reader_seats.clone();
        let guard = self.active.acquire(run_id).await?;
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
                    reader_seats.as_deref(),
                    &session,
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
/// session bound for `actor` (for its creator, when `target` names one),
/// then the paired session constructors, the gated write and the executor,
/// as a session's reader child pairs them. The gated write is bound to the
/// run before its config is read, so the config reads the run's first start
/// from the room's record. With `reader_seats`, the run's `self.spawn`
/// queues reader children in the room under a seat lent under its own id:
/// no attempt and no scope, its children on the host's meter, held to its
/// agent's list when `actor` is an agent (`parent_model_list`).
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one axis of the session run's host binding"
)]
fn run_in_off_record_session(
    vault: &Arc<Vault>,
    provider: &dyn McpCodeModeProvider,
    reader_seats: Option<&ReaderSeats>,
    target: &OffRecordRunSession,
    actor: WriteActor,
    run_ref: &str,
    run_id: EntityId,
    task: &str,
) -> Result<EngineExecutorOutcome, McpCodeExecutionError> {
    let binding = |error: oneiron::Error| McpCodeExecutionError::RunBinding(error.to_string());
    let rooms = vault.off_record_session_vault();
    let session = match target.creator {
        Some(creator) => rooms.bind_as_creator(&target.session_ref, creator),
        None => rooms.bind_for(&target.session_ref, actor.entity_ref()),
    }
    .map_err(binding)?;
    let door = Arc::new(OffRecordRunDoor {
        vault: Arc::clone(vault),
        caller: target.caller.clone(),
        actor,
    });
    let mut gated_write = GatedActorWrite::for_off_record_session(
        &session,
        actor,
        format!("off_record.execute:{run_ref}"),
    )
    .map_err(binding)?
    .with_agent_verb_door(door)
    .with_bound_run(run_id);
    if let Some(seats) = reader_seats {
        match parent_model_list(vault, actor) {
            Ok(listed) => {
                let mut seat = seats.seat(
                    run_id,
                    None,
                    target.caller.destination(),
                    provider.reader_window_tokens(),
                );
                seat.listed = listed;
                gated_write = gated_write.with_reader_spawn(seat);
            }
            Err(error) => {
                tracing::warn!(%error, run = %run_id.to_hex(), "a session run's agent definition did not read; its self.spawn stays unbound");
            }
        }
    }
    let config = provider
        .executor_config_on(vault, &gated_write, run_id, task)
        .map_err(binding)?;
    if config.run_id != run_id {
        return Err(McpCodeExecutionError::RunBinding(
            "provider changed the session run's identity".into(),
        ));
    }
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
    // The host's one type-feedback service (FIX 8277): the session's steps
    // keep their feedback with their run.
    if let Some(feedback) = provider.code_check() {
        executor = executor.with_code_check(feedback);
    }
    reactor
        .block_on(executor.run(&config))
        .map_err(|error| McpCodeExecutionError::Run(error.to_string()))
}

/// The model list a session run's reader children are held to (FIX 4539):
/// its agent's own, read from its stored definition now, when the run's
/// authenticated actor is an agent; none for the owner or any other actor,
/// or for an agent with no stored definition. The children's parent row
/// freezes it at the run's first spawn. `Err` when an agent's definition
/// does not read: its run then lends no spawn seat, as before.
fn parent_model_list(vault: &Vault, actor: WriteActor) -> oneiron::Result<Vec<AgentModel>> {
    if actor.actor_class() != EdgeActorClass::Agent {
        return Ok(Vec::new());
    }
    Ok(vault
        .get_agent_definition(&actor.entity_ref())?
        .map_or_else(Vec::new, |definition| definition.models))
}
