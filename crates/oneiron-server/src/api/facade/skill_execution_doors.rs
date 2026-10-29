//! Skill calls on the caller's attached run and owner-anchored pack outcomes.
use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::live_run::LiveRunCredential;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher, RunCall,
    SelfAgentVerbCall, SelfEffect,
};
use oneiron::memory::{
    HostWriteOrigin, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError,
    MemoryResult,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{
    self, LiveRunRequest, SkillPackCreditRequest, SkillPackOutcomeRequest, SkillPackReceipt,
    SkillPackReceiptRequest,
};
use oneiron::{ModelId, WriteActor};

use super::host_doors::support::{Listed, MaybeListed, internal, owner_proof, refused};
use super::{FacadeApiError, FacadeCall, facade_actor};
use crate::auth::CoreAuth;
use crate::server::{LiveRunCaller, LiveRunRefusal, SyncServer};

/// `self.skills.call` (`host_door_lists`): a callable skill answers JSON
/// made from its stored source, the verbs it calls and retained results.
/// Beside it, the rows the same execution read them from
/// ([`oneiron::engine_executor::execute_live_skill_call_listing`]): `None`
/// when one nested answer kept no set, never `[]` read off the SKILL id. A
/// refusal before the call runs, or after it for a revoked credential, lists
/// none.
pub(crate) async fn self_skills_call(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<oneiron::code_run::SkillCallInput>,
) -> MaybeListed<serde_json::Value> {
    skills_call(server, auth, session, input)
        .await
        .unwrap_or_else(|refusal| (Err(refusal), Some(Vec::new())))
}

async fn skills_call(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<oneiron::code_run::SkillCallInput>,
) -> MemoryResult<MaybeListed<serde_json::Value>> {
    const VERB: &str = "self.skills.call";
    if session.is_some() {
        return Err(MemoryError::new(
            oneiron::memory::MEMORY_CODE_OFF_RECORD_SESSION_DOOR,
            "callable skills require the attached run's canonical storage",
            &[],
        ));
    }
    let (actor, class) = facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
    let proof = auth.verified_slip().ok_or_else(credential_required)?;
    server
        .vault()
        .credential_read_key(proof)?
        .ok_or_else(credential_required)?;
    let writer = WriteActor::new(actor, class);
    let run = server
        .live_runs
        .resolve(
            &input.live_run,
            LiveRunCaller {
                actor: writer,
                credential: LiveRunCredential::of(&auth.idempotency_principal(), auth.locality()),
            },
        )
        .map_err(run_refusal)?;
    let held = run
        .hold(&server.live_runs, &server.vault)
        .await?
        .map_err(run_refusal)?;
    let model = ModelId::new(run.planner().1.to_owned())
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let provider = server
        .code_execution_host()
        .and_then(|host| host.engine_native())
        .filter(|host| host.provider().production_runtime_available())
        .map(|host| Arc::clone(host.provider()))
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "no callable skill runtime is available",
                &[],
            )
        })?;
    let door: Arc<dyn AgentVerbDoor> =
        match crate::api::mcp_gateway::skill_execution::skill_execution_door(
            server,
            auth,
            run.run_id(),
        )? {
            Some(door) => door,
            None => Arc::new(SkillCredentialDoor {
                server: Arc::clone(server),
                auth: auth.clone(),
                runtime: tokio::runtime::Handle::current(),
            }),
        };
    let auth = auth.clone();
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<MaybeListed<serde_json::Value>> {
        let binding = held.proof();
        let memory = crate::api::credential_memory(server.vault(), Some(&auth), actor, class)
            .at(auth.locality());
        if memory.get_entity(&input.spec.skill)?.value.is_none() {
            return Err(credential_required());
        }
        let dispatcher = HostSelfDispatcher::for_live_run(server.vault(), writer, &binding)?
            .with_callable_skills(Arc::clone(&server.vault))?
            .with_agent_verb_door(door.clone());
        let mut runtime = provider.runtime();
        // The callable is type-checked on the host's service as it is, never
        // loaded or waited on here; its feedback stays beside the run
        // (FIX 10389).
        let answer = oneiron::engine_executor::execute_live_skill_call_listing(
            server.vault(),
            &binding,
            &dispatcher,
            &model,
            input.spec,
            (runtime.as_mut(), provider.code_check()),
        );
        // A revoked credential receives no result, even if it died mid-call.
        let proof = auth.verified_slip().ok_or_else(credential_required)?;
        server
            .vault()
            .credential_read_key(proof)?
            .ok_or_else(credential_required)?;
        drop(held);
        Ok(answer)
    })
    .await
    .map_err(|_| internal(VERB))?
}

fn credential_required() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "a skill call requires the attached agent's own live credential and readable skill",
        &[],
    )
}

fn run_refusal(refusal: LiveRunRefusal) -> MemoryError {
    MemoryError::new(refusal.code(), refusal.message(), &[refusal.suggestion()])
}

/// A skill borrows exactly this request's credential. Each nested table verb
/// crosses the existing facade; run traps recheck the same credential and
/// record scope an action would. There is no actor-only or owner fallback.
struct SkillCredentialDoor {
    server: Arc<SyncServer>,
    auth: CoreAuth,
    runtime: tokio::runtime::Handle,
}

impl SkillCredentialDoor {
    fn read_key(&self) -> MemoryResult<ScopedReadActorKey> {
        let proof = self.auth.verified_slip().ok_or_else(credential_required)?;
        self.server
            .vault()
            .credential_read_key(proof)?
            .map(|key| key.at(self.auth.locality()))
            .ok_or_else(credential_required)
    }
}

impl AgentVerbDoor for SkillCredentialDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if let Err(error) = self.read_key() {
            return Ok(Err(AgentVerbRefusal { code: error.code }));
        }
        let server = Arc::clone(&self.server);
        let auth = self.auth.clone();
        let verb = call.verb.as_str();
        let input = call.input.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        self.runtime.spawn(async move {
            let id = invocation.to_hex();
            let call = FacadeCall::bound(&auth, None, Some(&id), None);
            let answer = super::call_verb(&server, &call, verb, Ok(input)).await;
            let _ = sender.send(answer);
        });
        Ok(match receiver.recv() {
            Ok(Ok(answer)) => Ok(AgentVerbAnswer::new(answer.value, answer.rows)),
            Ok(Err(error)) => Err(AgentVerbRefusal {
                code: error.into_memory_error().code,
            }),
            Err(_) => Err(AgentVerbRefusal {
                code: oneiron::memory::MEMORY_CODE_INTERNAL.to_owned(),
            }),
        })
    }

    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        let check = || -> MemoryResult<Option<ScopedReadActorKey>> {
            let key = self.read_key()?;
            if let RunCall::Bridge(effect) = call {
                super::action_routes::require_action_scope(&self.auth, effect.as_str())
                    .map_err(FacadeApiError::into_memory_error)?;
            }
            // A search, an edge's target, a consult's refs and a TASK
            // binding's TASK and workflow are read on the credential's lane.
            Ok(match call {
                RunCall::Bridge(
                    SelfEffect::MemorySearch
                    | SelfEffect::MemoryPutEdge
                    | SelfEffect::ConsultResult
                    | SelfEffect::WorkflowDispatch,
                ) => Some(key),
                _ => None,
            })
        };
        check().map_err(|error| AgentVerbRefusal { code: error.code })
    }

    fn withholds_retained(
        &self,
        rows: Option<&[oneiron::EntityId]>,
    ) -> Result<bool, AgentVerbRefusal> {
        let destination = self.auth.destination();
        if !destination.is_off_device() {
            return Ok(false);
        }
        let Some(rows) = rows else {
            return Ok(true);
        };
        crate::device_local::withholds_retained(self.server.vault(), destination, rows, &[])
            .map_err(|_| AgentVerbRefusal {
                code: oneiron::memory::MEMORY_CODE_INTERNAL.to_owned(),
            })
    }
}

/// `vault.skills.pack_receipt` (`host_door_lists`): the receipt ledger is a
/// side table, and the frozen receipt names its loaded versions, attribution
/// and outputs by ref without reading their bodies, so the list is complete
/// and empty.
pub(crate) async fn vault_skills_pack_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillPackReceiptRequest,
) -> Listed<SkillPackReceipt> {
    let owner = match owner_proof(auth, server, "vault.skills.pack_receipt") {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || {
        sdk::skill_pack_receipt_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.pack_receipt"))
    .and_then(|answer| answer);
    (answer, Vec::new())
}

/// `vault.skills.outcomes.project` (`host_door_lists`): the projection
/// reads receipts, evidence, versions and lineage edges to score credit, and
/// answers the shares and the persisted bit, no skill, turn or artifact
/// text, so the list is complete and empty.
pub(crate) async fn vault_skills_outcomes_project(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillPackOutcomeRequest,
) -> Listed<sdk::SkillPackOutcomeProjection> {
    let owner = match owner_proof(auth, server, "vault.skills.outcomes.project") {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || {
        sdk::skill_pack_outcome_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.outcomes.project"))
    .and_then(|answer| answer);
    (answer, Vec::new())
}

/// `vault.skills.outcomes.get` (`host_door_lists`): a point read of the
/// stored credit side row, its subjects and shares by ref, so the list is
/// complete and empty.
pub(crate) async fn vault_skills_outcomes_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillPackCreditRequest,
) -> Listed<Option<oneiron::skill_attribution::LateCreditReceipt>> {
    let owner = match owner_proof(auth, server, "vault.skills.outcomes.get") {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || {
        sdk::skill_pack_credit_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.outcomes.get"))
    .and_then(|answer| answer);
    (answer, Vec::new())
}
