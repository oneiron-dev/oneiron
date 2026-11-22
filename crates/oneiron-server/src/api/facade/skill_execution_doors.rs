//! Skill calls on the caller's attached run and owner-anchored pack outcomes.
use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::live_run::LiveRunCredential;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher, RunCall,
    SelfAgentVerbCall, SelfEffect,
};
use oneiron::engine_executor::{AdmittedSkillAnswer, AdmittedSkillText};
use oneiron::memory::{
    HostWriteOrigin, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError,
    MemoryResult,
};
use oneiron::runtime_hooks::{InvocationId, VerbHookPre};
use oneiron::task_verb::sdk::{
    self, LiveRunRequest, SkillPackCreditRequest, SkillPackOutcomeRequest, SkillPackReceipt,
    SkillPackReceiptRequest,
};
use oneiron::{EntityId, ModelId, WriteActor};

use super::host_doors::support::{
    Listed, MaybeListed, internal, owner_proof, refused, with_calling_origin,
};
use super::{FacadeApiError, FacadeCall, facade_actor};
use crate::auth::CoreAuth;
use crate::server::{LiveRunCaller, LiveRunRefusal, SyncServer};

/// `self.skills.call` (`host_door_lists`): a callable skill answers JSON
/// made from its stored source, the verbs it calls and retained results.
/// Beside it, the rows the same execution read them from
/// ([`oneiron::engine_executor::execute_live_skill_call_listing`]): `None`
/// when one nested answer kept no set, never `[]` read off the SKILL id. A
/// refusal before the call runs, or after it for a revoked credential, lists
/// none. `outer_hooks_live` is the generated facade's own pre chain's state
/// for this call (`!VerbHookPre::passed_through()`), carried to the admitted
/// entry it calls: that entry reads no binding for it again. While that
/// chain is live, an answer nesting past what a value may hold comes back as
/// its JSON text, which [`admitted_skill_text_post`] judges.
pub(crate) async fn self_skills_call(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<oneiron::code_run::SkillCallInput>,
    outer_hooks_live: bool,
) -> MaybeListed<AdmittedSkillAnswer> {
    skills_call(server, auth, session, input, outer_hooks_live)
        .await
        .unwrap_or_else(|refusal| (Err(refusal), Some(Vec::new())))
}

/// A graph workflow needs the attached run's host context. The ordinary
/// HTTP/MCP facade has no run or lease in this request; it must not guess
/// one from the actor or mint one. RunHostDoor serves this verb with its
/// actual registered lease, executor and current read proof.
pub(crate) async fn self_skills_graph(
    _server: &Arc<SyncServer>,
    _auth: &CoreAuth,
    _input: oneiron::receipt::GraphSkillRunRequest,
) -> Listed<oneiron::receipt::GraphSkillRunOutcome> {
    refused(MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        "graph workflow skills execute through the attached run's host door",
        &[],
    ))
}

async fn skills_call(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<oneiron::code_run::SkillCallInput>,
    outer_hooks_live: bool,
) -> MemoryResult<MaybeListed<AdmittedSkillAnswer>> {
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
                observer: super::admission_observer(),
            }),
        };
    let auth = auth.clone();
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<MaybeListed<AdmittedSkillAnswer>> {
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
            outer_hooks_live,
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

/// The attached run an admitted `self.skills.call` ran on, for its
/// post-hook view spill: the run its own `live_run` handle names. The door
/// resolved and ran under this same handle — its pre chain's args, which the
/// door decoded and nothing after it changes — so the parsed run is the run
/// the call's record stands on. `None` when the handle is absent or
/// malformed, which a call whose door ran never is.
pub(crate) fn skill_call_spill_run(hooks: &VerbHookPre) -> Option<EntityId> {
    hooks
        .args
        .get("live_run")?
        .as_str()
        .and_then(oneiron::code_run::live_run::parse_live_run_handle)
        .map(|(run, _)| run)
}

/// An admitted skill call's post-hook view as its caller reads it: spilled
/// and bound to the run as a readable result when it is too large for one
/// reply, else the view itself, exactly as the facade answered before. A
/// spill that fails — the run went while its post chain ran, or another
/// writer kept landing first — falls back to the view inline: the caller
/// still gets the data its hooks judged for it. Runs off the async runtime.
pub(crate) async fn spill_admitted_skill_view(
    server: &Arc<SyncServer>,
    run: Option<EntityId>,
    view: serde_json::Value,
    rows: Option<Vec<EntityId>>,
) -> serde_json::Value {
    let Some(run) = run else {
        return view;
    };
    if encoded_len(&view) <= oneiron::engine_executor::RESULT_REPLY_INLINE_BYTES {
        return view;
    }
    let fallback = view.clone();
    let server = Arc::clone(server);
    let spilled = super::clock_ingress::run_blocking(move || {
        oneiron::engine_executor::spill_admitted_skill_view(&server.vault, run, view, rows)
    })
    .await;
    match spilled {
        Ok(Ok(card)) => card,
        Ok(Err(error)) => {
            tracing::warn!(
                run = %run.to_hex(),
                error = ?error,
                "an admitted skill call's large view stays inline: its spill failed"
            );
            fallback
        }
        Err(error) => {
            tracing::warn!(
                run = %run.to_hex(),
                %error,
                "an admitted skill call's large view stays inline: its spill did not finish"
            );
            fallback
        }
    }
}

/// An admitted skill call's answer held as JSON text
/// ([`AdmittedSkillAnswer::Text`]; SKILL-ANSWER-DEEP-JSON-STACK-SAFE), past
/// the call's post chain `pre`, as its caller reads it
/// ([`oneiron::engine_executor::judge_admitted_skill_text`]: a view read
/// into a value, or the card of the view spilled to the run), then spilled
/// past the inline size as a value view is ([`spill_admitted_skill_view`]).
/// `rows` are the rows the answer was produced from. Runs off the async
/// runtime, as [`super::row_hooks_post`] runs a value's chain.
pub(crate) async fn admitted_skill_text_post(
    server: &Arc<SyncServer>,
    pre: VerbHookPre,
    answer: AdmittedSkillText,
    spill_run: Option<EntityId>,
    rows: Option<Vec<EntityId>>,
) -> Result<serde_json::Value, MemoryError> {
    let judged = {
        let server = Arc::clone(server);
        let rows = rows.clone();
        super::clock_ingress::run_blocking(move || {
            let (view, _) = crate::hook_decisions::collect_hook_decisions(move || {
                oneiron::engine_executor::judge_admitted_skill_text(
                    server.vault(),
                    pre,
                    answer,
                    rows,
                )
            });
            view
        })
        .await
        .map_err(|_| super::hooks::hooks_did_not_finish())??
    };
    Ok(spill_admitted_skill_view(server, spill_run, judged, rows).await)
}

/// Bytes `value` takes as JSON, holding none of them.
fn encoded_len(value: &serde_json::Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    match serde_json::to_writer(&mut count, value) {
        Ok(()) => count.0,
        Err(_) => usize::MAX,
    }
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
    /// The skill call's admission observer, taken where the door is built:
    /// a nested verb's wait in a line shows on the call's admission receipt
    /// (FIX 4735).
    observer: Option<Arc<dyn oneiron::work_line::LineObserver>>,
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
        origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if let Err(error) = self.read_key() {
            return Ok(Err(AgentVerbRefusal {
                hook_notice: None,
                code: error.code,
            }));
        }
        let server = Arc::clone(&self.server);
        let auth = self.auth.clone();
        let verb = call.verb.as_str();
        let input = call.input.clone();
        let origin = origin.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        // The skill's call is its run's (FIX 10748): its handles carry the
        // run's origin and its writes are witnessed for the run's lease.
        let observer = self.observer.clone();
        self.runtime.spawn(with_calling_origin(
            origin,
            super::with_admission_observer(observer, async move {
                let id = invocation.to_hex();
                let call = FacadeCall::bound(&auth, None, Some(&id), None);
                let answer = super::call_verb(&server, &call, verb, Ok(input)).await;
                let _ = sender.send(answer);
            }),
        ));
        Ok(match receiver.recv() {
            Ok(Ok(answer)) => Ok(AgentVerbAnswer::new(answer.value, answer.rows)),
            Ok(Err(error)) => Err(AgentVerbRefusal {
                hook_notice: None,
                code: error.into_memory_error().code,
            }),
            Err(_) => Err(AgentVerbRefusal {
                hook_notice: None,
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
            // A search, an edge's target, a consult's refs, a TASK binding's
            // TASK and workflow, and repo membership use the credential's lane.
            Ok(match call {
                RunCall::Bridge(effect) if effect.is_repo() => Some(key),
                RunCall::Bridge(
                    SelfEffect::MemorySearch
                    | SelfEffect::MemoryPutEdge
                    | SelfEffect::ConsultResult
                    | SelfEffect::WorkflowDispatch,
                ) => Some(key),
                _ => None,
            })
        };
        check().map_err(|error| AgentVerbRefusal {
            hook_notice: None,
            code: error.code,
        })
    }

    /// The host turn's hooks read on the credential's lane, with its proof
    /// and destination, as the run's own search does (FIX 9841).
    fn host_turn_read_key(&self) -> Option<ScopedReadActorKey> {
        self.read_key().ok()
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
                hook_notice: None,
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
    let answer = super::clock_ingress::run_blocking(move || {
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
    let answer = super::clock_ingress::run_blocking(move || {
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
    let answer = super::clock_ingress::run_blocking(move || {
        sdk::skill_pack_credit_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.outcomes.get"))
    .and_then(|answer| answer);
    (answer, Vec::new())
}
