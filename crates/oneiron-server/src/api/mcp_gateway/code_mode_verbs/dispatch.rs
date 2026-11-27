//! How a code-mode run's agent verbs reach their doors: admitted, executed and answered.
//! `McpCodeModeVerbs` (its `AgentVerbDoor` impl) and `run_code_mode_verb` are its call surface.
//! The code_mode_verbs root defines `McpCodeModeVerbs`; `oneiron::code_run` owns the verb records.

use super::*;

mod caller_code;
#[cfg(oneiron_test_support)]
mod test_door;
mod verb_call;

use self::caller_code::{
    caller_code_refused, caller_code_run_refusal, caller_code_verb_refusal, caller_speech_binding,
};
#[cfg(oneiron_test_support)]
pub(crate) use self::test_door::admit_run_call_for_test;
pub(crate) use self::verb_call::code_mode_line;
pub(super) use self::verb_call::{execute_code_mode_verb, execute_step_verdict};

impl McpCodeModeVerbs {
    /// Binds the door to the server runtime the `execute` call arrived on.
    /// Its program is the caller's ([`RunAuthor::Caller`]) unless
    /// [`Self::authored_by_engine_model`] says the engine's model wrote it, so
    /// a door built for any other run lends nothing (FIX
    /// CODE-MODE-LENDING-W8).
    pub(crate) fn new(
        server: &Arc<SyncServer>,
        actor: &McpCallContext,
        run_id: oneiron::EntityId,
    ) -> Self {
        Self {
            server: Arc::clone(server),
            actor: actor.clone(),
            runtime: tokio::runtime::Handle::current(),
            served: std::sync::Mutex::new(Vec::new()),
            answer_kept: std::sync::Mutex::new(None),
            run_id,
            guests: RunGuests::new(server, run_id),
            collector: crate::api::call_receipt::attempt_collector(),
            observer: crate::api::admission_observer(),
            author: RunAuthor::Caller,
        }
    }

    /// The door of a task run, whose steps the engine's model wrote from the
    /// caller's task: it keeps the run's services ([`RunAuthor::EngineModel`]).
    /// Only a task run's entry binds it (FIX CODE-MODE-LENDING-W8).
    pub(crate) fn authored_by_engine_model(mut self) -> Self {
        self.author = RunAuthor::EngineModel;
        self
    }

    /// The door of a run whose program its caller wrote (the MCP `execute`
    /// tool, FIX EXECUTE-CALLER-CODE): the caller's own per-verb gates and
    /// nothing the run would lend ([`RunAuthor::Caller`]). The `execute` tool
    /// binds it, and `resume` does for a run whose input is the caller's code.
    pub(crate) fn authored_by_caller(mut self) -> Self {
        self.author = RunAuthor::Caller;
        self
    }

    /// A browser row: this connector's binding, then its live session and
    /// Write at each call, whatever the row reads, then the run's guest. The
    /// guest is the host's: a direct call reaches the browser only through
    /// the caller's attached live run, which needs Write, and no direct door
    /// serves the desktop, so a desktop row is refused
    /// ([`MCP_DESKTOP_REFUSED`], FIX CODE-MODE-LENDING-W2).
    pub(super) fn call_browser(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if let Err(error) = mcp_admit_host_verb(&self.actor, call.verb)
            .and_then(|()| desktop_row_refusal(call.verb))
            .and_then(|()| mcp_browser_guest_gate(&self.server, &self.actor))
        {
            return refused(error);
        }
        let memory = crate::api::mcp_credential_memory(
            &self.server.vault,
            self.actor.auth.as_ref(),
            self.actor.actor_ref,
            self.actor.actor_class,
        )
        .at(self.actor.locality())
        .with_invocation(invocation);
        // Each routine decision is a verb call of its own, under a fresh
        // invocation.
        let asker = VerdictAsker::Connector(McpCallContext {
            invocation: None,
            hook_ask: None,
            ..self.actor.clone()
        });
        self.guests.call(
            &self.server,
            &self.runtime,
            call,
            origin,
            &memory,
            asker,
            self.actor.actor_ref,
        )
    }

    /// Only the test-only legacy task result lists the guest manifests: a
    /// caller-source run has no guests (FIX EXECUTE-SOURCE-BROWSER-PARITY).
    #[cfg(test)]
    pub(crate) fn manifests(&self) -> Vec<Value> {
        self.guests.manifests()
    }

    /// The rows this run's verb calls listed as served.
    pub(crate) fn served(&self) -> Vec<oneiron::EntityId> {
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The lane of the credential `execute` was admitted on, from where
    /// its caller sits: what a run's search and a session read read under.
    pub(super) fn credential_lane(&self) -> Result<ScopedReadActorKey, AgentVerbRefusal> {
        let unauthenticated = || AgentVerbRefusal {
            hook_notice: None,
            code: "mcp_auth_required".to_owned(),
            reason_codes: Vec::new(),
        };
        // A managed vault's attested owner carries no slip: he reads with his
        // own key, held to this request's owner proof, as a direct MCP read
        // does (`mcp_scoped_read`, FIX 5237).
        if let Some(auth) = self
            .actor
            .auth
            .as_ref()
            .filter(|auth| auth.managed_owner().is_some())
        {
            return crate::api::scoped_read_for_core_auth(&self.server.vault, auth)
                .map(|read| read.actor_key().clone())
                .map_err(|error| AgentVerbRefusal {
                    hook_notice: None,
                    code: match error.code() {
                        crate::error::ErrorCode::Forbidden
                        | crate::error::ErrorCode::HostActionRequiresSupportGrant
                        | crate::error::ErrorCode::OwnerBindingRequired => "forbidden",
                        _ => "engine_error",
                    }
                    .to_owned(),
                    reason_codes: Vec::new(),
                });
        }
        let proof = self
            .actor
            .auth
            .as_ref()
            .and_then(crate::auth::CoreAuth::verified_slip)
            .ok_or_else(unauthenticated)?;
        // The one builder every door's credential key comes from. A host
        // credential's refusal keeps its typed kind (FIX 2222).
        self.server
            .vault
            .credential_read_key(proof)
            .map_err(|error| AgentVerbRefusal {
                hook_notice: None,
                code: match error.kind() {
                    oneiron::ErrorKind::HostActionRequiresSupportGrant => {
                        super::tasks_response::MCP_HOST_ACTION_REFUSED
                    }
                    oneiron::ErrorKind::ScopedReadOwnerNotLive => "forbidden",
                    _ => "engine_error",
                }
                .to_owned(),
                reason_codes: Vec::new(),
            })?
            .map(|reader| reader.at(self.actor.locality()))
            .ok_or_else(unauthenticated)
    }

    /// A call the run serves itself meets this connector's door at each call
    /// too: a run row needs its own binding, and every call needs the
    /// session `execute` was admitted on, still live, and the grant its
    /// own effect needs (`mcp_run_call_gate`). A search reads
    /// under that credential's grants, as `vault.recall` does, from where its
    /// caller sits (DEC-0005).
    fn admit_bound_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        let refused = |error: McpGatewayError| AgentVerbRefusal {
            hook_notice: None,
            code: error.kind.to_owned(),
            reason_codes: error.reason_codes,
        };
        // A row's own binding: the effect's one row, or, for an effect shared
        // by several rows (Fold, Team, Leader), one of them. The exact row of
        // a shared effect is admitted first, by `admit_run_row`.
        if let RunCall::Bridge(effect) = call {
            let mut rows = RunVerb::ALL.iter().filter(|verb| verb.effect() == effect);
            if let Some(first) = rows.next()
                && mcp_admit_run_verb(&self.actor, *first).is_err()
                && !rows.any(|verb| mcp_admit_run_verb(&self.actor, *verb).is_ok())
            {
                mcp_admit_run_verb(&self.actor, *first).map_err(refused)?;
            }
        }
        mcp_run_call_gate(&self.server, &self.actor, call).map_err(refused)?;
        // Reading the reason is capture-only; a missing key must not refuse the decline.
        if matches!(call, RunCall::Bridge(SelfEffect::TasksRefuse)) {
            return Ok(self.host_turn_read_key());
        }
        // A search reads on the credential's lane, a facet stamp places only
        // a row that lane reads, a consult lands only refs it reads, and a
        // TASK binding reads its TASK and workflow there (FIX 5316).
        // A run's claim put and supersede check the records they name on
        // that lane too, as a facade row's is (FIX-LIST 25102).
        // The run repo rows read on that lane too (FIX 6867).
        if !matches!(
            call,
            RunCall::Bridge(
                SelfEffect::MemorySearch
                    | SelfEffect::MemoryPutEdge
                    | SelfEffect::MemoryPutClaim
                    | SelfEffect::MemorySupersedeClaim
                    | SelfEffect::ConsultResult
                    | SelfEffect::WorkflowDispatch
            )
        ) && !matches!(call, RunCall::Bridge(effect) if effect.is_repo())
        {
            return Ok(None);
        }
        self.credential_lane().map(Some)
    }
}

impl AgentVerbDoor for McpCodeModeVerbs {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        // The run holds the previous call's answer once it dispatches its
        // next call (FIX 10633): release what that answer kept now, so a
        // read's renderer turn cannot survive into this call.
        self.answer_recorded();
        if self.author == RunAuthor::Caller
            && let Some(reason) = caller_code_verb_refusal(call.verb)
        {
            return Ok(Err(caller_code_refused(reason)));
        }
        // A read of one of the caller's own runs' results: this door holds
        // the credential the run is derived from (FIX EXECUTE-CALLER-CODE).
        if matches!(call.verb, AgentVerb::VaultRunsReadResult) {
            return self.read_run_result(&call.input);
        }
        if call.verb.is_browser() {
            // The run's worker thread holds the call while the guest acts.
            return self.call_browser(call, origin, invocation);
        }
        let held = matches!(call.verb, AgentVerb::AiVerdict)
            .then(|| self.guests.held_image(&call.input))
            .flatten();
        // The run's worker thread drives its own reactor; the verb runs on the
        // server runtime, as a tool call would, and the worker waits for it.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        // A guest's verb is a call of its own: it resumes no hook pause
        // its run's request named.
        let actor = McpCallContext {
            invocation: Some(invocation),
            hook_ask: None,
            ..self.actor.clone()
        }
        // Each guest verb row reads its session folder's project as a tool call would
        // (RECALL-SESSION-PROJECT): a row that writes nothing and names no projects.
        .for_verb_row(call.verb.writes(), &call.input);
        let verb = call.verb.as_str();
        let input = call.input.clone();
        let run = McpCodeRun {
            origin: origin.clone(),
            run_id: self.run_id,
            author: self.author,
        };
        // What the answer holds (a deck preview's renderer) comes back with
        // it, kept until the answer is handed to the run (FIX 8238).
        let answered = HELD_IMAGE.scope(held, async move {
            let executed = crate::api::answer_hold::keeping(execute_code_mode_verb(
                &server, &actor, verb, input, run,
            ))
            .await;
            let _ = sender.send(executed);
        });
        // A live-run hold the verb makes names its attempt on the
        // `execute` call's receipt (FIX 10938).
        self.runtime
            .spawn(crate::api::call_receipt::with_attempt_collector(
                self.collector.clone(),
                crate::api::facade::with_admission_observer(self.observer.clone(), answered),
            ));
        let Ok((executed, kept)) = receiver.recv() else {
            return Ok(Err(AgentVerbRefusal {
                hook_notice: None,
                code: "engine_error".to_owned(),
                reason_codes: Vec::new(),
            }));
        };
        let answer = match executed {
            Ok(answer) => answer,
            Err(error) => return refused(error),
        };
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(answer.rows.iter().flatten().copied());
        *self
            .answer_kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(kept);
        Ok(Ok(answer))
    }

    /// The run's answer to the questions one of its connector calls waits on
    /// (FIX 3838): the host door an MCP `connector.answer` meets, for this
    /// connector's caller on the credential `execute` was admitted on.
    /// The run's admission and verb hooks already ran around it. The reply
    /// is foreign data and serves no vault rows.
    fn connector_answer(
        &self,
        request: &oneiron::task_verb::sdk::ConnectorAnswerRequest,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        // A new call means the run holds the previous answer (FIX 10633):
        // release what it kept before this one runs.
        self.answer_recorded();
        let Some(auth) = self.actor.auth.clone() else {
            return Ok(Err(AgentVerbRefusal {
                hook_notice: None,
                code: "mcp_auth_required".to_owned(),
                reason_codes: Vec::new(),
            }));
        };
        // The run's worker thread drives its own reactor; the answer runs on
        // the server runtime, as a tool call would, and the worker waits.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let caller = (self.actor.actor_ref, self.actor.actor_class);
        let request = request.clone();
        self.runtime.spawn(async move {
            let (answered, _) = crate::api::facade::host_doors::connector_answer(
                &server,
                &auth,
                caller,
                Some(invocation),
                request,
            )
            .await;
            let _ = sender.send(answered);
        });
        let refusal = |code: &str, reason_codes: Vec<String>| AgentVerbRefusal {
            hook_notice: None,
            code: code.to_owned(),
            reason_codes,
        };
        Ok(match receiver.recv() {
            Ok(Ok(reply)) => match serde_json::to_value(reply) {
                Ok(output) => Ok(AgentVerbAnswer::new(output, Some(Vec::new()))),
                Err(_) => Err(refusal("engine_error", Vec::new())),
            },
            Ok(Err(error)) => Err(refusal(&error.code, error.reason_codes)),
            Err(_) => Err(refusal("engine_error", Vec::new())),
        })
    }

    /// The exact row a shared-effect call was made through needs its own
    /// binding on the credential (FIX EXECUTE-CALLER-CODE): a connector
    /// bound to one of `self.fold`, `self.compact`, `self.unfold` and
    /// `self.folds` (or one `self.team.*` or `self.leader.*` row) calls that
    /// row alone, not every row of its effect. A name the run table does not
    /// hold is refused: it binds nothing.
    fn admit_run_row(&self, row: &'static str) -> Result<(), AgentVerbRefusal> {
        let Some(verb) = RunVerb::from_name(row) else {
            return Err(AgentVerbRefusal {
                hook_notice: None,
                code: "mcp_verb_not_bound".to_owned(),
                reason_codes: Vec::new(),
            });
        };
        mcp_admit_run_verb(&self.actor, verb).map_err(|error| AgentVerbRefusal {
            hook_notice: None,
            code: error.kind.to_owned(),
            reason_codes: error.reason_codes,
        })
    }

    /// A call a caller's own code makes is refused what no direct call
    /// reaches first (`caller_code_run_refusal`); then it meets the checks
    /// every call the run serves itself meets ([`Self::admit_bound_run_call`]).
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        if self.author == RunAuthor::Caller
            && let RunCall::Bridge(effect) = call
            && let Some(reason) = caller_code_run_refusal(effect)
        {
            return Err(caller_code_refused(reason));
        }
        self.admit_bound_run_call(call)
    }

    /// The outer skill call is the caller's own `self.skills.call`, which the
    /// facade admitted on the caller's credential before the skill's body
    /// runs, not a call the body made: it meets the checks a run call meets
    /// and none of the caller-code refusals, which still refuse each of the
    /// body's own calls (REVIEW-10594).
    fn admit_outer_skill_call(&self) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        self.admit_bound_run_call(RunCall::Bridge(SelfEffect::SkillsCall))
    }

    /// A run's speech writes a MESSAGE wherever its storage lands it, so the
    /// engine's program needs Write in its own run's conversation as in a room
    /// (`mcp_run_speech_gate`, FIX CODE-MODE-LENDING-W7). A caller's own speech is a
    /// call it chose to make: the row it is made through needs its binding,
    /// as a direct call's does, and it needs Write wherever it lands (FIX
    /// EXECUTE-CALLER-CODE). It reads nothing.
    fn admit_run_speech(
        &self,
        effect: SelfEffect,
        destination: oneiron::code_run::RunSpeechDestination,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        let gated = match self.author {
            RunAuthor::EngineModel => mcp_run_speech_gate(&self.server, &self.actor, destination),
            RunAuthor::Caller => caller_speech_binding(&self.actor, effect)
                .and_then(|()| mcp_caller_code_speech_gate(&self.server, &self.actor)),
        };
        gated.map_err(|error| AgentVerbRefusal {
            hook_notice: None,
            code: error.kind.to_owned(),
            reason_codes: error.reason_codes,
        })?;
        Ok(None)
    }

    /// The host turn's hooks read on the credential's lane, as the run's
    /// own search does (FIX 9841). A keyless reply stays keyless.
    fn host_turn_read_key(&self) -> Option<ScopedReadActorKey> {
        self.credential_lane().ok()
    }

    /// A read a session-bound run serves through the room (WILL L11-01)
    /// meets this connector's door as its run calls do: the verb's own
    /// binding, the session `execute` was admitted on, still live, the
    /// verb's own grant, and that credential's lane, from where its caller
    /// sits.
    fn admit_session_read(&self, verb: AgentVerb) -> Result<ScopedReadActorKey, AgentVerbRefusal> {
        mcp_admit_host_verb(&self.actor, verb)
            .and_then(|()| mcp_host_verb_gate(&self.server, &self.actor, verb))
            .map_err(|error| AgentVerbRefusal {
                hook_notice: None,
                code: error.kind.to_owned(),
                reason_codes: error.reason_codes,
            })?;
        self.credential_lane()
    }

    /// Rechecks a recorded verb's caller-code policy and binding (FIX
    /// CODE-MODE-LENDING-W11). Host-served result, browser and desktop rows
    /// also meet the gates their live call meets; session-bound rows meet the room's existing
    /// admission methods. The input-dependent scope and grade of a generated
    /// row's recorded answer stay at the generic Read check: the original
    /// arguments are not available here.
    fn admit_recorded_verb(&self, verb: AgentVerb) -> Result<(), AgentVerbRefusal> {
        if self.author == RunAuthor::Caller
            && let Some(reason) = caller_code_verb_refusal(verb)
        {
            return Err(caller_code_refused(reason));
        }
        let refused = |error: McpGatewayError| AgentVerbRefusal {
            hook_notice: None,
            code: error.kind.to_owned(),
            reason_codes: error.reason_codes,
        };
        if matches!(verb, AgentVerb::VaultRunsReadResult) {
            return mcp_admit_host_verb(&self.actor, verb)
                .and_then(|()| mcp_host_verb_gate(&self.server, &self.actor, verb))
                .map_err(refused);
        }
        // As `call_browser` admits the live row (FIX CODE-MODE-LENDING-W2).
        if verb.is_browser() {
            return mcp_admit_host_verb(&self.actor, verb)
                .and_then(|()| desktop_row_refusal(verb))
                .and_then(|()| mcp_browser_guest_gate(&self.server, &self.actor))
                .map_err(refused);
        }
        let surface = try_registered_surface(McpSurfaceMode::ToolFirst)
            .map_err(|error| refused(admission::mcp_surface_unavailable(error)))?;
        let name = verb.as_str();
        let Some(McpEndpointTool::Verb(tool)) = surface.resolve(name) else {
            if let Some(refusal) = oneiron::task_verb::sdk::wrong_root(name) {
                return Err(refused(mcp_facade_error(refusal)));
            }
            return Err(refused(McpGatewayError::new(
                -32601,
                "unknown_tool",
                format!("{name} is not a verb in the SDK verb table"),
            )));
        };
        admission::mcp_admit_bound_tool(&self.actor, tool.name).map_err(refused)
    }

    /// A room write a session-bound run stages (WILL L11-01, S01-2a) meets
    /// this connector's door as its session reads do, and lands under the
    /// credential's live ceiling (`session_write`).
    fn admit_session_write(
        &self,
        verb: AgentVerb,
    ) -> Result<oneiron::code_run::SessionWriteAdmission, AgentVerbRefusal> {
        self::session_write::admit(self, verb)
    }

    /// A result the run retained leaves this device again only while every
    /// row it was served from may leave now. Off this device, a result with
    /// no row set stays.
    fn withholds_retained(
        &self,
        rows: Option<&[oneiron::EntityId]>,
    ) -> Result<bool, AgentVerbRefusal> {
        let destination = self.actor.destination();
        if !destination.is_off_device() {
            return Ok(false);
        }
        let Some(rows) = rows else {
            return Ok(true);
        };
        crate::device_local::withholds_retained(&self.server.vault, destination, rows, &[]).map_err(
            |_| AgentVerbRefusal {
                hook_notice: None,
                code: "engine_error".to_owned(),
                reason_codes: Vec::new(),
            },
        )
    }

    /// A browser row's refusal words, as the run's guests kept them (FIX 6887).
    fn refusal_words(&self) -> Option<AgentVerbRefusalWords> {
        self.guests.refusal_words()
    }

    /// The run recorded the replay row for the answer just given (FIX
    /// 10633): what that answer holds is released now.
    fn answer_recorded(&self) {
        drop(
            self.answer_kept
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
    }
}

/// A run's desktop row is refused: no direct door serves the host's desktop
/// guest (FIX CODE-MODE-LENDING-W2).
fn desktop_row_refusal(verb: AgentVerb) -> Result<(), McpGatewayError> {
    if !verb.as_str().starts_with("self.desktop.") {
        return Ok(());
    }
    Err(McpGatewayError::new(
        -32020,
        MCP_DESKTOP_REFUSED,
        format!(
            "{} drives the host's desktop, which no direct call reaches, so a connector's run \
             does not either",
            verb.as_str()
        ),
    ))
}

/// A refused call as the run takes it: a verb hook's stop as the typed stop,
/// any other refusal as its stable code.
pub(super) fn refused<T>(error: McpGatewayError) -> oneiron::Result<Result<T, AgentVerbRefusal>> {
    match (error.hook, error.retry_after) {
        (Some(stop), _) => Err(oneiron::Error::from(*stop)),
        // A model call no provider answered goes back to the run as the
        // typed outage, which stops it until its caller enters it again
        // (FIX 3194).
        (None, Some(retry_after)) => Err(oneiron::Error::ProviderUnavailable { retry_after }),
        (None, None) => Ok(Err(AgentVerbRefusal {
            hook_notice: error.hook_notice.as_ref().map(|_| {
                serde_json::json!(oneiron::task_verb::revoke_lands::CALLER_NOTICE_SUMMARY)
            }),
            code: error.kind.to_owned(),
            reason_codes: error.reason_codes,
        })),
    }
}
