//! How a code-mode run's agent verbs reach their doors: admitted, executed and answered.
//! `McpCodeModeVerbs` (its `AgentVerbDoor` impl) and `run_code_mode_verb` are its call surface.
//! The code_mode_verbs root defines `McpCodeModeVerbs`; `oneiron::code_run` owns the verb records.

use super::*;

impl McpCodeModeVerbs {
    /// Binds the door to the server runtime the `execute_code` call arrived on.
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
            run_id,
            guests: RunGuests::new(server, run_id),
        }
    }

    /// A browser row: this connector's binding and live credential at each
    /// call, then the run's guest.
    pub(super) fn call_browser(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if let Err(error) = mcp_admit_host_verb(&self.actor, call.verb)
            .and_then(|()| mcp_execute_code_gate(&self.server, &self.actor))
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

    /// The lane of the credential `execute_code` was admitted on, from where
    /// its caller sits: what a run's search and a session read read under.
    pub(super) fn credential_lane(&self) -> Result<ScopedReadActorKey, AgentVerbRefusal> {
        let unauthenticated = || AgentVerbRefusal {
            code: "mcp_auth_required".to_owned(),
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
                    code: match error.code() {
                        crate::error::ErrorCode::Forbidden
                        | crate::error::ErrorCode::HostActionRequiresSupportGrant
                        | crate::error::ErrorCode::OwnerBindingRequired => "forbidden",
                        _ => "engine_error",
                    }
                    .to_owned(),
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
                code: match error.kind() {
                    oneiron::ErrorKind::HostActionRequiresSupportGrant => {
                        super::tasks_response::MCP_HOST_ACTION_REFUSED
                    }
                    oneiron::ErrorKind::ScopedReadOwnerNotLive => "forbidden",
                    _ => "engine_error",
                }
                .to_owned(),
            })?
            .map(|reader| reader.at(self.actor.locality()))
            .ok_or_else(unauthenticated)
    }
}

impl AgentVerbDoor for McpCodeModeVerbs {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
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
        };
        let verb = call.verb.as_str();
        let input = call.input.clone();
        let run = McpCodeRun {
            origin: origin.clone(),
            run_id: self.run_id,
        };
        // What the answer holds (a deck preview's renderer) comes back with
        // it, kept until the answer is handed to the run (FIX 8238).
        self.runtime.spawn(HELD_IMAGE.scope(held, async move {
            let executed = crate::api::answer_hold::keeping(execute_code_mode_verb(
                &server, &actor, verb, input, run,
            ))
            .await;
            let _ = sender.send(executed);
        }));
        let Ok((executed, kept)) = receiver.recv() else {
            return Ok(Err(AgentVerbRefusal {
                code: "engine_error".to_owned(),
            }));
        };
        let (output, listed) = match executed {
            Ok(executed) => executed,
            Err(error) => return refused(error),
        };
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(listed.iter().flatten().copied());
        let answer = AgentVerbAnswer {
            output,
            rows: listed,
        };
        drop(kept);
        Ok(Ok(answer))
    }

    /// The run's answer to the questions one of its connector calls waits on
    /// (FIX 3838): the host door an MCP `connector.answer` meets, for this
    /// connector's caller on the credential `execute_code` was admitted on.
    /// The run's admission and verb hooks already ran around it. The reply
    /// is foreign data and serves no vault rows.
    fn connector_answer(
        &self,
        request: &oneiron::task_verb::sdk::ConnectorAnswerRequest,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        let Some(auth) = self.actor.auth.clone() else {
            return Ok(Err(AgentVerbRefusal {
                code: "mcp_auth_required".to_owned(),
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
        let refusal = |code: &str| AgentVerbRefusal {
            code: code.to_owned(),
        };
        Ok(match receiver.recv() {
            Ok(Ok(reply)) => match serde_json::to_value(reply) {
                Ok(output) => Ok(AgentVerbAnswer {
                    output,
                    rows: Some(Vec::new()),
                }),
                Err(_) => Err(refusal("engine_error")),
            },
            Ok(Err(error)) => Err(refusal(&error.code)),
            Err(_) => Err(refusal("engine_error")),
        })
    }

    /// A call the run serves itself meets this connector's door at each call
    /// too: a run row needs its own binding, and every call needs the
    /// credential `execute_code` was admitted on, still live. A search reads
    /// under that credential's grants, as `vault.recall` does, from where its
    /// caller sits (DEC-0005).
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        let refused = |error: McpGatewayError| AgentVerbRefusal {
            code: error.kind.to_owned(),
        };
        if let RunCall::Bridge(effect) = call
            && let Some(verb) = RunVerb::ALL.iter().find(|verb| verb.effect() == effect)
        {
            mcp_admit_run_verb(&self.actor, *verb).map_err(refused)?;
        }
        mcp_execute_code_gate(&self.server, &self.actor).map_err(refused)?;
        // A search reads on the credential's lane, a facet stamp places only
        // a row that lane reads, a consult lands only refs it reads, and a
        // TASK binding reads its TASK and workflow there (FIX 5316).
        // The run repo rows read on that lane too (FIX 6867).
        if !matches!(
            call,
            RunCall::Bridge(
                SelfEffect::MemorySearch
                    | SelfEffect::MemoryPutEdge
                    | SelfEffect::ConsultResult
                    | SelfEffect::WorkflowDispatch
            )
        ) && !matches!(call, RunCall::Bridge(effect) if effect.is_repo())
        {
            return Ok(None);
        }
        self.credential_lane().map(Some)
    }

    /// A read a session-bound run serves through the room (WILL L11-01)
    /// meets this connector's door as its run calls do: the verb's own
    /// binding, the credential `execute_code` was admitted on, still live,
    /// and that credential's lane, from where its caller sits.
    fn admit_session_read(&self, verb: AgentVerb) -> Result<ScopedReadActorKey, AgentVerbRefusal> {
        mcp_admit_host_verb(&self.actor, verb)
            .and_then(|()| mcp_execute_code_gate(&self.server, &self.actor))
            .map_err(|error| AgentVerbRefusal {
                code: error.kind.to_owned(),
            })?;
        self.credential_lane()
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
                code: "engine_error".to_owned(),
            },
        )
    }

    /// A browser row's refusal words, as the run's guests kept them (FIX 6887).
    fn refusal_words(&self) -> Option<AgentVerbRefusalWords> {
        self.guests.refusal_words()
    }
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
            code: error.kind.to_owned(),
        })),
    }
}

pub(super) async fn execute_code_mode_verb(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    verb: &str,
    input: Value,
    run: McpCodeRun,
) -> Result<(Value, Option<Vec<oneiron::EntityId>>), McpGatewayError> {
    run_code_mode_verb(server, actor, verb, input, run, mcp_admit_scoped_verb).await
}

/// A browser batch's routine decision: the connector's `ai.verdict`, admitted
/// by its scope only, since the batch it is bound for carries it. Its
/// credential gate and hooks run as on any verb call.
pub(super) async fn execute_step_verdict(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    input: Value,
    run: McpCodeRun,
) -> Result<(Value, Vec<oneiron::EntityId>), McpGatewayError> {
    // Only the verdict is read; its rows are not.
    run_code_mode_verb(server, actor, "ai.verdict", input, run, mcp_admit_step_verb)
        .await
        .map(|(output, rows)| (output, rows.unwrap_or_default()))
}

/// How one verb call's tool binding and scope are admitted.
pub(super) type VerbAdmission = fn(
    &Arc<SyncServer>,
    crate::mcp::McpGeneratedVerbTool,
    &crate::mcp::McpVerbArguments,
    &McpCallContext,
) -> Result<(), McpGatewayError>;

pub(super) async fn run_code_mode_verb(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    verb: &str,
    input: Value,
    run: McpCodeRun,
    admit: VerbAdmission,
) -> Result<(Value, Option<Vec<oneiron::EntityId>>), McpGatewayError> {
    let surface = try_registered_surface(McpSurfaceMode::ToolFirst)
        .map_err(super::admission::mcp_surface_unavailable)?;
    let Some(McpEndpointTool::Verb(tool)) = surface.resolve(verb) else {
        if let Some(refusal) = oneiron::task_verb::sdk::wrong_root(verb) {
            return Err(super::mcp_facade_error(refusal));
        }
        return Err(McpGatewayError::new(
            -32601,
            "unknown_tool",
            format!("{verb} is not a verb in the SDK verb table"),
        ));
    };
    let arguments = mcp_agent_verb_arguments(tool.name, &input)?;
    arguments
        .validate(tool.name, tool)
        .map_err(mcp_tool_validation_error)?;
    admit(server, tool, &arguments, actor)?;
    mcp_verb_gate(server, tool, &arguments, actor)?;
    // A run's call is answered once and never continued; it tracks whether
    // a producer's path listed none (FIX 5988).
    let mut served = super::McpServed::default();
    let mut board_hooks = None;
    let origin = run.origin.clone();
    // A media call spends on the run's own line, as its steps do (FIX 780).
    let line = media_line(server, tool.name, run.run_id);
    let (output, ..) = crate::api::facade::host_doors::with_calling_origin(
        origin,
        crate::api::facade::host_doors::with_calling_line(
            line,
            execute_agent_verb_input(
                server,
                tool.name,
                input,
                actor,
                Some(run),
                &mut served,
                &mut board_hooks,
            ),
        ),
    )
    .await?;
    // A board read answers the run here: the receipt its hook rows owe is
    // recorded and their blocks spent as the answer returns (OF-579).
    if let Some(mut hooks) = board_hooks {
        hooks.record_receipt(server).await?;
        hooks.spend(server);
    }
    // An act whose rows are unknown answers off this device only that it
    // ran (FIX 5988); a read releases as before.
    super::served_rows::unknown_act_answer(tool.name, actor, output, served)
}

/// The `ai.*` media verbs a code-mode run's line pays for (FIX 780).
const LINE_VERBS: [&str; 8] = [
    "ai.options",
    "ai.image",
    "ai.speech",
    "ai.transcribe",
    "ai.embed",
    "ai.video",
    "ai.video.poll",
    "ai.video.cancel",
];

/// The line a code-mode run's `ai.*` media call spends on (FIX 780): code
/// mode's own meter, the one the run's steps spend on, under the run's own
/// name. `None` for any other verb, or where code mode lends no meter: that
/// call takes the owner's door, as a direct tool call does.
fn media_line(
    server: &SyncServer,
    verb: &str,
    run_id: oneiron::EntityId,
) -> Option<oneiron::llm::run_admission::RunAdmission> {
    if !LINE_VERBS.contains(&verb) {
        return None;
    }
    let meter = server
        .code_execution_host()?
        .engine_native()?
        .provider()
        .host_meter()?;
    let run = format!("code-mode:{}", run_id.to_hex());
    Some(server.ai.model_runtime().funded_run(run, meter, None))
}
