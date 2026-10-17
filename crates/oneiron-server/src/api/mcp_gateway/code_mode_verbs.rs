//! Code mode's verb calls at their SDK paths: the SDK verb table through the tool door.
//!
//! A code-mode verb call is the `tools/call` of that verb by the same
//! connector credential. Its input projects onto the tool's arguments for the
//! same argument rules, scoped admission and credential gate, then takes the
//! one generated dispatcher every MCP door shares. Code mode holds no
//! authority a direct tool call lacks; only the paging envelope is left out,
//! since the guest receives the verb's whole output. Its writes carry the
//! run's host-owned origin, not a source the guest's input names.
//!
//! A browser row (`self.browser.*`) is no tool. The run's own browser
//! answers it: one guest per run, started on the run's first admitted
//! browser call and removed when the run's door drops. The vault's
//! standing action grants set each browser effect class's press for the
//! run, and the built-in `oneiron.browser` pack must stand installed:
//! the browser is that connector pack's capability, never the engine's.
//!
//! Each call carries its step's invocation, so the row's verb hooks fire once
//! for it (ARCH-0080 §3): at the one dispatcher a verb row takes, or here for
//! a browser row. A hook's stop goes back to the run as the typed stop.
//!
//! The run's browser holds its screenshots (OF-523). An `ai.verdict` that
//! names one by its `blake3:` ref reads it from that browser, and a batch's
//! routine steps are the run's own `ai.verdict` calls through this door,
//! each with the step's screenshot handed in the same way.
//!
//! The vault's replay library (OF-598) rides the run's browser: the session
//! checks and replays a solved run's program, and the vault files it.
//!
//! A desktop row (`self.desktop.*`) takes the same door to the run's own
//! desktop guest, a Linux desktop the `[desktop]` section names, under the
//! same pack, grants and decider. Its screenshots answer an `ai.verdict`
//! as the browser's do.

use super::actor_dispatch::{mcp_execute_code_gate, mcp_tool_validation_error, mcp_verb_gate};
use super::admission::{mcp_admit_host_verb, mcp_admit_run_verb, mcp_admit_scoped_verb};
use super::tasks_response::{execute_agent_verb_input, mcp_agent_verb_arguments};
use super::{McpCallContext, McpGatewayError};
use crate::decision_verdict::{HELD_IMAGE, HELD_PREFIX, HeldImage};
use crate::mcp::{McpEndpointTool, McpSurfaceMode, registered_surface};
use crate::server::SyncServer;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, RunCall, SelfAgentVerbCall, SelfEffect,
};
use oneiron::consent::{BoundClass, BoundEnvelope, StandingConsentGrant};
use oneiron::memory::HostWriteOrigin;
use oneiron::runtime_hooks::InvocationId;
use oneiron::browser_library::{
    WorkflowRecord, file_workflow, record_workflow_run, site_workflows,
};
use oneiron::llm::decision::{DecisionRung, RoutineOutcome};
use oneiron::task_verb::sdk::{
    AgentVerb, AiVerdict, AiVerdictRequest, AiVerdictReversibility, RunVerb,
};
use oneiron_browser::{
    BrowserDriver, BrowserError, BrowserGuest, BrowserSession, DesktopGuest, DesktopSession,
    EFFECT_CLASSES, GuestLimits, LibraryCard, PressMode, RoutineAnswer, RoutineAsk,
    RoutineDecider, RoutineReply, SendPolicy, WorkflowLibrary, WorkflowProgram, WorkflowProof,
};
use oneiron_container::{EgressRelay, SessionManifest, SessionTransport};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

/// The verb door one `execute_code` run binds, under that call's connector.
pub(crate) struct McpCodeModeVerbs {
    server: Arc<SyncServer>,
    actor: McpCallContext,
    runtime: tokio::runtime::Handle,
    /// The rows this run's verb calls listed as served during this call
    /// (DEC-0005); each answer carries its own into the run's record too.
    served: std::sync::Mutex<Vec<oneiron::EntityId>>,
    /// This run's browser, when the host has a `[browser]` guest to give it.
    browser: Option<RunBrowser>,
    /// This run's desktop, when the host has a `[desktop]` guest to give it.
    desktop: Option<RunDesktop>,
}

/// One run's browser guest. It starts on the first call that needs it, is
/// never shared with another run, and goes when the run's door drops.
struct RunBrowser {
    guest: BrowserGuest,
    session: Mutex<Option<BrowserSession>>,
    vault: Arc<oneiron::Vault>,
    run_id: oneiron::EntityId,
}

/// One run's desktop guest, held as the run's browser is.
struct RunDesktop {
    guest: DesktopGuest,
    session: Mutex<Option<DesktopSession>>,
    vault: Arc<oneiron::Vault>,
    run_id: oneiron::EntityId,
}

/// A run's guest session as the door drives it: its verbs, whether its
/// sandbox was abandoned, and what its container proved.
trait RunGuestSession: BrowserDriver {
    fn abandoned(&self) -> bool;
    fn manifest(&self) -> &SessionManifest;
}

impl RunGuestSession for BrowserSession {
    fn abandoned(&self) -> bool {
        Self::abandoned(self)
    }

    fn manifest(&self) -> &SessionManifest {
        Self::manifest(self)
    }
}

impl RunGuestSession for DesktopSession {
    fn abandoned(&self) -> bool {
        Self::abandoned(self)
    }

    fn manifest(&self) -> &SessionManifest {
        Self::manifest(self)
    }
}

/// Starts one run's guest from a pinned image through the engine's tier
/// selector, behind the run's egress proxy, and receipts its manifest.
fn start_run_guest(
    vault: &Arc<oneiron::Vault>,
    run_id: oneiron::EntityId,
    runtime: &Path,
    image: &str,
    limits: GuestLimits,
    fixture: Option<&PathBuf>,
    entry: &str,
) -> Result<(SessionTransport, Arc<dyn EgressRelay>), BrowserError> {
    use oneiron::code_sandbox::{SandboxGuestTier, microvm::select_backend_for_session};
    use oneiron_container::{GuestSeccomp, GuestSpec, ImageRef};
    let unavailable = |e: String| BrowserError::Unavailable(e);
    let backend =
        select_backend_for_session(SandboxGuestTier::Untrusted, runtime.to_path_buf(), image)
            .map_err(|e| unavailable(e.to_string()))?;
    let spec = GuestSpec {
        image: ImageRef::pinned(image).map_err(|e| unavailable(e.to_string()))?,
        user: (10001, 10001),
        limits,
        seccomp: GuestSeccomp::EngineFence,
        read_only_mounts: fixture
            .iter()
            .map(|p| ((*p).clone(), PathBuf::from("/srv/fixture")))
            .collect(),
    };
    let relay: Arc<dyn EgressRelay> = Arc::new(
        oneiron::code_sandbox::egress::OpenEgressProxy::new(
            Arc::clone(vault),
            run_id,
            oneiron::code_sandbox::egress::EgressConfig::from_env()
                .map_err(|e| unavailable(e.to_string()))?,
        )
        .with_fixture(fixture.cloned()),
    );
    let transport = backend
        .start_session(&spec, &[entry.into()], Arc::clone(&relay))
        .map_err(|e| unavailable(e.to_string()))?;
    vault
        .append_sandbox_manifest_receipt(run_id, &transport.manifest)
        .map_err(|e| unavailable(e.to_string()))?;
    Ok((transport, relay))
}

/// One verb call on a run's guest session: an abandoned sandbox lands its
/// receipt and refuses, and an answer carries the session's manifest.
fn drive_run_guest<S: RunGuestSession>(
    vault: &oneiron::Vault,
    run_id: oneiron::EntityId,
    driver: &mut S,
    verb: AgentVerb,
    input: Value,
) -> Result<Value, BrowserError> {
    let result = oneiron::task_verb::sdk::invoke_browser(driver, verb.as_str(), input);
    if driver.abandoned() {
        vault
            .append_sandbox_abandon_receipt(run_id, driver.manifest())
            .map_err(|e| BrowserError::Unavailable(e.to_string()))?;
        return Err(BrowserError::Abandoned);
    }
    let mut output = result?;
    if let Some(output) = output.as_object_mut() {
        output.insert(
            "session_manifest".into(),
            serde_json::to_value(driver.manifest())
                .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
        );
    }
    Ok(output)
}

/// The press policy the vault's standing action grants set for one run's
/// browser: a grant naming a browser effect class covers it (no press),
/// and a budgeted grant covers that many sends as one reviewed batch.
/// No grant leaves the floor: a press per send.
fn browser_send_policy(server: &SyncServer) -> SendPolicy {
    let mut policy = SendPolicy::default();
    let Ok(grants) = server.vault.active_standing_consent_grants() else {
        return policy;
    };
    for grant in &grants {
        let StandingConsentGrant::Action(_) = grant else {
            continue;
        };
        let bound = grant.bound();
        let BoundClass::Action(class) = bound.class() else {
            continue;
        };
        let class = class.as_str();
        if !EFFECT_CLASSES.contains(&class) || SendPolicy::person_only(class) {
            continue;
        }
        let budget = match bound.envelope() {
            BoundEnvelope::Action(envelope) => envelope.budget(),
            BoundEnvelope::Disclosure(_) => None,
        };
        match budget {
            Some(count) => {
                policy.modes.insert(class.to_owned(), PressMode::PerBatch);
                policy
                    .batch
                    .insert(class.to_owned(), u32::try_from(count).unwrap_or(u32::MAX));
            }
            None => {
                policy.modes.insert(class.to_owned(), PressMode::None);
            }
        }
    }
    policy
}

/// A batch's routine steps through the host's ladder: each step is the
/// run's own `ai.verdict` call through this door (its admission, verb gate
/// and hooks), under the batch call's origin, with the step's screenshot
/// handed in from the run's browser as an evidence ref on the run.
#[derive(Clone)]
struct LadderDecider {
    server: Arc<SyncServer>,
    actor: McpCallContext,
    runtime: tokio::runtime::Handle,
    origin: HostWriteOrigin,
    run_id: oneiron::EntityId,
}

impl RoutineDecider for LadderDecider {
    fn decide(&mut self, ask: RoutineAsk<'_>) -> Result<RoutineReply, BrowserError> {
        let locate = ask.options.is_empty();
        let request = AiVerdictRequest {
            question: ask.question.to_owned(),
            options: ask.options,
            evidence: Vec::new(),
            state: Some(ask.state),
            // No model: the ladder stops at its rule rung.
            ceiling: ask.no_model.then_some(DecisionRung::Rule),
            // A step acts on a live page: at a cut it abstains and goes up.
            reversibility: AiVerdictReversibility::OutboundEffect,
            deadline_ms: None,
            routine: true,
            image: ask.image.map(|(image, _)| image.to_owned()),
            locate,
            misses: ask.misses,
            until_ms: ask.until_ms,
        };
        let input =
            serde_json::to_value(&request).map_err(|e| BrowserError::Decider(e.to_string()))?;
        let held = ask
            .image
            .map(|(image, png)| HeldImage::new(self.run_id, image, png.to_vec()));
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let actor = self.actor.clone();
        let origin = self.origin.clone();
        self.runtime.spawn(HELD_IMAGE.scope(held, async move {
            let _ = sender.send(
                execute_code_mode_verb(&server, &actor, "ai.verdict", input, origin).await,
            );
        }));
        let (output, _) = receiver
            .recv()
            .map_err(|_| BrowserError::Decider("the ladder did not answer".to_owned()))?
            .map_err(|error| BrowserError::Decider(format!("{}: {}", error.kind, error.message)))?;
        let verdict: AiVerdict = serde_json::from_value(output.clone())
            .map_err(|e| BrowserError::Decider(e.to_string()))?;
        let answer = match verdict.outcome {
            Some(RoutineOutcome::Act { candidate }) => RoutineAnswer::Act { candidate },
            Some(RoutineOutcome::Point { x, y, .. }) => RoutineAnswer::Point { x, y },
            Some(RoutineOutcome::None) => RoutineAnswer::None,
            Some(RoutineOutcome::Reobserve) => RoutineAnswer::Reobserve,
            Some(RoutineOutcome::AskUp { reason }) => RoutineAnswer::AskUp {
                reason: reason
                    .and_then(|reason| serde_json::to_value(reason).ok())
                    .and_then(|reason| reason.as_str().map(str::to_owned)),
            },
            None => {
                return Err(BrowserError::Decider(
                    "the ladder answered no routine outcome".to_owned(),
                ));
            }
        };
        Ok(RoutineReply {
            answer,
            screenshot: verdict.screenshot,
            until_ms: verdict.until_ms,
            decision: output,
        })
    }
}

/// The vault's replay library, as the run's browser files and reads it:
/// what it files names the run's caller.
struct VaultLibrary {
    vault: Arc<oneiron::Vault>,
    by: oneiron::EntityId,
}

fn library_failed(error: oneiron::Error) -> BrowserError {
    BrowserError::Library(error.to_string())
}

impl WorkflowLibrary for VaultLibrary {
    fn find(
        &mut self,
        site: &str,
        subgoal: Option<&str>,
    ) -> Result<Vec<LibraryCard>, BrowserError> {
        Ok(site_workflows(&self.vault, site, subgoal)
            .map_err(library_failed)?
            .iter()
            .map(WorkflowRecord::card)
            .collect())
    }

    fn program(&mut self, workflow: &str) -> Result<Option<WorkflowProgram>, BrowserError> {
        let Ok(id) = oneiron::EntityId::from_hex(workflow) else {
            return Ok(None);
        };
        Ok(oneiron::browser_library::workflow(&self.vault, id)
            .map_err(library_failed)?
            .map(|record| record.program))
    }

    fn admit(
        &mut self,
        site: &str,
        program: &WorkflowProgram,
        proof: &WorkflowProof,
    ) -> Result<String, BrowserError> {
        file_workflow(
            &self.vault,
            self.by,
            site,
            program,
            proof,
            self.vault.now_recorded_at(),
        )
        .map(|id| id.to_hex())
        .map_err(library_failed)
    }

    fn record_run(&mut self, workflow: &str, met: bool) -> Result<(), BrowserError> {
        let Ok(id) = oneiron::EntityId::from_hex(workflow) else {
            return Ok(());
        };
        record_workflow_run(&self.vault, id, met, self.vault.now_recorded_at())
            .map_err(library_failed)
    }
}

impl RunBrowser {
    fn call(
        &self,
        verb: AgentVerb,
        input: Value,
        decider: LadderDecider,
        library: VaultLibrary,
    ) -> Result<Value, BrowserError> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        if session.is_none() {
            let (transport, relay) = start_run_guest(
                &self.vault,
                self.run_id,
                &self.guest.runtime,
                &self.guest.image,
                self.guest.limits,
                self.guest.fixture.as_ref(),
                "/usr/local/bin/oneiron-browser-guest",
            )?;
            let started = BrowserSession::attach(&self.guest, transport, relay)?;
            *session = Some(started);
        }
        let driver = session.as_mut().ok_or(BrowserError::GuestLost)?;
        driver.set_decider(Box::new(decider));
        driver.set_library(Box::new(library));
        drive_run_guest(&self.vault, self.run_id, driver, verb, input)
    }
}

impl RunDesktop {
    fn call(
        &self,
        verb: AgentVerb,
        input: Value,
        decider: LadderDecider,
    ) -> Result<Value, BrowserError> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        if session.is_none() {
            // The desktop's own apps reach the network through the same
            // engine proxy, at the guest's fenced sockets.
            let (transport, _relay) = start_run_guest(
                &self.vault,
                self.run_id,
                &self.guest.runtime,
                &self.guest.image,
                self.guest.limits,
                None,
                "/usr/local/bin/oneiron-desktop-guest",
            )?;
            *session = Some(DesktopSession::attach(&self.guest, transport)?);
        }
        let driver = session.as_mut().ok_or(BrowserError::GuestLost)?;
        driver.set_decider(Box::new(decider));
        drive_run_guest(&self.vault, self.run_id, driver, verb, input)
    }
}

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
            browser: server.browser_guest().map(|guest| {
                let mut guest = guest.clone();
                guest.policy = browser_send_policy(server);
                RunBrowser {
                    guest,
                    session: Mutex::new(None),
                    vault: Arc::clone(&server.vault),
                    run_id,
                }
            }),
            desktop: server.desktop_guest().map(|guest| {
                let mut guest = guest.clone();
                guest.policy = browser_send_policy(server);
                RunDesktop {
                    guest,
                    session: Mutex::new(None),
                    vault: Arc::clone(&server.vault),
                    run_id,
                }
            }),
        }
    }

    /// A browser row: this connector's binding and live credential at each
    /// call, the row's verb hooks around the run's browser. Its answer
    /// derives from no vault row.
    fn call_browser(
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
        // The browser runs as its connector pack: no installed pack, no browser.
        if self.server.vault.require_builtin_channel_pack("browser").is_err() {
            return Ok(Err(AgentVerbRefusal {
                code: "browser_pack_not_installed".to_owned(),
            }));
        }
        let browser_refused = |error: BrowserError| {
            tracing::debug!(verb = call.verb.as_str(), %error, "code run browser call refused");
            AgentVerbRefusal {
                code: error.code().to_owned(),
            }
        };
        // A desktop row drives the run's desktop; every other row its browser.
        let desktop = call.verb.as_str().starts_with("self.desktop.");
        let run_id = if desktop {
            self.desktop.as_ref().map(|desktop| desktop.run_id)
        } else {
            self.browser.as_ref().map(|browser| browser.run_id)
        };
        let Some(run_id) = run_id else {
            return Ok(Err(browser_refused(BrowserError::Unbound)));
        };
        let memory = crate::api::credential_memory(
            &self.server.vault,
            self.actor.auth.as_ref(),
            self.actor.actor_ref,
            self.actor.actor_class,
        )
        .with_invocation(invocation);
        let verb = call.verb.as_str();
        let hooks = match oneiron::task_verb::verb_hook_boundary::row_pre(
            &memory,
            verb,
            call.input.clone(),
        ) {
            Ok(hooks) => hooks,
            Err(error) => return refused(super::mcp_facade_error(error)),
        };
        // Each routine decision is a verb call of its own, under a fresh
        // invocation.
        let decider = LadderDecider {
            server: Arc::clone(&self.server),
            actor: McpCallContext {
                invocation: None,
                ..self.actor.clone()
            },
            runtime: self.runtime.clone(),
            origin: origin.clone(),
            run_id,
        };
        let called = match (&self.desktop, &self.browser) {
            (Some(run), _) if desktop => run.call(call.verb, hooks.args.clone(), decider),
            (_, Some(run)) if !desktop => {
                let library = VaultLibrary {
                    vault: Arc::clone(&self.server.vault),
                    by: self.actor.actor_ref,
                };
                run.call(call.verb, hooks.args.clone(), decider, library)
            }
            _ => Err(BrowserError::Unbound),
        };
        let output = match called {
            Ok(output) => output,
            Err(error) => return Ok(Err(browser_refused(error))),
        };
        // An effect's answer carries its receipt, naming the page it acted on.
        if let Some(receipt) = output.get("receipt") {
            tracing::info!(verb, ?receipt, "browser effect receipt");
        }
        if let Some(receipts) = output.get("receipts") {
            tracing::info!(verb, ?receipts, "browser batch receipts");
        }
        match oneiron::task_verb::verb_hook_boundary::row_post(&self.server.vault, hooks, output) {
            Ok(output) => Ok(Ok(AgentVerbAnswer {
                output,
                rows: Some(Vec::new()),
            })),
            Err(error) => refused(super::mcp_facade_error(error)),
        }
    }

    /// The screenshot this run's browser or desktop holds under the
    /// `blake3:` ref an `ai.verdict` input names, when one holds it.
    fn held_image(&self, input: &Value) -> Option<HeldImage> {
        let handle = input
            .get("image")
            .and_then(Value::as_str)
            .filter(|handle| handle.starts_with(HELD_PREFIX))?;
        if let Some(browser) = self.browser.as_ref() {
            let session = browser
                .session
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(png) = session.as_ref().and_then(|s| s.image(handle)) {
                return Some(HeldImage::new(browser.run_id, handle, png.to_vec()));
            }
        }
        let desktop = self.desktop.as_ref()?;
        let session = desktop
            .session
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let png = session.as_ref()?.image(handle)?.to_vec();
        Some(HeldImage::new(desktop.run_id, handle, png))
    }

    pub(crate) fn manifests(&self) -> Vec<Value> {
        let browser = self
            .browser
            .as_ref()
            .and_then(|b| b.session.lock().ok())
            .and_then(|session| {
                session
                    .as_ref()
                    .and_then(|s| serde_json::to_value(s.manifest()).ok())
            });
        let desktop = self
            .desktop
            .as_ref()
            .and_then(|d| d.session.lock().ok())
            .and_then(|session| {
                session
                    .as_ref()
                    .and_then(|s| serde_json::to_value(s.manifest()).ok())
            });
        browser.into_iter().chain(desktop).collect()
    }

    /// The rows this run's verb calls listed as served.
    pub(crate) fn served(&self) -> Vec<oneiron::EntityId> {
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
            .then(|| self.held_image(&call.input))
            .flatten();
        // The run's worker thread drives its own reactor; the verb runs on the
        // server runtime, as a tool call would, and the worker waits for it.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let actor = McpCallContext {
            invocation: Some(invocation),
            ..self.actor.clone()
        };
        let verb = call.verb.as_str();
        let input = call.input.clone();
        let origin = origin.clone();
        self.runtime.spawn(HELD_IMAGE.scope(held, async move {
            let _ = sender.send(execute_code_mode_verb(&server, &actor, verb, input, origin).await);
        }));
        let Ok(executed) = receiver.recv() else {
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
            .extend(listed.iter().copied());
        Ok(Ok(AgentVerbAnswer {
            output,
            rows: Some(listed),
        }))
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
        // A search reads on the credential's lane, and a facet stamp places
        // only a row that lane reads.
        if !matches!(
            call,
            RunCall::Bridge(SelfEffect::MemorySearch | SelfEffect::MemoryPutEdge)
        ) {
            return Ok(None);
        }
        let unauthenticated = || AgentVerbRefusal {
            code: "mcp_auth_required".to_owned(),
        };
        let proof = self
            .actor
            .auth
            .as_ref()
            .and_then(crate::auth::CoreAuth::verified_slip)
            .ok_or_else(unauthenticated)?;
        // The one builder every door's credential key comes from.
        self.server
            .vault
            .credential_read_key(proof)
            .map_err(|_| AgentVerbRefusal {
                code: "engine_error".to_owned(),
            })?
            .map(|reader| Some(reader.at(self.actor.locality())))
            .ok_or_else(unauthenticated)
    }

    /// A result the run retained leaves this device again only while every
    /// row it was served from may leave now. Off this device, a result with
    /// no row set stays.
    fn withholds_retained(
        &self,
        rows: Option<&[oneiron::EntityId]>,
    ) -> Result<bool, AgentVerbRefusal> {
        let locality = self.actor.locality();
        if locality == oneiron::claim::CallerLocality::OnDevice {
            return Ok(false);
        }
        let Some(rows) = rows else {
            return Ok(true);
        };
        crate::device_local::withholds_retained(&self.server.vault, locality, rows, &[]).map_err(
            |_| AgentVerbRefusal {
                code: "engine_error".to_owned(),
            },
        )
    }
}

/// A refused call as the run takes it: a verb hook's stop as the typed stop,
/// any other refusal as its stable code.
fn refused<T>(error: McpGatewayError) -> oneiron::Result<Result<T, AgentVerbRefusal>> {
    match error.hook {
        Some(stop) => Err(oneiron::Error::from(*stop)),
        None => Ok(Err(AgentVerbRefusal {
            code: error.kind.to_owned(),
        })),
    }
}

async fn execute_code_mode_verb(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    verb: &str,
    input: Value,
    origin: HostWriteOrigin,
) -> Result<(Value, Vec<oneiron::EntityId>), McpGatewayError> {
    let Some(McpEndpointTool::Verb(tool)) =
        registered_surface(McpSurfaceMode::ToolFirst).resolve(verb)
    else {
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
    mcp_admit_scoped_verb(server, tool, &arguments, actor)?;
    mcp_verb_gate(server, tool, &arguments, actor)?;
    // A run's call is answered once and never continued.
    let mut served = Vec::new();
    let (output, ..) =
        execute_agent_verb_input(server, tool.name, input, actor, Some(origin), &mut served)
            .await?;
    Ok((output, served))
}
