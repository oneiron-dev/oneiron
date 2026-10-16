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

use super::actor_dispatch::{mcp_execute_code_gate, mcp_tool_validation_error, mcp_verb_gate};
use super::admission::{mcp_admit_host_verb, mcp_admit_run_verb, mcp_admit_scoped_verb};
use super::tasks_response::{execute_agent_verb_input, mcp_agent_verb_arguments};
use super::{McpCallContext, McpGatewayError};
use crate::mcp::{McpEndpointTool, McpSurfaceMode, registered_surface};
use crate::server::SyncServer;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, RunCall, SelfAgentVerbCall, SelfEffect,
};
use oneiron::consent::{BoundClass, BoundEnvelope, StandingConsentGrant};
use oneiron::memory::HostWriteOrigin;
use oneiron::task_verb::sdk::{AgentVerb, RunVerb};
use oneiron_browser::{
    BrowserError, BrowserGuest, BrowserSession, EFFECT_CLASSES, PressMode, SendPolicy,
};
use serde_json::Value;
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
}

/// One run's browser guest. It starts on the first call that needs it, is
/// never shared with another run, and goes when the run's door drops.
struct RunBrowser {
    guest: BrowserGuest,
    session: Mutex<Option<BrowserSession>>,
    vault: Arc<oneiron::Vault>,
    run_id: oneiron::EntityId,
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

impl RunBrowser {
    fn call(&self, verb: AgentVerb, input: Value) -> Result<Value, BrowserError> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        if session.is_none() {
            use oneiron::code_sandbox::{SandboxGuestTier, microvm::select_backend_for_session};
            use oneiron_container::{GuestSeccomp, GuestSpec, ImageRef};
            let unavailable = |e: String| BrowserError::Unavailable(e);
            let backend = select_backend_for_session(
                SandboxGuestTier::Untrusted,
                self.guest.runtime.clone(),
                &self.guest.image,
            )
            .map_err(|e| unavailable(e.to_string()))?;
            let spec = GuestSpec {
                image: ImageRef::pinned(&self.guest.image)
                    .map_err(|e| unavailable(e.to_string()))?,
                user: (10001, 10001),
                limits: self.guest.limits,
                seccomp: GuestSeccomp::EngineFence,
                read_only_mounts: self
                    .guest
                    .fixture
                    .iter()
                    .map(|p| (p.clone(), std::path::PathBuf::from("/srv/fixture")))
                    .collect(),
            };
            let relay: Arc<dyn oneiron_container::EgressRelay> = Arc::new(
                oneiron::code_sandbox::egress::OpenEgressProxy::new(
                    Arc::clone(&self.vault),
                    self.run_id,
                    oneiron::code_sandbox::egress::EgressConfig::from_env()
                        .map_err(|e| unavailable(e.to_string()))?,
                )
                .with_fixture(self.guest.fixture.clone()),
            );
            let transport = backend
                .start_session(
                    &spec,
                    &["/usr/local/bin/oneiron-browser-guest".into()],
                    Arc::clone(&relay),
                )
                .map_err(|e| unavailable(e.to_string()))?;
            self.vault
                .append_sandbox_manifest_receipt(self.run_id, &transport.manifest)
                .map_err(|e| unavailable(e.to_string()))?;
            let started = BrowserSession::attach(&self.guest, transport, relay)?;
            *session = Some(started);
        }
        let driver = session.as_mut().ok_or(BrowserError::GuestLost)?;
        let result = oneiron::task_verb::sdk::invoke_browser(driver, verb.as_str(), input);
        if driver.abandoned() {
            self.vault
                .append_sandbox_abandon_receipt(self.run_id, driver.manifest())
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
        }
    }

    /// A browser row: this connector's binding and live credential at each
    /// call, then the run's browser. Its answer derives from no vault row.
    fn call_browser(&self, call: &SelfAgentVerbCall) -> Result<AgentVerbAnswer, AgentVerbRefusal> {
        let refused = |error: McpGatewayError| AgentVerbRefusal {
            code: error.kind.to_owned(),
        };
        mcp_admit_host_verb(&self.actor, call.verb).map_err(refused)?;
        mcp_execute_code_gate(&self.server, &self.actor).map_err(refused)?;
        // The browser runs as its connector pack: no installed pack, no browser.
        self.server
            .vault
            .require_builtin_channel_pack("browser")
            .map_err(|_| AgentVerbRefusal {
                code: "browser_pack_not_installed".to_owned(),
            })?;
        let browser_refused = |error: BrowserError| {
            tracing::debug!(verb = call.verb.as_str(), %error, "code run browser call refused");
            AgentVerbRefusal {
                code: error.code().to_owned(),
            }
        };
        let browser = self
            .browser
            .as_ref()
            .ok_or_else(|| browser_refused(BrowserError::Unbound))?;
        let output = browser
            .call(call.verb, call.input.clone())
            .map_err(browser_refused)?;
        // An effect's answer carries its receipt, naming the page it acted on.
        if let Some(receipt) = output.get("receipt") {
            tracing::info!(
                verb = call.verb.as_str(),
                ?receipt,
                "browser effect receipt"
            );
        }
        if let Some(receipts) = output.get("receipts") {
            tracing::info!(
                verb = call.verb.as_str(),
                ?receipts,
                "browser batch receipts"
            );
        }
        Ok(AgentVerbAnswer {
            output,
            rows: Some(Vec::new()),
        })
    }

    pub(crate) fn manifests(&self) -> Vec<Value> {
        self.browser
            .as_ref()
            .and_then(|b| b.session.lock().ok())
            .and_then(|session| {
                session
                    .as_ref()
                    .and_then(|s| serde_json::to_value(s.manifest()).ok())
            })
            .into_iter()
            .collect()
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
    ) -> Result<AgentVerbAnswer, AgentVerbRefusal> {
        if call.verb.is_browser() {
            // The run's worker thread holds the call while the guest acts.
            return self.call_browser(call);
        }
        // The run's worker thread drives its own reactor; the verb runs on the
        // server runtime, as a tool call would, and the worker waits for it.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let actor = self.actor.clone();
        let verb = call.verb.as_str();
        let input = call.input.clone();
        let origin = origin.clone();
        self.runtime.spawn(async move {
            let _ = sender.send(execute_code_mode_verb(&server, &actor, verb, input, origin).await);
        });
        let (output, listed) = receiver
            .recv()
            .map_err(|_| AgentVerbRefusal {
                code: "engine_error".to_owned(),
            })?
            .map_err(|error| AgentVerbRefusal {
                code: error.kind.to_owned(),
            })?;
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(listed.iter().copied());
        Ok(AgentVerbAnswer {
            output,
            rows: Some(listed),
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
