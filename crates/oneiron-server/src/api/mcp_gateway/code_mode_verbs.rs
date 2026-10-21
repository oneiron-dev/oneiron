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
//! browser call and kept in the run's seat across its doors, until the run
//! ends or the seat sits idle (server/desktop_seats.rs). The vault's
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
//! checks a solved run's program, replays it on a fresh guest the host
//! starts for the same run ([`RunFreshGuest`]), and the vault files it.
//!
//! A desktop row (`self.desktop.*`) takes the same door to the run's own
//! desktop guest, a Linux desktop the `[desktop]` section names, under the
//! same pack, grants and decider. Its screenshots answer an `ai.verdict`
//! as the browser's do.
//!
//! An effect's receipt screenshot is kept for the call's own caller as a
//! blob artifact version when the receipt is made ([`ReceiptWriter`]), so it
//! outlives the guest's image queue and the guest.

mod browser_guest;
mod receipt_evidence;
mod session_write;
mod task_workflow;

// The strict library try a TASK-bound program's run takes before its
// planner (CUA E4).
#[allow(
    unused_imports,
    reason = "resident_pump's run_bound, its caller, lands in L09's CUA E4 TASK-side PR"
)]
pub(crate) use self::task_workflow::{WorkflowPreflight, preflight_task_workflow};

use self::receipt_evidence::ReceiptWriter;
use super::actor_dispatch::{mcp_execute_code_gate, mcp_tool_validation_error, mcp_verb_gate};
use super::admission::{
    mcp_admit_host_verb, mcp_admit_run_verb, mcp_admit_scoped_verb, mcp_admit_step_verb,
};
use super::tasks_response::{McpCodeRun, execute_agent_verb_input, mcp_agent_verb_arguments};
use super::{McpCallContext, McpGatewayError};
use crate::decision_host::PLACEMENT_BUDGET;
use crate::decision_verdict::{HELD_IMAGE, HELD_PREFIX, HeldImage};
use crate::mcp::{McpEndpointTool, McpSurfaceMode, try_registered_surface};
use crate::server::SyncServer;
use oneiron::browser_library::{
    Filing, Retired, RetiredWorkflow, WorkflowRecord, file_workflow, record_workflow_run,
    retire_workflow, retired_workflows, site_workflows, type_filter,
};
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, AgentVerbRefusalWords, RunCall,
    SelfAgentVerbCall, SelfEffect,
};
use oneiron::consent::{BoundClass, BoundEnvelope, StandingConsentGrant};
use oneiron::llm::decision::{AnswerContract, DecisionRung, HumanAskReason, RoutineOutcome};
use oneiron::memory::{HostWriteOrigin, Memory};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{
    AgentVerb, AiVerdict, AiVerdictRequest, AiVerdictReversibility, RunVerb,
};
use oneiron_browser::{
    Admitted, BrowserDriver, BrowserEngine, BrowserError, BrowserGuest, BrowserRequestHandler,
    BrowserSession, DesktopGuest, DesktopSession, EFFECT_CLASSES, FiledWorkflow, FreshGuest,
    GuestLimits, HandleRetention, LibraryCard, PressMode, RetiredCard, RoutineAnswer, RoutineAsk,
    RoutineDecider, RoutineReply, RunOutcome, SendPolicy, StrictDenial, StrictDenied,
    SupersedeRefusal, WorkflowLibrary, WorkflowProgram, WorkflowProof,
};
use oneiron_container::{EgressRelay, SessionManifest, SessionTransport};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Instant;

/// The verb door one `execute_code` run binds, under that call's connector.
pub(crate) struct McpCodeModeVerbs {
    server: Arc<SyncServer>,
    actor: McpCallContext,
    runtime: tokio::runtime::Handle,
    /// The rows this run's verb calls listed as served during this call
    /// (DEC-0005); each answer carries its own into the run's record too.
    served: std::sync::Mutex<Vec<oneiron::EntityId>>,
    /// The durable run this door serves, as `mcp_code_run_id` derived it:
    /// each verb call is made in it, and it creates the live lens cards they
    /// render (OF-181, FIX 2612 (a)).
    run_id: oneiron::EntityId,
    /// This run's browser and desktop.
    guests: RunGuests,
}

/// One run's guests: its browser, when the host has a `[browser]` guest to
/// give it, and its desktop, when it has a `[desktop]` one. Whichever door
/// the run binds admits each call before its guest acts.
pub(crate) struct RunGuests {
    browser: Option<RunBrowser>,
    desktop: Option<RunDesktop>,
    /// The words the newest browser call was refused with (FIX 6887).
    refused: browser_guest::KeptRefusal,
}

/// One run's browser guest. It starts on the first call that needs it and
/// is never shared with another run. Its seat is the run's own in the
/// server's registry (CUA-001), as the desktop's is: the owner can take the
/// browser over, and the run's next door (an MCP `execute_code` run's next
/// entry) finds the guest, cart and login with it, this one leaves. The
/// guest ends when the run ends, or once its seat sits idle with no door of
/// the run bound.
struct RunBrowser {
    guest: BrowserGuest,
    session: Arc<crate::server::BrowserSeat>,
    seats: Arc<crate::server::BrowserSeats>,
    vault: Arc<oneiron::Vault>,
    run_id: oneiron::EntityId,
    /// Whether this door gave the run's browser its press policy yet: a
    /// browser an earlier door started takes this door's at its first call
    /// here, and spends it down after.
    policy_set: AtomicBool,
    /// The host's retained line a browser this door starts charges its live
    /// handles to (C013).
    handles: crate::server::HandleLine,
    /// The server's browser readiness each guest it starts moves (FIX 7670).
    readiness: crate::config::browser::BrowserReadinessCell,
}

impl Drop for RunBrowser {
    fn drop(&mut self) {
        self.seats.unbind(self.run_id, &self.session);
    }
}

/// One run's desktop guest. Its seat is the run's own in the server's
/// registry (CUA-001): the owner can take the desktop over, and the run's
/// next door finds the guest this one leaves. The guest ends when the run
/// ends, or once its seat sits idle with no door of the run bound.
struct RunDesktop {
    guest: DesktopGuest,
    session: Arc<crate::server::DesktopSeat>,
    seats: Arc<crate::server::DesktopSeats>,
    vault: Arc<oneiron::Vault>,
    run_id: oneiron::EntityId,
    /// Whether this door gave the run's desktop its press policy yet, as
    /// [`RunBrowser`]'s does: a budgeted grant's batch count spends down
    /// across this door's calls and never refills at one.
    policy_set: AtomicBool,
}

impl Drop for RunDesktop {
    fn drop(&mut self) {
        self.seats.unbind(self.run_id, &self.session);
    }
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

/// A run guest's start that stopped: the error its caller answers, and the
/// phase it stopped at, which a browser's start gives the server's browser
/// readiness (FIX 7670). A desktop's start keeps the error alone.
struct GuestStartFailure {
    phase: oneiron_vault_contract::BrowserUnavailableReason,
    error: BrowserError,
}

impl From<GuestStartFailure> for BrowserError {
    fn from(failure: GuestStartFailure) -> Self {
        failure.error
    }
}

/// Starts one run's guest from a pinned image through the engine's tier
/// selector, behind the run's egress proxy, on `command`, and receipts its
/// manifest.
fn start_run_guest(
    vault: &Arc<oneiron::Vault>,
    run_id: oneiron::EntityId,
    runtime: &Path,
    image: &str,
    limits: GuestLimits,
    fixture: Option<&PathBuf>,
    command: &[std::ffi::OsString],
) -> Result<(SessionTransport, Arc<dyn EgressRelay>), GuestStartFailure> {
    use oneiron::code_sandbox::{SandboxGuestTier, microvm::select_backend_for_session};
    use oneiron_container::{GuestSeccomp, GuestSpec, ImageRef};
    use oneiron_vault_contract::BrowserUnavailableReason as Phase;
    let unavailable = |phase, e: String| GuestStartFailure {
        phase,
        error: BrowserError::Unavailable(e),
    };
    let backend =
        select_backend_for_session(SandboxGuestTier::Untrusted, runtime.to_path_buf(), image)
            .map_err(|e| unavailable(Phase::SandboxUnavailable, e.to_string()))?;
    let spec = GuestSpec {
        image: ImageRef::pinned(image)
            .map_err(|e| unavailable(Phase::GuestStartFailed, e.to_string()))?,
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
                .map_err(|e| unavailable(Phase::GuestStartFailed, e.to_string()))?,
        )
        .with_fixture(fixture.cloned()),
    );
    let transport = backend
        .start_session(&spec, command, Arc::clone(&relay))
        .map_err(|e| unavailable(Phase::GuestStartFailed, e.to_string()))?;
    vault
        .append_sandbox_manifest_receipt(run_id, &transport.manifest)
        .map_err(|e| unavailable(Phase::SessionReceiptFailed, e.to_string()))?;
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
/// run's own `ai.verdict` call through its door (a connector's scope
/// admission, verb gate and hooks, or an agent run's hooks), under the batch call's
/// origin, with the step's screenshot handed in from the run's browser as an
/// evidence ref on the run.
#[derive(Clone)]
struct LadderDecider {
    server: Arc<SyncServer>,
    asker: VerdictAsker,
    runtime: tokio::runtime::Handle,
    origin: HostWriteOrigin,
    run_id: oneiron::EntityId,
}

/// Whom a run's routine decisions are asked for.
#[derive(Clone)]
pub(crate) enum VerdictAsker {
    /// The `execute_code` connector: each decision is an `ai.verdict` call by
    /// that credential, under a fresh invocation. The browser batch it is
    /// bound for carries it, so `ai.verdict` need not be bound itself.
    Connector(McpCallContext),
    /// A public browser call keeps the request's own credential for both
    /// routine verdicts and screenshot writes, with no agent-only fallback.
    Credential(crate::auth::CoreAuth, oneiron::WriteActor),
    /// A pumped run's own agent, which holds no credential: each decision is
    /// the agent's `ai.verdict` through its run's host door, under a fresh
    /// invocation, on the run's own line when its entry bound one (so a
    /// room-funded run's step verdicts bill its payer, FIX 3574).
    Agent(
        oneiron::WriteActor,
        Option<oneiron::llm::run_admission::RunAdmission>,
    ),
}

/// A strict run's step no rung answered, with no model asked (CUA E2
/// strict denial, CALLS row): it goes up at zero tokens, its decision a
/// [`StrictDenied`] record, and the subgoal's clock as it was.
fn strict_denied(denial: StrictDenial, question: &str, until_ms: Option<u64>) -> RoutineReply {
    RoutineReply {
        answer: RoutineAnswer::Denied { denial },
        screenshot: false,
        until_ms,
        decision: StrictDenied::decision(denial, question),
    }
}

impl RoutineDecider for LadderDecider {
    fn decide(&mut self, ask: RoutineAsk<'_>) -> Result<RoutineReply, BrowserError> {
        let (strict, until_ms) = (ask.no_model, ask.until_ms);
        // Strict: a screenshot is read only from the Local-vision rung up,
        // so the step goes up before any rung is asked or admitted.
        if strict && ask.image.is_some() {
            return Ok(strict_denied(StrictDenial::Image, ask.question, until_ms));
        }
        let question = ask.question.to_owned();
        // A step with no candidates finds its target in the screenshot.
        let contract = if ask.options.is_empty() {
            AnswerContract::Box
        } else {
            AnswerContract::Choice {
                options: ask.options,
            }
        };
        let request = AiVerdictRequest {
            question: question.clone(),
            contract,
            evidence: Vec::new(),
            state: Some(ask.state),
            // No model: the ladder stops at its rule rung.
            ceiling: ask.no_model.then_some(DecisionRung::Rule),
            // A step acts on a live page: at a cut it abstains and goes up.
            reversibility: AiVerdictReversibility::OutboundEffect,
            deadline_ms: None,
            routine: true,
            image: ask.image.map(|(image, _)| image.to_owned()),
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
        let origin = self.origin.clone();
        match self.asker.clone() {
            VerdictAsker::Connector(actor) => {
                let run = McpCodeRun {
                    origin,
                    run_id: self.run_id,
                };
                self.runtime.spawn(HELD_IMAGE.scope(held, async move {
                    let _ = sender.send(execute_step_verdict(&server, &actor, input, run).await);
                }));
            }
            VerdictAsker::Credential(auth, _) => {
                self.runtime.spawn(HELD_IMAGE.scope(held, async move {
                    let id = InvocationId::mint().to_hex();
                    let call = crate::api::facade::FacadeCall::bound(&auth, None, Some(&id), None);
                    let answer =
                        crate::api::facade::call_verb(&server, &call, "ai.verdict", Ok(input))
                            .await
                            .map(|answer| (answer.value, answer.rows.unwrap_or_default()))
                            .map_err(|error| super::mcp_facade_error(error.into_memory_error()));
                    let _ = sender.send(answer);
                }));
            }
            VerdictAsker::Agent(actor, line) => {
                self.runtime.spawn_blocking(move || {
                    let answered = crate::server::answer_as_agent(
                        &server,
                        actor,
                        &origin,
                        InvocationId::mint(),
                        AgentVerb::AiVerdict,
                        input,
                        held,
                        line.as_ref(),
                    );
                    // Only the verdict is read here; its rows are not.
                    let answered =
                        answered.map(|(output, rows)| (output, rows.unwrap_or_default()));
                    let _ = sender.send(answered.map_err(super::mcp_facade_error));
                });
            }
        }
        let answered = receiver
            .recv()
            .map_err(|_| BrowserError::Decider("the ladder did not answer".to_owned()))?;
        let (output, _) = match answered {
            // Strict: no rung up to the rule ceiling takes the question, as
            // the ladder finds before it runs any.
            Err(error) if strict && error.kind == "model_unavailable" => {
                return Ok(strict_denied(StrictDenial::NoRule, &question, until_ms));
            }
            Err(error) => {
                let detail = format!("{}: {}", error.kind, error.message);
                return Err(BrowserError::Decider(detail));
            }
            Ok(answered) => answered,
        };
        let verdict: AiVerdict = serde_json::from_value(output.clone())
            .map_err(|e| BrowserError::Decider(e.to_string()))?;
        let answer = match verdict.outcome {
            Some(RoutineOutcome::Act { candidate }) => RoutineAnswer::Act { candidate },
            Some(RoutineOutcome::Point { x, y, .. }) => RoutineAnswer::Point { x, y },
            Some(RoutineOutcome::None) => RoutineAnswer::None,
            Some(RoutineOutcome::Reobserve) => RoutineAnswer::Reobserve,
            // The subgoal's clock cut the call: the step stops on it.
            Some(RoutineOutcome::AskUp {
                reason: Some(HumanAskReason::Deadline),
            }) => RoutineAnswer::Deadline,
            // Strict: the rule rung ran and gave no answer; its receipt
            // stands as the decision.
            Some(RoutineOutcome::AskUp { reason: Some(_) }) if strict => RoutineAnswer::Denied {
                denial: StrictDenial::RuleAbstained,
            },
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
/// what it files names the run's caller, placed through the host's ladder.
struct VaultLibrary {
    server: Arc<SyncServer>,
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
        type_ref: Option<&str>,
    ) -> Result<Vec<LibraryCard>, BrowserError> {
        // A filter that names no task type is the caller's input refused.
        let type_ref = type_ref
            .map(type_filter)
            .transpose()
            .map_err(|malformed| BrowserError::Input(malformed.to_string()))?;
        let records = site_workflows(&self.server.vault, site, subgoal, type_ref.as_ref())
            .map_err(library_failed)?;
        Ok(records.iter().map(WorkflowRecord::card).collect())
    }

    fn program(&mut self, workflow: &str) -> Result<Option<FiledWorkflow>, BrowserError> {
        let Ok(id) = oneiron::EntityId::from_hex(workflow) else {
            return Ok(None);
        };
        Ok(oneiron::browser_library::workflow(&self.server.vault, id)
            .map_err(library_failed)?
            .map(|record| FiledWorkflow {
                program: record.program,
                proof: record.proof,
            }))
    }

    fn admit(
        &mut self,
        site: &str,
        program: &WorkflowProgram,
        proof: &WorkflowProof,
        supersedes: Option<&str>,
    ) -> Result<Admitted, BrowserError> {
        let Ok(supersedes) = supersedes.map(oneiron::EntityId::from_hex).transpose() else {
            return Ok(Admitted::Refused(SupersedeRefusal::Malformed));
        };
        let deadline = RetrievalDeadline::hard(Instant::now(), PLACEMENT_BUDGET);
        let decisions = self
            .server
            .decision_host()
            .placement_decisions(self.by, &deadline);
        let filing = file_workflow(
            &self.server.vault,
            self.by,
            site,
            program,
            proof,
            self.server.vault.now_recorded_at(),
            Some(&decisions),
            supersedes,
        )
        .map_err(library_failed)?;
        Ok(match filing {
            Filing::Filed { id, superseded } => Admitted::Filed {
                workflow: id.to_hex(),
                superseded,
            },
            Filing::Refused(why) => Admitted::Refused(why),
        })
    }

    fn record_run(&mut self, workflow: &str, outcome: &RunOutcome) -> Result<(), BrowserError> {
        let Ok(id) = oneiron::EntityId::from_hex(workflow) else {
            return Ok(());
        };
        record_workflow_run(
            &self.server.vault,
            id,
            outcome,
            self.by,
            self.server.vault.now_recorded_at(),
        )
        .map_err(library_failed)
    }

    fn retire(
        &mut self,
        workflow: &str,
        reason: Option<&str>,
    ) -> Result<Option<LibraryCard>, BrowserError> {
        let Ok(id) = oneiron::EntityId::from_hex(workflow) else {
            return Ok(None);
        };
        let retired = retire_workflow(
            &self.server.vault,
            id,
            self.by,
            reason,
            self.server.vault.now_recorded_at(),
        )
        .map_err(library_failed)?;
        match retired {
            Retired::Taken(record) => Ok(Some(record.card())),
            Retired::NotFiled => Ok(None),
            Retired::NotFiler => Err(BrowserError::Library(format!(
                "workflow {workflow} was filed from another caller's run; only that caller retires it"
            ))),
        }
    }

    fn retired(&mut self, site: &str) -> Result<Vec<RetiredCard>, BrowserError> {
        Ok(retired_workflows(&self.server.vault, site)
            .map_err(library_failed)?
            .iter()
            .map(RetiredWorkflow::card)
            .collect())
    }
}

/// The fresh browser a proposal's replay runs on (CUA E1): a new guest for
/// the same run, started on the run browser's own path
/// ([`browser_guest::start_run_browser`]), so it has its own proved fence,
/// the run's egress door and grants, and its own live-handle charge; on the
/// engine the proposing browser runs, in its request custody, with its own
/// decider and keeper of receipt screenshots for the same call. It takes
/// nothing of the proposing page here: the session carries its sign-ins
/// into it, and runs the replay.
struct RunFreshGuest {
    vault: Arc<oneiron::Vault>,
    run_id: oneiron::EntityId,
    guest: BrowserGuest,
    handles: crate::server::HandleLine,
    readiness: crate::config::browser::BrowserReadinessCell,
    decider: LadderDecider,
    invocation: Option<InvocationId>,
}

impl FreshGuest for RunFreshGuest {
    fn start(
        &mut self,
        engine: BrowserEngine,
        requests: Option<Arc<dyn BrowserRequestHandler>>,
    ) -> Result<BrowserSession, BrowserError> {
        let guest = BrowserGuest {
            engine,
            ..self.guest.clone()
        };
        let mut session = browser_guest::start_run_browser(
            &self.vault,
            self.run_id,
            &guest,
            &self.handles,
            &self.readiness,
            requests,
        )?;
        let writer = ReceiptWriter::new(
            &self.decider.server,
            self.decider.asker.clone(),
            &self.decider.origin,
            self.invocation,
            self.run_id,
        );
        session.set_decider(Box::new(self.decider.clone()));
        session.set_receipt_sink(Box::new(writer));
        Ok(session)
    }

    fn state_charge(&self) -> Box<dyn HandleRetention> {
        self.handles.charge()
    }
}

impl RunBrowser {
    /// The browser the host gives run `run_id`, under the press policy the
    /// vault's standing grants set, when it has a `[browser]` guest.
    fn new(server: &SyncServer, run_id: oneiron::EntityId) -> Option<Self> {
        let mut guest = server.browser_guest()?.clone();
        guest.policy = browser_send_policy(server);
        let session = server.browser_seats.bind(run_id, &server.vault);
        Some(Self {
            guest,
            session,
            seats: Arc::clone(&server.browser_seats),
            vault: Arc::clone(&server.vault),
            run_id,
            policy_set: AtomicBool::new(false),
            handles: crate::server::HandleLine::of(server),
            readiness: server.browser_readiness().clone(),
        })
    }

    /// The fresh guest this run's proposals replay on, for one call of
    /// `decider`'s caller (`invocation`).
    fn fresh_guest(
        &self,
        decider: LadderDecider,
        invocation: Option<InvocationId>,
    ) -> RunFreshGuest {
        RunFreshGuest {
            vault: Arc::clone(&self.vault),
            run_id: self.run_id,
            guest: self.guest.clone(),
            handles: self.handles.clone(),
            readiness: self.readiness.clone(),
            decider,
            invocation,
        }
    }

    fn call(
        &self,
        verb: AgentVerb,
        input: Value,
        decider: LadderDecider,
        library: VaultLibrary,
        writer: ReceiptWriter,
        fresh: RunFreshGuest,
    ) -> Result<Value, BrowserError> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        if session.is_none() {
            // The session keeps the starter its engine switches take. No
            // host request handler: its pages take the run's relay.
            let started = browser_guest::start_run_browser(
                &self.vault,
                self.run_id,
                &self.guest,
                &self.handles,
                &self.readiness,
                None,
            )?;
            *session = Some(started);
        }
        let driver = session.as_mut().ok_or(BrowserError::GuestLost)?;
        if !self.policy_set.swap(true, Ordering::AcqRel) {
            driver.set_policy(self.guest.policy.clone());
        }
        driver.set_decider(Box::new(decider));
        driver.set_library(Box::new(library));
        driver.set_receipt_sink(Box::new(writer));
        driver.set_fresh_guest(Box::new(fresh));
        // While a person is asked or holds the browser, the session refuses
        // the verb `browser_taken_over`; the first answer after they hand it
        // back carries the takeover's record as `takeover`. An answer after
        // the agent's verbs moved to another tab (one its act opened, or the
        // one a closed tab gave way to) names the move as `switched`. Every
        // answer names the engine that ran it (FIX 6680).
        let mut output = drive_run_guest(&self.vault, self.run_id, driver, verb, input)?;
        self.seats.asked(self.run_id, driver.takeover());
        if let Some(object) = output.as_object_mut() {
            object.insert("engine".into(), Value::from(driver.engine().as_str()));
            if let Some(record) = driver.take_returned() {
                object.insert(
                    "takeover".into(),
                    serde_json::to_value(record)
                        .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
                );
            }
            if let Some(switch) = driver.take_switched() {
                object.insert(
                    "switched".into(),
                    serde_json::to_value(switch)
                        .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
                );
            }
        }
        Ok(output)
    }
}

impl RunDesktop {
    /// The desktop the host gives run `run_id`, as [`RunBrowser::new`] gives
    /// its browser, when it has a `[desktop]` guest.
    fn new(server: &SyncServer, run_id: oneiron::EntityId) -> Option<Self> {
        let mut guest = server.desktop_guest()?.clone();
        guest.policy = browser_send_policy(server);
        let session = server.desktop_seats.bind(run_id, &server.vault);
        Some(Self {
            guest,
            session,
            seats: Arc::clone(&server.desktop_seats),
            vault: Arc::clone(&server.vault),
            run_id,
            policy_set: AtomicBool::new(false),
        })
    }

    /// A desktop verb. While a person is asked or holds the desktop, the
    /// session refuses it `desktop_taken_over`; the first answer after they
    /// hand it back carries the takeover's record as `takeover`. An answer
    /// after the window the agent's verbs read was gone, and the session
    /// gave way to the window in front, names the move as `switched`. A
    /// handover raises the owners' inbox Ask.
    fn call(
        &self,
        verb: AgentVerb,
        input: Value,
        decider: LadderDecider,
        writer: ReceiptWriter,
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
                &["/usr/local/bin/oneiron-desktop-guest".into()],
            )?;
            *session = Some(DesktopSession::attach(&self.guest, transport)?);
        }
        let driver = session.as_mut().ok_or(BrowserError::GuestLost)?;
        if !self.policy_set.swap(true, Ordering::AcqRel) {
            driver.set_policy(self.guest.policy.clone());
        }
        driver.set_decider(Box::new(decider));
        driver.set_receipt_sink(Box::new(writer));
        let mut output = drive_run_guest(&self.vault, self.run_id, driver, verb, input)?;
        self.seats.asked(self.run_id, driver.takeover());
        if let Some(object) = output.as_object_mut() {
            if let Some(record) = driver.take_returned() {
                object.insert(
                    "takeover".into(),
                    serde_json::to_value(record)
                        .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
                );
            }
            if let Some(switch) = driver.take_switched() {
                object.insert(
                    "switched".into(),
                    serde_json::to_value(switch)
                        .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
                );
            }
        }
        Ok(output)
    }
}

impl RunGuests {
    /// The guests the host gives run `run_id`.
    pub(crate) fn new(server: &SyncServer, run_id: oneiron::EntityId) -> Self {
        Self {
            browser: RunBrowser::new(server, run_id),
            desktop: RunDesktop::new(server, run_id),
            refused: browser_guest::KeptRefusal::default(),
        }
    }

    /// Binds only this attached run's browser for a public host call.
    pub(crate) fn browser(server: &SyncServer, run_id: oneiron::EntityId) -> Self {
        Self {
            browser: RunBrowser::new(server, run_id),
            desktop: None,
            refused: browser_guest::KeptRefusal::default(),
        }
    }

    /// The words the run's newest browser call was refused with, for
    /// `browser_unsupported` alone (FIX 6887).
    pub(crate) fn refusal_words(&self) -> Option<AgentVerbRefusalWords> {
        self.refused.words()
    }

    /// A code-mode call fires the row's hooks once around the shared guest door.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one axis of the caller's door"
    )]
    pub(crate) fn call(
        &self,
        server: &Arc<SyncServer>,
        runtime: &tokio::runtime::Handle,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        memory: &Memory<'_>,
        asker: VerdictAsker,
        by: oneiron::EntityId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        self.refused.keep(None);
        if let Err(refusal) = self.admits(call.verb, server) {
            return Ok(Err(refusal));
        }
        let hooks = match oneiron::task_verb::verb_hook_boundary::browser_row_pre(
            memory,
            call.verb.as_str(),
            call.input.clone(),
        ) {
            Ok(hooks) => hooks,
            Err(error) => return refused(super::mcp_facade_error(error)),
        };
        let admitted = SelfAgentVerbCall {
            verb: call.verb,
            input: hooks.args.clone(),
        };
        let answer =
            match self.call_admitted(server, runtime, &admitted, origin, memory, asker, by)? {
                Ok(answer) => answer,
                Err(refused) => {
                    self.refused.keep(Some(&refused));
                    return Ok(Err(AgentVerbRefusal { code: refused.code }));
                }
            };
        match oneiron::task_verb::verb_hook_boundary::row_post(&server.vault, hooks, answer.output)
        {
            Ok(output) => Ok(Ok(AgentVerbAnswer {
                output,
                rows: answer.rows,
            })),
            Err(error) => refused(super::mcp_facade_error(error)),
        }
    }

    /// The facade and MCP host doors already crossed the row's hooks. They
    /// take this same guest admission and driver without firing hooks twice.
    /// A refusal carries its code, and for `browser_unsupported` the
    /// engine's words naming the verb that serves it (FIX 6862).
    #[expect(
        clippy::too_many_arguments,
        reason = "the admitted caller and run are separate axes"
    )]
    pub(crate) fn call_admitted(
        &self,
        server: &Arc<SyncServer>,
        runtime: &tokio::runtime::Handle,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        memory: &Memory<'_>,
        asker: VerdictAsker,
        by: oneiron::EntityId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusalWords>> {
        if let Err(refusal) = self.admits(call.verb, server) {
            return Ok(Err(browser_guest::code_words(refusal.code)));
        }
        let verb = call.verb.as_str();
        let desktop = verb.starts_with("self.desktop.");
        let run_id = if desktop {
            self.desktop.as_ref().map(|guest| guest.run_id)
        } else {
            self.browser.as_ref().map(|guest| guest.run_id)
        }
        .ok_or(oneiron::Error::InvariantViolation(
            "admitted guest has no run",
        ))?;
        let writer = ReceiptWriter::new(server, asker.clone(), origin, memory.invocation(), run_id);
        let decider = LadderDecider {
            server: Arc::clone(server),
            asker,
            runtime: runtime.clone(),
            origin: origin.clone(),
            run_id,
        };
        let called = match (&self.desktop, &self.browser) {
            (Some(run), _) if desktop => run.call(call.verb, call.input.clone(), decider, writer),
            (_, Some(run)) if !desktop => {
                let library = VaultLibrary {
                    server: Arc::clone(server),
                    by,
                };
                let fresh = run.fresh_guest(decider.clone(), memory.invocation());
                let input = call.input.clone();
                run.call(call.verb, input, decider, library, writer, fresh)
            }
            _ => Err(BrowserError::Unbound),
        };
        let output = match called {
            Ok(output) => output,
            Err(error) => return Ok(Err(browser_guest::refusal_words(&error))),
        };
        // An effect's answer carries its receipt, naming the page it acted on.
        if let Some(receipt) = output.get("receipt") {
            tracing::info!(verb, ?receipt, "browser effect receipt");
        }
        if let Some(receipts) = output.get("receipts") {
            tracing::info!(verb, ?receipts, "browser batch receipts");
        }
        Ok(Ok(AgentVerbAnswer {
            output,
            rows: Some(Vec::new()),
        }))
    }

    fn admits(&self, verb: AgentVerb, server: &SyncServer) -> Result<(), AgentVerbRefusal> {
        // The browser runs as its connector pack: no installed pack, no browser.
        if server
            .vault
            .require_builtin_channel_pack("browser")
            .is_err()
        {
            return Err(AgentVerbRefusal {
                code: "browser_pack_not_installed".to_owned(),
            });
        }
        // A desktop row drives the run's desktop; every other row its browser.
        let desktop = verb.as_str().starts_with("self.desktop.");
        // The browser guest runs only once its setup connection is checked.
        if !desktop
            && server
                .vault
                .require_pack_connection_verified("oneiron.browser", "browser-guest")
                .is_err()
        {
            return Err(AgentVerbRefusal {
                code: "browser_connection_unchecked".to_owned(),
            });
        }
        let run_id = if desktop {
            self.desktop.as_ref().map(|desktop| desktop.run_id)
        } else {
            self.browser.as_ref().map(|browser| browser.run_id)
        };
        if run_id.is_none() {
            return Err(AgentVerbRefusal {
                code: BrowserError::Unbound.code().to_owned(),
            });
        }
        Ok(())
    }

    /// The screenshot this run's browser or desktop holds under the
    /// `blake3:` ref an `ai.verdict` input names, when one holds it.
    pub(crate) fn held_image(&self, input: &Value) -> Option<HeldImage> {
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
            run_id,
            guests: RunGuests::new(server, run_id),
        }
    }

    /// A browser row: this connector's binding and live credential at each
    /// call, then the run's guest.
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
    fn credential_lane(&self) -> Result<ScopedReadActorKey, AgentVerbRefusal> {
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
                        crate::error::ErrorCode::Forbidden => "forbidden",
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
        self.runtime.spawn(HELD_IMAGE.scope(held, async move {
            let _ = sender.send(execute_code_mode_verb(&server, &actor, verb, input, run).await);
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
            .extend(listed.iter().flatten().copied());
        Ok(Ok(AgentVerbAnswer {
            output,
            rows: listed,
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

/// The door a reader child's run binds (ARCH-0079 #reader-forks). It runs
/// no verb, and of the calls the run serves itself admits only its report,
/// `self.context`, `self.think` and reads of what it recorded. What the
/// child read leaves this device again by its parent caller's rule
/// (DEC-0005), as the door that caller's run binds rules. It holds no
/// credential of the parent's, and no model endpoint's proof.
pub(crate) struct ReaderChildDoor {
    vault: Arc<oneiron::Vault>,
    /// Where the parent run's caller's rows go: its locality, with the
    /// machine its connection proved (FIX 4937).
    caller: oneiron::settings::ReadDestination,
}

impl ReaderChildDoor {
    pub(crate) fn new(
        vault: Arc<oneiron::Vault>,
        caller: impl Into<oneiron::settings::ReadDestination>,
    ) -> Self {
        Self {
            vault,
            caller: caller.into(),
        }
    }
}

fn read_only() -> AgentVerbRefusal {
    AgentVerbRefusal {
        code: crate::server::READER_CHILD_READ_ONLY.to_owned(),
    }
}

impl AgentVerbDoor for ReaderChildDoor {
    fn call(
        &self,
        _: &SelfAgentVerbCall,
        _: &HostWriteOrigin,
        _: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(read_only()))
    }

    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        match call {
            RunCall::RecordedOutput
            | RunCall::Bridge(SelfEffect::ReaderReport | SelfEffect::Context | SelfEffect::Think) => {
                Ok(None)
            }
            _ => Err(read_only()),
        }
    }

    /// The parent caller's rule: on this device nothing is withheld; off
    /// it, a result leaves again only while every row it was served from
    /// may, and one with no row set stays.
    fn withholds_retained(
        &self,
        rows: Option<&[oneiron::EntityId]>,
    ) -> Result<bool, AgentVerbRefusal> {
        if !self.caller.is_off_device() {
            return Ok(false);
        }
        let Some(rows) = rows else {
            return Ok(true);
        };
        crate::device_local::withholds_retained(&self.vault, &self.caller, rows, &[]).map_err(
            |_| AgentVerbRefusal {
                code: "engine_error".to_owned(),
            },
        )
    }
}

/// A refused call as the run takes it: a verb hook's stop as the typed stop,
/// any other refusal as its stable code.
fn refused<T>(error: McpGatewayError) -> oneiron::Result<Result<T, AgentVerbRefusal>> {
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

async fn execute_code_mode_verb(
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
async fn execute_step_verdict(
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
type VerbAdmission = fn(
    &Arc<SyncServer>,
    crate::mcp::McpGeneratedVerbTool,
    &crate::mcp::McpVerbArguments,
    &McpCallContext,
) -> Result<(), McpGatewayError>;

async fn run_code_mode_verb(
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
    let (output, ..) = crate::api::facade::host_doors::with_calling_origin(
        origin,
        execute_agent_verb_input(
            server,
            tool.name,
            input,
            actor,
            Some(run),
            &mut served,
            &mut board_hooks,
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
