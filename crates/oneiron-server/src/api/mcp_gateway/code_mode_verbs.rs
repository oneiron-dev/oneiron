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
//!
//! The secrets a run's guest finds (card numbers, security codes, one-time
//! codes, passwords) become custody records bound to the run where they are
//! found, through the call's [`RunSecretCustody`] on the run's browser, its
//! fresh admission guest and its desktop (FIX 8028); the guest types and
//! checks them by handle, and the seat's end erases them.

mod browser_guest;
mod dispatch;
mod field_writer;
mod guests;
mod library;
mod program_admission;
mod reader;
mod receipt_evidence;
mod secret_custody;
mod session_write;
mod solved_runs;
mod task_workflow;
mod verdict;

// The strict library try a TASK-bound program's run takes before its
// planner (CUA E4).
pub(crate) use self::task_workflow::{WorkflowPreflight, preflight_task_workflow};

use self::dispatch::*;
use self::field_writer::RunFieldWriter;
use self::guests::*;
use self::receipt_evidence::ReceiptWriter;
use self::secret_custody::RunSecretCustody;
use self::solved_runs::BrowserCapture;
use super::actor_dispatch::{mcp_execute_code_gate, mcp_tool_validation_error, mcp_verb_gate};
use super::admission::{
    mcp_admit_host_verb, mcp_admit_run_verb, mcp_admit_scoped_verb, mcp_admit_step_verb,
};
use super::tasks_response::{McpCodeRun, execute_agent_verb_input, mcp_agent_verb_arguments};
use super::{
    McpCallContext, McpGatewayError, McpServed, admission, mcp_facade_error, served_rows,
    tasks_response,
};
use crate::ai_host::browser_planner::BrowserPlannerRun;
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
use oneiron::secret_custody::RunSecretSeat;
use oneiron::task_verb::sdk::{
    AgentVerb, AiVerdict, AiVerdictRequest, AiVerdictReversibility, RunVerb,
};
use oneiron_browser::{
    Admitted, BrowserDriver, BrowserEngine, BrowserError, BrowserGuest, BrowserRequestHandler,
    BrowserSession, DesktopGuest, DesktopSession, EFFECT_CLASSES, FiledWorkflow, FreshGuest,
    GuestLimits, HandleRetention, LibraryCard, PressMode, RetiredCard, RoutineAnswer, RoutineAsk,
    RoutineDecider, RoutineReply, RunOutcome, SecretCustody, SendPolicy, StrictDenial,
    StrictDenied, SupersedeRefusal, TextCheck, TextCheckReply, WorkflowLibrary, WorkflowProgram,
    WorkflowProof,
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
    /// The run's browser planner state beside its browser's seat (CUA E5),
    /// fed how each batch and library run ended.
    planner: Option<Arc<BrowserPlannerRun>>,
    /// The payer the attached live run bills (FIX 8902), for a caller whose
    /// door bound no line of its own: its Fill writer bills it.
    payer: Option<oneiron::llm::run_admission::PayerPerson>,
    /// The admission job this run is (CUA E8b): what it files is kept
    /// against the job, placed by rule alone, and it captures no evidence.
    admission: Option<oneiron::browser_library::ProgramAdmissionFiling>,
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

/// What a run guest's fixture origin serves: a host directory, mounted
/// read-only in the guest, or the one upstream the run's relay forwards to,
/// host-side, with no mount (FIX 8061). A desktop's serves neither.
#[derive(Clone, Copy, Default)]
struct RunGuestFixture<'a> {
    directory: Option<&'a PathBuf>,
    forward: Option<std::net::SocketAddrV4>,
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

/// The vault's replay library, as the run's browser files and reads it:
/// what it files names the run's caller, placed through the host's ladder.
struct VaultLibrary {
    server: Arc<SyncServer>,
    by: oneiron::EntityId,
    /// The caller's solved-run scope, which a program it files covers its
    /// group in (CUA E8a); none for a library that files nothing.
    scope: Option<oneiron::browser_library::SolvedRunScope>,
    /// The admission job its filing files for (CUA E8b): placed by rule
    /// alone, and kept against the job in the filing's write.
    admission: Option<oneiron::browser_library::ProgramAdmissionFiling>,
}

/// The fresh browser a proposal's replay runs on (CUA E1): a new guest for
/// the same run, started on the run browser's own path
/// ([`browser_guest::start_run_browser`]), so it has its own proved fence,
/// the run's egress door and grants, and its own live-handle charge; on the
/// engine the proposing browser runs, in its request custody, with its own
/// decider and keeper of receipt screenshots for the same call, and the
/// run's secret custody (FIX 8028): the replay is the same run. It takes
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
    secrets: Arc<dyn SecretCustody>,
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
