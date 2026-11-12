//! A thing-child as a scoped code-mode agent (FIX 7508, DREAMER ROW 3).
//!
//! One planned thing's branch (`thing.is_some()`; size and exposure siblings
//! stay apart) runs as one scoped child of a host-bound parent code run. The
//! engine frames every extraction slice of the branch, its neighbourhood
//! rendered in, as owned result occurrences of that parent run and lends
//! only those, with the union of the slices' readable resources and no
//! writable one. The agent is lent two ports and nothing else:
//! `self.dreamer.thing.extract`, which runs one slice's extraction step, and
//! `self.dreamer.thing.decide`, which runs the branch's correction pack. Each
//! port runs on its parent's own wake, guard and durable-step identity: the
//! very step today's per-slice path runs, so that path, run after the agent
//! settles, replays every slice the agent extracted from its memo and decides
//! nothing again. Root assembly, the evidence verifier, sealed promotion and
//! the nightly merge stay the engine's, unchanged.
//!
//! The agent returns engine-issued proposal refs ([`ThingProposalRef`]) and
//! its coverage; the engine checks each against the drafts it staged and
//! never takes a candidate, a trust or a hash from the agent. A host that
//! cannot lend what the agent needs leaves the branch on today's path with a
//! typed reason, never a refusal.

use std::collections::{BTreeMap, BTreeSet};

use super::sieve_ports::PortFuture;
use crate::attempt_queue::AttemptRecord;
use crate::code_run::{DelegatedSource, ReaderJobState};
use crate::dreamer_wake::WakeAttemptContext;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::WriteActor;
use oneiron_model::llm::{BudgetGuard, Scope};

mod input;
mod proposals;
mod serve;

pub(super) use serve::{ThingPass, ThingPassEnd};

/// The port that runs one lent slice's extraction step.
pub const THING_EXTRACT_PORT: &str = "self.dreamer.thing.extract";

/// The port that runs the branch's correction pack over every slice's
/// drafts.
pub const THING_DECIDE_PORT: &str = "self.dreamer.thing.decide";

/// Why a thing branch runs today's per-slice path (`THING_CHILD_EXECUTION_MODE`,
/// CALLS): the vault's recipe policy turned the agent off for this attempt.
pub const THING_CHILD_CODE_MODE_OFF: &str = "thing_child_code_mode_off";

/// ... the executor's host lent no thing-child host (the non-server
/// factory).
pub const THING_CHILD_HOST_ABSENT: &str = "thing_child_host_absent";

/// ... every slice of the branch is low-trust (one of its TURNs imported, or
/// a low-trust prior head it shows): its framed input would be lent as
/// clean, which the loan may not do. With some slices clean, those are lent
/// and only the low-trust ones stay on today's path (FIX 9017).
pub const THING_CHILD_LOW_TRUST: &str = "thing_child_low_trust";

/// ... the host has no verified code runtime, no reader runner or no scoped
/// profile registry.
pub const THING_CHILD_RUNTIME_UNBOUND: &str = "thing_child_runtime_unbound";

/// ... the loan was refused: its parent's lease, its ports, its scope or its
/// inputs.
pub const THING_CHILD_LOAN_REFUSED: &str = "thing_child_loan_refused";

/// ... the child was not queued.
pub const THING_CHILD_SPAWN_REFUSED: &str = "thing_child_spawn_refused";

/// ... the inputs or the launch met an engine error before any child ran.
pub const THING_CHILD_LAUNCH_FAILED: &str = "thing_child_launch_failed";

/// ... the child settled with slices it never extracted, short of no clock:
/// today's path takes those slices (and replays the rest).
pub const THING_CHILD_UNCOVERED: &str = "thing_child_uncovered";

/// The refusal a port call meets once its parent stopped serving it.
pub const THING_CHILD_PARENT_GONE: &str = "thing_child_parent_gone";

/// The refusal a port call meets for an input that is not its kind's: an
/// extract of no lent slice, a decide of no lent pack.
pub const THING_PORT_INPUT_UNKNOWN: &str = "thing_port_input_unknown";

/// The refusal a port call meets for an input its row's type does not take.
pub const THING_PORT_INPUT_INVALID: &str = "thing_port_input_invalid";

/// The refusal an extract meets when its slice's reply broke the extraction
/// contract: charged, not memoized, and asked again on the next try.
pub const THING_SLICE_REFUSED: &str = "thing_slice_refused";

/// The stop a child's parent puts on it when a port's durable step parked
/// the attempt.
pub const THING_CHILD_TRAPPED: &str = "thing_child_trapped";

/// The stop a child's parent puts on it when its wake is spent: the
/// unfinished slices are continuation debt (Rule 5).
pub const THING_CHILD_CHECKPOINT: &str = "thing_child_checkpoint";

/// The stop a child's parent puts on it when a port's read was refused and
/// the attempt parks to ask again.
pub const THING_CHILD_REFUSED: &str = "thing_child_refused";

/// The stop a child's parent puts on it when serving a port failed.
pub const THING_CHILD_PARENT_FAILED: &str = "thing_child_parent_failed";

/// What a host lends a thing's agent: its code runtime, its reader runner
/// and the profile its run takes (the extraction role's model, on the
/// parent's own wake guard). Injected beside the executor's extraction
/// ports, so the engine never depends on a server.
pub trait ThingChildHost: Send + Sync {
    /// The input window, in tokens, of the model the agent runs on, when the
    /// host knows it: the inputs are packed by it. With none, they are
    /// packed by the vault's `thing_child_fallback_window_tokens` (FIX 9020).
    fn window_tokens(&self) -> Option<u64>;

    /// Why the host cannot launch an agent now, if it cannot: checked before
    /// anything is committed.
    fn unavailable(&self) -> Option<&'static str>;

    /// Lends `launch`'s inputs to one scoped child and queues it. The
    /// answer's `Unavailable` names why nothing was queued; the branch then
    /// runs today's path.
    ///
    /// # Errors
    ///
    /// The route's own read and write errors.
    fn launch(&self, launch: ThingChildLaunch<'_, '_>) -> Result<ThingChildStart>;
}

/// One launch of a thing's agent: the wake and the leased attempt it runs
/// under, the parent's guard and actor, the host-bound parent run whose
/// committed results are lent by name, the resource bound the loan
/// attenuates and the scope it lends, the exact ports, the spawn's key and
/// the agent's ask.
pub struct ThingChildLaunch<'l, 'c> {
    pub ctx: &'l WakeAttemptContext<'c>,
    pub leased: &'l AttemptRecord,
    pub guard: &'l BudgetGuard,
    pub actor: WriteActor,
    pub parent_run: EntityId,
    pub inputs: BTreeMap<String, DelegatedSource>,
    pub bound: Scope,
    pub scope: Scope,
    pub ports: BTreeSet<String>,
    pub intent_key: String,
    pub ask: String,
}

/// What a launch came to.
pub enum ThingChildStart {
    /// The child is queued; its session serves its ports and reports its
    /// settlement.
    Launched(Box<dyn ThingChildSession>),
    /// Nothing was queued, for this reason.
    Unavailable(&'static str),
}

/// A launched child as its parent waits on it, inside its wake and while
/// its lease holds.
pub trait ThingChildSession {
    /// The child's run.
    fn child_run(&self) -> EntityId;

    /// The next port call the child makes, or its settlement; `None` when
    /// neither came within one collect beat.
    ///
    /// # Errors
    ///
    /// The route's own read errors.
    fn next(&mut self) -> PortFuture<'_, Result<Option<ThingChildEvent>>>;

    /// Stops serving the child: every later port call and model call of it
    /// is refused, and it settles with `code`.
    fn stop(&mut self, code: &'static str);

    /// Closes the count of the child's own generation on its parent's guard
    /// and returns the units it spent so far, for the parent to charge once
    /// (FIX 9015). A call admitted before the close that settles after it is
    /// never cancelled or lost: the host charges its terminal usage to the
    /// attempt's line when it settles, and the line holds it owed until then
    /// ([`crate::dreamer_runner::DreamerRunnerStore::owe_late_calls`]).
    fn close_generation(&self) -> u64;
}

/// What a waiting parent is handed.
pub enum ThingChildEvent {
    Port(ThingPortCall),
    Settled(ThingChildSettled),
}

/// A settled child: its state, why its wait is done, and its report's
/// bytes when it reported one.
pub struct ThingChildSettled {
    pub state: ReaderJobState,
    pub reason: Option<String>,
    pub report: Option<Vec<u8>>,
}

/// One port call, owned and already scoped: the lent input it names,
/// resolved by the child's own enforced read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThingPortRequest {
    Extract { input: String },
    Decide { pack: String },
}

/// A port's answer: the row's output, or its refusal code.
pub type ThingPortReply = std::result::Result<serde_json::Value, &'static str>;

/// One port call and where its answer goes.
pub struct ThingPortCall {
    request: ThingPortRequest,
    reply: Box<dyn FnOnce(ThingPortReply) + Send>,
}

impl ThingPortCall {
    #[must_use]
    pub fn new(request: ThingPortRequest, reply: Box<dyn FnOnce(ThingPortReply) + Send>) -> Self {
        Self { request, reply }
    }

    /// What the call asks.
    #[must_use]
    pub fn request(&self) -> &ThingPortRequest {
        &self.request
    }

    /// Answers the call.
    pub fn answer(self, reply: ThingPortReply) {
        (self.reply)(reply);
    }
}

#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_consolidation::thing_agent::{
    ThingDecideInput, ThingDecideOutput, ThingExtractInput, ThingExtractOutput, ThingProposalRef,
};
