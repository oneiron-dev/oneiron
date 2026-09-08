//! Dispatch domain types, outcome enums, and pinned key/sentinel constants.

use serde::{Deserialize, Serialize};

use crate::agent_def::{AgentCeiling, AgentDefinition};
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::context_projection::ContextSpec;
use crate::entity_id::EntityId;
use crate::failure_ladder::HealerCase;

/// Payload-level attempt type carried inside the `"dreamer"` queue kind —
/// invisible to existing dreamer consumers, which match on their own types.
pub const AGENT_DISPATCH_ATTEMPT_TYPE: &str = "agent.dispatch";

/// Envelope-provenance key carrying the dispatched agent's label on
/// milestone claims (the B1 attribution home). The milestone machinery
/// STAMPS this key from the attempt payload at the admission door and the
/// durable index refuses milestones whose stamped value disagrees with the
/// payload — attribution cannot be forged to another agent.
pub const AGENT_DISPATCH_MILESTONE_AGENT_KEY: &str = "agent";

/// Stable logical id of the always-available generic base agent definition.
pub const DEFAULT_BASE_LOGICAL_ID: &str = "sys.default";

/// Pinned schema version of the dispatch input map; decode rejects others.
///
/// ONE-1709 bumps the codec ADDITIVELY, not by version: the three spawn keys
/// below are optional and default to absent, so a persisted schema-v1 row
/// decodes exactly as it did before this ticket, with `None`/empty defaults.
pub const AGENT_DISPATCH_INPUT_SCHEMA_VERSION: u64 = 1;

/// The pinned dispatch-input body keys (dreamer-payload-side snake_case).
pub const AGENT_DISPATCH_INPUT_KEYS: [&str; 8] = [
    "schema_version",
    "target",
    "agent_def",
    "preset",
    "definition",
    "context_spec",
    "context_from",
    "depth_remaining",
];

pub(super) const KEY_SCHEMA_VERSION: &str = AGENT_DISPATCH_INPUT_KEYS[0];

pub(super) const KEY_TARGET: &str = AGENT_DISPATCH_INPUT_KEYS[1];

pub(super) const KEY_AGENT_DEF: &str = AGENT_DISPATCH_INPUT_KEYS[2];

pub(super) const KEY_PRESET: &str = AGENT_DISPATCH_INPUT_KEYS[3];

pub(super) const KEY_DEFINITION: &str = AGENT_DISPATCH_INPUT_KEYS[4];

pub(super) const KEY_CONTEXT_SPEC: &str = AGENT_DISPATCH_INPUT_KEYS[5];

pub(super) const KEY_CONTEXT_FROM: &str = AGENT_DISPATCH_INPUT_KEYS[6];

pub(super) const KEY_DEPTH_REMAINING: &str = AGENT_DISPATCH_INPUT_KEYS[7];

/// Recursion budget every NEW ROOT dispatch persists when the caller names
/// none. Structural, not policy: the ceiling lattice bounds authority, this
/// bounds how many levels of it can exist at all. Admission additionally
/// CLAMPS the persisted root budget to [`CONTEXT_PROJECTION_MAX_ANCESTORS`],
/// so no stored lineage can exceed the ancestor-projection walk.
pub const AGENT_DISPATCH_ROOT_DEPTH_REMAINING: u8 = 8;

/// The configured compatibility cap for a parent whose persisted depth is
/// absent or unreadable — a schema-v1 row, or an attempt that is not an
/// agent dispatch at all. Such a parent yields children at `cap - 1`, so a
/// legacy lineage is bounded rather than unbounded.
pub const AGENT_DISPATCH_COMPAT_DEPTH_CAP: u8 = 4;

/// Domain separator for the deterministic attenuated-fork row id.
pub(super) const ATTENUATED_FORK_ID_DOMAIN: &[u8] = b"oneiron.agent_dispatch.attenuated_fork.v1";

pub(super) const TARGET_CUSTOM: &str = "custom";

/// Legacy `target` discriminant. DECODER-PRIVATE after ONE-1890: encode never
/// emits it again; it survives only so persisted pre-1890 dispatch rows stay
/// recoverable (crash-recovery carve-out to the no-legacy law).
pub(super) const TARGET_SYSTEM: &str = "system";

/// What a dispatch names: a stored AGENT_DEF row. Labels carry no authority —
/// actor identity at the gate is keyed on the entity id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDispatchTarget {
    Custom(EntityId),
}

/// The decoded dispatch payload: the target plus the composition snapshot
/// frozen at dispatch time.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentDispatchInput {
    pub target: AgentDispatchTarget,
    pub definition: AgentDefinition,
    /// Additive/defaulted. A DESCRIPTOR, resolved at dispatch — never a frozen
    /// projection, so a resumed agent reads fresh state.
    pub context_spec: Option<ContextSpec>,
    /// Additive/defaulted. SETTLED sibling TASK ids only — each must bind at
    /// dispatch to that task's `Completed` terminal result ref under the
    /// spawning parent attempt and run; deliberately kept separate from
    /// `context_spec`, because panel blindness relies on the separation.
    pub context_from: Vec<EntityId>,
    /// Additive/defaulted v1 compatibility field; every new root writes `Some`.
    /// LOAD-BEARING: [`AgentDispatcher::dispatch`] refuses to enqueue a child
    /// under a parent whose stored value is `Some(0)`.
    pub depth_remaining: Option<u8>,
}

impl AgentDispatchInput {
    /// The pre-ONE-1709 payload shape: no spawn context, no depth budget.
    #[must_use]
    pub const fn frozen(target: AgentDispatchTarget, definition: AgentDefinition) -> Self {
        Self {
            target,
            definition,
            context_spec: None,
            context_from: Vec::new(),
            depth_remaining: None,
        }
    }
}

/// The lead's typed spawn input: what a spawning agent contributes beyond the
/// target itself.
///
/// A side-struct rather than three more [`DispatchAgent`] fields, so ONE-1699's
/// and ONE-1700's dispatch call sites keep their exact literals. Every value
/// here is a REQUEST: the dispatcher clamps `depth_remaining` to the stored
/// parent budget and refuses a `context_spec` that widens the parent's.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentSpawnContext {
    pub context_spec: Option<ContextSpec>,
    pub context_from: Vec<EntityId>,
    pub depth_remaining: Option<u8>,
}

impl AgentSpawnContext {
    #[must_use]
    pub fn with_context_spec(mut self, spec: ContextSpec) -> Self {
        self.context_spec = Some(spec);
        self
    }

    #[must_use]
    pub fn with_context_from(mut self, context_from: Vec<EntityId>) -> Self {
        self.context_from = context_from;
        self
    }

    #[must_use]
    pub const fn with_depth_remaining(mut self, depth_remaining: u8) -> Self {
        self.depth_remaining = Some(depth_remaining);
        self
    }
}

/// The target a parented dispatch actually enqueued, after the live parent
/// ceiling clamped the requested child row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttenuatedDispatchTarget {
    pub target: AgentDispatchTarget,
    pub requested_definition_ref: EntityId,
    pub dispatched_definition_ref: EntityId,
    pub parent_ceiling: AgentCeiling,
    pub effective_child_ceiling: AgentCeiling,
    pub forked_for_attenuation: bool,
}

/// `min` over the two-point authority lattice: `Proposed` wins over `Auto`.
#[must_use]
pub const fn restrict_agent_ceiling(requested: AgentCeiling, parent: AgentCeiling) -> AgentCeiling {
    if requested.widens_beyond(parent) {
        parent
    } else {
        requested
    }
}

/// Caller input for [`AgentDispatcher::dispatch`].
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchAgent {
    pub target: AgentDispatchTarget,
    /// Run-tree branch parent (pass-through to the queue payload).
    pub parent_attempt: Option<AttemptId>,
    /// Caller dedupe key; namespaced at the queue level as
    /// `"agent.dispatch:" + key` so `Existing` always names an agent-dispatch
    /// row (M6 resolution 2026-07-10).
    ///
    /// ACCEPTED RESIDUAL: the prefix is forgeable — any caller of the open
    /// `DreamerRunnerStore::enqueue` API can preclaim a namespaced key with a
    /// non-dispatch payload, failing later dispatches on that one key
    /// (targeted dedupe DoS). Closing it would require hashing the attempt type
    /// into the queue-level dedupe key inside `attempt_queue.rs`, which is
    /// deliberately untouched (hypnos coordination wall). The residual is
    /// bounded: enqueue requires vault-local access — the same trust domain
    /// as dispatch itself per the D13 non-boundary ruling — and a preclaimed
    /// key surfaces as a typed `InvalidAgentDispatchInput` error, never a
    /// silent wrong-attempt reuse.
    pub dedupe_key: Option<String>,
    /// Pass-through run id; dispatch never mints one (host concern).
    pub run_id: Option<String>,
    /// Current wall-clock unix SECONDS chosen by the caller. Queue readiness
    /// timestamps (`ready_at`) are seconds, never milliseconds (E5).
    pub now: u64,
}

/// A dispatched (or deduped-existing) attempt row plus its decoded input.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentDispatchStatus {
    pub attempt: AttemptRecord,
    pub input: AgentDispatchInput,
}

/// Typed dispatch outcome mirroring the queue's enqueue outcome.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum AgentDispatchOutcome {
    Dispatched(AgentDispatchStatus),
    Existing(AgentDispatchStatus),
}

/// An unauthorized kill request parked for an authority decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillProposal {
    pub spawn_attempt_id: AttemptId,
    pub proposer: AttemptId,
}

/// Typed result of requesting cancellation of an agent spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KillOutcome {
    /// The spawn transitioned to `Cancelled` synchronously.
    Killed,
    /// A leased spawn received a durable cooperative interrupt request.
    CancellationRequested,
    /// The spawn was already terminal, so no kill effect occurred.
    AlreadyTerminal,
    Proposed(KillProposal),
}

/// Refusal reason for the configured-healer arm (ONE-1887 §5).
///
/// A configured healer needs the failing case's INDIVIDUALLY DURABLE refs —
/// the failing `attempt_id`, `evidence_ref`, `pre_fail_checkpoint_ref`, and
/// `qa_thread_ref`. This base exposes no reference-context seam that can carry
/// them: [`AgentDispatchInput::context_spec`] is a projection DESCRIPTOR and
/// [`AgentDispatchInput::context_from`] admits only SETTLED sibling TASK
/// results under the spawning parent attempt and run. Case material must never
/// be smuggled through `dedupe_key`, `run_id`, a briefing string, or a new
/// parallel queue payload, so the arm refuses until that seam lands rather
/// than dispatching a healer that cannot read its own case.
pub(super) const HEALER_REFERENCE_CONTEXT_SEAM_ABSENT: &str =
    "healer slot dispatch requires a durable reference-context seam this base does not expose";

/// Which healer a failure scope routes its cases to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealerSlot {
    /// The default slot until the configured ARCH-0066 healer agent exists. It
    /// is an explicit typed outcome, never a silently dropped case.
    Reserved,
    /// Lowercase-hex EntityId spelling.
    AgentDef { agent_def_ref: String },
}

/// Caller input for [`AgentDispatcher::dispatch_healer_slot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchHealer {
    pub slot: HealerSlot,
    pub case: HealerCase,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Typed healer-slot outcome.
#[derive(Debug, Clone, PartialEq)]
pub enum HealerSlotOutcome {
    Reserved { case: HealerCase },
    Dispatched(AgentDispatchStatus),
    Existing(AgentDispatchStatus),
}
