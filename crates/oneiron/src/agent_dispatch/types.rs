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
pub const AGENT_DISPATCH_INPUT_KEYS: [&str; 19] = [
    "schema_version",
    "target",
    "agent_def",
    "preset",
    "definition",
    "context_spec",
    "context_from",
    "depth_remaining",
    "project_ref",
    "spawn_intent",
    "scope",
    "healer_case",
    "task_type_ref",
    "budget",
    "launch",
    "origin_conversation",
    "room",
    "join",
    "team",
];

pub(super) const KEY_SCHEMA_VERSION: &str = AGENT_DISPATCH_INPUT_KEYS[0];

pub(super) const KEY_TARGET: &str = AGENT_DISPATCH_INPUT_KEYS[1];

pub(super) const KEY_AGENT_DEF: &str = AGENT_DISPATCH_INPUT_KEYS[2];

pub(super) const KEY_PRESET: &str = AGENT_DISPATCH_INPUT_KEYS[3];

pub(super) const KEY_DEFINITION: &str = AGENT_DISPATCH_INPUT_KEYS[4];

pub(super) const KEY_CONTEXT_SPEC: &str = AGENT_DISPATCH_INPUT_KEYS[5];

pub(super) const KEY_CONTEXT_FROM: &str = AGENT_DISPATCH_INPUT_KEYS[6];

pub(super) const KEY_DEPTH_REMAINING: &str = AGENT_DISPATCH_INPUT_KEYS[7];

pub(super) const KEY_PROJECT_REF: &str = AGENT_DISPATCH_INPUT_KEYS[8];
pub(super) const KEY_SPAWN_INTENT: &str = AGENT_DISPATCH_INPUT_KEYS[9];
pub(super) const KEY_SCOPE: &str = AGENT_DISPATCH_INPUT_KEYS[10];
pub(super) const KEY_TASK_TYPE_REF: &str = AGENT_DISPATCH_INPUT_KEYS[12];
pub(super) const KEY_BUDGET: &str = AGENT_DISPATCH_INPUT_KEYS[13];
pub(super) const KEY_LAUNCH: &str = AGENT_DISPATCH_INPUT_KEYS[14];
/// OF-221: the conversation a root dispatch's host stamped as its origin.
pub(super) const KEY_ORIGIN_CONVERSATION: &str = AGENT_DISPATCH_INPUT_KEYS[15];
pub(super) const KEY_ROOM: &str = AGENT_DISPATCH_INPUT_KEYS[16];
pub(super) const KEY_JOIN: &str = AGENT_DISPATCH_INPUT_KEYS[17];
/// OF-540: the team run the dispatch works in.
pub(super) const KEY_TEAM: &str = AGENT_DISPATCH_INPUT_KEYS[18];

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
    /// Saved inert ordered composition; never an agent actor.
    Workflow(EntityId),
}

impl AgentDispatchTarget {
    /// Returns an agent identity only for an actual AGENT_DEF target.
    pub fn agent_definition_ref(&self) -> crate::error::Result<EntityId> {
        match self {
            Self::Custom(id) => Ok(*id),
            Self::Workflow(_) => Err(super::widen_record::invalid(
                "workflow is not an agent actor",
            )),
        }
    }
}

/// The decoded dispatch payload: the target plus the composition snapshot
/// frozen at dispatch time.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentDispatchInput {
    /// Typed reference-only diagnostic context, never a prompt or task patch.
    pub healer_case: Option<HealerCase>,
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
    /// LOAD-BEARING: [`AgentDispatcher::dispatch`](crate::agent_dispatch::AgentDispatcher::dispatch) refuses to enqueue a child
    /// under a parent whose stored value is `Some(0)`.
    pub depth_remaining: Option<u8>,
    /// The responsibility space whose live depth row bounds this spawn.
    pub project_ref: Option<EntityId>,
    /// Hash of the normalized caller request, separate from the live depth snapshot.
    pub spawn_intent: Option<String>,
    /// Exact branch-resource restriction, never a replacement for live authority.
    /// An absent value grants no branch-resource access.
    pub scope: Option<crate::llm::Scope>,
    /// OF-543 ONE TASK TYPE stamp, placed once at spawn. Required: every
    /// spawn carries a `typeRef`, and an unsure placement is the root —
    /// never an absent/untyped spawn.
    pub type_ref: crate::task_type::TaskTypeRef,
    /// The spawn's requested `budget` (OF-532): a hard carve under the parent's
    /// cap, in the parent scope's unit.
    pub budget: Option<u64>,
    /// The launch statement frozen at launch (OF-532): agent count, expected
    /// spend and cap, as the caller saw them. The cost part of the spawn
    /// receipt.
    pub launch: Option<super::LaunchStatement>,
    /// The room the launch works in (OF-531), as the spawn asked.
    pub room: Option<crate::workspace_roster::RoomWork>,
    /// The join receipt the launch re-proved in its own transaction (OF-531).
    pub join: Option<crate::workspace_roster::JoinReceiptRef>,
    /// OF-540: the team run this dispatch works in, frozen once at spawn.
    /// `None` is no team run; the terminal receipt stamps it otherwise.
    pub team: Option<super::TeamRunStamp>,
}

impl AgentDispatchInput {
    /// The pre-ONE-1709 payload shape: no spawn context, no depth budget.
    #[must_use]
    pub fn frozen(target: AgentDispatchTarget, definition: AgentDefinition) -> Self {
        Self {
            target,
            definition,
            healer_case: None,
            context_spec: None,
            context_from: Vec::new(),
            depth_remaining: None,
            project_ref: None,
            spawn_intent: None,
            scope: None,
            type_ref: crate::task_type::TaskTypeRef::seeded_root(),
            budget: None,
            launch: None,
            room: None,
            join: None,
            team: None,
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
    pub healer_case: Option<HealerCase>,
    pub context_spec: Option<ContextSpec>,
    pub context_from: Vec<EntityId>,
    pub depth_remaining: Option<u8>,
    pub project_ref: Option<EntityId>,
    /// None inherits the stored parent's resource restriction. A root with
    /// None has deny-all resource scope; ordinary non-resource calls still run.
    pub scope: Option<crate::llm::Scope>,
    /// OF-543: the placed task type, when the spawner (or the placement
    /// skill it routed) already placed this spawn. None means dispatch
    /// places it as the root — the unsure answer — never untyped.
    pub type_ref: Option<crate::task_type::TaskTypeRef>,
    /// The canon spawn table's `budget` (optional; set = pin): a hard carve
    /// under the parent's cap the child can never pass. Unset, the child holds
    /// its calibrated expected spend and may top up to the ancestor's cap.
    pub budget: Option<u64>,
    /// A ROOT launch's spend scope. A child spends under its parent's and
    /// never names one. A root without one runs unmetered by any lease tree.
    pub spend: Option<super::SpawnSpend>,
    /// OF-221: the conversation whose request starts this work, stamped by
    /// the host at its admission boundary. Read for a root only; a child
    /// always inherits its parent's stored origin, so a spawning agent can
    /// never name one.
    pub origin_conversation: Option<EntityId>,
    /// The room the agent works in (OF-531). Set, the launch re-proves the
    /// agent's join there before it reserves or enqueues; unset, nothing
    /// changes.
    pub room: Option<crate::workspace_roster::RoomWork>,
    /// OF-540: the team run this spawn works in. Set wins, so a nested team
    /// names its own; None keeps the parent's frozen stamp, and a root
    /// without one is no team run.
    pub team: Option<super::TeamRunStamp>,
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
    pub fn with_project(mut self, project_ref: EntityId) -> Self {
        self.project_ref = Some(project_ref);
        self
    }

    pub const fn with_depth_remaining(mut self, depth_remaining: u8) -> Self {
        self.depth_remaining = Some(depth_remaining);
        self
    }

    #[must_use]
    pub fn with_type_ref(mut self, type_ref: crate::task_type::TaskTypeRef) -> Self {
        self.type_ref = Some(type_ref);
        self
    }

    #[must_use]
    pub const fn with_budget(mut self, budget: u64) -> Self {
        self.budget = Some(budget);
        self
    }

    #[must_use]
    pub fn with_spend(mut self, spend: super::SpawnSpend) -> Self {
        self.spend = Some(spend);
        self
    }

    #[must_use]
    pub const fn with_origin_conversation(mut self, conversation: EntityId) -> Self {
        self.origin_conversation = Some(conversation);
        self
    }

    #[must_use]
    pub fn with_team(mut self, team: super::TeamRunStamp) -> Self {
        self.team = Some(team);
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

/// Caller input for [`AgentDispatcher::dispatch`](crate::agent_dispatch::AgentDispatcher::dispatch).
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
    /// Context widening is parked; no child has been enqueued.
    ProposedWiden(Box<super::ContextWidenProposal>),
    WorkflowDispatched(Box<super::WorkflowDispatchStatus>),
    WorkflowExisting(Box<super::WorkflowDispatchStatus>),
}

impl AgentDispatchOutcome {
    /// The launch statement frozen at launch: what the caller is told before
    /// the work runs. `None` for a parked widening, which launched nothing.
    #[must_use]
    pub fn launch(&self) -> Option<&super::LaunchStatement> {
        match self {
            Self::Dispatched(status) | Self::Existing(status) => status.input.launch.as_ref(),
            Self::WorkflowDispatched(status) | Self::WorkflowExisting(status) => {
                status.launch.as_ref()
            }
            Self::ProposedWiden(_) => None,
        }
    }
}

/// The lease a killing attempt holds: what its claim returned. A spawner
/// kills only while it is the runtime executing its attempt, so it names the
/// lease it runs under, not just the attempt id every queue read shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillerLease {
    pub attempt: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
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

/// Which healer a failure scope routes its cases to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealerSlot {
    /// No healer: the case goes only to the human surface. It is an explicit
    /// typed outcome, never a silently dropped case.
    Reserved,
    /// The Coach, the second base agent (ARCH-0066 #coach): the default slot.
    /// The case also wakes one Coach heal attempt on the Dreamer's runner.
    Coach,
    /// Lowercase-hex EntityId spelling.
    AgentDef { agent_def_ref: String },
}

/// Caller input for [`AgentDispatcher::dispatch_healer_slot`](crate::agent_dispatch::AgentDispatcher::dispatch_healer_slot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchHealer {
    pub slot: HealerSlot,
    pub case: HealerCase,
    pub run_id: Option<String>,
    pub now: u64,
}

/// How much a spawn cares (ARCH-0079 #spawn): the same five words vendors
/// use for reasoning effort, so a model reads `care: xhigh` without
/// explanation. On one call it sets reasoning effort; on a spawn the planner
/// reads it with the need and the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CareLevel {
    Light,
    Medium,
    High,
    #[serde(rename = "xhigh")]
    XHigh,
    Max,
}

impl CareLevel {
    /// Every care level, cheapest first.
    pub const ALL: [Self; 5] = [
        Self::Light,
        Self::Medium,
        Self::High,
        Self::XHigh,
        Self::Max,
    ];

    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Medium => "medium",
            Self::High => "high",
            Self::XHigh => "xhigh",
            Self::Max => "max",
        }
    }

    /// Parse a wire token.
    pub fn from_token(token: &str) -> crate::error::Result<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "light" => Ok(Self::Light),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "xhigh" => Ok(Self::XHigh),
            "max" => Ok(Self::Max),
            _ => Err(super::widen_record::invalid("unknown care level")),
        }
    }

    /// Ladder position, 0 (light) to 4 (max).
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Light => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::XHigh => 3,
            Self::Max => 4,
        }
    }

    /// The reasoning effort one call at this care level runs. The effort
    /// ladder tops out at `xhigh`, so `max` care spends its extra care on
    /// team shape and budget instead.
    #[must_use]
    pub const fn reasoning_effort(self) -> crate::llm::ReasoningEffort {
        match self {
            Self::Light => crate::llm::ReasoningEffort::Low,
            Self::Medium => crate::llm::ReasoningEffort::Medium,
            Self::High => crate::llm::ReasoningEffort::High,
            Self::XHigh | Self::Max => crate::llm::ReasoningEffort::XHigh,
        }
    }
}

/// One spawn field as the parent set it (ARCH-0079 #seed-pin): a seed sets
/// where the planner starts, with a weight counted in runs; a pin fixes the
/// value and the planner never overrides it. Unset fields are the planner's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SpawnOverride<T> {
    Seed { value: T, weight_runs: f64 },
    Pin { value: T },
}

impl<T> SpawnOverride<T> {
    #[must_use]
    pub const fn value(&self) -> &T {
        match self {
            Self::Seed { value, .. } | Self::Pin { value } => value,
        }
    }

    #[must_use]
    pub const fn is_pin(&self) -> bool {
        matches!(self, Self::Pin { .. })
    }

    /// Prior weight in runs; a pin is a seed of infinite weight.
    #[must_use]
    pub fn weight_runs(&self) -> f64 {
        match self {
            Self::Seed { weight_runs, .. } => *weight_runs,
            Self::Pin { .. } => f64::INFINITY,
        }
    }
}

/// What a parent says when it spawns (ARCH-0079 #spawn): the required need,
/// separate from the prompt, plus optional care, notes and seeded or pinned
/// model, width, pattern and budget. The planner routes on the need and
/// fills in everything unset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpawnNeed {
    /// What the parent needs, in one or two lines. Required, non-blank.
    pub need: String,
    /// How much the parent cares; inferred from the need when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub care: Option<CareLevel>,
    /// Constraints and preferences (a model family, a time limit, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// The task's ONE TASK TYPE stamp (OF-543), the planner-card key; an
    /// absent or unknown type reads the root card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<SpawnOverride<crate::llm::ModelId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<SpawnOverride<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<SpawnOverride<super::team_shape::CoordinationPattern>>,
    /// Hard spend cap for the whole spawn, in lease units. A seed or pin
    /// here only ever narrows the caller's budget, never widens it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_cap_units: Option<SpawnOverride<u64>>,
}

impl SpawnNeed {
    #[must_use]
    pub fn new(need: impl Into<String>) -> Self {
        Self {
            need: need.into(),
            care: None,
            notes: None,
            task_type: None,
            model: None,
            width: None,
            pattern: None,
            budget_cap_units: None,
        }
    }

    /// The door every planner entry runs first: the need is required and
    /// non-blank, a width override names at least one agent, and a seed
    /// weight is a positive finite run count.
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.need.trim().is_empty() {
            return Err(super::widen_record::invalid("spawn need is required"));
        }
        if let Some(width) = &self.width
            && *width.value() == 0
        {
            return Err(super::widen_record::invalid(
                "spawn width must be at least 1",
            ));
        }
        let weights = [
            self.model.as_ref().map(SpawnOverride::weight_runs),
            self.width.as_ref().map(SpawnOverride::weight_runs),
            self.pattern.as_ref().map(SpawnOverride::weight_runs),
            self.budget_cap_units
                .as_ref()
                .map(SpawnOverride::weight_runs),
        ];
        if weights
            .into_iter()
            .flatten()
            .any(|w| w != f64::INFINITY && (!w.is_finite() || w <= 0.0))
        {
            return Err(super::widen_record::invalid(
                "spawn seed weight must be positive",
            ));
        }
        Ok(())
    }

    /// The pinned model, when the parent pinned one.
    #[must_use]
    pub fn pinned_model(&self) -> Option<&crate::llm::ModelId> {
        self.model
            .as_ref()
            .filter(|o| o.is_pin())
            .map(SpawnOverride::value)
    }

    /// The pinned width, when the parent pinned one.
    #[must_use]
    pub fn pinned_width(&self) -> Option<u32> {
        self.width
            .as_ref()
            .filter(|o| o.is_pin())
            .map(|o| *o.value())
    }

    /// The pinned pattern, when the parent pinned one.
    #[must_use]
    pub fn pinned_pattern(&self) -> Option<super::team_shape::CoordinationPattern> {
        self.pattern
            .as_ref()
            .filter(|o| o.is_pin())
            .map(|o| *o.value())
    }
}

/// Typed healer-slot outcome.
#[derive(Debug, Clone, PartialEq)]
pub enum HealerSlotOutcome {
    Reserved {
        case: HealerCase,
    },
    /// The case, for the human surface, and the Coach heal attempt it woke
    /// (or the one an earlier route of the same case already woke).
    Coach {
        case: HealerCase,
        attempt: crate::attempt_queue::AttemptId,
    },
    Dispatched(AgentDispatchStatus),
    Existing(AgentDispatchStatus),
}
