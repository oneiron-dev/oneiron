//! Moved from `crates/oneiron/src/code_run/dispatcher/workflow_dispatch/operations.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::code_run::dispatcher::workflow_dispatch::operations::agent_definition::AgentCeilingInput;
pub use crate::code_run::dispatcher::workflow_dispatch::operations::agent_definition::AgentMcpInput;
pub use crate::code_run::dispatcher::workflow_dispatch::operations::agent_definition::AgentScopeInput;
pub use crate::code_run::dispatcher::workflow_dispatch::operations::agent_definition::AgentSkillInput;
use oneiron_authority::federation::ScopeAxis;
use oneiron_authority::federation::ScopeId;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MEMORY_CODE_INVALID_STATE;
use oneiron_contracts::memory::MEMORY_CODE_NOT_FOUND;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_run_budget::run_budget::DeclaredMaximum;
use oneiron_run_budget::run_budget::LeaseUnit;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::config::context_spec::ContextSpec;
use oneiron_store::gate_decision::types::GateDecisionId;
use oneiron_store::workflow_definition::WorkflowDefinition;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;

/// A new composition at a new WORKFLOW id. Each step names a live AGENT_DEF;
/// an occupied id is refused, never edited.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSaveRequest {
    pub workflow_ref: EntityId,
    pub name: String,
    pub steps: Vec<EntityId>,
}

/// An edit of exactly the revision the caller read; the door assigns the next.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowUpdateRequest {
    pub workflow_ref: EntityId,
    pub expected_revision: u64,
    pub name: String,
    pub steps: Vec<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRequest {
    pub workflow_ref: EntityId,
}

/// The saved revision. Steps are definition refs; a dispatch captures each
/// step's definition revision when it admits the run.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkflowView {
    pub workflow_ref: EntityId,
    pub name: String,
    pub steps: Vec<EntityId>,
    pub revision: u64,
    pub forked_from: Option<EntityId>,
}

/// Starts one run of a saved workflow as the owner: a root with no parent,
/// through the ordinary dispatch admission for every step. The briefing is
/// the work each step reads and grants no read scope; `context_spec` is a
/// request, resolved against each step's own scope. A retry with the same
/// intent key returns the same run; another request under it is refused.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDispatchRequest {
    pub workflow_ref: EntityId,
    pub intent_key: String,
    pub briefing: String,
    #[serde(default)]
    pub context_spec: Option<ContextSpec>,
    /// A TASK this run realizes: an idle standard task the owner owns, on
    /// the engine's runner lane, that no try realizes now. The run's root is
    /// its try and settles it when the run ends; the steps stay TASK-less.
    /// Absent, the run realizes no TASK.
    #[serde(default)]
    pub task_ref: Option<EntityId>,
}

/// Starts one run of a saved workflow that realizes a TASK, from a leased
/// agent run and as that agent (FIX 5316). The TASK is an idle standard
/// task the agent owns, on the engine's runner lane, that no try realizes
/// now; the run's root is its try and settles it when the run ends, and
/// the steps stay TASK-less. The try the run's lease holds is its real
/// parent: every step inherits that try's run, project, scope, context and
/// depth bounds, and the run spends under its lease tree. The briefing and
/// `context_spec` are as an owner's dispatch takes them. A retry with the
/// same intent key and request returns the same run; another request under
/// it is refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowBoundDispatchRequest {
    pub workflow_ref: EntityId,
    pub intent_key: String,
    pub briefing: String,
    #[serde(default)]
    pub context_spec: Option<ContextSpec>,
    pub task_ref: EntityId,
}

/// Starts one run of a saved workflow that realizes a TASK, as the member
/// whose own verified credential calls (FIX 5316). The TASK is an idle
/// standard task the member owns, on the engine's runner lane, that no try
/// realizes now; the run's root is its try and settles it when the run
/// ends, and the steps stay TASK-less. The member pays: the run is a root
/// whose spend scope opens under the cap they set and were shown, with them
/// as its payer, and a step this host cannot bill them for holds on the
/// owners' payer-needed ask, never on the owner's account. The TASK, the
/// workflow and each step's definition are read on the member's own lane.
/// Each step's context is what the member's own grants read of what
/// `context_spec` asks for: a row they do not read is left out, never
/// refused, and the step is told how many were. A retry with the same
/// intent key, request and terms returns the same run; another under it is
/// refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPersonDispatchRequest {
    pub workflow_ref: EntityId,
    pub intent_key: String,
    pub briefing: String,
    #[serde(default)]
    pub context_spec: Option<ContextSpec>,
    pub task_ref: EntityId,
    /// The most the run may spend, as the member set it: more than zero.
    pub cap_units: u64,
    /// The engine's named lease unit; a monetary line names its money unit.
    pub unit: String,
    /// When the member was shown `cap_units`, in host milliseconds.
    pub shown_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunRequest {
    pub root_attempt_ref: EntityId,
}

/// A settled step's attempt and the result it pinned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkflowStepRun {
    pub ordinal: usize,
    pub requested_agent_ref: EntityId,
    pub dispatched_agent_ref: EntityId,
    pub attempt_ref: EntityId,
    pub result_ref: String,
}
pub mod agent_definition;
