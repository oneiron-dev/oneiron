//! `dispatch(agent)` — AGENT-3 (ONE-1445, OF-334) over the OF-193 durable
//! runner substrate.
//!
//! Dispatch instantiates a saved [`AgentDefinition`](crate::agent_def::AgentDefinition) row as a durable
//! run-tree branch: it rides the dreamer runner queue
//! (kind `"dreamer"`, payload `job_type "agent.dispatch"`), inheriting BLAKE3
//! dedupe, atomic budgeted admission, lease-timeout recovery, park/resume and
//! durable milestone claims with zero new queue machinery. Authority
//! separation lives in the `WriteEnvelope` actor, never in queue plumbing.
//!
//! The one subtle rule (design D11): the definition's **composition** is
//! frozen into the payload at dispatch time — checkpoint/resume replays
//! exactly what was dispatched — while its **authority** (ceiling) is never
//! read from the snapshot; the gate resolves it live from the stored entity +
//! manifest at every write, so narrowing or revoking bites a running agent
//! immediately. The snapshot's embedded `ceiling` field is ignored uniformly.
//!
//! The dispatchability predicate here is a liveness/UX check, not a security
//! boundary: the queue and codec are `pub`, so a hand-crafted payload can be
//! enqueued around it — and is still bounded live by the envelope/gate
//! lattice.

mod agent_run;
mod attenuation;
mod budget_hold;
mod codec;
mod context;
mod dispatch;
mod fanout_statement;
mod healer_context;
mod healer_repair;
pub(crate) use healer_context::validate as validate_healer_case;
mod kill;
mod launch;
mod leader_planner;
mod leader_starter;
pub use leader_starter::{
    LeaderResponsibility, LeaderStarter, LeaderStarterSkills, LeaderTaskContext, LeaderTeamPlanner,
};
mod origin;
pub(crate) use origin::dispatch_origin_conversation;
mod planner;
mod planner_live;
mod project_conversation;
mod project_proposal;
mod resident;
mod room_join;
mod spend_calibration;
mod spend_lease;
mod spend_record;
mod task_type_tree;
mod team_shape;
mod team_stamp;
mod types;
mod widen;
mod widen_record;
mod workflow;
mod workflow_host;
mod workflow_pump;
mod workflow_record;

pub use workflow_record::{WorkflowDispatchStatus, WorkflowProgress, WorkflowStepResult};

#[cfg(test)]
mod workflow_tests;

pub use self::widen_record::ContextWidenProposal;
#[allow(unused_imports)] // The Coach's widen_denial_findings switches to the window.
pub(crate) use self::widen_record::{unlanded_widens_by_parent, unlanded_widens_by_parent_since};

pub use self::fanout_statement::{
    ExceptionalWidthCheck, FanoutCaller, FanoutStatement, FanoutWork, PeerCount, WidthCheckClass,
};
pub use self::project_conversation::ProjectConversationSkills;
pub use self::project_proposal::{ProjectDetection, ProjectDetectionRun};

pub use self::launch::{
    LaunchNode, LaunchPlan, LaunchRole, LaunchStatement, SpawnSpend, SpendCapView,
};
pub use self::spend_calibration::{
    AgentSpendCalibration, ExpectedSpend, LAUNCH_COST_PRIOR_UNITS, SpendBasis,
};
pub(crate) use self::spend_lease::payer_binds_in_txn;
pub use self::spend_record::{
    ChildSpend, SpendPayer, SpendRead, SpendRefused, SpendScope, SpendScopeId, SpendSettlement,
    SpendSignal, SpendState,
};

pub use self::budget_hold::{
    BudgetHoldLease, BudgetHoldNotice, BudgetHoldState, HeldAttempt, PartialResultHold,
};
pub use self::codec::{
    agent_dispatch_actor, agent_dispatch_payload_agent_id, decode_agent_dispatch_input,
    encode_agent_dispatch_input,
};
pub(crate) use self::codec::{attempt_task_type_ref, attempt_team_stamp, record_dispatch_input};
pub use self::dispatch::AgentDispatcher;
pub use self::leader_planner::VaultLeaderTeamPlanner;
pub use self::planner::{
    AvailableModel, CostEnvelope, MeasuredRate, PatternCandidate, PlanBudget, PlannerDecisions,
    PlannerEvidence, PlannerQuestionContext, PlannerRung, PlannerThresholds, ShapeQuote,
    SkillRevisionRef, SpawnPlanReceipt, TeamPlan, plan_spawn, plan_spawn_routed, planner_rung_for,
    resolve_care, top_shapes,
};
pub use self::planner_live::{LivePlanRequest, PlannerSeat, PlannerSkills};
pub(crate) use self::task_type_tree::load_team_type_tree_in_txn;
pub use self::task_type_tree::{
    TASK_TYPE_TREE_FILE, load_team_type_tree, store_team_type_tree, team_shape_skill_in_force,
};
pub use self::team_shape::{
    CoordinationPattern, TEAM_SHAPE_LESSONS, TEAM_SHAPE_SKILL_NAME, TeamShape, team_shape_skill,
};
pub use self::team_stamp::{TeamRunStamp, team_pattern};
pub use self::types::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AGENT_DISPATCH_COMPAT_DEPTH_CAP, AGENT_DISPATCH_INPUT_KEYS,
    AGENT_DISPATCH_INPUT_SCHEMA_VERSION, AGENT_DISPATCH_MILESTONE_AGENT_KEY, AgentDispatchInput,
    AgentDispatchOutcome, AgentDispatchStatus, AgentDispatchTarget, AgentSpawnContext,
    AttenuatedDispatchTarget, CareLevel, DEFAULT_BASE_LOGICAL_ID, DispatchAgent, DispatchHealer,
    HealerSlot, HealerSlotOutcome, KillOutcome, KillProposal, KillerLease, SpawnNeed,
    SpawnOverride, restrict_agent_ceiling,
};

#[cfg(test)]
mod kill_spawn_tests;
#[cfg(test)]
mod tests;

// The flat agent_dispatch.rs module used to provide these names to the sibling
// test module through `use super::*`: free helpers the tests name bare, and
// the crate imports the tests name bare. After the directory split the seam
// re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::attenuation::*;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::agent_def::{AgentDefinition, encode_agent_definition};
#[cfg(test)]
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptState,
    CancelStanding, InterveneAttempt,
};
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
#[cfg(test)]
use crate::context_projection::ContextSpec;
#[cfg(test)]
use crate::dreamer_runner::{DreamerAttemptPayload, DreamerRunnerStore};
#[cfg(test)]
use crate::edge::EdgeActorClass;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::failure_ladder::HealerCase;
#[cfg(test)]
use rmpv::Value;

pub use agent_run::AgentRun;
pub use resident::{ResidentAgentSpec, ResidentGoalRecord, ResidentWakeMode};

#[cfg(test)]
mod resident_tests;
