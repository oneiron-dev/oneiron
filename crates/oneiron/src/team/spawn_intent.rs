//! The owner's planned spawn under an intent key (DOOR-111): what the owner
//! asks, what the host serves the ask, and what the engine froze for it.
//!
//! [`crate::agent_dispatch::AgentDispatcher::plan_reserved_spawn_as_owner`]
//! reserves the intent, places its type and plans it at the root, and
//! launches nothing. A replay of the same key returns what it froze.
//! [`crate::agent_dispatch::AgentDispatcher::launch_reserved_spawn_as_owner`]
//! then launches the plan, a team through its pattern skill, and a replay
//! returns what launched.

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::{
    PlannerDecisions, PlannerSeat, PlannerSkills, SpawnPlanReceipt, SpawnSpend,
};
use crate::attempt_queue::AttemptId;
use crate::code_run::SelfSpawnAsk;
use crate::task_type::{PlacementDecisions, TaskTypeRef};

/// One planned spawn the owner asks for: the key that names it, the ask the
/// planner reads, the work itself and the type the owner asks for, if any.
/// The same key with the same ask names the same intent; the same key with
/// another ask is refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSpawnRequest {
    /// The owner's key for this spawn.
    pub intent_key: String,
    /// What the owner needs, with the knobs seeded or pinned. The planner
    /// routes on it.
    pub ask: SelfSpawnAsk,
    /// The work itself, which the spawned agent reads as its briefing.
    pub prompt: String,
    /// The type the owner asks for: kept when the root tree holds it, else
    /// the engine places the need.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_type: Option<TaskTypeRef>,
}

/// What the host serves one owner's planned spawn: its seats, the planner's
/// skills, the executor it plans on (`model@revision`), its ladders for the
/// type placement and the shape pick, the root spend scope it opened, and
/// the placement adapter that places and plans the ask. Host configuration,
/// borrowed for one call.
pub struct PlannedSpawnHost<'a> {
    /// The seats the spawn may run on: a model and its AGENT_DEF each.
    pub seats: &'a [PlannerSeat],
    /// The team-shape skill and each rung's workflow skill.
    pub skills: &'a PlannerSkills,
    /// The `model@revision` the host plans on. A root's skill reads stamp
    /// no manifest, so nothing records it yet.
    pub executor: &'a str,
    /// The host's ladder for the type placement; unset, the placement
    /// skill's rule rung reads alone.
    pub placement: Option<&'a PlacementDecisions<'a>>,
    /// The host's ladder for the shape pick; unset, the deterministic plan
    /// answers.
    pub planner: Option<&'a PlannerDecisions<'a>>,
    /// The root spend scope the launch is stated under; unset, unmetered.
    pub spend: Option<&'a SpawnSpend>,
    /// The adapter that places and plans the ask.
    pub placement_adapter: &'a str,
    /// The adapter's own idempotency key, when it keeps one. Only a keyed
    /// adapter may resume an intent a crash left in flight, and only under
    /// the same adapter and key.
    pub placement_key: Option<&'a str>,
}

/// Where the owner's spawn stands: a planned intent before or at its
/// launch, or a spawned agent the queue holds, which the spawn observation
/// reads as launched. In flight or in doubt is no stand: the owner is
/// refused and asks again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpawnPhase {
    /// Placed and planned: the stamp and the plan are frozen, and nothing
    /// launched yet.
    Planned,
    /// Queued: the leader and each member, bound as one team, or a solo's
    /// one agent.
    Launched,
    /// Placement, the planner or the launch refused; the refusal is kept.
    Refused,
}

/// What one planned intent holds for its owner: its key, its phase, the
/// type the engine placed and the plan it froze, the refusal it kept, and
/// once launched, what launched.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedIntentView {
    pub intent_key: String,
    pub phase: SpawnPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placed: Option<TaskTypeRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<SpawnPlanReceipt>,
    /// Why placement, the planner or the launch refused, and what the owner
    /// can do next.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// The leader's queued attempt, or a solo's one agent; `None` until
    /// launched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_attempt: Option<AttemptId>,
    /// Each member's queued attempt, in launch order; empty for a solo and
    /// until launched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_attempts: Vec<AttemptId>,
    /// The team the launch bound; `None` for a solo and until launched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_ref: Option<String>,
}
