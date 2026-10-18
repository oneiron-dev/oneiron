//! The owner's planned spawn door (DOOR-111, slice 10): the owner launches
//! one reserved planned agent or team under an intent key.
//!
//! The ask is the one a leased parent's `self.agents.spawn` states: the
//! need, how much it matters, notes, and each knob seeded or pinned, every
//! token read by its own domain's parser. The engine reserves the intent,
//! places its type, plans it at the root and launches the plan, as
//! [`AgentDispatcher::launch_reserved_spawn_as_owner`] does; the same key
//! answers what it kept. A host that lends no planner is refused before
//! anything is reserved.

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::{AgentDispatcher, CareLevel, CoordinationPattern, SpawnOverride};
use crate::code_run::SelfSpawnAsk;
use crate::consent::AuthenticatedOwner;
use crate::llm::ModelId;
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult};
use crate::task_type::TaskTypeRef;
use crate::team::{
    PatternLaunchRunner, PlannedIntentView, PlannedSpawnHost, PlannedSpawnRequest, SpawnPhase,
};
use crate::{EntityId, Vault};

use super::super::door_reads::{entity, plan_view};
use super::{PlanObservation, TypeStamp};

const NO_PLANNER: &str =
    "this host serves no planner seats; nothing is reserved under this intent key";
const NO_PLANNER_FIX: &str = "Ask through a server whose [models.planner] seats name an AGENT_DEF this vault holds; the intent key is still free.";

/// One knob of the owner's ask (ARCH-0079 #seed-pin): a seed is where the
/// planner starts, weighted in runs; a pin is never overridden.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SpawnAskKnob<T> {
    Seed { value: T, weight_runs: f64 },
    Pin { value: T },
}

impl<T> SpawnAskKnob<T> {
    /// The engine's override, its value read by `read`, its weight or pin
    /// as given.
    fn into_override<U>(
        self,
        read: impl FnOnce(T) -> MemoryResult<U>,
    ) -> MemoryResult<SpawnOverride<U>> {
        Ok(match self {
            Self::Seed { value, weight_runs } => SpawnOverride::Seed {
                value: read(value)?,
                weight_runs,
            },
            Self::Pin { value } => SpawnOverride::Pin {
                value: read(value)?,
            },
        })
    }
}

/// One planned spawn the owner asks for: the key that names it, the work,
/// the type the owner asks for, and the ask the planner reads. Unset knobs
/// are the planner's. The same key with the same ask names the same intent;
/// the same key with another ask is refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpawnIntentRequest {
    /// The owner's key for this spawn.
    pub intent_key: String,
    /// The work itself, which the spawned agent reads as its briefing.
    pub prompt: String,
    /// The type the owner asks for: kept when the root tree holds it, else
    /// the engine places the need.
    #[serde(default)]
    pub requested_type: Option<TypeStamp>,
    /// What the owner needs, in one or two lines. The planner routes on it.
    pub need: String,
    /// How much it matters: `light`, `medium`, `high`, `xhigh` or `max`;
    /// inferred from the need when unset.
    #[serde(default)]
    pub care: Option<String>,
    /// Constraints and preferences (a model family, a time limit, ...).
    #[serde(default)]
    pub notes: Option<String>,
    /// The model, as `provider/name@revision`.
    #[serde(default)]
    pub model: Option<SpawnAskKnob<String>>,
    /// How many agents run it.
    #[serde(default)]
    pub width: Option<SpawnAskKnob<u32>>,
    /// Who decides: `solo`, `ceo_decides`, `committee`, `vote`, `market` or
    /// `rotation`.
    #[serde(default)]
    pub pattern: Option<SpawnAskKnob<String>>,
    /// The whole spawn's hard spend cap, in lease units. It only ever
    /// narrows what may be spent.
    #[serde(default)]
    pub budget_cap_units: Option<SpawnAskKnob<u64>>,
}

/// Where the owner's planned spawn stands: its phase, the type the engine
/// placed, the refusal it kept and, once launched, what launched. A
/// projection of the selected plan, not the whole plan receipt: the asked
/// need, the alternatives weighed, the care, effort and rung resolved and
/// the per-agent cost evidence stay in the receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpawnIntentReply {
    pub intent_key: String,
    pub phase: SpawnPhase,
    /// The stamp placed once; `None` when placement or the planner refused.
    #[serde(default)]
    pub placed: Option<TypeStamp>,
    /// Why placement, the planner or the launch refused, and what the owner
    /// can do next.
    #[serde(default)]
    pub refusal: Option<String>,
    /// The leader's queued attempt, or a solo's one agent; `None` until
    /// launched.
    #[serde(default)]
    pub root_attempt: Option<EntityId>,
    /// Each member's queued attempt, in launch order; empty for a solo and
    /// until launched.
    pub member_attempts: Vec<EntityId>,
    /// The team the launch bound; `None` for a solo and until launched.
    #[serde(default)]
    pub team_ref: Option<String>,
    /// The AGENT_DEF the plan seats; `None` with no plan.
    #[serde(default)]
    pub agent_def_ref: Option<EntityId>,
    /// The selected plan, frozen; `None` when placement or the planner
    /// refused.
    #[serde(default)]
    pub plan: Option<PlanObservation>,
}

/// Launches, as the owner, the planned spawn `input` asks for under its
/// intent key, on `host`'s planner: the intent is reserved, placed, planned
/// at the root and launched, a team through its pattern skill on `runner`,
/// and a replay of the key answers what it kept. Only the owner's proof,
/// the plan and the dispatcher's own admission bound the launch.
///
/// # Errors
///
/// `BAD_REQUEST` for a care, model or pattern its domain does not read;
/// `MODEL_UNAVAILABLE` with no `host`, before anything is reserved; a stale
/// owner proof; the engine's refusals, as
/// [`AgentDispatcher::launch_reserved_spawn_as_owner`] gives them; storage
/// errors.
pub fn spawn_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SpawnIntentRequest,
    host: Option<&PlannedSpawnHost<'_>>,
    runner: Option<&dyn PatternLaunchRunner>,
    at: u64,
) -> MemoryResult<SpawnIntentReply> {
    owner.revalidate(vault)?;
    let request = planned_request(input)?;
    let Some(host) = host else {
        return Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            NO_PLANNER,
            &[NO_PLANNER_FIX],
        ));
    };
    let view = AgentDispatcher::new(vault)
        .launch_reserved_spawn_as_owner(owner, &request, host, runner, at)?;
    reply_view(view)
}

/// The engine's request: each token read by its domain's parser, and every
/// seed weight and pin kept as given.
fn planned_request(input: SpawnIntentRequest) -> MemoryResult<PlannedSpawnRequest> {
    let ask = SelfSpawnAsk {
        need: input.need,
        care: input.care.as_deref().map(care).transpose()?,
        notes: input.notes,
        model: input
            .model
            .map(|knob| knob.into_override(model))
            .transpose()?,
        width: input.width.map(|knob| knob.into_override(Ok)).transpose()?,
        pattern: input
            .pattern
            .map(|knob| knob.into_override(pattern))
            .transpose()?,
        budget_cap_units: input
            .budget_cap_units
            .map(|knob| knob.into_override(Ok))
            .transpose()?,
    };
    Ok(PlannedSpawnRequest {
        intent_key: input.intent_key,
        ask,
        prompt: input.prompt,
        requested_type: input
            .requested_type
            .map(|stamp| TaskTypeRef::new(stamp.node_id, stamp.tree_version)),
    })
}

fn care(token: &str) -> MemoryResult<CareLevel> {
    CareLevel::from_token(token).map_err(|_| {
        MemoryError::bad_request_with(
            format!("care {token:?} is not a care level"),
            &["Name light, medium, high, xhigh or max, or leave care to the need."],
        )
    })
}

fn model(token: String) -> MemoryResult<ModelId> {
    ModelId::new(token.as_str()).map_err(|error| {
        MemoryError::bad_request_with(
            format!("model {token:?} is not a model id: {error}"),
            &["Name the model as provider/name@revision, or leave it to the planner."],
        )
    })
}

fn pattern(token: String) -> MemoryResult<CoordinationPattern> {
    CoordinationPattern::from_token(&token).map_err(|_| {
        MemoryError::bad_request_with(
            format!("pattern {token:?} is not a coordination pattern"),
            &[
                "Name solo, ceo_decides, committee, vote, market or rotation, or leave it to the planner.",
            ],
        )
    })
}

/// The intent as the wire carries it: the selected plan projected as the
/// spawn read projects it, and each attempt that launched as the entity id
/// its run carries.
fn reply_view(view: PlannedIntentView) -> MemoryResult<SpawnIntentReply> {
    Ok(SpawnIntentReply {
        intent_key: view.intent_key,
        phase: view.phase,
        placed: view.placed.as_ref().map(TypeStamp::from),
        refusal: view.refusal,
        root_attempt: view.root_attempt.map(entity).transpose()?,
        member_attempts: view
            .member_attempts
            .into_iter()
            .map(entity)
            .collect::<crate::error::Result<_>>()?,
        team_ref: view.team_ref,
        agent_def_ref: view.plan.as_ref().map(|plan| plan.plan.agent_def),
        plan: view.plan.as_ref().map(plan_view),
    })
}
