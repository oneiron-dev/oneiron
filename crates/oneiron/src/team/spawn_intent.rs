//! The owner's planned spawn under an intent key (DOOR-111): what the owner
//! asks, what the host serves the ask, and what the engine froze for it.
//!
//! [`crate::agent_dispatch::AgentDispatcher::plan_reserved_spawn_as_owner`]
//! reserves the intent, places its type and plans it at the root, and
//! launches nothing. A replay of the same key returns what it froze.
//! [`crate::agent_dispatch::AgentDispatcher::launch_reserved_spawn_as_owner`]
//! then launches the plan, a team through its pattern skill, and a replay
//! returns what launched.
//!
//! A leased agent's planned spawn reads the same way under its real parent
//! attempt (DOOR-111 S4c):
//! [`crate::agent_dispatch::AgentDispatcher::plan_reserved_spawn_for_attempt`]
//! reserves, places and plans it over the parent's lease, and
//! [`crate::agent_dispatch::AgentDispatcher::launch_planned_spawn_for_attempt`]
//! launches it under that attempt.
//!
//! A planned team's leader then reads what its launch froze (DOOR-111
//! S4c-5):
//! [`crate::agent_dispatch::AgentDispatcher::planned_launch_for_leader`]
//! answers its team, its members, the start and the exact pack that start
//! ran on, never the skill's current head.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::{
    AgentSpawnContext, PlannerDecisions, PlannerSeat, PlannerSkills, SpawnPlanReceipt, SpawnSpend,
};
use crate::attempt_queue::AttemptId;
use crate::code_run::{SelfSpawnAsk, TaskExposure};
use crate::entity_id::EntityId;
use crate::skill::LoadedSkillPack;
use crate::task_type::{PlacementDecisions, TaskTypeRef};

use super::PatternLaunchSpec;

/// Domain of a frozen pattern pack's body hash.
const PACK_BODY_CONTEXT: &str = "oneiron spawn frozen pattern pack body v1";

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

/// One planned spawn a leased agent asks for (DOOR-111 S4c): the key that
/// names it under the agent's real parent attempt, the ask the planner
/// reads, and the context the agent asks its child to run in. The same key
/// with the same request names the same intent; the same key with another
/// request is refused.
#[derive(Debug, Clone, PartialEq)]
pub struct LeasedSpawnRequest {
    /// The agent's key for this spawn.
    pub intent_key: String,
    /// What the agent needs, with the knobs seeded or pinned. The planner
    /// routes on it.
    pub ask: SelfSpawnAsk,
    /// The context the agent asks for: its briefing and projection, sibling
    /// results, scope, comm, room, objectives, depth, project, type and
    /// carve. The launch keeps it whole and stamps the plan, the type the
    /// plan read and the one cap on the leader.
    pub context: AgentSpawnContext,
}

/// What the host serves one planned spawn, the owner's or a leased
/// agent's: its seats, the planner's skills, the executor it plans on
/// (`model@revision`), its ladders for the type placement and the shape
/// pick, the root spend scope it opened, and the placement adapter that
/// places and plans the ask. Host configuration, borrowed for one call.
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
    /// A leased spawn spends under its parent's scope and names none.
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
    /// An erase of its asker or of the AGENT_DEF its plan seats took its
    /// text: it keeps its receipt, its ids and times, and never launches.
    Erased,
}

/// Whose erase left a planned spawn erased (Engine 10-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpawnErasure {
    /// The asker's.
    AskerErased,
    /// The AGENT_DEF its plan seats: a launch on it records this and
    /// launches nothing.
    TargetErased,
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
    /// Whose erase took the intent's text; `None` unless it is erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erasure: Option<SpawnErasure>,
}

/// The exact pattern pack a team's start ran on, frozen with that start
/// (DOOR-111 S4c-3): the entity that loaded, its `skill_id` and revision,
/// the admitted files as they loaded and their body hash. Only the engine
/// freezes one, and a planned leader's run reads its pattern from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenPatternPack {
    entity: EntityId,
    skill_id: String,
    version: String,
    /// The files, path and bytes; `None` for a native record-only skill,
    /// which has no file tree.
    files: Option<Vec<FrozenPackFile>>,
    body_hash: [u8; 32],
}

/// One admitted file of a frozen pack. Rule 5 caps no file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenPackFile {
    path: String,
    content: Vec<u8>,
}

impl FrozenPatternPack {
    /// The snapshot of `pack` as it loaded.
    pub(crate) fn of(pack: &LoadedSkillPack) -> Self {
        let files: Option<Vec<FrozenPackFile>> = pack.source_files.as_ref().map(|files| {
            files
                .iter()
                .map(|file| FrozenPackFile {
                    path: file.path.clone(),
                    content: file.content.clone(),
                })
                .collect()
        });
        Self {
            entity: pack.entity,
            skill_id: pack.record.skill_id.clone(),
            version: pack.record.version.clone(),
            body_hash: pack_body_hash(files.as_deref()),
            files,
        }
    }

    /// The skill entity that loaded.
    #[must_use]
    pub fn entity(&self) -> EntityId {
        self.entity
    }

    /// The `skill_id` that loaded.
    #[must_use]
    pub fn skill_id(&self) -> &str {
        &self.skill_id
    }

    /// The revision that loaded.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The admitted files in load order; `None` for a record-only skill.
    #[must_use]
    pub fn files(&self) -> Option<&[FrozenPackFile]> {
        self.files.as_deref()
    }

    /// BLAKE3 over the files as they loaded.
    #[must_use]
    pub fn body_hash(&self) -> [u8; 32] {
        self.body_hash
    }

    /// Whether the files still hash to the body hash frozen with them.
    pub(crate) fn holds_body(&self) -> bool {
        pack_body_hash(self.files.as_deref()) == self.body_hash
    }
}

impl FrozenPackFile {
    /// The file's path in the pack.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The file's bytes as they loaded.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

/// What a planned team's leader leads, as its launch froze it (DOOR-111
/// S4c-5): the team the launch bound, each member it queued in launch
/// order, the start the pattern runner wrote and the exact pack that start
/// ran on. The leader's run reads its pattern from this snapshot, never
/// from the skill's current head. An erased intent's team keeps its ids and
/// no start or pack (Engine 10-22).
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedLeaderLaunch {
    /// The leader try the launch queued, which the team is bound under; a
    /// retry or continuation of it leads the same team.
    pub root: AttemptId,
    pub team_ref: String,
    pub members: Vec<AttemptId>,
    /// `None` once an erase took the intent's text.
    pub start: Option<PatternLaunchSpec>,
    /// `None` once an erase took the intent's text.
    pub pack: Option<FrozenPatternPack>,
    /// Where each of the leader's runs put the pack's SKILL.md in its task,
    /// by its executor run id; empty until one has. A continued run, whose
    /// task is its source run's fork, reuses its source's rather than append
    /// the body again.
    pub exposures: BTreeMap<EntityId, TaskExposure>,
    /// The span each of those runs' exposures named, by its executor run id,
    /// once an erase took the pack; empty while the pack stands.
    pub erased_pack_spans: BTreeMap<EntityId, ErasedPackSpan>,
}

/// Where a leader run's task held the frozen pack's SKILL.md, as an erased
/// intent keeps it (FIX 11787): the byte span, separator included, and the
/// hash of those bytes, with no skill, revision or text. A continuation
/// claimed after the erase reads no pack, and its task, its source run's
/// fork, still holds the text there; the span lets it lay a tombstone over
/// exactly those bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasedPackSpan {
    pub start: usize,
    pub end: usize,
    /// BLAKE3 of the task bytes in `start..end`.
    pub content_hash: [u8; 32],
}

impl From<&TaskExposure> for ErasedPackSpan {
    fn from(exposure: &TaskExposure) -> Self {
        Self {
            start: exposure.start,
            end: exposure.end,
            content_hash: exposure.content_hash,
        }
    }
}

/// A frozen pack's body hash: BLAKE3 over its files, each path and its
/// bytes framed, in load order; a record-only pack frames none.
fn pack_body_hash(files: Option<&[FrozenPackFile]>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PACK_BODY_CONTEXT);
    match files {
        None => {
            hasher.update(&[0]);
        }
        Some(files) => {
            hasher.update(&[1]);
            hasher.update(&(files.len() as u64).to_be_bytes());
            for file in files {
                hasher.update(&(file.path.len() as u64).to_be_bytes());
                hasher.update(file.path.as_bytes());
                hasher.update(&(file.content.len() as u64).to_be_bytes());
                hasher.update(&file.content);
            }
        }
    }
    *hasher.finalize().as_bytes()
}
