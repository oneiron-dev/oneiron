//! The leased child's planned spawn (DOOR-111 S4c-1): a leased agent's
//! `self.agents.spawn` with an ask, reserved under its intent key before
//! anything places or plans it.
//!
//! The intent is the agent's, under its real parent attempt: the actor is
//! the one the parent's own dispatch runs as, and the row key frames that
//! attempt. The digest covers the original request only (the key, the ask
//! and the context as asked, on the parent's run), never the placed type or
//! the plan. Custody is committed before the parent's tree places the type
//! or its planner plans it, as the owner's is, and the reservation and the
//! settle each prove the parent's current lease and actor in their own
//! writer. A kept answer replays before anything places, asks a model,
//! rechecks the tree or admits depth. No owner proof stands in for the
//! agent.
//!
//! The exact pack a team's start ran on is frozen here with that start
//! (S4c-3), for the owner's launch and a leased one alike: the leader reads
//! its pattern from the snapshot, never from the skill's current head.

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::widen_record::invalid;
use crate::agent_dispatch::{
    AgentDispatcher, CommReach, LivePlanRequest, SpawnPlanReceipt, TeamRunStamp,
};
use crate::attempt_queue::AttemptRecord;
use crate::code_run::SelfSpawnAsk;
use crate::context_projection::ContextSpec;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::failure_ladder::HealerCase;
use crate::skill::LoadedSkillPack;
use crate::task_type::TaskTypeRef;
use crate::team::{LeasedSpawnRequest, PlannedIntentView, PlannedSpawnHost};
use crate::workspace_roster::RoomWork;

use super::{Asker, IntentAsk, IntentName, Reserved};

/// Domain of a leased intent's request digest.
const LEASED_ASK_DIGEST_CONTEXT: &str = "oneiron spawn leased intent ask v1";
/// Domain of a frozen pattern pack's body hash.
const PACK_BODY_CONTEXT: &str = "oneiron spawn frozen pattern pack body v1";

/// The original leased request as its digest reads it: the key, the planner
/// ask and the context as the agent asked for it, on its parent's run.
/// Never the placed type or the plan.
#[derive(Serialize)]
struct LeasedAsk<'a> {
    intent_key: &'a str,
    ask: &'a SelfSpawnAsk,
    type_ref: Option<&'a TaskTypeRef>,
    context_spec: Option<&'a ContextSpec>,
    context_from: &'a [EntityId],
    scope: Option<&'a crate::llm::Scope>,
    comm: Option<CommReach>,
    room: Option<RoomWork>,
    objectives: Option<&'a [String]>,
    depth_remaining: Option<u8>,
    project_ref: Option<EntityId>,
    budget: Option<u64>,
    team: Option<&'a TeamRunStamp>,
    healer_case: Option<&'a HealerCase>,
    run_id: Option<&'a str>,
}

/// The exact pattern pack a team's start ran on, frozen with that start
/// (DOOR-111 S4c-3): the entity that loaded, its `skill_id` and revision,
/// the admitted files as they loaded and their body hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenPatternPack {
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
struct FrozenPackFile {
    path: String,
    content: Vec<u8>,
}

impl FrozenPatternPack {
    /// The snapshot of `pack` as it loaded.
    pub(super) fn of(pack: &LoadedSkillPack) -> Self {
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
}

impl AgentDispatcher<'_> {
    /// A leased agent's planned spawn under its intent key (DOOR-111 S4c):
    /// the engine reserves the intent under the agent's real parent
    /// attempt, places its type once against the tree that parent works in,
    /// plans it on the live planner over the parent's lease, and freezes the
    /// placed stamp and the plan receipt. Nothing launches. The same key with
    /// the same request returns what was frozen, a kept refusal or a launch
    /// included, and never plans again.
    ///
    /// `leased` is the parent's live attempt under the lease the caller
    /// holds, and `actor` the agent the caller runs: the parent's own
    /// dispatch must run as it. `host` is the planner the host lends the
    /// run; a leased spawn spends under its parent's scope and names no root
    /// spend. A placement or planner refusal is kept and returned as the
    /// view's refusal, not as an error.
    ///
    /// # Errors
    ///
    /// A parent that no longer holds its lease or runs as another actor; a
    /// blank key or need; a host that names a root spend; a key that names
    /// another request; an intent in doubt, or in flight under another
    /// placement adapter or key; custody another call took; storage errors.
    pub fn plan_reserved_spawn_for_attempt(
        &self,
        leased: &AttemptRecord,
        actor: &EntityId,
        request: &LeasedSpawnRequest,
        host: &PlannedSpawnHost<'_>,
        at: u64,
    ) -> Result<PlannedIntentView> {
        check_leased_request(request, host)?;
        let name = IntentName::leased(leased, actor, request)?;
        let reservation = match self.reserve_planned_intent_for_attempt(&name, request, host, at)? {
            Reserved::Answered(view) => return Ok(*view),
            Reserved::Custody(reservation) => reservation,
        };
        // Custody is committed: no writer is held while placement and the
        // planner may ask a model.
        let placed = self.place_and_plan_for_attempt(leased, request, host, at);
        self.settle_placed_and_planned(&name, &reservation, placed, at)
    }

    /// Reserves the intent `name` names under the leased parent, in one
    /// writer, as the owner's is reserved: the parent's lease and actor
    /// first, then the key. The row keeps the agent's key and ask, the
    /// parent and the project it works in.
    fn reserve_planned_intent_for_attempt(
        &self,
        name: &IntentName<'_>,
        request: &LeasedSpawnRequest,
        host: &PlannedSpawnHost<'_>,
        at: u64,
    ) -> Result<Reserved> {
        let ask = || IntentAsk::Leased {
            intent_key: request.intent_key.clone(),
            ask: request.ask.clone(),
        };
        self.reserve_planned_intent(name, ask, host, at)
    }

    /// Places the request's type once against the tree the parent works
    /// in, the requested stamp kept when that tree holds it, then plans the
    /// ask at that stamp over the parent's lease, as a leased planned spawn
    /// always has. Runs only under custody, with no writer held.
    fn place_and_plan_for_attempt(
        &self,
        leased: &AttemptRecord,
        request: &LeasedSpawnRequest,
        host: &PlannedSpawnHost<'_>,
        at: u64,
    ) -> Result<(TaskTypeRef, SpawnPlanReceipt)> {
        let placed = self.place_spawn_type(
            leased,
            &request.ask.need,
            request.context.type_ref.as_ref(),
            host.placement,
        )?;
        let plan = self.plan_spawn_for_attempt(
            leased,
            &LivePlanRequest {
                need: request.ask.clone().into_need(placed.clone()),
                seats: host.seats,
                skills: host.skills,
                executor: host.executor,
                decisions: host.planner,
            },
            at,
        )?;
        Ok((placed, plan))
    }

    /// The project a leased parent works in, once its current lease and
    /// actor are proved on `txn`: the writer's own proof, never a prior
    /// read's.
    pub(super) fn leased_root_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        leased: &AttemptRecord,
        actor: &EntityId,
    ) -> Result<EntityId> {
        self.live_planner_lease_in_txn(txn, leased, actor)?
            .project_ref
            .ok_or_else(|| {
                invalid(
                    "a leased planned spawn's parent works in no project; spawn from an agent \
                     dispatched into one",
                )
            })
    }
}

impl<'a> IntentName<'a> {
    /// The leased agent's intent `request` names under `leased`, its digest
    /// over the original request on the parent's run.
    pub(in super::super) fn leased(
        leased: &'a AttemptRecord,
        actor: &'a EntityId,
        request: &'a LeasedSpawnRequest,
    ) -> Result<Self> {
        Ok(Self {
            asker: Asker::Leased { leased, actor },
            intent_key: &request.intent_key,
            digest: leased_ask_digest(request, leased.run_id.as_deref())?,
        })
    }
}

/// The request's own shape, before anything is reserved: a key and a need,
/// and a host that names no root spend, since a leased spawn spends under
/// its parent's scope. Rule 5 caps no text.
fn check_leased_request(request: &LeasedSpawnRequest, host: &PlannedSpawnHost<'_>) -> Result<()> {
    if request.intent_key.trim().is_empty() {
        return Err(invalid("a planned spawn names its intent key"));
    }
    if request.ask.need.trim().is_empty() {
        return Err(invalid("a planned spawn states its need"));
    }
    if host.spend.is_some() {
        return Err(invalid(
            "a leased planned spawn spends under its parent's scope; its host names no root \
             spend scope",
        ));
    }
    Ok(())
}

/// The digest of the original leased request in its canonical encoding:
/// the key, the ask with its seeds and pins, and the context as the agent
/// asked for it, on its parent's run `run_id`.
fn leased_ask_digest(request: &LeasedSpawnRequest, run_id: Option<&str>) -> Result<[u8; 32]> {
    let context = &request.context;
    let asked = LeasedAsk {
        intent_key: &request.intent_key,
        ask: &request.ask,
        type_ref: context.type_ref.as_ref(),
        context_spec: context.context_spec.as_ref(),
        context_from: &context.context_from,
        scope: context.scope.as_ref(),
        comm: context.comm,
        room: context.room,
        objectives: context.objectives.as_deref(),
        depth_remaining: context.depth_remaining,
        project_ref: context.project_ref,
        budget: context.budget,
        team: context.team.as_ref(),
        healer_case: context.healer_case.as_ref(),
        run_id,
    };
    let asked = rmp_serde::to_vec_named(&asked)
        .map_err(|_| invalid("a leased planned spawn's request does not encode"))?;
    let mut hasher = blake3::Hasher::new_derive_key(LEASED_ASK_DIGEST_CONTEXT);
    hasher.update(&asked);
    Ok(*hasher.finalize().as_bytes())
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
