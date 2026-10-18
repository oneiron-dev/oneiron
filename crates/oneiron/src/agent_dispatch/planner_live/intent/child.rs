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
//! The exact pack a team's start ran on is frozen with that start (S4c-3),
//! for the owner's launch and a leased one alike. The team's leader reads
//! it here (S4c-5): its dispatch dedupe key names the intent, and a retry
//! or continuation of it, which carries the same key, leads the same team.
//! Its run reads the pattern from the snapshot, never from the skill's
//! current head, and records the pack on its own lease, once.

use std::collections::HashSet;

use serde::Serialize;

use crate::agent_dispatch::widen_record::invalid;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatcher, CommReach, LivePlanRequest, SpawnPlanReceipt,
    TeamRunStamp,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ManifestEntry, ManifestKind};
use crate::code_run::{SelfSpawnAsk, TaskExposure};
use crate::context_projection::ContextSpec;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::failure_ladder::HealerCase;
use crate::task_type::TaskTypeRef;
use crate::team::{LeasedSpawnRequest, PlannedIntentView, PlannedLeaderLaunch, PlannedSpawnHost};
use crate::workspace_roster::RoomWork;

use super::{Asker, INTENTS, IntentAsk, IntentName, IntentPhase, Reserved};

/// Domain of a leased intent's request digest.
const LEASED_ASK_DIGEST_CONTEXT: &str = "oneiron spawn leased intent ask v1";
/// A planned group's leader's dispatch dedupe key, past the dispatch's own
/// prefix: `planned:<intent row key hex>:leader`. A member's ends
/// `:member:<n>`, so it names no leader.
const LEADER_KEY_PREFIX: &str = ":planned:";
const LEADER_KEY_SUFFIX: &str = ":leader";

const LEADER_DAMAGED: &str = "this planned leader's launch is damaged: its intent is missing or \
     not launched, its launch queued another leader, or its team lacks the start or the frozen \
     pack; spawn the team again under a new intent key";
const PACK_DAMAGED: &str = "this planned leader's frozen pattern pack is not the revision its \
     plan froze, or its files no longer match their hash; nothing newer is loaded in its place; \
     spawn the team again under a new intent key";
const NOT_A_LEADER: &str = "this attempt leads no planned team, so there is no frozen pattern \
     pack to record for it; run it as the agent it is";
const NOT_THE_PACK: &str = "this exposure is not the planned leader's frozen pattern pack; expose \
     the pack its launch froze, under that skill and revision";
const LEASE_UNHELD: &str = "a planned leader's pack is recorded under its run's live lease; run \
     the leader under the lease its claim took";

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

    /// The planned team `leader` leads, as its launch froze it (DOOR-111
    /// S4c-5): the team, its members in launch order, the start the pattern
    /// runner wrote and the exact pack that start ran on, with where the
    /// leader's last fresh run put that pack's SKILL.md in its task. The
    /// leader's dispatch dedupe key names the intent, and a retry or
    /// continuation of the leader, which carries the same key, leads it too.
    /// `None` for an attempt that leads no planned team: a planned solo, a
    /// member carrying the same plan, or any other run.
    ///
    /// # Errors
    ///
    /// A damaged launch, never `None`: an intent the key names that is
    /// missing or not launched, a leader the launch did not queue, a team
    /// without its start or its pack, or a pack that is not its plan's
    /// revision or no longer holds the bytes it hashed; storage errors.
    pub fn planned_launch_for_leader(
        &self,
        leader: AttemptId,
    ) -> Result<Option<PlannedLeaderLaunch>> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(self
            .planned_leader_in_txn(&txn, leader)?
            .map(|(_, launch)| launch))
    }

    /// Records a planned leader's run on its own lease (DOOR-111 S4c-5), in
    /// one writer that proves the lease and reads the launch again: the
    /// frozen pack's manifest row, once (a row of the same skill and
    /// revision already on the attempt stands for it, since a manifest
    /// append keeps every row), the executor that runs it when the attempt
    /// names none yet, and `exposure`, where the run put the pack's SKILL.md
    /// in its task, which a continuation of the run reuses.
    ///
    /// # Errors
    ///
    /// An attempt that leads no planned team, or no longer holds the lease
    /// `leased` names; an exposure of anything but the frozen pack; as
    /// [`Self::planned_launch_for_leader`]; storage errors.
    pub fn record_planned_leader_run(
        &self,
        leased: &AttemptRecord,
        exposure: &TaskExposure,
        executor: &str,
        at: u64,
    ) -> Result<()> {
        let lease_owner = leased
            .lease_owner
            .as_deref()
            .ok_or_else(|| invalid(LEASE_UNHELD))?;
        let mut txn = self.vault.store.env.write_txn()?;
        let (key, launch) = self
            .planned_leader_in_txn(&txn, leased.id)?
            .ok_or_else(|| invalid(NOT_A_LEADER))?;
        let pack = &launch.pack;
        let entry = ManifestEntry::new(ManifestKind::Skill, pack.skill_id(), pack.version(), at);
        if exposure.skill != pack.entity()
            || exposure.revision != entry.wire_form()
            || exposure.start > exposure.end
        {
            return Err(invalid(NOT_THE_PACK));
        }
        self.vault
            .record_manifest_once_in_txn(&mut txn, leased, lease_owner, executor, entry)?;
        let mut row = INTENTS
            .get(&self.vault.store, &txn, &key)?
            .ok_or_else(|| invalid(LEADER_DAMAGED))?;
        row.leader_exposure = Some(exposure.clone());
        row.updated_at = at;
        INTENTS.put(&self.vault.store, &mut txn, &key, &row)?;
        txn.commit()?;
        Ok(())
    }

    /// The planned team `leader` leads and its intent's row key, read on
    /// `txn` as [`Self::planned_launch_for_leader`] reads it.
    fn planned_leader_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        leader: AttemptId,
    ) -> Result<Option<([u8; 32], PlannedLeaderLaunch)>> {
        let Some(record) = AttemptQueue::new(self.vault).get_in_txn(txn, leader)? else {
            return Ok(None);
        };
        let Some(key) = leader_intent_key(&record)? else {
            return Ok(None);
        };
        let row = INTENTS
            .get(&self.vault.store, txn, &key)?
            .filter(|row| row.phase == IntentPhase::Launched)
            .ok_or_else(|| invalid(LEADER_DAMAGED))?;
        let root = row.root_attempt.ok_or_else(|| invalid(LEADER_DAMAGED))?;
        if !self.leads_in_txn(txn, &record, root)? {
            return Err(invalid(LEADER_DAMAGED));
        }
        let pattern = row
            .plan
            .as_ref()
            .and_then(|plan| plan.plan.pattern_skill.as_ref());
        let (team_ref, start, pack) = match (row.team_ref, row.pattern_launch, row.pattern_pack) {
            // A planned solo leads no team.
            (None, None, None) => return Ok(None),
            (Some(team_ref), Some(start), Some(pack)) => (team_ref, start, pack),
            _ => return Err(invalid(LEADER_DAMAGED)),
        };
        let frozen = pattern.is_some_and(|pattern| {
            pattern.skill == pack.entity() && pattern.version == pack.version()
        });
        if !frozen || !pack.holds_body() {
            return Err(invalid(PACK_DAMAGED));
        }
        let launch = PlannedLeaderLaunch {
            team_ref,
            members: row.member_attempts,
            start,
            pack,
            exposure: row.leader_exposure,
        };
        Ok(Some((key, launch)))
    }

    /// Whether `attempt` is `root`, the leader its launch queued, or a retry
    /// or continuation of it: each try back through its predecessor carries
    /// the leader's dedupe key, and the walk reaches `root`.
    fn leads_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: &AttemptRecord,
        root: AttemptId,
    ) -> Result<bool> {
        let queue = AttemptQueue::new(self.vault);
        let mut seen = HashSet::new();
        let mut current = attempt.id;
        let mut previous = attempt.retry_of;
        while current != root {
            let Some(id) = previous else {
                return Ok(false);
            };
            if !seen.insert(id) {
                return Ok(false);
            }
            let Some(record) = queue.get_in_txn(txn, id)? else {
                return Ok(false);
            };
            if record.dedupe_key != attempt.dedupe_key {
                return Ok(false);
            }
            current = id;
            previous = record.retry_of;
        }
        Ok(true)
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

/// The intent row key a planned leader's dispatch dedupe key names; `None`
/// for an attempt queued under any other key, a member's included.
fn leader_intent_key(record: &AttemptRecord) -> Result<Option<[u8; 32]>> {
    let Some(hex) = record
        .dedupe_key
        .as_deref()
        .and_then(|key| key.strip_prefix(AGENT_DISPATCH_ATTEMPT_TYPE))
        .and_then(|key| key.strip_prefix(LEADER_KEY_PREFIX))
        .and_then(|key| key.strip_suffix(LEADER_KEY_SUFFIX))
    else {
        return Ok(None);
    };
    let key = blake3::Hash::from_hex(hex).map_err(|_| invalid(LEADER_DAMAGED))?;
    Ok(Some(*key.as_bytes()))
}
