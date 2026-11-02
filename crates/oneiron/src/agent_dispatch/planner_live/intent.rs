//! The reserved spawn intent (DOOR-111 S2, S4c-1): a planned spawn, durable
//! under its asker's intent key.
//!
//! One row per framed (actor, parent, intent key): the owner's root intent
//! has no parent, and a leased agent's (`child`) names the real attempt it
//! spawns from. The row keeps the original ask and its digest, the
//! placement adapter that holds custody and the custody fence, and, once
//! settled, the placed stamp and the frozen plan receipt, or the refusal
//! placement or the planner gave. Custody is taken and committed before any
//! adapter or model call, no writer is held across one, and the settling
//! write lands only under the fence its custody was taken with. A leased
//! agent proves its parent's current lease and actor again in every writer
//! it acts through.
//!
//! A replay never plans again. The same key with another ask is refused; a
//! planned or refused intent answers what it kept. An intent found in flight
//! is never rerun (Engine ruling (b), 10-19): unkeyed, it is in doubt and the
//! asker asks again under a new key; under a keyed adapter, the same adapter
//! and key resume it under a fresh fence, so an older custody can no longer
//! settle it.
//!
//! A planned intent then launches (S4a, `team_launch`). A team's pattern
//! start is frozen first, with the exact pack it ran on, the first pair
//! frozen winning; the launched row, with the identities the launch queued,
//! is written in the launch's own group writer. A launched intent answers
//! them and never launches again. Its leader's run reads the frozen pack
//! from the row (`child`, S4c-5), and the row keeps, for each of the
//! leader's runs, where that run put the pack's SKILL.md in its task, which
//! a continuation of that run reuses.
//!
//! An actor's scrub forgets it as the asker of every intent it asked and
//! keeps the rest (FIX 4582): the forgotten asker can no longer replay,
//! settle or launch it, and one it left in flight is in doubt (FIX 5097).
//! Behind the permanent hard-delete marker, an erase of an intent's asker
//! or of the AGENT_DEF its plan seats leaves the intent's erased form
//! (`erase`): its ids and times and no text. A launch on it launches nothing.

mod child;
mod erase;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::code_run::{SelfSpawnAsk, TaskExposure};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::skill::LoadedSkillPack;
use crate::task_type::TaskTypeRef;
use crate::team::{
    ErasedPackSpan, FrozenPatternPack, PatternLaunchSpec, PlannedIntentView, PlannedSpawnHost,
    PlannedSpawnRequest, SpawnErasure, SpawnPhase,
};

use super::super::widen_record::invalid;
use super::super::{AgentDispatcher, SpawnPlanReceipt};
use super::LivePlanRequest;
use erase::put_intent_in_txn;

/// Domain of an intent's row key.
const INTENT_KEY_CONTEXT: &str = "oneiron spawn planned intent key v1";
/// Domain of an intent's ask digest.
const ASK_DIGEST_CONTEXT: &str = "oneiron spawn planned intent ask v1";

/// Framed (actor, parent, intent key) → the intent it names.
const INTENTS: SideTable<[u8; 32], PlannedIntent, Named> =
    SideTable::new(&side_table::SPAWN_PLANNED_INTENT);

const DIFFERENT_ASK: &str = "this intent key already names a different ask; repeat that ask, \
     or ask under a new intent key";
const IN_DOUBT: &str = "this planned spawn was in flight when it was asked again and is in \
     doubt; it is never rerun, so ask again under a new intent key";
const HELD_ELSEWHERE: &str = "this planned spawn is in flight under another placement adapter \
     or key; resume it with that adapter and key, or ask under a new intent key";
const CUSTODY_LOST: &str = "another call took custody of this planned spawn before it settled; \
     ask again under the same intent key to read where it stands";

/// Where a stored intent stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IntentPhase {
    /// One call holds custody: placement or the planner may be asking a
    /// model.
    InFlight,
    /// An unkeyed call was in flight when the key was asked again, or its
    /// asker was erased while it was (FIX 5097). It may have run, so it is
    /// never rerun.
    InDoubt,
    Planned,
    /// Queued and bound in the launch's own writer. It never launches
    /// again.
    Launched,
    Refused,
    /// An erase of its asker or its plan's target took its text (`erase`).
    Erased,
}

impl From<SpawnPhase> for IntentPhase {
    fn from(phase: SpawnPhase) -> Self {
        match phase {
            SpawnPhase::Planned => Self::Planned,
            SpawnPhase::Launched => Self::Launched,
            SpawnPhase::Refused => Self::Refused,
            SpawnPhase::Erased => Self::Erased,
        }
    }
}

/// The original ask an intent keeps, as its asker gave it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IntentAsk {
    /// The owner's request.
    Owner(PlannedSpawnRequest),
    /// A leased agent's key and planner ask. The context it asked for rides
    /// the digest, and its launch reads it from the asking call.
    Leased {
        intent_key: String,
        ask: SelfSpawnAsk,
    },
}

impl IntentAsk {
    fn intent_key(&self) -> &str {
        match self {
            Self::Owner(request) => &request.intent_key,
            Self::Leased { intent_key, .. } => intent_key,
        }
    }
}

/// One stored intent, live or in its erased form, which keeps its ids and
/// times and none of its text (`erase`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedIntent {
    /// The asker: the owner, from the proof's revalidation, or the leased
    /// agent its parent's own dispatch runs as; `None` once an erase has
    /// forgotten it.
    actor: Option<EntityId>,
    /// The asker's erase selector (FIX 9182): a domain-separated hash of the
    /// asker's id, kept when a plain scrub forgets the asker, so a later hard
    /// erase of that asker still finds the intent. It names no one, confers
    /// nothing and is never shown; the asker's erase clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    asker_erase_key: Option<[u8; 32]>,
    /// The spawning attempt; an owner's root intent has none.
    parent: Option<AttemptId>,
    /// The original ask as its asker gave it, and its digest; neither once
    /// erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ask: Option<IntentAsk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ask_digest: Option<[u8; 32]>,
    /// The project the intent was reserved in: the root project, or the
    /// one the leased parent works in.
    project: EntityId,
    phase: IntentPhase,
    /// The custody the last reservation took: only it settles the intent.
    fence: [u8; 16],
    created_at: u64,
    updated_at: u64,
    /// The adapter that holds custody, and its own key when it keeps one.
    placement_adapter: String,
    placement_key: Option<String>,
    placed: Option<TaskTypeRef>,
    plan: Option<SpawnPlanReceipt>,
    refusal: Option<String>,
    /// A team's pattern start, frozen before it launches, and the exact
    /// pack it ran on, frozen with it as one pair.
    pattern_launch: Option<PatternLaunchSpec>,
    pattern_pack: Option<FrozenPatternPack>,
    /// Where each of a launched team's leader's runs put the frozen pack's
    /// SKILL.md in its task, by its executor run id (S4c-5). Each run
    /// writes its own, and a continuation reads its source run's.
    leader_exposures: BTreeMap<EntityId, TaskExposure>,
    /// Each of those runs' spans, text-free, once an erase took the
    /// exposures (`erase`); a continuation claimed after the erase
    /// tombstones its source run's.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    erased_pack_spans: BTreeMap<EntityId, ErasedPackSpan>,
    /// What the launch queued and bound: the leader, or a solo's one agent,
    /// each member in launch order, and the team.
    root_attempt: Option<AttemptId>,
    member_attempts: Vec<AttemptId>,
    team_ref: Option<String>,
    /// Whose erase took the intent's text; `None` while it is live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    erasure: Option<SpawnErasure>,
}

impl PlannedIntent {
    /// What a settled intent answers under `intent_key`, the key its asker
    /// names it by, which an erased intent no longer keeps. One in flight or
    /// in doubt has not settled.
    fn view(&self, intent_key: &str) -> Result<PlannedIntentView> {
        let phase = match self.phase {
            IntentPhase::Planned => SpawnPhase::Planned,
            IntentPhase::Launched => SpawnPhase::Launched,
            IntentPhase::Refused => SpawnPhase::Refused,
            IntentPhase::Erased => SpawnPhase::Erased,
            IntentPhase::InFlight | IntentPhase::InDoubt => return Err(invalid(CUSTODY_LOST)),
        };
        Ok(PlannedIntentView {
            intent_key: intent_key.to_owned(),
            phase,
            placed: self.placed.clone(),
            plan: self.plan.clone(),
            refusal: self.refusal.clone(),
            root_attempt: self.root_attempt,
            member_attempts: self.member_attempts.clone(),
            team_ref: self.team_ref.clone(),
            erasure: self.erasure,
        })
    }

    /// Whether this row holds the ask `name` names, its key and digest. An
    /// erased row keeps neither: its row key, which frames the asker, the
    /// parent and the key, names it.
    fn asks(&self, name: &IntentName<'_>) -> bool {
        self.phase == IntentPhase::Erased
            || (self
                .ask
                .as_ref()
                .is_some_and(|ask| ask.intent_key() == name.intent_key)
                && self.ask_digest == Some(name.digest))
    }
}

/// Who asks for an intent: the owner at the root, or a leased agent under
/// its real parent attempt, as the caller binds it.
#[derive(Clone, Copy)]
enum Asker<'a> {
    Owner(&'a AuthenticatedOwner),
    Leased {
        leased: &'a AttemptRecord,
        actor: &'a EntityId,
    },
}

/// One intent as its asker names it: who asks, under which key, and the
/// digest of the original ask.
pub(super) struct IntentName<'a> {
    asker: Asker<'a>,
    intent_key: &'a str,
    digest: [u8; 32],
}

impl<'a> IntentName<'a> {
    /// The owner's intent `request` names.
    pub(super) fn owner(
        owner: &'a AuthenticatedOwner,
        request: &'a PlannedSpawnRequest,
    ) -> Result<Self> {
        Ok(Self {
            asker: Asker::Owner(owner),
            intent_key: &request.intent_key,
            digest: ask_digest(request)?,
        })
    }
}

/// The custody one reservation took: the intent's row key and the fence it
/// settles under.
struct IntentReservation {
    key: [u8; 32],
    fence: [u8; 16],
}

/// What a reservation found: what the key already holds, or custody.
enum Reserved {
    Answered(Box<PlannedIntentView>),
    Custody(IntentReservation),
}

/// A planned intent a launch reads, under its row key and the key its asker
/// names it by.
pub(super) struct PlannedLaunch {
    key: [u8; 32],
    row: PlannedIntent,
    intent_key: String,
}

impl PlannedLaunch {
    /// The intent's key digest in hex, which the launch's dedupe keys and
    /// team reference carry.
    pub(super) fn digest_hex(&self) -> String {
        bytes_to_hex_lower(&self.key)
    }

    /// The plan the intent froze.
    pub(super) fn plan(&self) -> Result<&SpawnPlanReceipt> {
        self.row
            .plan
            .as_ref()
            .ok_or_else(|| invalid("a planned intent holds its plan"))
    }

    /// A team's pattern start, once one is frozen.
    pub(super) fn spec(&self) -> Option<&PatternLaunchSpec> {
        self.row.pattern_launch.as_ref()
    }

    /// Whether this read still holds what `read` was read with: the same
    /// custody fence, placed stamp and plan, and the same frozen start and
    /// pack.
    pub(super) fn holds_frozen(&self, read: &Self) -> bool {
        self.row.fence == read.row.fence
            && self.row.placed == read.row.placed
            && self.row.plan == read.row.plan
            && self.row.pattern_launch == read.row.pattern_launch
            && self.row.pattern_pack == read.row.pattern_pack
    }
}

/// Where a planned intent stands for its launch.
pub(super) enum LaunchStand {
    /// Still planned: the launch reads it.
    Planned(Box<PlannedLaunch>),
    /// Launched or refused since: what it kept.
    Settled(Box<PlannedIntentView>),
}

impl AgentDispatcher<'_> {
    /// The owner's planned spawn under an intent key (DOOR-111): the engine
    /// reserves the intent, places its type once against the root project's
    /// tree, plans it there, and freezes the placed stamp and the plan
    /// receipt. Nothing launches. The same key with the same ask returns
    /// what was frozen, a kept refusal or a launch included, and never plans
    /// again.
    ///
    /// Custody is committed before placement or the planner may ask a model,
    /// and no writer is held across either. A placement or planner refusal
    /// is kept and returned as the view's refusal, not as an error.
    ///
    /// # Errors
    ///
    /// An owner proof that no longer holds; a blank key, need or prompt; a
    /// key that names another ask; an intent in doubt, or in flight under
    /// another placement adapter or key; custody another call took; storage
    /// errors.
    pub fn plan_reserved_spawn_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: &PlannedSpawnRequest,
        host: &PlannedSpawnHost<'_>,
        at: u64,
    ) -> Result<PlannedIntentView> {
        check_request(request)?;
        let name = IntentName::owner(owner, request)?;
        let ask = || IntentAsk::Owner(request.clone());
        let reservation = match self.reserve_planned_intent(&name, ask, host, at)? {
            Reserved::Answered(view) => return Ok(*view),
            Reserved::Custody(reservation) => reservation,
        };
        // Custody is committed: no writer is held while placement and the
        // planner may ask a model.
        let placed = self.place_and_plan_as_owner(owner, request, host, at);
        self.settle_placed_and_planned(&name, &reservation, placed, at)
    }

    /// Reserves the intent `name` names, in one writer: the asker's proof
    /// first, then the key. A new key, or an in-flight one its keyed adapter
    /// resumes, takes custody under a fresh fence and commits. A settled key
    /// answers what it kept; an unkeyed call found in flight leaves the
    /// intent in doubt.
    fn reserve_planned_intent(
        &self,
        name: &IntentName<'_>,
        ask: impl FnOnce() -> IntentAsk,
        host: &PlannedSpawnHost<'_>,
        at: u64,
    ) -> Result<Reserved> {
        let mut txn = self.vault.store.env.write_txn()?;
        let (actor, parent, project) = self.asker_in_txn(&txn, name.asker)?;
        let key = intent_row_key(&actor, parent, name.intent_key);
        let fence = fresh_fence();
        let existing = INTENTS.get(&self.vault.store, &txn, &key)?;
        let mut reserved = match existing {
            None => PlannedIntent {
                actor: Some(actor),
                asker_erase_key: Some(erase::asker_erase_key(&actor)),
                parent,
                ask: Some(ask()),
                ask_digest: Some(name.digest),
                project,
                phase: IntentPhase::InFlight,
                fence,
                created_at: at,
                updated_at: at,
                placement_adapter: host.placement_adapter.to_owned(),
                placement_key: host.placement_key.map(str::to_owned),
                placed: None,
                plan: None,
                refusal: None,
                pattern_launch: None,
                pattern_pack: None,
                leader_exposures: BTreeMap::new(),
                erased_pack_spans: BTreeMap::new(),
                root_attempt: None,
                member_attempts: Vec::new(),
                team_ref: None,
                erasure: None,
            },
            // An intent whose asker an erase forgot is no longer this
            // asker's.
            Some(row) if row.actor != Some(actor) || row.parent != parent || !row.asks(name) => {
                return Err(invalid(DIFFERENT_ASK));
            }
            Some(row) => {
                let phase = row.phase;
                match phase {
                    // A settled or erased intent answers what it kept.
                    IntentPhase::Planned
                    | IntentPhase::Launched
                    | IntentPhase::Refused
                    | IntentPhase::Erased => {
                        let view = row.view(name.intent_key)?;
                        return Ok(Reserved::Answered(Box::new(view)));
                    }
                    IntentPhase::InDoubt => return Err(invalid(IN_DOUBT)),
                    IntentPhase::InFlight if row.placement_key.is_none() => {
                        // The unkeyed call may have run; it is never rerun.
                        tracing::warn!(
                            actor = %actor.to_hex(),
                            "a planned spawn found in flight is now in doubt"
                        );
                        let mut row = PlannedIntent {
                            phase: IntentPhase::InDoubt,
                            updated_at: at,
                            ..row
                        };
                        put_intent_in_txn(&self.vault.store, &mut txn, &key, &mut row)?;
                        txn.commit()?;
                        return Err(invalid(IN_DOUBT));
                    }
                    IntentPhase::InFlight
                        if row.placement_adapter != host.placement_adapter
                            || row.placement_key.as_deref() != host.placement_key =>
                    {
                        return Err(invalid(HELD_ELSEWHERE));
                    }
                    // Its keyed adapter resumes it under a fresh fence, so
                    // the older custody can no longer settle it.
                    IntentPhase::InFlight => PlannedIntent {
                        fence,
                        updated_at: at,
                        ..row
                    },
                }
            }
        };
        put_intent_in_txn(&self.vault.store, &mut txn, &key, &mut reserved)?;
        txn.commit()?;
        Ok(Reserved::Custody(IntentReservation { key, fence }))
    }

    /// Places the ask's type once against the root tree, then plans the ask
    /// at that stamp. Runs only under custody, with no writer held.
    fn place_and_plan_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: &PlannedSpawnRequest,
        host: &PlannedSpawnHost<'_>,
        at: u64,
    ) -> Result<(TaskTypeRef, SpawnPlanReceipt)> {
        let placed = self.place_spawn_type_as_owner(
            owner,
            &request.ask.need,
            request.requested_type.as_ref(),
            host.placement,
        )?;
        let plan = self.plan_spawn_as_owner(
            owner,
            &LivePlanRequest {
                need: request.ask.clone().into_need(placed.clone()),
                seats: host.seats,
                skills: host.skills,
                executor: host.executor,
                decisions: host.planner,
            },
            host.spend,
            at,
        )?;
        Ok((placed, plan))
    }

    /// Settles the intent `reservation` took custody of with what placement
    /// and the planner answered: the placed stamp and the plan, or the
    /// refusal they gave, which the intent keeps. A storage fault is no
    /// answer, and the intent stays in flight.
    fn settle_placed_and_planned(
        &self,
        name: &IntentName<'_>,
        reservation: &IntentReservation,
        placed: Result<(TaskTypeRef, SpawnPlanReceipt)>,
        at: u64,
    ) -> Result<PlannedIntentView> {
        match placed {
            Ok((placed, plan)) => {
                self.settle_planned_intent(name, reservation, SpawnPhase::Planned, at, |row| {
                    row.placed = Some(placed);
                    row.plan = Some(plan);
                })
            }
            Err(error) if retained(&error) => {
                let refusal = format!("{error}; ask again under a new intent key");
                self.settle_planned_intent(name, reservation, SpawnPhase::Refused, at, |row| {
                    row.refusal = Some(refusal);
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Settles the intent `reservation` took custody of, in one writer, and
    /// only while it is still in flight under that custody's fence and its
    /// asker, whom the row key frames, is not erased.
    fn settle_planned_intent(
        &self,
        name: &IntentName<'_>,
        reservation: &IntentReservation,
        phase: SpawnPhase,
        at: u64,
        settle: impl FnOnce(&mut PlannedIntent),
    ) -> Result<PlannedIntentView> {
        let mut txn = self.vault.store.env.write_txn()?;
        self.prove_lease_in_txn(&txn, name.asker)?;
        let mut row = INTENTS
            .get(&self.vault.store, &txn, &reservation.key)?
            .filter(|row| {
                row.phase == IntentPhase::InFlight
                    && row.fence == reservation.fence
                    && row.actor.is_some()
            })
            .ok_or_else(|| invalid(CUSTODY_LOST))?;
        settle(&mut row);
        row.phase = phase.into();
        row.updated_at = at;
        put_intent_in_txn(&self.vault.store, &mut txn, &reservation.key, &mut row)?;
        txn.commit()?;
        row.view(name.intent_key)
    }

    /// The asker's actor, the attempt it spawns from and the project, proved
    /// on `txn`: the owner's proof and the root project, or the leased
    /// parent's current lease and actor and the project it works in.
    fn asker_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        asker: Asker<'_>,
    ) -> Result<(EntityId, Option<AttemptId>, EntityId)> {
        match asker {
            Asker::Owner(owner) => {
                let (actor, project) = self.owner_root_in_txn(owner, txn)?;
                Ok((actor, None, project))
            }
            Asker::Leased { leased, actor } => {
                let project = self.leased_root_in_txn(txn, leased, actor)?;
                Ok((*actor, Some(leased.id), project))
            }
        }
    }

    /// A leased asker's parent lease and actor, proved again in a writer
    /// that settles or refuses its intent. The owner's settle and refusal
    /// stand on the intent's custody, as they always have.
    fn prove_lease_in_txn(&self, txn: &heed::RoTxn<'_>, asker: Asker<'_>) -> Result<()> {
        match asker {
            Asker::Owner(_) => Ok(()),
            Asker::Leased { leased, actor } => {
                self.leased_root_in_txn(txn, leased, actor).map(drop)
            }
        }
    }

    /// Where the intent `name` names stands for its launch, on `txn`: the
    /// asker's proof first, then the intent under its key, which must still
    /// name that asker and hold the same ask. A launched, refused or erased
    /// intent answers what it kept.
    pub(super) fn planned_launch_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        name: &IntentName<'_>,
    ) -> Result<LaunchStand> {
        let (actor, parent, _) = self.asker_in_txn(txn, name.asker)?;
        let key = intent_row_key(&actor, parent, name.intent_key);
        let row = INTENTS
            .get(&self.vault.store, txn, &key)?
            .filter(|row| row.actor == Some(actor))
            .ok_or_else(|| invalid(CUSTODY_LOST))?;
        if !row.asks(name) {
            return Err(invalid(DIFFERENT_ASK));
        }
        launch_stand(key, row, name.intent_key)
    }

    /// Freezes the pattern start a runner wrote for a planned team, with the
    /// exact pack it ran on, in one writer under a fresh proof of the asker.
    /// The first pair frozen wins: a later one is dropped, so one intent
    /// never launches two. Answers where the intent stands after, its frozen
    /// start included.
    pub(super) fn freeze_pattern_launch(
        &self,
        name: &IntentName<'_>,
        spec: PatternLaunchSpec,
        pack: &LoadedSkillPack,
        at: u64,
    ) -> Result<LaunchStand> {
        let mut txn = self.vault.store.env.write_txn()?;
        let mut planned = match self.planned_launch_in_txn(&txn, name)? {
            LaunchStand::Planned(planned) if planned.row.pattern_launch.is_none() => planned,
            stand => return Ok(stand),
        };
        planned.row.pattern_launch = Some(spec);
        planned.row.pattern_pack = Some(FrozenPatternPack::of(pack));
        planned.row.updated_at = at;
        put_intent_in_txn(&self.vault.store, &mut txn, &planned.key, &mut planned.row)?;
        txn.commit()?;
        // An erase that reached it while the runner ran took the start too.
        if planned.row.phase == IntentPhase::Erased {
            let view = planned.row.view(name.intent_key)?;
            return Ok(LaunchStand::Settled(Box::new(view)));
        }
        Ok(LaunchStand::Planned(planned))
    }

    /// Marks a planned intent launched in the launch's own group writer,
    /// with the leader or solo agent it queued, its members and its team.
    /// The group commits it.
    pub(super) fn launch_planned_intent_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        planned: PlannedLaunch,
        root: AttemptId,
        members: Vec<AttemptId>,
        team_ref: Option<String>,
        at: u64,
    ) -> Result<PlannedIntentView> {
        let PlannedLaunch {
            key,
            mut row,
            intent_key,
        } = planned;
        row.phase = IntentPhase::Launched;
        row.root_attempt = Some(root);
        row.member_attempts = members;
        row.team_ref = team_ref;
        row.updated_at = at;
        put_intent_in_txn(&self.vault.store, wtxn, &key, &mut row)?;
        row.view(&intent_key)
    }

    /// Keeps a launch's refusal under an intent still planned, as a
    /// placement or planner refusal is kept. An intent another call
    /// launched, refused or erased meanwhile answers what it kept; one whose
    /// asker an erase forgot meanwhile takes no refusal, and one whose target
    /// an erase reached takes its erased form instead.
    pub(super) fn refuse_planned_launch(
        &self,
        name: &IntentName<'_>,
        planned: &PlannedLaunch,
        refusal: String,
        at: u64,
    ) -> Result<PlannedIntentView> {
        let mut txn = self.vault.store.env.write_txn()?;
        self.prove_lease_in_txn(&txn, name.asker)?;
        let row = INTENTS
            .get(&self.vault.store, &txn, &planned.key)?
            .filter(|row| row.actor.is_some())
            .ok_or_else(|| invalid(CUSTODY_LOST))?;
        let PlannedLaunch { key, mut row, .. } =
            match launch_stand(planned.key, row, name.intent_key)? {
                LaunchStand::Planned(current) => *current,
                LaunchStand::Settled(view) => return Ok(*view),
            };
        row.phase = IntentPhase::Refused;
        row.refusal = Some(refusal);
        row.updated_at = at;
        put_intent_in_txn(&self.vault.store, &mut txn, &key, &mut row)?;
        txn.commit()?;
        row.view(name.intent_key)
    }
}

/// The ask's own shape, before anything is reserved: a key, a need and a
/// prompt. Rule 5 caps no text.
fn check_request(request: &PlannedSpawnRequest) -> Result<()> {
    if request.intent_key.trim().is_empty() {
        return Err(invalid("a planned spawn names its intent key"));
    }
    if request.ask.need.trim().is_empty() {
        return Err(invalid("a planned spawn states its need"));
    }
    if request.prompt.trim().is_empty() {
        return Err(invalid("a planned spawn carries its prompt"));
    }
    Ok(())
}

/// The row key: BLAKE3 over the framed actor, parent and intent key.
fn intent_row_key(actor: &EntityId, parent: Option<AttemptId>, intent_key: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(INTENT_KEY_CONTEXT);
    hasher.update(actor.as_bytes());
    // The parent: none, for an owner's root intent; else the attempt a
    // leased agent spawns from.
    match parent {
        None => {
            hasher.update(&[0]);
        }
        Some(parent) => {
            hasher.update(&[1]);
            hasher.update(parent.as_bytes());
        }
    }
    hasher.update(&(intent_key.len() as u64).to_be_bytes());
    hasher.update(intent_key.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The digest of the original ask in its canonical encoding: the need with
/// its seeds and pins, the prompt and the requested type, as the owner gave
/// them. Never the owner's choices laid under it, the evidence or the plan.
fn ask_digest(request: &PlannedSpawnRequest) -> Result<[u8; 32]> {
    let ask = rmp_serde::to_vec_named(&(&request.ask, &request.prompt, &request.requested_type))
        .map_err(|_| invalid("a planned spawn's ask does not encode"))?;
    let mut hasher = blake3::Hasher::new_derive_key(ASK_DIGEST_CONTEXT);
    hasher.update(&ask);
    Ok(*hasher.finalize().as_bytes())
}

/// Where a stored intent stands for its launch: planned, or settled with
/// what it kept, under `intent_key`, the key its asker names it by. One in
/// flight or in doubt has not planned.
fn launch_stand(key: [u8; 32], row: PlannedIntent, intent_key: &str) -> Result<LaunchStand> {
    if row.phase != IntentPhase::Planned {
        return Ok(LaunchStand::Settled(Box::new(row.view(intent_key)?)));
    }
    let intent_key = intent_key.to_owned();
    Ok(LaunchStand::Planned(Box::new(PlannedLaunch {
        key,
        row,
        intent_key,
    })))
}

fn fresh_fence() -> [u8; 16] {
    let mut fence = [0; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut fence);
    fence
}

/// A placement, planner or launch refusal, which the intent keeps. A
/// storage fault is no answer: the intent stays in flight, so the next ask
/// finds it in doubt, or resumes it under its keyed adapter; a launch's
/// stays planned.
pub(super) fn retained(error: &Error) -> bool {
    !matches!(error, Error::Storage(_) | Error::Io(_) | Error::MapFull)
}
