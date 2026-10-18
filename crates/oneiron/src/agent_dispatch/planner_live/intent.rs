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
//! from the row (`child`, S4c-5), and the row keeps where that run put the
//! pack's SKILL.md in its task, which a continuation of the run reuses.

mod child;

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
    FrozenPatternPack, PatternLaunchSpec, PlannedIntentView, PlannedSpawnHost, PlannedSpawnRequest,
    SpawnPhase,
};

use super::super::widen_record::invalid;
use super::super::{AgentDispatcher, SpawnPlanReceipt};
use super::LivePlanRequest;

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
    /// An unkeyed call was in flight when the key was asked again. It may
    /// have run, so it is never rerun.
    InDoubt,
    Planned,
    /// Queued and bound in the launch's own writer. It never launches
    /// again.
    Launched,
    Refused,
}

impl From<SpawnPhase> for IntentPhase {
    fn from(phase: SpawnPhase) -> Self {
        match phase {
            SpawnPhase::Planned => Self::Planned,
            SpawnPhase::Launched => Self::Launched,
            SpawnPhase::Refused => Self::Refused,
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

/// One stored intent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedIntent {
    /// The asker: the owner, from the proof's revalidation, or the leased
    /// agent its parent's own dispatch runs as.
    actor: EntityId,
    /// The spawning attempt; an owner's root intent has none.
    parent: Option<AttemptId>,
    /// The original ask as its asker gave it, and its digest.
    ask: IntentAsk,
    ask_digest: [u8; 32],
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
    /// Where a launched team's leader's last fresh run put the frozen
    /// pack's SKILL.md in its task (S4c-5).
    leader_exposure: Option<TaskExposure>,
    /// What the launch queued and bound: the leader, or a solo's one agent,
    /// each member in launch order, and the team.
    root_attempt: Option<AttemptId>,
    member_attempts: Vec<AttemptId>,
    team_ref: Option<String>,
}

impl PlannedIntent {
    fn view(&self, phase: SpawnPhase) -> PlannedIntentView {
        PlannedIntentView {
            intent_key: self.ask.intent_key().to_owned(),
            phase,
            placed: self.placed.clone(),
            plan: self.plan.clone(),
            refusal: self.refusal.clone(),
            root_attempt: self.root_attempt,
            member_attempts: self.member_attempts.clone(),
            team_ref: self.team_ref.clone(),
        }
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

/// A planned intent a launch reads, under its row key.
pub(super) struct PlannedLaunch {
    key: [u8; 32],
    row: PlannedIntent,
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
        let reserved = match existing {
            None => PlannedIntent {
                actor,
                parent,
                ask: ask(),
                ask_digest: name.digest,
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
                leader_exposure: None,
                root_attempt: None,
                member_attempts: Vec::new(),
                team_ref: None,
            },
            Some(row)
                if row.actor != actor
                    || row.parent != parent
                    || row.ask.intent_key() != name.intent_key
                    || row.ask_digest != name.digest =>
            {
                return Err(invalid(DIFFERENT_ASK));
            }
            Some(row) => {
                let phase = row.phase;
                match phase {
                    IntentPhase::Planned => {
                        let view = row.view(SpawnPhase::Planned);
                        return Ok(Reserved::Answered(Box::new(view)));
                    }
                    IntentPhase::Launched => {
                        let view = row.view(SpawnPhase::Launched);
                        return Ok(Reserved::Answered(Box::new(view)));
                    }
                    IntentPhase::Refused => {
                        let view = row.view(SpawnPhase::Refused);
                        return Ok(Reserved::Answered(Box::new(view)));
                    }
                    IntentPhase::InDoubt => return Err(invalid(IN_DOUBT)),
                    IntentPhase::InFlight if row.placement_key.is_none() => {
                        // The unkeyed call may have run; it is never rerun.
                        tracing::warn!(
                            actor = %actor.to_hex(),
                            "a planned spawn found in flight is now in doubt"
                        );
                        let row = PlannedIntent {
                            phase: IntentPhase::InDoubt,
                            updated_at: at,
                            ..row
                        };
                        INTENTS.put(&self.vault.store, &mut txn, &key, &row)?;
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
        INTENTS.put(&self.vault.store, &mut txn, &key, &reserved)?;
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
    /// only while it is still in flight under that custody's fence.
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
            .filter(|row| row.phase == IntentPhase::InFlight && row.fence == reservation.fence)
            .ok_or_else(|| invalid(CUSTODY_LOST))?;
        settle(&mut row);
        row.phase = phase.into();
        row.updated_at = at;
        INTENTS.put(&self.vault.store, &mut txn, &reservation.key, &row)?;
        txn.commit()?;
        Ok(row.view(phase))
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
    /// asker's proof first, then the intent under its key, which must hold
    /// the same ask. A launched or refused intent answers what it kept.
    pub(super) fn planned_launch_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        name: &IntentName<'_>,
    ) -> Result<LaunchStand> {
        let (actor, parent, _) = self.asker_in_txn(txn, name.asker)?;
        let key = intent_row_key(&actor, parent, name.intent_key);
        let row = INTENTS
            .get(&self.vault.store, txn, &key)?
            .ok_or_else(|| invalid(CUSTODY_LOST))?;
        if row.ask_digest != name.digest {
            return Err(invalid(DIFFERENT_ASK));
        }
        launch_stand(key, row)
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
        INTENTS.put(&self.vault.store, &mut txn, &planned.key, &planned.row)?;
        txn.commit()?;
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
        let PlannedLaunch { key, mut row } = planned;
        row.phase = IntentPhase::Launched;
        row.root_attempt = Some(root);
        row.member_attempts = members;
        row.team_ref = team_ref;
        row.updated_at = at;
        INTENTS.put(&self.vault.store, wtxn, &key, &row)?;
        Ok(row.view(SpawnPhase::Launched))
    }

    /// Keeps a launch's refusal under an intent still planned, as a
    /// placement or planner refusal is kept. An intent another call
    /// launched or refused meanwhile answers what it kept.
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
            .ok_or_else(|| invalid(CUSTODY_LOST))?;
        let PlannedLaunch { key, mut row } = match launch_stand(planned.key, row)? {
            LaunchStand::Planned(current) => *current,
            LaunchStand::Settled(view) => return Ok(*view),
        };
        row.phase = IntentPhase::Refused;
        row.refusal = Some(refusal);
        row.updated_at = at;
        INTENTS.put(&self.vault.store, &mut txn, &key, &row)?;
        txn.commit()?;
        Ok(row.view(SpawnPhase::Refused))
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
/// what it kept. One in flight or in doubt has not planned.
fn launch_stand(key: [u8; 32], row: PlannedIntent) -> Result<LaunchStand> {
    let settled = match row.phase {
        IntentPhase::Planned => None,
        IntentPhase::Launched => Some(SpawnPhase::Launched),
        IntentPhase::Refused => Some(SpawnPhase::Refused),
        IntentPhase::InFlight | IntentPhase::InDoubt => return Err(invalid(CUSTODY_LOST)),
    };
    Ok(match settled {
        Some(phase) => LaunchStand::Settled(Box::new(row.view(phase))),
        None => LaunchStand::Planned(Box::new(PlannedLaunch { key, row })),
    })
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
