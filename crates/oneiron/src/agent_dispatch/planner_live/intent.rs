//! The reserved spawn intent (DOOR-111 S2): the owner's planned spawn,
//! durable under its intent key.
//!
//! One row per framed (owner, parent, intent key); an owner's root intent
//! has no parent. The row keeps the owner's original ask and its digest, the
//! placement adapter that holds custody and the custody fence, and, once
//! settled, the placed stamp and the frozen plan receipt, or the refusal
//! placement or the planner gave. Custody is taken and committed before any
//! adapter or model call, no writer is held across one, and the settling
//! write lands only under the fence its custody was taken with.
//!
//! A replay never plans again. The same key with another ask is refused; a
//! planned or refused intent answers what it kept. An intent found in flight
//! is never rerun (Engine ruling (b), 10-19): unkeyed, it is in doubt and the
//! owner asks again under a new key; under a keyed adapter, the same adapter
//! and key resume it under a fresh fence, so an older custody can no longer
//! settle it.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::task_type::TaskTypeRef;
use crate::team::{PlannedIntentPhase, PlannedIntentView, PlannedSpawnHost, PlannedSpawnRequest};

use super::super::widen_record::invalid;
use super::super::{AgentDispatcher, SpawnPlanReceipt};
use super::LivePlanRequest;

/// Domain of an intent's row key.
const INTENT_KEY_CONTEXT: &str = "oneiron spawn planned intent key v1";
/// Domain of an intent's ask digest.
const ASK_DIGEST_CONTEXT: &str = "oneiron spawn planned intent ask v1";

/// Framed (owner, parent, intent key) → the intent it names.
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
    Refused,
}

impl From<PlannedIntentPhase> for IntentPhase {
    fn from(phase: PlannedIntentPhase) -> Self {
        match phase {
            PlannedIntentPhase::Planned => Self::Planned,
            PlannedIntentPhase::Refused => Self::Refused,
        }
    }
}

/// One stored intent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedIntent {
    /// The owner who asked, from the proof's revalidation.
    actor: EntityId,
    /// The spawning attempt; an owner's root intent has none.
    parent: Option<AttemptId>,
    /// The original ask as the owner gave it, and its digest.
    ask: PlannedSpawnRequest,
    ask_digest: [u8; 32],
    /// The root project the intent was reserved in.
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
}

impl PlannedIntent {
    fn view(&self, phase: PlannedIntentPhase) -> PlannedIntentView {
        PlannedIntentView {
            intent_key: self.ask.intent_key.clone(),
            phase,
            placed: self.placed.clone(),
            plan: self.plan.clone(),
            refusal: self.refusal.clone(),
        }
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

impl AgentDispatcher<'_> {
    /// The owner's planned spawn under an intent key (DOOR-111): the engine
    /// reserves the intent, places its type once against the root project's
    /// tree, plans it there, and freezes the placed stamp and the plan
    /// receipt. Nothing launches. The same key with the same ask returns
    /// what was frozen, a kept refusal included, and never plans again.
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
        let reservation = match self.reserve_planned_intent_as_owner(owner, request, host, at)? {
            Reserved::Answered(view) => return Ok(*view),
            Reserved::Custody(reservation) => reservation,
        };
        // Custody is committed: no writer is held while placement and the
        // planner may ask a model.
        match self.place_and_plan_as_owner(owner, request, host, at) {
            Ok((placed, plan)) => {
                self.settle_planned_intent(&reservation, PlannedIntentPhase::Planned, at, |row| {
                    row.placed = Some(placed);
                    row.plan = Some(plan);
                })
            }
            Err(error) if retained(&error) => {
                let refusal = format!("{error}; ask again under a new intent key");
                self.settle_planned_intent(&reservation, PlannedIntentPhase::Refused, at, |row| {
                    row.refusal = Some(refusal);
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Reserves the intent `request` names, in one writer: the owner's proof
    /// first, then the key. A new key, or an in-flight one its keyed adapter
    /// resumes, takes custody under a fresh fence and commits. A settled key
    /// answers what it kept; an unkeyed call found in flight leaves the
    /// intent in doubt.
    fn reserve_planned_intent_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: &PlannedSpawnRequest,
        host: &PlannedSpawnHost<'_>,
        at: u64,
    ) -> Result<Reserved> {
        let digest = ask_digest(request)?;
        let mut txn = self.vault.store.env.write_txn()?;
        let (actor, project) = self.owner_root_in_txn(owner, &txn)?;
        let key = intent_row_key(&actor, &request.intent_key);
        let fence = fresh_fence();
        let existing = INTENTS.get(&self.vault.store, &txn, &key)?;
        let reserved = match existing {
            None => PlannedIntent {
                actor,
                parent: None,
                ask: request.clone(),
                ask_digest: digest,
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
            },
            Some(row)
                if row.actor != actor
                    || row.ask.intent_key != request.intent_key
                    || row.ask_digest != digest =>
            {
                return Err(invalid(DIFFERENT_ASK));
            }
            Some(row) => {
                let phase = row.phase;
                match phase {
                    IntentPhase::Planned => {
                        let view = row.view(PlannedIntentPhase::Planned);
                        return Ok(Reserved::Answered(Box::new(view)));
                    }
                    IntentPhase::Refused => {
                        let view = row.view(PlannedIntentPhase::Refused);
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

    /// Settles the intent `reservation` took custody of, in one writer, and
    /// only while it is still in flight under that custody's fence.
    fn settle_planned_intent(
        &self,
        reservation: &IntentReservation,
        phase: PlannedIntentPhase,
        at: u64,
        settle: impl FnOnce(&mut PlannedIntent),
    ) -> Result<PlannedIntentView> {
        let mut txn = self.vault.store.env.write_txn()?;
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

/// The row key: BLAKE3 over the framed owner, parent and intent key.
fn intent_row_key(actor: &EntityId, intent_key: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(INTENT_KEY_CONTEXT);
    hasher.update(actor.as_bytes());
    // The parent: none, for an owner's root intent.
    hasher.update(&[0]);
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

fn fresh_fence() -> [u8; 16] {
    let mut fence = [0; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut fence);
    fence
}

/// A placement or planner refusal, which the intent keeps. A storage fault
/// is no answer: the intent stays in flight, so the next ask finds it in
/// doubt, or resumes it under its keyed adapter.
fn retained(error: &Error) -> bool {
    !matches!(error, Error::Storage(_) | Error::Io(_) | Error::MapFull)
}
