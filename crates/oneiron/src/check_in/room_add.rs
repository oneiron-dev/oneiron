//! The check-in of an add of someone else to a room or thread (ARCH-0082
//! #agent-room-add; ROLES-CHECKIN P2.6a, piece 2m; Engine rulings
//! P26-SHAPE Q2 to Q4 = A and P26-AGENT-GRANT = A, 15 Nov 02:04).
//!
//! The door that adds someone else judges the add in its own writer,
//! before the add, under the `room_add` act class (ROOM-ADD-ROW = A):
//!
//! * a person's add is their own judgment ([`person_door_check_in_in_txn`]):
//!   the vault's owner, and a member under their membership role, whose
//!   `room_add` cell asks when unsure, go at once with basis `sure`; a
//!   Guest's role has no such verb and is refused. A person with no role on
//!   the vault reads no cell, and their add is not judged;
//! * an agent's add is judged on its own live owner Grant that lists the
//!   door's verb ([`judge_door_act_in_txn`]). No decision model judges an
//!   agent's act yet, so the unsure test is never sure and the add waits:
//!   with no `check_in_ref` the agent's own pending check-in for this exact
//!   add is opened in the door's writer, or the open one found, and the door
//!   answers `CHECK_IN_PENDING` naming it; the call that names the approved
//!   check-in spends it in the writer that lands the add. An agent no such
//!   Grant gives the power is refused, naming the route: the Owner grants it
//!   the verb, and its add then checks in. That narrows main, where an agent
//!   added on its room standing alone.
//!
//! A closed room (ARCH-0082 #closed-room; P26-SHAPE Q5 = A): any add to it
//! asks the room's owners, whoever adds ([`closed_room_check_in_in_txn`]).
//! A person who owns the room adds at once; every other adder (the Admin, a
//! Deputy, a member, a person with no role on the vault, an agent on its
//! Grant) waits AlwaysAsk on the one rung [`super::Rung::RoomOwner`], with
//! no delay window and no undo plan, so an unanswered ask holds. The adder's
//! call naming the approved ask spends it; an ordinary ask of the same add
//! is never spent there.
//!
//! An agent's add is from now on (canon #agent-room-add): the door refuses
//! an agent's add that asks for the earlier history ([`agent_add_is_from_now`])
//! before it judges, so nothing opens. Full history for the newcomer needs
//! the affected people's OK, which no door collects yet (FIX row
//! [ROOM-ADD-FULL-HISTORY-AFFECTED-OK]).

use super::act_class::ActClass;
use super::asker::{AskGo, AskVerdict, agent_door_grant_in_txn, judge_door_act_in_txn};
use super::chain::{NoAgentVerdict, VerifiedChain};
use super::effect::{
    CheckInDecision, DoorAct, DoorCheckIn, person_door_check_in_in_txn, spend_in_txn,
};
use super::mode::CheckInMode;
use super::pending::{
    OpenPendingCheckIn, consume_pending_check_in_in_txn, open_keyed_pending_check_in_in_txn,
    open_keyed_room_owner_check_in_in_txn, pending_check_in_in_txn,
};
use super::policy::CheckInScope;
use super::resolve::{CheckInRequest, ResolvedMode, WaitReason, resolve_mode};
use super::role_preset::RolePreset;
use super::waits::refuse;
use crate::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// The reason an agent's add that asks for the earlier history is refused
/// with (`FORBIDDEN`): an agent's add is from now on (ARCH-0082
/// #agent-room-add; P26-SHAPE Q4 = A).
pub const ROOM_ADD_FROM_NOW_REASON: &str = "check_in.room_add:from_now_only";

/// The reason an agent's add with no live owner Grant that gives it the
/// power is refused with (`FORBIDDEN`), naming the route: the Owner grants
/// the verb (P26-AGENT-GRANT = A).
pub const ROOM_ADD_NOT_GRANTED_REASON: &str = "check_in.room_add:owner_grants_verb";

/// The digest of adding `newcomer` to `room`, or to its private thread
/// rooted at `thread`, with the earlier history when `full_history`: the
/// effect an agent's add waits on and the call naming its approved
/// check-in spends (P2.6a). BLAKE3, key derived from `oneiron check_in room
/// add v1`, over the room's 16 id bytes, one byte 1 and the thread root's
/// 16 bytes or one byte 0, the newcomer's 16 bytes and one byte, 1 for the
/// full history.
#[must_use]
pub fn room_add_effect_digest(
    room: &EntityId,
    thread: Option<&EntityId>,
    newcomer: &EntityId,
    full_history: bool,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in room add v1");
    hasher.update(room.as_bytes());
    match thread {
        Some(root) => {
            hasher.update(&[1]).update(root.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(newcomer.as_bytes());
    hasher.update(&[u8::from(full_history)]);
    *hasher.finalize().as_bytes()
}

/// Refuses an agent's add that asks for the earlier history, before
/// anything is judged or opened: an agent's add is from now on (P26-SHAPE
/// Q4 = A).
///
/// # Errors
///
/// `FORBIDDEN` ([`ROOM_ADD_FROM_NOW_REASON`]) when `memory`'s caller is an
/// agent and `full_history` is asked.
pub(crate) fn agent_add_is_from_now(memory: &Memory<'_>, full_history: bool) -> MemoryResult<()> {
    if full_history && memory.actor_class() == EdgeActorClass::Agent {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "{ROOM_ADD_FROM_NOW_REASON}: an agent's add is from now on; the earlier history needs the OK of the people it holds, which an agent cannot give"
            ),
            &["Add from now on, or ask a person in the room to add with the earlier history."],
        ));
    }
    Ok(())
}

/// Judges `memory`'s caller's add of someone else to `room`, the effect
/// `effect_digest` names, at the door `verb`, in the door's writer `txn`;
/// with `check_in_ref`, spends that approved ask when the add waits. Into a
/// closed room, every add is judged ([`closed_room_check_in_in_txn`]).
/// Elsewhere `None` for a person with no role on the vault: the add is not
/// judged.
///
/// # Errors
///
/// A Guest's add; an agent no live owner Grant gives the power
/// (`FORBIDDEN`, [`ROOM_ADD_NOT_GRANTED_REASON`]); a `check_in_ref` that names no row, another
/// asker's or another act's ask, another effect, or an ask that is not
/// eligible or already spent; storage errors.
pub(crate) fn room_add_check_in_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    verb: &str,
    room: EntityId,
    effect_digest: [u8; 32],
    check_in_ref: Option<&EntityId>,
) -> MemoryResult<Option<DoorCheckIn>> {
    let vault = memory.vault();
    let actor = memory.actor();
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    if crate::workspace_roster::room_is_closed_in(vault, txn, room)? {
        return closed_room_check_in_in_txn(
            memory,
            txn,
            verb,
            room,
            effect_digest,
            check_in_ref,
            now,
        )
        .map(Some);
    }
    if memory.actor_class() != EdgeActorClass::Agent {
        if crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)? {
            return Ok(Some(DoorCheckIn::Go(own_judgment(RolePreset::Owner))));
        }
        let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
            return Ok(None);
        };
        let Some((grant, role)) = vault.member_grant_in_txn(txn, creation.vault_id, actor)? else {
            return Ok(None);
        };
        let door = DoorAct {
            person: actor,
            role: RolePreset::of_grant_role(role),
            grant,
            verb,
            act: ActClass::RoomAdd,
            scope: CheckInScope::default(),
            effect_digest,
        };
        return Ok(Some(person_door_check_in_in_txn(
            vault,
            txn,
            &door,
            check_in_ref,
            now,
        )?));
    }
    let scope = CheckInScope::default();
    let (verdict, role) = judge_door_act_in_txn(memory, txn, verb, ActClass::RoomAdd, &scope)?;
    let (asker, grant, mode, reason) = match verdict {
        AskVerdict::Go { reason, .. } => {
            let mode = (reason == AskGo::NeverAsk).then_some(CheckInMode::NeverAsk);
            return Ok(Some(DoorCheckIn::Go(CheckInDecision {
                act_class: ActClass::RoomAdd.as_str().to_owned(),
                role: role.as_str().to_owned(),
                mode: mode.map(|mode| mode.as_str().to_owned()),
                basis: reason.as_str().to_owned(),
                check_in: None,
                requester: None,
            })));
        }
        AskVerdict::Wait {
            asker,
            grant,
            mode,
            reason,
            ..
        } => (asker, grant, mode, reason),
        AskVerdict::Absent { why } => return Err(not_granted(verb, why)),
        AskVerdict::Propose { .. } | AskVerdict::Unstated => {
            return Err(not_granted(verb, NO_POWER));
        }
    };
    let door = DoorAct {
        person: asker,
        role,
        grant,
        verb,
        act: ActClass::RoomAdd,
        scope,
        effect_digest,
    };
    if let Some(id) = check_in_ref {
        return Ok(Some(spend_in_txn(vault, txn, &door, mode, id, now)?));
    }
    let (row, _) = open_keyed_pending_check_in_in_txn(
        vault,
        txn,
        OpenPendingCheckIn {
            asker,
            grant_ref: grant.to_hex(),
            verb: verb.to_owned(),
            act: ActClass::RoomAdd,
            scope: door.scope.clone(),
            effect_digest,
            mode,
            reason,
            asker_wait_secs: None,
            until: None,
            undo_plan: None,
            delay_window: None,
        },
        memory.invocation().map(|invocation| invocation.0),
        &VerifiedChain::new(&NoAgentVerdict),
        now,
    )?;
    Ok(Some(DoorCheckIn::Wait(row.id)))
}

/// The receipt role of an adder with no role on the vault: a person a room
/// seats who holds no membership grant (ARCH-0082 #closed-room).
const NO_VAULT_ROLE: &str = "none";

/// Judges an add into the closed `room` (ARCH-0082 #closed-room; P26-SHAPE
/// Q5 = A), whoever adds, in the door's writer `txn`. A person who owns the
/// room ([`crate::conversation::room_owners_in`]) adds at once, basis
/// `room_owner`. Anyone else's add waits AlwaysAsk on the room's owners
/// alone: an agent on the live owner Grant that lists `verb` (refused
/// without one, as in an open room), a person under their membership role
/// (a Guest is refused) or with no role on the vault (the ask records no
/// grant). With `check_in_ref`, spends the caller's approved ask of this
/// room for this add.
///
/// # Errors
///
/// An agent no live owner Grant gives the power, a Guest's add, a
/// `check_in_ref` that is not the caller's ask of this room's owners for
/// this add or that is not eligible or already spent; storage errors.
fn closed_room_check_in_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    verb: &str,
    room: EntityId,
    effect_digest: [u8; 32],
    check_in_ref: Option<&EntityId>,
    now: u64,
) -> MemoryResult<DoorCheckIn> {
    let vault = memory.vault();
    let actor = memory.actor();
    let scope = CheckInScope::default();
    let (grant_ref, role) = if memory.actor_class() == EdgeActorClass::Agent {
        let (verdict, role) = judge_door_act_in_txn(memory, txn, verb, ActClass::RoomAdd, &scope)?;
        match verdict {
            AskVerdict::Go { .. } | AskVerdict::Wait { .. } => {}
            AskVerdict::Absent { why } => return Err(not_granted(verb, why)),
            AskVerdict::Propose { .. } | AskVerdict::Unstated => {
                return Err(not_granted(verb, NO_POWER));
            }
        }
        let grant = agent_door_grant_in_txn(memory, txn, verb, &scope)?
            .ok_or_else(|| not_granted(verb, NO_POWER))?;
        (grant.to_hex(), role.as_str())
    } else {
        let (grant, role) = match vault.shared_vault_creation_in_txn(txn)? {
            Some(creation) => match vault.member_grant_in_txn(txn, creation.vault_id, actor)? {
                Some((grant, role)) => (Some(grant), Some(RolePreset::of_grant_role(role))),
                None => (None, None),
            },
            None => (None, None),
        };
        if crate::conversation::room_owners_in(vault, txn, room)?.contains(&actor) {
            let role = if crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)? {
                RolePreset::Owner.as_str()
            } else {
                role.map_or(NO_VAULT_ROLE, RolePreset::as_str)
            };
            return Ok(DoorCheckIn::Go(closed_room_decision(
                role,
                "room_owner",
                None,
            )));
        }
        if let Some(role) = role {
            let request = CheckInRequest {
                act: ActClass::RoomAdd,
                role,
                holds_power: true,
                explicit_mode: None,
                standing_row: None,
            };
            if matches!(
                resolve_mode(&request),
                ResolvedMode::Propose | ResolvedMode::Absent
            ) {
                return Err(
                    refuse("the person's role does not hold the power for this act").into(),
                );
            }
        }
        (
            grant.as_ref().map(EntityId::to_hex).unwrap_or_default(),
            role.map_or(NO_VAULT_ROLE, RolePreset::as_str),
        )
    };
    if let Some(id) = check_in_ref {
        let row = pending_check_in_in_txn(&vault.store, txn, id)?.ok_or(Error::EntityNotFound)?;
        if row.asker != actor
            || row.verb != verb
            || row.act != ActClass::RoomAdd
            || row.scope != scope
            || row.room != Some(room)
        {
            return Err(refuse(
                "the check-in is not this adder's ask of the closed room's owners for this add",
            )
            .into());
        }
        let basis = consume_pending_check_in_in_txn(vault, txn, id, &effect_digest, now)?;
        return Ok(DoorCheckIn::Go(closed_room_decision(
            role,
            basis.as_str(),
            Some(*id),
        )));
    }
    let (row, _) = open_keyed_room_owner_check_in_in_txn(
        vault,
        txn,
        OpenPendingCheckIn {
            asker: actor,
            grant_ref,
            verb: verb.to_owned(),
            act: ActClass::RoomAdd,
            scope,
            effect_digest,
            mode: CheckInMode::AlwaysAsk,
            reason: WaitReason::AlwaysAsk,
            asker_wait_secs: None,
            until: None,
            undo_plan: None,
            delay_window: None,
        },
        room,
        memory.invocation().map(|invocation| invocation.0),
        &VerifiedChain::new(&NoAgentVerdict),
        now,
    )?;
    Ok(DoorCheckIn::Wait(row.id))
}

/// A closed room's add as `role`, mode AlwaysAsk, on `basis`.
fn closed_room_decision(role: &str, basis: &str, check_in: Option<EntityId>) -> CheckInDecision {
    CheckInDecision {
        act_class: ActClass::RoomAdd.as_str().to_owned(),
        role: role.to_owned(),
        mode: Some(CheckInMode::AlwaysAsk.as_str().to_owned()),
        basis: basis.to_owned(),
        check_in: check_in.as_ref().map(EntityId::to_hex),
        requester: None,
    }
}

const NO_POWER: &str = "no live owner Grant of the caller gives it the power";

/// The live vault owner's own add, which a door has already proved her to
/// make (`rooms.invite` admits only her): her own judgment, so she is sure
/// (P26-SHAPE Q2 (iv) = A).
pub(crate) fn owner_room_add_decision() -> CheckInDecision {
    own_judgment(RolePreset::Owner)
}

/// A person's own add under `role`, whose `room_add` cell asks when unsure:
/// their own judgment, so they are sure.
fn own_judgment(role: RolePreset) -> CheckInDecision {
    CheckInDecision {
        act_class: ActClass::RoomAdd.as_str().to_owned(),
        role: role.as_str().to_owned(),
        mode: Some(CheckInMode::AskWhenUnsure.as_str().to_owned()),
        basis: "sure".to_owned(),
        check_in: None,
        requester: None,
    }
}

fn not_granted(verb: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{ROOM_ADD_NOT_GRANTED_REASON}: {why}: an agent adds someone else only on a live owner Grant that lists {verb}, and its add then checks in"
        ),
        &["Ask the vault's Owner to grant the agent the verb."],
    )
}
