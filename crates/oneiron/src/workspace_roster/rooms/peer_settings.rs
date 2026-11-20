//! A federation peer's room body (ROOM-BODY-REPLICA-SETTINGS; Engine ruling
//! 20 Nov 23:56 = A). A member peer's CONVERSATION row is first-party here:
//! it takes no import stamp, and the body guard checks a room's settings
//! only for this vault's own writes
//! ([`crate::conversation::validate_put_in_txn`]). So each setting a peer's
//! body changes on the row this vault holds is judged as its local door
//! judges a caller, with the peer's sender as the caller (ARCH-0040:34,
//! ARCH-0043:37), less the doors' write-actor check: the peer's grant
//! authenticated the sender. Own-device replay stays trust-blind
//! (ARCH-0040:261), and a room this vault does not hold yet lands as it came.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::EdgeActorClass;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::conversation::{ConversationBody, RoomRole};
use crate::error::RecordError;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use crate::write_envelope::WriteActor;

/// The verdict a peer's room body is refused with. Typed as the peer's
/// bytes, so an admission refuses the update and an import quarantines the
/// row.
const PEER_ROOM_SETTING_REFUSAL: &str =
    "a federation peer cannot change a room setting it holds no power over";

/// The refusal of `body`, the room body a federation peer's `sender` sent for
/// `room`, read in `txn`: `Some` when it changes a setting of the row this
/// vault holds that `sender` holds no power over. The settings are whether
/// the room is closed, its pin policy, its pins and unpin records, its
/// members' roles and its members. `None` lets the body land, as it does for
/// a room this vault does not hold.
///
/// # Errors
///
/// A body or a held row that does not decode; storage errors.
pub(crate) fn peer_room_settings_refusal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    sender: EntityId,
    body: &[u8],
) -> Result<Option<Error>> {
    let Some(held) = held_body_in(vault, txn, room)? else {
        return Ok(None);
    };
    let body = ConversationBody::from_bytes(body)?;
    let class = match vault.get_entity_type_in_txn(txn, &sender)? {
        Some(ENTITY_TYPE_PERSON) => Some(EdgeActorClass::Human),
        Some(ENTITY_TYPE_AGENT_DEF) => Some(EdgeActorClass::Agent),
        _ => None,
    };
    let allowed = match class {
        Some(class) => changes_allowed(
            vault,
            txn,
            room,
            WriteActor::new(sender, class),
            &held,
            &body,
        )?,
        // A sender this vault holds as no PERSON or agent holds no room power.
        None => !changes_setting(&held, &body),
    };
    Ok((!allowed).then(|| RecordError::InvalidConversationBody(PEER_ROOM_SETTING_REFUSAL).into()))
}

/// The CONVERSATION row this vault holds for `room`, if any.
fn held_body_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Option<ConversationBody>> {
    match crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &room)? {
        Some(raw)
            if raw.first() == Some(&ENTITY_TYPE_CONVERSATION)
                && raw.len() > ENTITY_METADATA_HEADER_LEN =>
        {
            Ok(Some(ConversationBody::from_bytes(
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )?))
        }
        _ => Ok(None),
    }
}

/// Whether `body` changes any setting of `held`.
fn changes_setting(held: &ConversationBody, body: &ConversationBody) -> bool {
    body.closed != held.closed
        || body.pin_policy != held.pin_policy
        || changes_pins(held, body)
        || retained_roles(held, body) != body.roles
        || member_set(body) != member_set(held)
}

/// Whether `caller` holds the power over each setting `body` changes on
/// `held`, each judged as its door judges it: the closed bit as the
/// closed-setting door ([`super::closed::closes_room_in`]), the pin policy
/// and the pins as the pin doors ([`super::pins`]), the roles as the role
/// door ([`crate::conversation::person_delegates_roles_in`], a person only),
/// and the members as [`members_allowed`] says.
fn changes_allowed(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: WriteActor,
    held: &ConversationBody,
    body: &ConversationBody,
) -> Result<bool> {
    if body.closed != held.closed && !super::closed::closes_room_in(vault, txn, room, caller)? {
        return Ok(false);
    }
    if body.pin_policy != held.pin_policy
        && !super::pins::sets_pin_policy_in(vault, txn, room, caller)?
    {
        return Ok(false);
    }
    if changes_pins(held, body) && !super::pins::changes_pins_in(vault, txn, room, caller)? {
        return Ok(false);
    }
    if retained_roles(held, body) != body.roles
        && !(caller.actor_class() == EdgeActorClass::Human
            && crate::conversation::person_delegates_roles_in(
                vault,
                txn,
                room,
                caller.entity_ref(),
                true,
            )?)
    {
        return Ok(false);
    }
    members_allowed(vault, txn, room, caller, held, body)
}

/// Whether `caller` may make the member changes `body` makes to `held`:
/// each added member as one who answers the room's admission (a host, or
/// its nearest project leader), each removed one as its own leave or the
/// vault owner's removal, as the room leave door allows.
fn members_allowed(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: WriteActor,
    held: &ConversationBody,
    body: &ConversationBody,
) -> Result<bool> {
    let (held_members, members) = (member_set(held), member_set(body));
    if members.difference(&held_members).next().is_some()
        && !crate::workspace_roster::join_door::peer_admission_party_in_txn(
            vault, txn, room, caller,
        )?
    {
        return Ok(false);
    }
    Ok(held_members
        .difference(&members)
        .all(|removed| *removed == caller.entity_ref())
        || crate::workspace_roster::room_leave::owner_removes_in_txn(vault, txn, caller))
}

/// Whether `body` changes `held`'s pins or the unpin records beside them.
fn changes_pins(held: &ConversationBody, body: &ConversationBody) -> bool {
    body.pins != held.pins || body.unpinned != held.unpinned
}

/// `held`'s roles of the people who stay members in `body`: a member's leave
/// ends its role with it, as the membership door writes it.
fn retained_roles(held: &ConversationBody, body: &ConversationBody) -> BTreeMap<String, RoomRole> {
    let mut retained = held.roles.clone();
    retained.retain(|person, _| body.member_ids.iter().any(|id| id.to_hex() == *person));
    retained
}

/// The members a body names, in no order.
fn member_set(body: &ConversationBody) -> BTreeSet<EntityId> {
    body.member_ids.iter().copied().collect()
}
