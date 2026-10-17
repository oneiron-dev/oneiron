//! The audience an assembly reads for: the room a request names, and the caller's read narrowed
//! to that room's roster or to the contacts present. The context pack and a board's hook pins
//! when no retrieval runs (OF-579) both read through these, so a record meets one clamp.

use super::super::{core_engine_error, parse_entity_id_param};
use super::RoomAudience;
use crate::auth::CoreAuth;
use crate::error::ApiError;

/// Room `room_id`'s members under the caller's own read, and the audience they make. A room
/// the caller cannot read is one that does not exist; members read its roster by membership,
/// as their room turns do.
pub(crate) fn resolve_core_room(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    room_id: Option<oneiron::EntityId>,
) -> Result<(Option<Vec<oneiron::EntityId>>, Option<RoomAudience>), ApiError> {
    let principal = auth
        .principal_ref()
        .and_then(|id| oneiron::EntityId::from_hex(id).ok());
    let room_members = room_id
        .map(|room| {
            vault
                .room_audience_members_under(scoped_read, room, principal)
                .map_err(|error| core_engine_error("room audience failed", error))
        })
        .transpose()?;
    let room = room_members
        .as_deref()
        .map(|members| RoomAudience::resolve(vault, auth, members))
        .transpose()?;
    Ok((room_members, room))
}

/// The caller's read narrowed to the audience it speaks to: a room's met world set, roster and
/// its own agents' reads; else the caller and each contact present, through the contact's one
/// linked PERSON; else the read as it is.
pub(crate) fn narrow_to_core_audience<'a>(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    scoped_read: oneiron::claim::ScopedRead<'a>,
    room_members: Option<&[oneiron::EntityId]>,
    room: Option<&RoomAudience>,
    interlocutors: Option<&oneiron::InterlocutorSet>,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    if let (Some(members), Some(room)) = (room_members, room) {
        // Every row a room reads lies in its members' met world set, as a
        // room turn's ceiling holds it (ARCH-0067 §8).
        let scoped_read = match vault
            .room_world_set(members)
            .map_err(|e| core_engine_error("room world set failed", e))?
        {
            Some(worlds) => scoped_read.within_worlds(worlds),
            None => scoped_read,
        };
        return Ok(scoped_read
            .for_audience(members)
            .with_peer_reads(room.agent_reads()));
    }
    let Some(set) = interlocutors.filter(|set| set.has_non_owner()) else {
        return Ok(scoped_read);
    };
    // Contact records are not PERSON identities. Only a unique explicit
    // person link may resolve one; unresolved participants fail closed.
    let mut audience = Vec::new();
    let mut unresolved = false;
    if let Some(actor) = auth.principal_ref() {
        audience.push(parse_entity_id_param(actor, "principal_ref")?);
    }
    for party in set.non_owner() {
        let Some(contact) = party
            .contact_ref()
            .and_then(|id| oneiron::EntityId::from_hex(id).ok())
        else {
            unresolved = true;
            break;
        };
        let people = vault
            .targets(
                &contact,
                oneiron::EdgeKind::About,
                Some(oneiron::registry::ENTITY_TYPE_PERSON),
            )
            .map_err(|e| core_engine_error("audience person resolution failed", e))?;
        if people.len() != 1 {
            unresolved = true;
            break;
        }
        audience.push(people[0]);
    }
    if unresolved {
        audience.clear();
    }
    Ok(scoped_read.for_audience(&audience))
}
