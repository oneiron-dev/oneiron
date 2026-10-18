//! A thread turn a session overlay stages (FIX 3122, the rest of FIX 2951).
//! ARCH-0052: "content reads take the union; authority reads base."
//!
//! A stretch stages its turns under its own shell, never the room, so the
//! room witness cannot bind them. This binds a project room stretch's
//! thread turn as that witness binds one on base: its root, the room whose
//! membership the thread reads under, the trunk turn it hangs off and, on
//! the root, the audience it names. The turns its links name are read in
//! the composed view, so a thread opens on a turn the stretch staged or
//! continues one base holds; the audience, the room's membership and the
//! writer's place in both are read on base. A 1:1 stretch has no room to
//! read a thread under, and an ordinary room's thread opens on its DAG, so
//! a witness opens none in either.

use super::audience::{
    ThreadBinding, names_actor_in, private_members_readable_in, thread_binding,
    thread_root_readable_with_read_in, validate_private_audience_in,
};
use super::*;
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The thread binding the turn `id`, which a stretch in `room` (`None` for
/// a 1:1) stages under `shell`, is born with or holds; `None` off any
/// thread. `actor` is the witness's bound actor. Refuses what the room
/// witness refuses on base: links that name no live turn of the stretch or
/// its room, a stored turn's thread restated otherwise, an audience named
/// anywhere but on a thread's root or one `actor` cannot name, and a
/// private thread `actor`, or a member it mentions, is off.
#[expect(
    clippy::too_many_arguments,
    reason = "the overlay landing's view, stretch, turn and actor in one call"
)]
pub(crate) fn overlay_thread_binding_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    room: Option<EntityId>,
    shell: EntityId,
    id: EntityId,
    actor: EntityId,
    input: &WitnessTurn,
) -> Result<Option<ThreadBinding>> {
    let stored = match live_entity_row_in_txn(dbs, txn, &id)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } => Some(thread_binding(&body)?),
        _ => None,
    };
    let project = match room {
        Some(room) if super::super::project::ROOM_PROJECT.contains(&vault.store, txn, &room)? => {
            Some(room)
        }
        _ => None,
    };
    let Some(room) = project else {
        // No thread opens here. A stored thread turn still takes words from
        // its audience alone.
        if input.thread_audience.is_some() {
            return Err(invalid());
        }
        if let Some(Some(held)) = &stored
            && !thread_root_readable_with_read_in(vault, dbs, txn, held.root, &[actor])?
        {
            return Err(invalid());
        }
        return Ok(None);
    };
    // The links the turn's messages name, as the room witness reads them.
    let mut parent = None;
    let mut anchor = None;
    let mut mentions = Vec::new();
    for message in &input.messages {
        let metadata = message.metadata.as_ref();
        for (field, out) in [
            ("room_reply_to", &mut parent),
            ("room_thread_of", &mut anchor),
        ] {
            if let Some(value) = metadata.and_then(|m| m.get(field)) {
                let found = EntityId::from_hex(value.as_str().ok_or_else(invalid)?)?;
                if out.as_ref().is_some_and(|prior| *prior != found) {
                    return Err(invalid());
                }
                *out = Some(found);
            }
        }
        mentions.extend(metadata.and_then(|m| m.get("room_mentions")));
    }
    // A live TURN of the stretch or its room, and the thread it holds.
    let binding_of = |target: EntityId| -> Result<Option<ThreadBinding>> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } = live_entity_row_in_txn(dbs, txn, &target)?
        else {
            return Err(invalid());
        };
        let owners = crate::conversation_dag::edge_ids(
            dbs,
            txn,
            &target,
            crate::edge::EdgeKind::ChildOf,
            false,
            2,
        )?;
        if owners.len() != 1 || (owners[0] != shell && owners[0] != room) {
            return Err(invalid());
        }
        thread_binding(&body)
    };
    // A thread hangs off a trunk turn.
    if let Some(anchor) = anchor
        && binding_of(anchor)?.is_some()
    {
        return Err(invalid());
    }
    let inherited = match parent {
        Some(parent) => binding_of(parent)?,
        None => None,
    };
    let named = match inherited {
        // A reply in a thread lands in it, under its root's room and anchor.
        Some(held) => {
            if held.room != room || anchor.is_some_and(|anchor| Some(anchor) != held.anchor) {
                return Err(invalid());
            }
            Some(ThreadBinding {
                root: held.root,
                room,
                anchor: held.anchor,
                audience: None,
            })
        }
        // A turn naming its anchor and answering it, or nothing, opens a
        // thread there; one answering another trunk turn stays on the trunk.
        None => match anchor {
            Some(anchor) if parent.is_none_or(|parent| parent == anchor) => Some(ThreadBinding {
                root: id,
                room,
                anchor: Some(anchor),
                audience: input.thread_audience.clone(),
            }),
            Some(_) | None => None,
        },
    };
    // A stored TURN keeps the thread it was born in: a retry names no
    // thread, or the same one.
    let minted = stored.is_none();
    let binding = match (stored, named) {
        (None, named) => named,
        (Some(None), None) => None,
        (Some(Some(held)), None) => Some(held),
        (Some(Some(held)), Some(next))
            if (next.root, next.room, next.anchor) == (held.root, held.room, held.anchor) =>
        {
            Some(held)
        }
        _ => return Err(invalid()),
    };
    // A thread's root names its audience once, from the room's members on
    // base; a retry may repeat the same set, and no other turn names one.
    match &binding {
        Some(held) if held.root == id => {
            if input
                .thread_audience
                .as_ref()
                .is_some_and(|set| Some(set) != held.audience.as_ref())
            {
                return Err(invalid());
            }
            if minted && let Some(set) = &held.audience {
                validate_private_audience_in(vault, txn, room, actor, set)?;
            }
        }
        _ if input.thread_audience.is_some() => return Err(invalid()),
        _ => {}
    }
    let Some(held) = &binding else {
        return Ok(None);
    };
    let audience = if held.root == id {
        held.audience.clone()
    } else {
        let root = binding_of(held.root)?.ok_or_else(invalid)?;
        if (root.root, root.room, root.anchor) != (held.root, held.room, held.anchor) {
            return Err(invalid());
        }
        root.audience
    };
    // The writer stands in a private thread's audience and is still one of
    // the room's members; a member it mentions is named there, a pen
    // through its PERSON (FIX 3123).
    if !private_members_readable_in(vault, txn, room, audience.as_ref(), &[actor])? {
        return Err(invalid());
    }
    if let Some(audience) = &audience {
        for value in mentions {
            for handle in value.as_array().ok_or_else(invalid)? {
                let handle = handle.as_str().ok_or_else(invalid)?;
                let named = HANDLES
                    .get(&vault.store, txn, &(room, handle.to_owned()))?
                    .ok_or_else(invalid)?;
                if !names_actor_in(vault, txn, audience, named)? {
                    return Err(invalid());
                }
            }
        }
    }
    Ok(binding)
}
