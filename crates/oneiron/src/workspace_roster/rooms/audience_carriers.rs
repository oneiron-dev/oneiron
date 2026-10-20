//! Thread audience edit carriers under an erase (FIX 5640).
//!
//! A window carries an audience edit as the TURN it is. A copy that names
//! someone this vault erased, or that differs from the held copy only in
//! whom it names erased, settles by one rule ([`settled_in`]): it names no
//! one where this vault's own hard-delete marker says so
//! ([`crate::deletion::ACTOR_ERASE_CARRIER_SOURCE`]) or its room-person
//! erase marker does for the edit's room, an id it never held included (FIX
//! 6094), and each slot either copy erased stays erased
//! ([`crate::deletion::ACTOR_ERASE_CARRIER_MERGE`]). Two live people in one
//! slot, or any other difference, still meet the immutable edit's bound.
//! Ingest rewrites the held edit in place when the copy erases more of it,
//! its retained revisions started over ([`super::audience_erase`]), and
//! takes the copy in the settled form, so a late unerased copy never names
//! an erased person again. Every export, the reverse mirror and the sweep
//! rewrite a carrier that names more than its settled form, the window
//! pinned history-free first. No edit is deleted.

use std::borrow::Cow;

use loro::{CommitOptions, LoroDoc};

use super::audience::{ThreadBinding, thread_binding};
use super::audience_erase::rewrite_audience_edit_in_txn;
use super::audience_events::{
    AudienceEvent, ROOM_THREAD_AUDIENCE_KEY, audience_event, erased_here_in, event_body,
    live_edit_in,
};
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::ENTITY_TYPE_TURN;
use crate::sync::bridge::BRIDGE_ORIGIN;
use crate::sync::loro_support::{map_for_each_bytes, map_insert_bytes};
use crate::sync::types::WindowKey;
use crate::workspace_roster::RosterActor;

/// The audience edit the carried TURN row `blob` carries, with its thread
/// binding; `None` for any other row, and for an edit that does not decode,
/// which the put refuses as it would. Only a body that spells the edit's
/// key is decoded.
fn carried_edit(blob: &[u8]) -> Option<(ThreadBinding, AudienceEvent)> {
    if EntityMetadataHeader::parse(blob)?.entity_type != ENTITY_TYPE_TURN {
        return None;
    }
    let body = blob.get(ENTITY_METADATA_HEADER_LEN..)?;
    let key = ROOM_THREAD_AUDIENCE_KEY.as_bytes();
    if !body.windows(key.len()).any(|window| window == key) {
        return None;
    }
    let event = audience_event(body).ok()??;
    Some((thread_binding(body).ok()??, event))
}

/// The one edit a held and a carried copy of it settle to where they differ
/// only in whom they name erased: each slot no one where either copy made
/// it no one. `None` when they differ in anything else, or name two
/// different people in one slot.
fn merged(held: &AudienceEvent, carried: &AudienceEvent) -> Option<AudienceEvent> {
    if (held.root, held.op, held.history, held.request)
        != (carried.root, carried.op, carried.history, carried.request)
    {
        return None;
    }
    let erased = held.person.stand_in(held.root);
    if carried.person.stand_in(carried.root) != erased {
        return None;
    }
    Some(AudienceEvent {
        person: crate::deletion::carrier_actor_merged(held.person, carried.person, erased)?,
        by: crate::deletion::carrier_actor_merged(held.by, carried.by, RosterActor::Erased)?,
        ..*held
    })
}

/// How a held and a carried copy of one edit settle: the held copy's form
/// when the meeting erases more of it, and the carried copy's.
struct Settled {
    held: Option<AudienceEvent>,
    carried: AudienceEvent,
}

/// [`Settled`] for `carried`, bound by `binding`, at `id`: first the people
/// this vault erased, then the held copy's slots, where it holds one under
/// the same binding.
fn settled_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    binding: &ThreadBinding,
    carried: AudienceEvent,
) -> Result<Settled> {
    let mut settled = Settled {
        held: None,
        carried: erased_here_in(vault, txn, binding.room, carried)?,
    };
    if let Some((held_binding, held)) = live_edit_in(vault, txn, id)?
        && held_binding == *binding
        && let Some(both) = merged(&held, &settled.carried)
    {
        settled.held = (both != held).then_some(both);
        settled.carried = both;
    }
    Ok(settled)
}

/// The body `data` of the carried row `blob` at `id` as this vault admits
/// it: an audience edit in its settled form, the held edit rewritten in
/// place first when the copy erases more of it; any other row as it came.
///
/// # Errors
///
/// Storage errors, or a held edit that cannot be rewritten.
pub(crate) fn carried_audience_edit_in_txn<'a>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    blob: &[u8],
    data: Cow<'a, [u8]>,
) -> Result<Cow<'a, [u8]>> {
    let Some((binding, carried)) = carried_edit(blob) else {
        return Ok(data);
    };
    let settled = settled_in(vault, wtxn, id, &binding, carried)?;
    if let Some(held) = &settled.held {
        rewrite_audience_edit_in_txn(vault, wtxn, id, held)?;
    }
    if settled.carried == carried {
        return Ok(data);
    }
    Ok(Cow::Owned(event_body(&binding, &settled.carried)?))
}

/// Rewrites, under the same key, each audience edit carrier in `doc` that
/// names more than its settled form: every export, the reverse mirror and
/// the sweep. The window `history_free` names is pinned history-free first:
/// the operation a rewrite replaces still names them. Whether anything
/// changed.
///
/// # Errors
///
/// Storage errors, or a rewrite that cannot be written.
pub(crate) fn scrub_audience_edits(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    let entities = doc.get_map("entities");
    let mut carried = Vec::new();
    map_for_each_bytes(&entities, |map_key, blob| {
        if let Ok(id) = EntityId::from_hex(map_key)
            && let Some((binding, event)) = carried_edit(blob)
        {
            let header = blob[..ENTITY_METADATA_HEADER_LEN].to_vec();
            carried.push((map_key.to_owned(), id, header, binding, event));
        }
    });
    let mut rewrites = Vec::new();
    if !carried.is_empty() {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, id, mut blob, binding, event) in carried {
            let settled = settled_in(vault, &rtxn, &id, &binding, event)?.carried;
            if settled != event {
                blob.extend_from_slice(&event_body(&binding, &settled)?);
                rewrites.push((map_key, blob));
            }
        }
    }
    if rewrites.is_empty() {
        return Ok(false);
    }
    // Pin BEFORE the rewrite: the operation it replaces still names them.
    if let Some(key) = history_free {
        crate::sync::window::require_history_free_window(vault, key)?;
    }
    for (map_key, blob) in &rewrites {
        map_insert_bytes(&entities, map_key, blob)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}
