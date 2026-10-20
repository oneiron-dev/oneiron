//! A NOTE review bundle (KS7-2), under the NOTEs its waiting forks and
//! landings name. A bundle over one NOTE rides whole in that NOTE's
//! compartment. A bundle over several is split by NOTE: each member NOTE's
//! compartment holds a fragment with only its own forks and landings, its
//! path naming the NOTE and every member in the bundle's order, and its own
//! sealed copy of the explainer the members share ([`SHARED_EXPLAINER`]).
//! Each waiting fork's opener and each landing's actor is an actor part.
//!
//! A restore mirrors the erase: a landing whose actor did not open names no
//! one, a waiting fork whose opener did not open leaves the bundle and takes
//! the explainer with it, and a bundle left with no member is not written.
//! Fragments merge into the bundle the owners restored before them hold, in
//! the bundle's order, and the explainer stays readable while any member
//! NOTE's compartment opens.

use std::collections::BTreeSet;

use heed::RoTxn;

use super::super::proposals::{
    ACTOR_ERASE_PENDING_NOTE_FORK, NOTE_PROPOSAL_BUNDLE, NoteActor, NoteReviewBundle,
    PendingNoteForkErase,
};
use super::fill;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OwnerRef, RowLocator, RowPart, TypedRow, Unresolved,
};

/// The field a waiting fork's opener fills, before the fork's id.
const WAITING: &str = "waiting ";

/// The field a landing's actor fills, before the receipt's id.
const LANDED: &str = "landed ";

/// The explainer a bundle that lost a waiting fork keeps, as the erase
/// writes it.
const REDACTED: &str = "redacted";

/// CALLS SHARED_EXPLAINER (FIX 6073, Engine 10-20 09:2x): shared NOTE bundle
/// explainer = shared atom per member. The explainer of a bundle over
/// several NOTEs is its own atom at this path, one sealed copy held by each
/// member NOTE: one member's erase retires only its copy, and the text stays
/// readable until the last member is erased. Each copy names every waiting
/// fork's opener as an actor part, so every copy reads "redacted" once any
/// of them did not open, as the erase leaves the bundle.
const SHARED_EXPLAINER: &str = "explainer ";

pub(super) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    for row in rows::typed_rows(dbs, txn, NOTE_PROPOSAL_BUNDLE, out)? {
        let notes: BTreeSet<EntityId> = row
            .value
            .waiting
            .iter()
            .map(|fork| fork.note)
            .chain(row.value.landed.iter().map(|receipt| receipt.note))
            .collect();
        let mut members = notes.iter();
        match (members.next(), members.next()) {
            (Some(note), None) => {
                let owner = OwnerRef::entity(note);
                rows::split_actors(out, owner, NOTE_PROPOSAL_BUNDLE, row, take_actors)?;
            }
            (Some(_), Some(_)) => split(out, row, &notes)?,
            (None, _) => out.unclassified(row.at, None, Unresolved::NoOwner),
        }
    }
    Ok(())
}

/// Ids in one canonical spelling, comma-joined.
fn ids(list: impl Iterator<Item = EntityId>) -> String {
    list.map(|id| id.to_hex()).collect::<Vec<_>>().join(",")
}

/// Where `id` sits in a part path's member order.
fn place(order: &[&str], id: &EntityId) -> Option<usize> {
    let hex = id.to_hex();
    order.iter().position(|held| *held == hex)
}

/// Splits a bundle over several NOTEs into one fragment and one explainer
/// copy per member NOTE.
fn split(
    out: &mut Captured,
    row: TypedRow<EntityId, NoteReviewBundle>,
    notes: &BTreeSet<EntityId>,
) -> Result<()> {
    if !rows::spells_back(NOTE_PROPOSAL_BUNDLE, &row) {
        let reason = Unresolved::ActorSplit(rows::NOT_SPELLED_BACK);
        out.unclassified(row.at, None, reason);
        return Ok(());
    }
    let bundle = &row.value;
    let order = format!(
        "{};{}",
        ids(bundle.waiting.iter().map(|fork| fork.fork)),
        ids(bundle.landed.iter().map(|receipt| receipt.id)),
    );
    let openers: Vec<(EntityId, EntityId)> = bundle
        .waiting
        .iter()
        .filter_map(|fork| match fork.actor {
            NoteActor::Actor(opener) => Some((fork.fork, opener)),
            NoteActor::Erased => None,
        })
        .collect();
    let held = ids(openers.iter().map(|(fork, _)| *fork));
    for note in notes {
        let mut fragment = NoteReviewBundle {
            id: bundle.id,
            waiting: bundle
                .waiting
                .iter()
                .filter(|fork| fork.note == *note)
                .cloned()
                .collect(),
            landed: bundle
                .landed
                .iter()
                .filter(|receipt| receipt.note == *note)
                .cloned()
                .collect(),
            explainer: String::new(),
        };
        let actors = take_actors(&mut fragment);
        let at = row.at.fragment(format!("{}:{order}", note.to_hex()));
        let copy = row
            .at
            .fragment(format!("{SHARED_EXPLAINER}{}:{held}", note.to_hex()));
        let value = NOTE_PROPOSAL_BUNDLE.encode_value(&fragment)?;
        let member = out.owner(OwnerRef::entity(note));
        for (field, actor) in actors {
            member.actor_parts.push(ActorPart {
                actor_entity: actor,
                content_locator: at.clone(),
                field,
                bytes: actor.as_bytes().to_vec(),
            });
        }
        member.rows.push(RowPart::NoActor { at, value });
        for (fork, opener) in &openers {
            member.actor_parts.push(ActorPart {
                actor_entity: *opener,
                content_locator: copy.clone(),
                field: format!("{WAITING}{}", fork.to_hex()),
                bytes: opener.as_bytes().to_vec(),
            });
        }
        member.rows.push(RowPart::NoActor {
            at: copy,
            value: bundle.explainer.clone().into_bytes(),
        });
    }
    Ok(())
}

fn take_actors(bundle: &mut NoteReviewBundle) -> Vec<(String, EntityId)> {
    let mut actors = Vec::new();
    for fork in &mut bundle.waiting {
        if let NoteActor::Actor(id) = std::mem::replace(&mut fork.actor, NoteActor::Erased) {
            actors.push((format!("{WAITING}{}", fork.fork.to_hex()), id));
        }
    }
    for receipt in &mut bundle.landed {
        if let NoteActor::Actor(id) = std::mem::replace(&mut receipt.actor, NoteActor::Erased) {
            actors.push((format!("{LANDED}{}", receipt.id.to_hex()), id));
        }
    }
    actors
}

fn put_actor(bundle: &mut NoteReviewBundle, field: &str, actor: EntityId) -> Result<()> {
    let slot = if let Some(id) = field.strip_prefix(WAITING) {
        bundle
            .waiting
            .iter_mut()
            .find(|fork| fork.fork.to_hex() == id)
            .map(|fork| &mut fork.actor)
    } else if let Some(id) = field.strip_prefix(LANDED) {
        bundle
            .landed
            .iter_mut()
            .find(|receipt| receipt.id.to_hex() == id)
            .map(|receipt| &mut receipt.actor)
    } else {
        None
    };
    fill(slot.ok_or_else(rows::bad_part)?, actor)
}

/// Takes out each waiting fork whose opener did not open, as the erase
/// does; whether any went.
fn drop_unopened(bundle: &mut NoteReviewBundle) -> bool {
    let waiting = bundle.waiting.len();
    if ACTOR_ERASE_PENDING_NOTE_FORK == PendingNoteForkErase::Delete {
        bundle
            .waiting
            .retain(|fork| fork.actor != NoteActor::Erased);
    }
    bundle.waiting.len() != waiting
}

/// A bundle part with its opened actors back, as the erase leaves it for
/// each actor that did not open: a whole bundle, a member NOTE's fragment
/// merged into the bundle `view` holds, or a member's explainer copy put in
/// it. `None` while no member is left.
pub(super) fn join(
    dbs: &impl ManifestDbs,
    view: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if let Some(copy) = at.path.strip_prefix(SHARED_EXPLAINER) {
        return join_explainer(dbs, view, at, copy, value, parts);
    }
    if !at.path.is_empty() {
        return join_fragment(dbs, view, at, value, parts);
    }
    let mut bundle = rows::join_actors(NOTE_PROPOSAL_BUNDLE, value, parts, put_actor)?;
    if drop_unopened(&mut bundle) {
        bundle.explainer = REDACTED.to_owned();
    }
    if bundle.waiting.is_empty() && bundle.landed.is_empty() {
        return Ok(None);
    }
    NOTE_PROPOSAL_BUNDLE.encode_value(&bundle).map(Some)
}

/// The bundle `view` holds at `at`'s key, restored by an earlier part.
fn restored(
    dbs: &impl ManifestDbs,
    view: &RoTxn<'_>,
    at: &RowLocator,
) -> Result<Option<NoteReviewBundle>> {
    let key = at
        .key
        .strip_prefix(NOTE_PROPOSAL_BUNDLE.decl().prefix)
        .and_then(EntityId::decode_key)
        .ok_or_else(rows::bad_part)?;
    NOTE_PROPOSAL_BUNDLE.get(dbs, view, &key)
}

/// A member NOTE's fragment, merged into the bundle in the bundle's order.
/// The explainer stays as the copies put it.
fn join_fragment(
    dbs: &impl ManifestDbs,
    view: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    let (waiting, landed) = at
        .path
        .split_once(':')
        .and_then(|(_, order)| order.split_once(';'))
        .ok_or_else(rows::bad_part)?;
    let waiting: Vec<&str> = waiting.split(',').collect();
    let landed: Vec<&str> = landed.split(',').collect();
    let mut fragment = rows::join_actors(NOTE_PROPOSAL_BUNDLE, value, parts, put_actor)?;
    drop_unopened(&mut fragment);
    let mut merged = match restored(dbs, view, at)? {
        Some(mut earlier) => {
            if earlier.id != fragment.id {
                return Err(rows::bad_part());
            }
            earlier.waiting.extend(fragment.waiting);
            earlier.landed.extend(fragment.landed);
            earlier
        }
        None => fragment,
    };
    if merged
        .waiting
        .iter()
        .any(|fork| place(&waiting, &fork.fork).is_none())
        || merged
            .landed
            .iter()
            .any(|receipt| place(&landed, &receipt.id).is_none())
    {
        return Err(rows::bad_part());
    }
    merged
        .waiting
        .sort_by_key(|fork| place(&waiting, &fork.fork));
    merged
        .landed
        .sort_by_key(|receipt| place(&landed, &receipt.id));
    if merged.waiting.is_empty() && merged.landed.is_empty() {
        return Ok(None);
    }
    NOTE_PROPOSAL_BUNDLE.encode_value(&merged).map(Some)
}

/// A member's explainer copy, put in the bundle its fragment merged into:
/// the text while every waiting fork's opener opened, else "redacted". Every
/// copy reads the same, so a later copy finds the explainer an earlier one
/// put; `None` when no fragment left a bundle.
fn join_explainer(
    dbs: &impl ManifestDbs,
    view: &RoTxn<'_>,
    at: &RowLocator,
    copy: &str,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    let (_, held) = copy.split_once(':').ok_or_else(rows::bad_part)?;
    let held: Vec<String> = held
        .split(',')
        .filter(|fork| !fork.is_empty())
        .map(|fork| format!("{WAITING}{fork}"))
        .collect();
    if parts.iter().any(|part| {
        !held.contains(&part.field)
            || part.bytes.as_slice() != part.actor_entity.as_bytes().as_slice()
    }) {
        return Err(rows::bad_part());
    }
    let text = String::from_utf8(value.to_vec()).map_err(|_| rows::bad_part())?;
    let explainer = if ACTOR_ERASE_PENDING_NOTE_FORK == PendingNoteForkErase::Delete
        && parts.len() != held.len()
    {
        REDACTED.to_owned()
    } else {
        text
    };
    let Some(mut bundle) = restored(dbs, view, at)? else {
        return Ok(None);
    };
    if !bundle.explainer.is_empty() && bundle.explainer != explainer {
        return Err(rows::bad_part());
    }
    bundle.explainer = explainer;
    NOTE_PROPOSAL_BUNDLE.encode_value(&bundle).map(Some)
}
