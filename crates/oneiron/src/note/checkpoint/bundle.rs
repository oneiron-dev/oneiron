//! A NOTE review bundle (KS7-2), under the NOTE its waiting forks and
//! landings name. Its explainer is text all its members share, so a bundle
//! over several NOTEs has no one owner and is not compartmented. Each waiting
//! fork's opener and each landing's actor is an actor part.
//!
//! A restore mirrors the erase: a landing whose actor did not open names no
//! one, a waiting fork whose opener did not open leaves the bundle and takes
//! the explainer with it, and a bundle left with no member is not written.

use std::collections::BTreeSet;

use heed::RoTxn;

use super::super::proposals::{
    ACTOR_ERASE_PENDING_NOTE_FORK, NOTE_PROPOSAL_BUNDLE, NoteActor, NoteReviewBundle,
    PendingNoteForkErase,
};
use super::fill;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{self, ActorPart, Captured, OwnerRef, Unresolved};

/// The field a waiting fork's opener fills, before the fork's id.
const WAITING: &str = "waiting ";

/// The field a landing's actor fills, before the receipt's id.
const LANDED: &str = "landed ";

/// The explainer a bundle that lost a waiting fork keeps, as the erase
/// writes it.
const REDACTED: &str = "redacted";

pub(super) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    for row in rows::typed_rows(dbs, txn, NOTE_PROPOSAL_BUNDLE, out)? {
        let notes: BTreeSet<EntityId> = row
            .value
            .waiting
            .iter()
            .map(|fork| fork.note)
            .chain(row.value.landed.iter().map(|receipt| receipt.note))
            .collect();
        let mut notes = notes.into_iter();
        match (notes.next(), notes.next()) {
            (Some(note), None) => {
                let owner = OwnerRef::entity(&note);
                rows::split_actors(out, owner, NOTE_PROPOSAL_BUNDLE, row, take_actors)?;
            }
            (Some(_), Some(_)) => out.unclassified(row.at, None, Unresolved::SharedOwners),
            (None, _) => out.unclassified(row.at, None, Unresolved::NoOwner),
        }
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

/// A bundle with its opened actors back, as the erase leaves it for each
/// actor that did not open; `None` when no member is left.
pub(super) fn join(value: &[u8], parts: &[&ActorPart]) -> Result<Option<Vec<u8>>> {
    let mut bundle = rows::join_actors(NOTE_PROPOSAL_BUNDLE, value, parts, put_actor)?;
    let waiting = bundle.waiting.len();
    if ACTOR_ERASE_PENDING_NOTE_FORK == PendingNoteForkErase::Delete {
        bundle
            .waiting
            .retain(|fork| fork.actor != NoteActor::Erased);
    }
    if bundle.waiting.len() != waiting {
        bundle.explainer = REDACTED.to_owned();
    }
    if bundle.waiting.is_empty() && bundle.landed.is_empty() {
        return Ok(None);
    }
    NOTE_PROPOSAL_BUNDLE.encode_value(&bundle).map(Some)
}
