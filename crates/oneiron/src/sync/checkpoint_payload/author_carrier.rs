//! A window's copy of an identity-topology author carrier (FIX 17143): an
//! `entities` value whose row is an author attribution names the actor it
//! attributes, so that actor is split out, as the vault's own carrier row
//! goes under it (`crate::ports::checkpoint`). A carrier has no erased form:
//! an attribution names an actor or is none. So the copy holds the carrier's
//! own id in the actor's place, a placeholder only, and a carrier whose
//! actor does not open goes, never that stand-in, as the live erase deletes
//! it (`crate::identity_topology::redact_actor_in_txn`).

use super::{Holder, Placement, ValueSplit};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::identity_topology::{
    StoredIdentityOpAction, StoredIdentityOpEvent, author_carrier_actor,
    decode_identity_topology_event_body, encode_identity_topology_event_body,
};
use crate::store::checkpoint_payload::rows::{OwnerRef, bad_part};
use crate::write_envelope::WriteActor;

/// The field the attributed actor fills.
const ATTRIBUTED: &str = "author_attribution.actor";

/// Where the window value `value` of the entity `id` goes when it is an
/// author carrier: under the carrier's tree, its actor split out. `None`
/// when it is no carrier, or when its split does not give it back whole.
pub(super) fn entry(id: EntityId, value: &[u8]) -> Option<Placement> {
    let author = author_carrier_actor(value)?;
    let no_one = with_actor(value, |actor| WriteActor::new(id, actor.actor_class())).ok()?;
    let back = with_actor(&no_one, |actor| {
        WriteActor::new(author, actor.actor_class())
    })
    .ok()?;
    if back != value {
        return None;
    }
    Some(Placement::Split {
        holders: vec![Holder::new(OwnerRef::entity(&id), Vec::new())],
        split: ValueSplit {
            no_one,
            actors: vec![(ATTRIBUTED.to_owned(), author)],
        },
    })
}

/// The carrier `placeholder` of the entity `id` names, with its actor back;
/// `None` when the actor did not open.
///
/// # Errors
///
/// A placeholder that is no carrier holding `id` in its actor's place, or a
/// field this split does not spell.
pub(super) fn fill(
    id: EntityId,
    placeholder: &[u8],
    opened: &[(&str, EntityId)],
) -> Result<Option<Vec<u8>>> {
    if author_carrier_actor(placeholder) != Some(id) {
        return Err(bad_part());
    }
    match opened {
        [] => Ok(None),
        [(field, actor)] if *field == ATTRIBUTED => with_actor(placeholder, |held| {
            WriteActor::new(*actor, held.actor_class())
        })
        .map(Some),
        _ => Err(bad_part()),
    }
}

/// The carrier row `row` with its attributed actor replaced by `actor` of
/// the one it holds; its header and every other field as they stand.
fn with_actor(row: &[u8], actor: impl FnOnce(&WriteActor) -> WriteActor) -> Result<Vec<u8>> {
    let header = row.get(..ENTITY_METADATA_HEADER_LEN).ok_or_else(bad_part)?;
    let body = row.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(bad_part)?;
    let mut record: StoredIdentityOpEvent = decode_identity_topology_event_body(body)?;
    let StoredIdentityOpAction::AuthorAttribution { actor: held, .. } = &mut record.action else {
        return Err(bad_part());
    };
    *held = actor(held);
    let mut out = header.to_vec();
    out.extend(encode_identity_topology_event_body(&record)?);
    Ok(out)
}
