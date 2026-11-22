//! Where each window root map's values go (KS7-3a): the typed owner,
//! dependency and actor dispatch KS7-3b's Loro projection asks of every
//! value it finds, in a window's shallow root, its latest state, its
//! retained operations and its pending and queued updates alike. Each map
//! is read with its own family's codec, never by guessing from text: an
//! entity row by its kind, an edge by its two ends, a NOTE workflow record
//! by the NOTE it binds, a room's rows by the turn or room they ride with,
//! a pin by its citer and the message it quotes, a message document by its
//! message, an author carrier by the actor it attributes (FIX 17143). A
//! value naming a live actor no split here takes out, a nested
//! history, and a map no adapter reads stay unclassified, named. A Loro
//! PeerID is the writer of an operation, never an owner of what it wrote.
//! Each map's row ([`super::descriptor`]) names its hooks, here and in the
//! families.
//!
//! KS7-3b also asks which keys may stand plaintext in a skeleton
//! ([`super::descriptor::key_refusal`]), which of the others it withholds in
//! an atom of their own ([`withheld_key`], FIX 10279), and how a split value
//! or key takes its opened actors back ([`root_fill`], [`key_fill`]).

use loro::LoroValue;

use super::rows::named;
use super::{KeyClass, KindPlacement, Placement, SyncPayloadOwners, SyncUnclassified};
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::checkpoint::EntityRowPlacement;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE};
use crate::store::checkpoint_payload::rows::{OtherClient, OwnerRef, Unresolved, bad_part};
use crate::sync::bridge::{format_edge_key, parse_edge_key};
use crate::sync::carrier_parts::is_part_key;
use crate::sync::custody::CUSTODY_MAP;
use crate::sync::document_pins::DOCUMENT_PINS_MAP;
use crate::sync::ingest::{admit_peer_origin_carrier, admit_writer_proof_carrier};
use crate::sync::room_turns::ROOM_TURNS_MAP;
use crate::sync::row_birth::ROW_BIRTHS_MAP;
use crate::sync::selector::HELD_EDIT_CAUSALITY_KEY;
use crate::sync::withdrawn_cutoffs::{
    CarriedCutoff, EPOCH_FLOOR, admit_withdrawn_cutoff_carrier, epoch_floor_scope,
};

/// An `authored_by` edge, whose key names its actor.
const AUTHORED_BY: &str = "an authored_by edge names its actor";

/// An entity's whole document (a deck body's `tables` and `charts` roots
/// among its nested containers), whose history only its own split takes
/// out.
const ENTITY_DOCUMENT: &str = "an entity's whole document and its nested history";

/// A value no adapter reads: it keeps the group whole.
fn undecodable() -> Placement {
    Placement::unclassified(None, SyncUnclassified::Undecodable)
}

/// An entity row under its id. An author carrier's actor is split out (FIX
/// 17143).
pub(super) fn entity(key: &str, value: &[u8], owners: &dyn SyncPayloadOwners) -> Placement {
    named(key).map_or_else(undecodable, |id| {
        super::author_carrier::entry(id, value).unwrap_or_else(|| entity_row(id, value, owners))
    })
}

/// An edge under its canonical key.
pub(super) fn edge(key: &str, value: &[u8]) -> Placement {
    match parse_edge_key(key) {
        // An authored_by edge is its source's: the actor it names rides
        // in its withheld key alone (FIX 10279, `withheld_key`), so the
        // edge goes with that actor. Its value must be the kind's own
        // layout, which holds no actor.
        Some((source, EdgeKind::AuthoredBy, actor))
            if format_edge_key(&source, EdgeKind::AuthoredBy, &actor) == key
                && crate::edge::decode_edge_value_for_kind(EdgeKind::AuthoredBy, value).is_ok() =>
        {
            Placement::owned(OwnerRef::entity(&source), Vec::new())
        }
        Some((_, EdgeKind::AuthoredBy, _)) => undecodable(),
        // Any other edge holds while both its ends do.
        Some((source, _, target)) => Placement::Structure {
            dependencies: vec![OwnerRef::entity(&source), OwnerRef::entity(&target)],
        },
        None => undecodable(),
    }
}

/// A tombstone names a deleted id, and outlives it.
pub(super) fn tombstone(key: &str, _: &[u8]) -> Placement {
    named(key).map_or_else(undecodable, |_| Placement::Structure {
        dependencies: Vec::new(),
    })
}

/// A neutral delete's causality: no adapter reads it, so a value in this
/// root keeps the group whole.
pub(super) fn held_edit_causality(_: &str, _: &[u8]) -> Placement {
    Placement::unclassified(None, SyncUnclassified::UnknownRoot)
}

/// A retained claim world, held while its entity is.
pub(super) fn retained_claim_world(key: &str, value: &[u8]) -> Placement {
    match named(key) {
        Some(id) if value.len() == 16 => Placement::Structure {
            dependencies: vec![OwnerRef::entity(&id)],
        },
        _ => undecodable(),
    }
}

/// A peer's origin, held while its entity is.
pub(super) fn peer_origin(key: &str, value: &[u8]) -> Placement {
    match (named(key), admit_peer_origin_carrier(key, &binary(value))) {
        (Some(id), Ok(())) => Placement::Structure {
            dependencies: vec![OwnerRef::entity(&id)],
        },
        _ => undecodable(),
    }
}

/// A writer's proof holds while its MESSAGE row does (FIX 12113).
pub(super) fn message_writer(key: &str, value: &[u8]) -> Placement {
    match (named(key), admit_writer_proof_carrier(key, &binary(value))) {
        (Some(id), Ok(())) => Placement::Structure {
            dependencies: vec![OwnerRef::entity(&id)],
        },
        _ => undecodable(),
    }
}

/// A withdrawn artifact's cutoff, held while the artifact is; a
/// conversation's floor, while its session and conversation are.
pub(super) fn withdrawn_cutoff(key: &str, value: &[u8]) -> Placement {
    match admit_withdrawn_cutoff_carrier(key, &binary(value)) {
        Ok(CarriedCutoff::Withdrawn(artifact, _)) => Placement::Structure {
            dependencies: vec![OwnerRef::entity(&artifact)],
        },
        Ok(CarriedCutoff::EpochFloor(scope, _, _)) => Placement::Structure {
            dependencies: std::iter::once(scope.session)
                .chain(scope.conversation)
                .map(|id| OwnerRef::entity(&id))
                .collect(),
        },
        Err(_) => undecodable(),
    }
}

/// An entity's whole document, named by its entity.
pub(super) fn entity_document(key: &str, _: &[u8]) -> Placement {
    Placement::unclassified(
        named(key).map(|id| OwnerRef::entity(&id)),
        SyncUnclassified::ActorSplit(ENTITY_DOCUMENT),
    )
}

/// KS-2 carries every ASSET byte, a by-reference body's too.
pub(super) fn asset_body_ref(_: &str, _: &[u8]) -> Placement {
    Placement::Dispatched(OtherClient::Body)
}

/// An entity's row bytes, placed by its kind as the registry places it. A
/// CLAIM or a NOTE is placed from its own bytes, as its getter places the
/// row (FIX 10279): an ordinary CLAIM and a NOTE that names no one are their
/// tree's, a dreamer step's CLAIM is the response client's, and an origin
/// CLAIM or a NOTE core with a live author stays whole, named.
pub(super) fn entity_row(id: EntityId, value: &[u8], owners: &dyn SyncPayloadOwners) -> Placement {
    let owner = OwnerRef::entity(&id);
    let header = EntityMetadataHeader::parse(value);
    if header
        .as_ref()
        .is_some_and(|header| [ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE].contains(&header.entity_type))
    {
        return match crate::ports::checkpoint::entity_row_placement(value) {
            EntityRowPlacement::Owner => Placement::owned(owner, Vec::new()),
            EntityRowPlacement::Other(client) => Placement::Dispatched(client),
            // Only an identity-topology carrier is one, and no such kind
            // takes this branch: a window's copy splits in
            // `author_carrier`, and a thin cache copy stays whole.
            EntityRowPlacement::Actor(_) => {
                Placement::unclassified(Some(owner), SyncUnclassified::UnknownKind)
            }
            EntityRowPlacement::Unclassified(reason) => {
                Placement::unclassified(Some(owner), unclassified(reason))
            }
        };
    }
    let kind = header.map(|header| owners.entity_kind(header.entity_type));
    match kind {
        Some(KindPlacement::Owner) => Placement::owned(owner, Vec::new()),
        Some(KindPlacement::Other(client)) => Placement::Dispatched(client),
        Some(KindPlacement::Unclassified(reason)) => Placement::unclassified(Some(owner), reason),
        None => Placement::unclassified(Some(owner), SyncUnclassified::Undecodable),
    }
}

/// The sync reason for a row the getter's rule leaves whole.
fn unclassified(reason: Unresolved) -> SyncUnclassified {
    match reason {
        Unresolved::Undecodable => SyncUnclassified::Undecodable,
        Unresolved::UnknownKind => SyncUnclassified::UnknownKind,
        Unresolved::NoOwner | Unresolved::SharedOwners => SyncUnclassified::NoOwner,
        Unresolved::ActorSplit(why) => SyncUnclassified::ActorSplit(why),
    }
}

/// `value` as the window map holds it.
fn binary(value: &[u8]) -> LoroValue {
    LoroValue::Binary(value.to_vec().into())
}

/// An edge's key: an authored_by edge's names its actor; any other edge's
/// is opaque in its canonical spelling.
pub(super) fn edge_key(key: &str) -> std::result::Result<KeyClass, SyncUnclassified> {
    match parse_edge_key(key) {
        Some((_, EdgeKind::AuthoredBy, _)) => Err(SyncUnclassified::ActorSplit(AUTHORED_BY)),
        Some((source, kind, target)) if format_edge_key(&source, kind, &target) == key => {
            Ok(KeyClass::Opaque)
        }
        _ => Ok(KeyClass::Payload),
    }
}

/// Only neutral deletes use this map's one key. A value in this root still
/// has no adapter and keeps the group whole.
pub(super) fn held_edit_causality_key(
    key: &str,
) -> std::result::Result<KeyClass, SyncUnclassified> {
    if key == HELD_EDIT_CAUSALITY_KEY {
        Ok(KeyClass::Opaque)
    } else {
        Err(SyncUnclassified::UnknownRoot)
    }
}

/// A withdrawn artifact's id; a conversation's floor names its session, then
/// its conversation (FIX 5029).
pub(super) fn withdrawn_cutoff_key(key: &str) -> KeyClass {
    match key.strip_prefix(EPOCH_FLOOR) {
        Some(filed) if epoch_floor_scope(filed).is_ok() => KeyClass::Opaque,
        Some(_) => KeyClass::Payload,
        None if named(key).is_some() => KeyClass::Opaque,
        None => KeyClass::Payload,
    }
}

/// A wake's key: its turn and registration in their one spelling.
pub(super) fn turn_program_wake_key(key: &str) -> KeyClass {
    if crate::sync::turn_programs::wake_key_is_opaque(key) {
        KeyClass::Opaque
    } else {
        KeyClass::Payload
    }
}

/// The field a withheld key's actor fills.
const KEY_ACTOR: &str = "actor";

/// A window map key the skeleton withholds in an atom of its own: its
/// rightful holders and, for a key that names an actor, that actor split
/// out of it.
pub(super) struct WithheldKey {
    pub(super) holders: Vec<super::Holder>,
    pub(super) split: Option<super::ValueSplit>,
}

/// How the skeleton withholds `key` of the window root map `root`, a key
/// that may not stand plaintext (FIX 10279, FIX 10278): an authored_by
/// edge's key is its source's, the actor it names split out, so the key, and
/// the edge with it, goes with that actor; a whole document pin's key, the
/// digest of the pin naming no one, is its citer's, held while the message
/// it quotes is, as the pin is. `None` for every other key: a part's digest
/// is withheld under its manifests' holders ([`super::descriptor::withheld_part_key`]), a
/// custody digest beside its client's copy ([`withheld_client_key`]), and any
/// other keeps its window whole as [`super::descriptor::key_refusal`] names.
pub(super) fn withheld_key(root: &str, key: &str) -> Option<WithheldKey> {
    match root {
        "edges" => {
            let (source, kind, actor) = parse_edge_key(key)?;
            if !matches!(kind, EdgeKind::AuthoredBy)
                || format_edge_key(&source, kind, &actor) != key
            {
                return None;
            }
            let stem = key.strip_suffix(actor.to_hex().as_str())?;
            Some(WithheldKey {
                holders: vec![super::Holder::new(OwnerRef::entity(&source), Vec::new())],
                split: Some(super::ValueSplit {
                    no_one: stem.as_bytes().to_vec(),
                    actors: vec![(KEY_ACTOR.to_owned(), actor)],
                }),
            })
        }
        DOCUMENT_PINS_MAP if !is_part_key(key) => {
            let (message, citation) = crate::room_codec::document_pins::key_ids(key)?;
            Some(WithheldKey {
                holders: vec![super::Holder::new(
                    OwnerRef::entity(&citation),
                    vec![OwnerRef::entity(&message)],
                )],
                split: None,
            })
        }
        _ => None,
    }
}

/// The client the skeleton withholds `key` of `root` for, beside that
/// client's copy of its value (FIX 10278): a protected input, a witness part
/// or a sealed copy in the custody map is filed under a digest of it, and the
/// credential client's copy holds both. `None` for every other key.
pub(super) fn withheld_client_key(root: &str, key: &str) -> Option<OtherClient> {
    (root == CUSTODY_MAP
        && matches!(
            crate::sync::custody::checkpoint::key_class(key),
            KeyClass::Digest
        ))
    .then_some(OtherClient::Credential)
}

/// The key `no_one`, a split of a withheld key of `root`, with each of
/// `opened` back: `None` when the actor it names did not open. A field the
/// family does not spell, or a key that is not its family's in its one
/// spelling, refuses.
pub(super) fn key_fill(
    root: &str,
    no_one: &[u8],
    opened: &[(&str, EntityId)],
) -> Result<Option<String>> {
    match root {
        "edges" => {
            let stem = std::str::from_utf8(no_one).map_err(|_| bad_part())?;
            let actor = match opened {
                [] => return Ok(None),
                [(KEY_ACTOR, actor)] => *actor,
                _ => return Err(bad_part()),
            };
            let key = format!("{stem}{}", actor.to_hex());
            match parse_edge_key(&key) {
                Some((source, EdgeKind::AuthoredBy, target))
                    if target == actor
                        && format_edge_key(&source, EdgeKind::AuthoredBy, &target) == key =>
                {
                    Ok(Some(key))
                }
                _ => Err(bad_part()),
            }
        }
        _ => Err(bad_part()),
    }
}

/// The value `no_one`, a split of the value under `key` in `root`, with
/// each of `opened` (a field and its actor) back: `None` when its family
/// drops it for an actor that did not open. `holes` is every field the
/// split took out, opened or not: a family that drops what did not open
/// tells it from what the stored value already named no one in (FIX 10282).
/// A field the family does not spell refuses.
pub(super) fn root_fill(
    root: &str,
    key: &str,
    no_one: &[u8],
    opened: &[(&str, EntityId)],
    holes: &std::collections::BTreeSet<&str>,
) -> Result<Option<Vec<u8>>> {
    match root {
        ROOM_TURNS_MAP => crate::sync::room_turns::checkpoint::fill(no_one, opened),
        "head_move_receipts" | "note_forks" | "note_proposals" => {
            crate::sync::note::checkpoint::fill(root, no_one, opened, holes)
        }
        DOCUMENT_PINS_MAP => crate::sync::document_pins::checkpoint::fill(no_one, opened),
        ROW_BIRTHS_MAP => crate::sync::row_birth::checkpoint::fill(key, no_one, opened),
        "entities" => {
            let id = named(key).ok_or_else(bad_part)?;
            super::author_carrier::fill(id, no_one, opened)
        }
        _ => Err(bad_part()),
    }
}
