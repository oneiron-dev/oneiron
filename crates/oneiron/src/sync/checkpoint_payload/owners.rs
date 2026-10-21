//! Where each window root map's values go (KS7-3a): the typed owner,
//! dependency and actor dispatch KS7-3b's Loro projection asks of every
//! value it finds, in a window's shallow root, its latest state, its
//! retained operations and its pending and queued updates alike. Each map
//! is read with its own family's codec, never by guessing from text: an
//! entity row by its kind, an edge by its two ends, a NOTE workflow record
//! by the NOTE it binds, a room's rows by the turn or room they ride with,
//! a pin by its citer and the message it quotes, a message document by its
//! message. A value naming a live actor no split here takes out, a nested
//! history, and a map no adapter reads stay unclassified, named. A Loro
//! PeerID is the writer of an operation, never an owner of what it wrote.

use loro::LoroValue;

use super::rows::named;
use super::{KindPlacement, Placement, SyncPayloadOwners, SyncUnclassified};
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::store::checkpoint_payload::rows::{OtherClient, OwnerRef};
use crate::sync::bridge::parse_edge_key;
use crate::sync::custody::CUSTODY_MAP;
use crate::sync::document_pins::DOCUMENT_PINS_MAP;
use crate::sync::ingest::{PEER_ORIGIN_MAP, admit_peer_origin_carrier};
use crate::sync::message_docs::MESSAGE_DOCS_MAP;
use crate::sync::room_facts::ROOM_FACTS_MAP;
use crate::sync::room_turns::ROOM_TURNS_MAP;
use crate::sync::row_birth::ROW_BIRTHS_MAP;
use crate::sync::schema::ASSET_BODY_REFS_MAP;
use crate::sync::withdrawn_cutoffs::{
    CarriedCutoff, WITHDRAWN_CUTOFFS_MAP, admit_withdrawn_cutoff_carrier,
};

/// An `authored_by` edge, whose key names its actor.
const AUTHORED_BY: &str = "an authored_by edge names its actor";

/// A row birth, which names the actor that made its row.
const ROW_BIRTH: &str = "a row birth names the actor that made its row";

/// An entity's whole document (a deck body's `tables` and `charts` roots
/// among its nested containers), whose history only its own split takes
/// out.
const ENTITY_DOCUMENT: &str = "an entity's whole document and its nested history";

/// Where the value `value` under `key` in the window root map `root` goes.
/// `owners` places an entity row by its kind.
pub(crate) fn root_entry(
    root: &str,
    key: &str,
    value: &[u8],
    owners: &dyn SyncPayloadOwners,
) -> Placement {
    let structure = |dependencies: Vec<OwnerRef>| Placement::Structure { dependencies };
    let undecodable = || Placement::unclassified(None, SyncUnclassified::Undecodable);
    let entity = named(key);
    match root {
        "entities" => entity.map_or_else(undecodable, |id| entity_row(id, value, owners)),
        "edges" => match parse_edge_key(key) {
            Some((source, EdgeKind::AuthoredBy, _)) => Placement::unclassified(
                Some(OwnerRef::entity(&source)),
                SyncUnclassified::ActorSplit(AUTHORED_BY),
            ),
            // Any other edge holds while both its ends do.
            Some((source, _, target)) => {
                structure(vec![OwnerRef::entity(&source), OwnerRef::entity(&target)])
            }
            None => undecodable(),
        },
        // A tombstone names a deleted id, and outlives it.
        "tombstones" => entity.map_or_else(undecodable, |_| structure(Vec::new())),
        "retained_claim_worlds" => match entity {
            Some(id) if value.len() == 16 => structure(vec![OwnerRef::entity(&id)]),
            _ => undecodable(),
        },
        ROW_BIRTHS_MAP => entity.map_or_else(undecodable, |id| {
            Placement::unclassified(
                Some(OwnerRef::entity(&id)),
                SyncUnclassified::ActorSplit(ROW_BIRTH),
            )
        }),
        PEER_ORIGIN_MAP => match (entity, admit_peer_origin_carrier(key, &binary(value))) {
            (Some(id), Ok(())) => structure(vec![OwnerRef::entity(&id)]),
            _ => undecodable(),
        },
        WITHDRAWN_CUTOFFS_MAP => match admit_withdrawn_cutoff_carrier(key, &binary(value)) {
            Ok(CarriedCutoff::Withdrawn(artifact, _)) => {
                structure(vec![OwnerRef::entity(&artifact)])
            }
            Ok(CarriedCutoff::EpochFloor(session, _, _)) => {
                structure(vec![OwnerRef::entity(&session)])
            }
            Err(_) => undecodable(),
        },
        "documents" | "document_heads" | "head_move_receipts" | "note_forks" | "note_proposals" => {
            crate::sync::note::checkpoint::entry(root, key, value)
        }
        "entity_documents" => Placement::unclassified(
            entity.map(|id| OwnerRef::entity(&id)),
            SyncUnclassified::ActorSplit(ENTITY_DOCUMENT),
        ),
        CUSTODY_MAP => crate::sync::custody::checkpoint::entry(key, value),
        ROOM_TURNS_MAP => crate::sync::room_turns::checkpoint::entry(key, value),
        ROOM_FACTS_MAP => crate::sync::room_facts::checkpoint::entry(key, value),
        DOCUMENT_PINS_MAP => crate::sync::document_pins::checkpoint::entry(key, value),
        MESSAGE_DOCS_MAP => crate::sync::message_docs::checkpoint::entry(key, value),
        // KS-2 carries every ASSET byte, a by-reference body's too.
        ASSET_BODY_REFS_MAP => Placement::Dispatched(OtherClient::Body),
        _ => Placement::unclassified(None, SyncUnclassified::UnknownRoot),
    }
}

/// An entity's row bytes, placed by its kind as the registry places it.
pub(super) fn entity_row(id: EntityId, value: &[u8], owners: &dyn SyncPayloadOwners) -> Placement {
    let owner = OwnerRef::entity(&id);
    let kind =
        EntityMetadataHeader::parse(value).map(|header| owners.entity_kind(header.entity_type));
    match kind {
        Some(KindPlacement::Owner) => Placement::owned(owner, Vec::new()),
        Some(KindPlacement::Other(client)) => Placement::Dispatched(client),
        Some(KindPlacement::Unclassified(reason)) => Placement::unclassified(Some(owner), reason),
        None => Placement::unclassified(Some(owner), SyncUnclassified::Undecodable),
    }
}

/// `value` as the window map holds it.
fn binary(value: &[u8]) -> LoroValue {
    LoroValue::Binary(value.to_vec().into())
}
