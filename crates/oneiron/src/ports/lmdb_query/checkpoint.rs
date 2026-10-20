//! The checkpoint getter of the entity and edge rows (KS7-2): each raw
//! entity row by its own entity tree, and each edge read with the strict
//! edge codec. The rows are the raw ones, never a materialized live read, so
//! retained and deleted rows are captured as they stand.
//!
//! A kind another custody client seals is handed to it, never sealed here:
//! SECRET_CUSTODY to KS-6, WORLD_KEY_PAD to KS-5, ASSET bytes to KS-2, and a
//! dreamer step's CLAIM, which holds a model response, to KS-2B. An
//! `authored_by` edge names its actor, so it is the authored entity's
//! actor-keyed row; every other edge is structure that holds while both its
//! ends do. Nothing calls this until KS7-5, and only once
//! CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::decode_claim_body;
use crate::edge::{EdgeKind, parse_strict_edge_record};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::actor_erase::OriginClaimKind;
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
    ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_WORLD_KEY_PAD, entity_type_registry_entry,
};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OtherClient, OwnerRef, OwnerRows, Restored, RowDb, RowLocator,
    Unresolved,
};

/// The carrier an identity op's row is: its body names the actors it
/// stamps, and the live erase rewrites it in place (`IDENTITY_OPS`).
const IDENTITY_OP_ACTORS: &str = "identity op body names its actors";

/// The carrier an origin claim is: its body names its actor, and the live
/// erase rewrites it in place (`ORIGIN_CLAIMS`).
const ORIGIN_CLAIM_ACTORS: &str = "origin claim body names its actor";

/// Where an entity row's bytes go.
enum Placement {
    /// Its own entity tree's compartment.
    Owner,
    /// Another custody client's.
    Other(OtherClient),
    /// None: it stays under the vault-wide seal.
    Unclassified(Unresolved),
}

/// Where an entity row's bytes go, by its kind.
fn placement(value: &[u8]) -> Placement {
    let Some(header) = EntityMetadataHeader::parse(value) else {
        return Placement::Unclassified(Unresolved::Undecodable);
    };
    match header.entity_type {
        kind if entity_type_registry_entry(kind).is_none() => {
            Placement::Unclassified(Unresolved::UnknownKind)
        }
        ENTITY_TYPE_SECRET_CUSTODY => Placement::Other(OtherClient::Credential),
        ENTITY_TYPE_WORLD_KEY_PAD => Placement::Other(OtherClient::WorldPad),
        ENTITY_TYPE_ASSET => Placement::Other(OtherClient::Body),
        ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT => {
            Placement::Unclassified(Unresolved::ActorSplit(IDENTITY_OP_ACTORS))
        }
        ENTITY_TYPE_CLAIM => claim_placement(&value[ENTITY_METADATA_HEADER_LEN..]),
        _ => Placement::Owner,
    }
}

/// A CLAIM's place, by its predicate: a dreamer step's holds a model
/// response; an origin claim names its actor with no lossless split.
fn claim_placement(body: &[u8]) -> Placement {
    match decode_claim_body(body, true) {
        Ok(claim) if claim.predicate == crate::llm::DREAMER_STEP_PREDICATE => {
            Placement::Other(OtherClient::Response)
        }
        Ok(claim) if OriginClaimKind::of(&claim.predicate).is_some() => {
            Placement::Unclassified(Unresolved::ActorSplit(ORIGIN_CLAIM_ACTORS))
        }
        Ok(_) => Placement::Owner,
        Err(_) => Placement::Unclassified(Unresolved::Undecodable),
    }
}

fn entity_key(key: &[u8]) -> Option<EntityId> {
    EntityId::from_bytes(key.try_into().ok()?).ok()
}

fn entity_row(out: &mut Captured, key: Vec<u8>, value: Vec<u8>) {
    let at = RowLocator::row(RowDb::Entities, key);
    let Some(id) = entity_key(&at.key) else {
        out.unclassified(at, None, Unresolved::Undecodable);
        return;
    };
    let owner = OwnerRef::entity(&id);
    match placement(&value) {
        Placement::Owner => out.exact(owner, at, value),
        Placement::Other(client) => out.dispatch(client, at, value),
        Placement::Unclassified(reason) => out.unclassified(at, Some(owner), reason),
    }
}

fn edge_row(out: &mut Captured, db: RowDb, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
    let at = RowLocator::row(db, key);
    let Ok(edge) = parse_strict_edge_record(&at.key, &value) else {
        out.unclassified(at, None, Unresolved::Undecodable);
        return Ok(());
    };
    if edge.kind != EdgeKind::AuthoredBy {
        let ends = vec![
            OwnerRef::entity(&edge.source),
            OwnerRef::entity(&edge.target),
        ];
        out.structure(at, value, ends);
        return Ok(());
    }
    // An outgoing row leads with the authored entity, an incoming one with
    // its actor, so the placeholder keeps neither id.
    let (authored, actor) = match db {
        RowDb::EdgesIn => (edge.target, edge.source),
        _ => (edge.source, edge.target),
    };
    rows::actor_keyed(out, OwnerRef::entity(&authored), actor, &at, &[], &value)
}

/// Every entity and edge row in `txn`, by owner.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in dbs.entities().iter(txn)? {
        let (key, value) = row?;
        entity_row(&mut out, key.to_vec(), value.to_vec());
    }
    for (db, table) in [
        (RowDb::EdgesOut, dbs.edges_out()),
        (RowDb::EdgesIn, dbs.edges_in()),
    ] {
        for row in table.iter(txn)? {
            let (key, value) = row?;
            edge_row(&mut out, db, key.to_vec(), value.to_vec())?;
        }
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    matches!(at.db, RowDb::Entities | RowDb::EdgesOut | RowDb::EdgesIn)
}

/// The bundle framing of `rows`' entity and edge parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

/// An entity row an entity tree holds (an ordinary kind, never another
/// client's), or an `authored_by` edge.
fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    match at.db {
        RowDb::Entities if entity_key(&at.key).is_some() => match placement(value) {
            Placement::Owner => Ok(()),
            _ => Err(rows::bad_part()),
        },
        RowDb::EdgesOut | RowDb::EdgesIn => {
            let edge = parse_strict_edge_record(&at.key, value)?;
            if edge.kind == EdgeKind::AuthoredBy {
                Ok(())
            } else {
                Err(rows::bad_part())
            }
        }
        _ => Err(rows::bad_part()),
    }
}

/// Puts `opened`'s entity rows back exactly, and each `authored_by` edge
/// whose actor opened.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, rows::no_join)
}
