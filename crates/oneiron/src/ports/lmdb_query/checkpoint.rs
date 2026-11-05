//! Core half of `ports::lmdb_query::checkpoint`: its store-layer items live in `oneiron_store::ports::lmdb_query::checkpoint` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

pub(crate) use oneiron_store::ports::lmdb_query::checkpoint::*;

use heed::{RoTxn, RwTxn};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::{EdgeKind, parse_strict_edge_record};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::note::checkpoint::{CORE_RAW_REFS, join_core_row, reads_core_row, split_core_row};
use crate::origin::actor_erase::OriginClaimKind;
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_NOTE,
    ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_WORLD_KEY_PAD, entity_type_registry_entry,
};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OtherClient, OwnerRef, OwnerRows, Restored, RowDb,
    RowLocator, Unresolved,
};
use crate::write_envelope::claim_body::decode_claim_body;

/// Where an entity row's bytes go.
pub(crate) enum EntityRowPlacement {
    /// Its own entity tree's compartment.
    Owner,
    /// Another custody client's.
    Other(OtherClient),
    /// None: it stays under the vault-wide seal.
    Unclassified(Unresolved),
}

/// Where an entity row's bytes go, by its kind and, for a CLAIM or a NOTE,
/// by what its own bytes hold: the one rule for the row and for every sync
/// copy of it (FIX 10279).
pub(crate) fn entity_row_placement(value: &[u8]) -> EntityRowPlacement {
    let Some(header) = EntityMetadataHeader::parse(value) else {
        return EntityRowPlacement::Unclassified(Unresolved::Undecodable);
    };
    match header.entity_type {
        kind if entity_type_registry_entry(kind).is_none() => {
            EntityRowPlacement::Unclassified(Unresolved::UnknownKind)
        }
        ENTITY_TYPE_SECRET_CUSTODY => EntityRowPlacement::Other(OtherClient::Credential),
        ENTITY_TYPE_WORLD_KEY_PAD => EntityRowPlacement::Other(OtherClient::WorldPad),
        ENTITY_TYPE_ASSET => EntityRowPlacement::Other(OtherClient::Body),
        ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT => {
            EntityRowPlacement::Unclassified(Unresolved::ActorSplit(IDENTITY_OP_ACTORS))
        }
        ENTITY_TYPE_CLAIM => claim_placement(&value[ENTITY_METADATA_HEADER_LEN..]),
        ENTITY_TYPE_NOTE => note_placement(value),
        _ => EntityRowPlacement::Owner,
    }
}

/// A NOTE core's place, by its author (FIX 6072): an erased NOTE's empty
/// shell and a core that names no one are their tree's as they stand. A
/// live author's erase would change the raw bytes the revision refs, the
/// short id and the citation views are derived from, which no restore
/// derives again yet, so that core stays under the vault-wide seal.
fn note_placement(value: &[u8]) -> EntityRowPlacement {
    if value.len() == ENTITY_METADATA_HEADER_LEN {
        return EntityRowPlacement::Owner;
    }
    match split_core_row(value) {
        Ok(split) if split.actors.is_empty() => EntityRowPlacement::Owner,
        Ok(_) => EntityRowPlacement::Unclassified(Unresolved::ActorSplit(CORE_RAW_REFS)),
        Err(reason) => EntityRowPlacement::Unclassified(Unresolved::ActorSplit(reason)),
    }
}

/// A CLAIM's place, by its predicate: a dreamer step's holds a model
/// response; an origin claim names its actor with no lossless split.
fn claim_placement(body: &[u8]) -> EntityRowPlacement {
    match decode_claim_body(body, true) {
        Ok(claim) if claim.predicate == crate::model_step_record::DREAMER_STEP_PREDICATE => {
            EntityRowPlacement::Other(OtherClient::Response)
        }
        Ok(claim) if OriginClaimKind::of(&claim.predicate).is_some() => {
            EntityRowPlacement::Unclassified(Unresolved::ActorSplit(ORIGIN_CLAIM_ACTORS))
        }
        Ok(_) => EntityRowPlacement::Owner,
        Err(_) => EntityRowPlacement::Unclassified(Unresolved::Undecodable),
    }
}

fn entity_row(out: &mut Captured, key: Vec<u8>, value: Vec<u8>) {
    let at = RowLocator::row(RowDb::Entities, key);
    let Some(id) = entity_key(&at.key) else {
        out.unclassified(at, None, Unresolved::Undecodable);
        return;
    };
    let owner = OwnerRef::entity(&id);
    match entity_row_placement(&value) {
        EntityRowPlacement::Owner => out.exact(owner, at, value),
        EntityRowPlacement::Other(client) => out.dispatch(client, at, value),
        EntityRowPlacement::Unclassified(reason) => out.unclassified(at, Some(owner), reason),
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
/// client's; a NOTE core the split reads, whichever author its join put
/// back), or an `authored_by` edge.
fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    match at.db {
        RowDb::Entities if entity_key(&at.key).is_some() => match entity_row_placement(value) {
            EntityRowPlacement::Owner => Ok(()),
            _ if is_note(value) && reads_core_row(value) => Ok(()),
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

/// A no-one-form part: only a NOTE core is one, its opened author put back
/// by NOTE's own join; every other part is no split of this getter's.
fn join(
    view: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if at.db == RowDb::Entities && is_note(value) {
        return join_core_row(value, parts).map(Some);
    }
    rows::no_join(view, at, value, parts)
}

/// Puts `opened`'s entity rows back exactly, each `authored_by` edge whose
/// actor opened, and each NOTE core split with its opened author back.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, join)
}
