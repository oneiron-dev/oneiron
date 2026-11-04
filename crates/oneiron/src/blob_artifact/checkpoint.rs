//! The checkpoint getter of blob artifact versions (KS7-2): each artifact's
//! head record and version records under the artifact's own entity tree.
//! These are metadata only: the bytes a version names sit in an ASSET, and
//! KS-2 seals every ASSET's bytes, inline or file (the entity getter hands
//! each ASSET row to it), so nothing here seals them twice. The version
//! highwater, claim and reference rows hold no payload and stay structure.
//! It also places the artifact's hosting rows (pointer, publish admission,
//! serving descriptor) under the artifact (FIX 10436).
//!
//! A version's MadeBy names its process's actor: the compartment keeps the
//! record with the artifact in that place, and the actor is an actor part.
//! The erased-producer form stays in the record with no actor part (FIX 9619);
//! any other process actor must open on restore or its version stays out.
//! The host production witness is a separate actor payload: if it does not
//! open, only the witness is erased and version availability is unchanged. Nothing
//! calls this until KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use super::erase::erased_producer;
use super::production::OutputProductionStamp;
use super::store_keys::{encode_value, read_value};
use super::versions::{BlobArtifactVersion, HEAD, VERSIONS};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{Raw, SideKey, SideTable};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator, RowPart,
    TypedRow, Unresolved,
};

/// The field the MadeBy process's actor fills.
const PROCESS: &str = "made_by.process.actor";
const PRODUCTION: &str = "production";

/// Moves the process's actor out, leaving `artifact` in its place.
fn take_process(
    version: &mut BlobArtifactVersion,
    artifact: EntityId,
    erased: EntityId,
) -> Vec<(String, EntityId)> {
    if version.made_by.process.actor == erased {
        return Vec::new();
    }
    let actor = std::mem::replace(&mut version.made_by.process.actor, artifact);
    vec![(PROCESS.to_owned(), actor)]
}

/// The host witness belongs to its producer's compartment as one payload:
/// none of its attempt or run links remain in the artifact skeleton.
fn split_version<K: SideKey>(
    out: &mut Captured,
    table: SideTable<K, BlobArtifactVersion, Raw>,
    row: TypedRow<K, BlobArtifactVersion>,
    artifact: EntityId,
    erased: EntityId,
) -> Result<()> {
    let owner = OwnerRef::entity(&artifact);
    if !rows::spells_back(table, &row) {
        out.unclassified(
            row.at,
            Some(owner),
            Unresolved::ActorSplit(rows::NOT_SPELLED_BACK),
        );
        return Ok(());
    }
    let TypedRow {
        at,
        mut value,
        bytes,
        ..
    } = row;
    let actors = take_process(&mut value, artifact, erased);
    let production = match &value.production {
        OutputProductionStamp::Host(host) => Some((
            host.actor(),
            encode_value(
                &value.production.to_value(),
                "production checkpoint encode failed",
            )?,
        )),
        OutputProductionStamp::Unknown | OutputProductionStamp::Erased => None,
    };
    if actors.is_empty() && production.is_none() {
        out.exact(owner, at, bytes);
        return Ok(());
    }
    if production.is_some() {
        value.production = OutputProductionStamp::Erased;
    }
    let content = table.encode_value(&value)?;
    let rows = out.owner(owner);
    for (field, actor) in actors {
        rows.actor_parts.push(ActorPart {
            actor_entity: actor,
            content_locator: at.clone(),
            field,
            bytes: actor.as_bytes().to_vec(),
        });
    }
    if let Some((actor, bytes)) = production {
        rows.actor_parts.push(ActorPart {
            actor_entity: actor,
            content_locator: at.clone(),
            field: PRODUCTION.to_owned(),
            bytes,
        });
    }
    rows.rows.push(RowPart::NoActor { at, value: content });
    Ok(())
}

/// The existing process part still decides version availability. A missing
/// production part erases only that witness; it never withholds the version.
fn join_version<K: SideKey>(
    table: SideTable<K, BlobArtifactVersion, Raw>,
    value: &[u8],
    parts: &[&ActorPart],
    erased: EntityId,
) -> Result<Option<Vec<u8>>> {
    let mut version = table.decode_value(value)?;
    let mut process_seen = version.made_by.process.actor == erased;
    let mut production_seen = false;
    for part in parts {
        match part.field.as_str() {
            PROCESS if !process_seen => {
                let id: [u8; 16] = part
                    .bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| rows::bad_part())?;
                let actor = EntityId::from_bytes(id)?;
                if actor != part.actor_entity {
                    return Err(rows::bad_part());
                }
                version.made_by.process.actor = actor;
                process_seen = true;
            }
            PRODUCTION
                if !production_seen && version.production == OutputProductionStamp::Erased =>
            {
                let production = OutputProductionStamp::from_value(&read_value(
                    &part.bytes,
                    "production checkpoint",
                )?)?;
                if !matches!(&production, OutputProductionStamp::Host(host) if host.actor() == part.actor_entity)
                {
                    return Err(rows::bad_part());
                }
                version.production = production;
                production_seen = true;
            }
            _ => return Err(rows::bad_part()),
        }
    }
    if process_seen {
        table.encode_value(&version).map(Some)
    } else {
        Ok(None)
    }
}

/// Every head and version record in `txn`, by artifact.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let erased = erased_producer()?;
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, HEAD, &mut out)? {
        let artifact = row.key;
        split_version(&mut out, HEAD, row, artifact, erased)?;
    }
    for row in rows::typed_rows(dbs, txn, VERSIONS, &mut out)? {
        let artifact = row.key.0;
        split_version(&mut out, VERSIONS, row, artifact, erased)?;
    }
    out.merge(crate::artifact_hosting::checkpoint::capture(dbs, txn)?);
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    at.in_table(HEAD.decl())
        || at.in_table(VERSIONS.decl())
        || crate::artifact_hosting::checkpoint::owns(at)
}

/// The bundle framing of `rows`' version parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(HEAD.decl()) {
        rows::check_row(HEAD, at, value)
    } else if at.in_table(VERSIONS.decl()) {
        rows::check_row(VERSIONS, at, value)
    } else if crate::artifact_hosting::checkpoint::owns(at) {
        crate::artifact_hosting::checkpoint::check(at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// A record with its actor back; `None` when the actor did not open.
fn join(
    txn: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    let erased = erased_producer()?;
    if at.in_table(HEAD.decl()) {
        return join_version(HEAD, value, parts, erased);
    }
    if at.in_table(VERSIONS.decl()) {
        return join_version(VERSIONS, value, parts, erased);
    }
    if crate::artifact_hosting::checkpoint::owns(at) {
        return crate::artifact_hosting::checkpoint::join(txn, at, value, parts);
    }
    Err(rows::bad_part())
}

/// Puts `opened`'s records back, each whose actor opened.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, join)
}
