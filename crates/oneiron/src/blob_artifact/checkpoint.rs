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
//! record with the artifact in that place, and the actor is an actor part. A
//! version record has no erased form, so a restore writes it back only when
//! its actor opens; otherwise the version is left out, never written with a
//! stand-in. Nothing calls this until KS7-5, and only once
//! CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use super::versions::{BlobArtifactVersion, HEAD, VERSIONS};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
};

/// The field the MadeBy process's actor fills.
const PROCESS: &str = "made_by.process.actor";

/// Moves the process's actor out, leaving `artifact` in its place.
fn take_process(version: &mut BlobArtifactVersion, artifact: EntityId) -> Vec<(String, EntityId)> {
    let actor = std::mem::replace(&mut version.made_by.process.actor, artifact);
    vec![(PROCESS.to_owned(), actor)]
}

fn put_process(version: &mut BlobArtifactVersion, field: &str, actor: EntityId) -> Result<()> {
    if field != PROCESS {
        return Err(rows::bad_part());
    }
    version.made_by.process.actor = actor;
    Ok(())
}

/// Every head and version record in `txn`, by artifact.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, HEAD, &mut out)? {
        let artifact = row.key;
        rows::split_actors(
            &mut out,
            OwnerRef::entity(&artifact),
            HEAD,
            row,
            |version| take_process(version, artifact),
        )?;
    }
    for row in rows::typed_rows(dbs, txn, VERSIONS, &mut out)? {
        let artifact = row.key.0;
        rows::split_actors(
            &mut out,
            OwnerRef::entity(&artifact),
            VERSIONS,
            row,
            |version| take_process(version, artifact),
        )?;
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
    if at.in_table(HEAD.decl()) {
        if parts.is_empty() {
            return Ok(None);
        }
        let head = rows::join_actors(HEAD, value, parts, put_process)?;
        return HEAD.encode_value(&head).map(Some);
    }
    if at.in_table(VERSIONS.decl()) {
        if parts.is_empty() {
            return Ok(None);
        }
        let version = rows::join_actors(VERSIONS, value, parts, put_process)?;
        return VERSIONS.encode_value(&version).map(Some);
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
