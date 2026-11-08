//! The checkpoint getter of codebase snapshots (KS7-2): each snapshot's file
//! manifest and its repo, project, fork and scope index rows under the tree
//! of the CODE_ARTIFACT it snapshots. The index keys spell the repo, the
//! project and the fork and scope hashes, so they are sealed with the
//! snapshot, never left beside it. A scope row naming one of the ASSETs a
//! snapshot's files are stored as goes to the body client (KS-2), which seals
//! every ASSET; a fork hash is never a compartment. The custody report a fork
//! hash keys is shared by every snapshot of that fork, so no one snapshot
//! holds it and it is not compartmented. Nothing calls this until KS7-5, and
//! only once CHECKPOINT_PAYLOADS_ENABLED is on.
//!
//! FIX 4299 (CODE-CUSTODY-01): a snapshot row now names the registered
//! repository it belongs to, and its scope key derives from that anchor or
//! from the commit-free locator. Both ride the snapshot row and its scope
//! rows under the snapshot's own tree; `check` decodes each with the one
//! snapshot codec, so a row of the old shape refuses rather than restores.
//! The anchor's retained configuration is its CODE body, an ordinary entity
//! row, never a row here.
//!
//! FIX 4300: a scope also holds its registered anchor and every symbol of
//! each snapshot's manifest. A scope row naming a CODE_ARTIFACT or a
//! CODE_SYMBOL goes under that entity's own tree.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::{CUSTODY_REPORTS, FORK_INDEX, PROJECT_INDEX, REPO_INDEX, SCOPE_INDEX, SNAPSHOTS};
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_CODE_SYMBOL};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OtherClient, OwnerRef, OwnerRows, Restored, RowLocator,
    Unresolved,
};

/// Where a scope row goes, by the entity its id names: a snapshot's tree,
/// an anchor's or a symbol's own tree, the body client for an ASSET, or
/// nowhere for an id that names none of them.
fn scope_row(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    snapshots: &BTreeSet<EntityId>,
    id: &EntityId,
    at: RowLocator,
    value: Vec<u8>,
    out: &mut Captured,
) -> Result<()> {
    if snapshots.contains(id) {
        out.exact(OwnerRef::entity(id), at, value);
        return Ok(());
    }
    let kind = dbs
        .entities()
        .get(txn, id.as_bytes())?
        .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type));
    match kind {
        Some(ENTITY_TYPE_ASSET) => out.dispatch(OtherClient::Body, at, value),
        Some(ENTITY_TYPE_CODE_ARTIFACT | ENTITY_TYPE_CODE_SYMBOL) => {
            out.exact(OwnerRef::entity(id), at, value);
        }
        _ => out.unclassified(at, None, Unresolved::NoOwner),
    }
    Ok(())
}

/// Every codebase row in `txn`, by snapshot.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    let mut snapshots = BTreeSet::new();
    for row in rows::typed_rows(dbs, txn, SNAPSHOTS, &mut out)? {
        snapshots.insert(row.key);
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for table in [REPO_INDEX, PROJECT_INDEX] {
        for row in rows::typed_rows(dbs, txn, table, &mut out)? {
            out.exact(OwnerRef::entity(&row.key.id), row.at, row.bytes);
        }
    }
    for row in rows::typed_rows(dbs, txn, FORK_INDEX, &mut out)? {
        out.exact(OwnerRef::entity(&row.key.id), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, SCOPE_INDEX, &mut out)? {
        let id = row.key.id;
        scope_row(dbs, txn, &snapshots, &id, row.at, row.bytes, &mut out)?;
    }
    for row in rows::typed_rows(dbs, txn, CUSTODY_REPORTS, &mut out)? {
        out.unclassified(row.at, None, Unresolved::SharedOwners);
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    [
        SNAPSHOTS.decl(),
        REPO_INDEX.decl(),
        PROJECT_INDEX.decl(),
        FORK_INDEX.decl(),
        SCOPE_INDEX.decl(),
    ]
    .into_iter()
    .any(|decl| at.in_table(decl))
}

/// The bundle framing of `rows`' codebase parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(SNAPSHOTS.decl()) {
        rows::check_row(SNAPSHOTS, at, value)
    } else if at.in_table(REPO_INDEX.decl()) {
        rows::check_row(REPO_INDEX, at, value)
    } else if at.in_table(PROJECT_INDEX.decl()) {
        rows::check_row(PROJECT_INDEX, at, value)
    } else if at.in_table(FORK_INDEX.decl()) {
        rows::check_row(FORK_INDEX, at, value)
    } else if at.in_table(SCOPE_INDEX.decl()) {
        rows::check_row(SCOPE_INDEX, at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// Puts `opened`'s codebase rows back exactly.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, rows::no_join)
}
