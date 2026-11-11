//! The checkpoint getter of code revisions (KS7-2): every revision row under
//! the tree of the session it belongs to. A record and its integrity fold go
//! with the record's session, a frontier and a session index row with the
//! session they name, a fork and its parent index row with the fork's own
//! session (the index row holding while the parent session does), a child
//! index row, a stranded proposal ([`super::super::proposals::checkpoint`])
//! and a promotion receipt ([`super::super::promotion::checkpoint`]) with the
//! session of the revision they name. A row whose revision no record or
//! proposal names is not compartmented.
//!
//! A finalized or stranded revision's author is erasable attribution, outside
//! its integrity fold (FIX 6258): the split leaves the metadata naming no one
//! under the session, and the author is an actor part, so a restore whose
//! author did not open gives the revision the erase leaves. No revision row
//! names another actor.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::super::CodeRevision;
use super::super::keys::{
    FORK_PARENT_INDEX, FORKS, FRONTIER, INTEGRITY, PARENT_INDEX, RECORDS, SESSION_INDEX,
};
use super::super::promotion::checkpoint as promotion;
use super::super::proposals::checkpoint as proposals;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
    Unresolved,
};

/// The field a revision's author fills.
const COMMIT_AUTHOR: &str = "commit_author";

/// Moves a revision's author out, leaving its metadata naming no one.
pub(crate) fn take_author(revision: &mut CodeRevision) -> Vec<(String, EntityId)> {
    revision
        .commit_metadata
        .as_mut()
        .and_then(|meta| meta.author.take())
        .map(|actor| (COMMIT_AUTHOR.to_owned(), actor))
        .into_iter()
        .collect()
}

/// Puts an opened author back where the split left none.
pub(crate) fn put_author(revision: &mut CodeRevision, field: &str, actor: EntityId) -> Result<()> {
    match revision.commit_metadata.as_mut() {
        Some(meta) if field == COMMIT_AUTHOR && meta.author.is_none() => {
            meta.author = Some(actor);
            Ok(())
        }
        _ => Err(rows::bad_part()),
    }
}

/// Files a row under the session `revision` belongs to; a revision no
/// record or proposal names leaves it uncompartmented.
pub(crate) fn by_revision(
    out: &mut Captured,
    sessions: &BTreeMap<EntityId, EntityId>,
    revision: &EntityId,
    at: RowLocator,
    bytes: Vec<u8>,
) {
    match sessions.get(revision) {
        Some(session) => out.exact(OwnerRef::entity(session), at, bytes),
        None => out.unclassified(at, None, Unresolved::NoOwner),
    }
}

/// Every code-revision row in `txn`, by session.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    let mut sessions = BTreeMap::new();
    for row in rows::typed_rows(dbs, txn, RECORDS, &mut out)? {
        if row.value.revision_id != row.key {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        sessions.insert(row.key, row.value.session_id);
        let owner = OwnerRef::entity(&row.value.session_id);
        rows::split_actors(&mut out, owner, RECORDS, row, take_author)?;
    }
    proposals::capture(dbs, txn, &mut sessions, &mut out)?;
    for row in rows::typed_rows(dbs, txn, INTEGRITY, &mut out)? {
        if row.value.revision_id != row.key {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        out.exact(OwnerRef::entity(&row.value.session_id), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, FRONTIER, &mut out)? {
        if row.value.session_id != row.key {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, FORKS, &mut out)? {
        if row.value.fork_session_id != row.key {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, SESSION_INDEX, &mut out)? {
        out.exact(OwnerRef::entity(&row.key.0), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, PARENT_INDEX, &mut out)? {
        let child = row.key.1;
        by_revision(&mut out, &sessions, &child, row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, FORK_PARENT_INDEX, &mut out)? {
        let (parent, fork) = row.key;
        let owner = OwnerRef::entity(&fork);
        out.depends(owner, &row.at, OwnerRef::entity(&parent));
        out.exact(owner, row.at, row.bytes);
    }
    promotion::capture(dbs, txn, &sessions, &mut out)?;
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    [
        RECORDS.decl(),
        INTEGRITY.decl(),
        FRONTIER.decl(),
        FORKS.decl(),
        SESSION_INDEX.decl(),
        PARENT_INDEX.decl(),
        FORK_PARENT_INDEX.decl(),
    ]
    .into_iter()
    .any(|decl| at.in_table(decl))
        || proposals::owns(at)
        || promotion::owns(at)
}

/// The bundle framing of `rows`' code-revision parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(RECORDS.decl()) {
        rows::check_row(RECORDS, at, value)
    } else if at.in_table(INTEGRITY.decl()) {
        rows::check_row(INTEGRITY, at, value)
    } else if at.in_table(FRONTIER.decl()) {
        rows::check_row(FRONTIER, at, value)
    } else if at.in_table(FORKS.decl()) {
        rows::check_row(FORKS, at, value)
    } else if at.in_table(SESSION_INDEX.decl()) {
        rows::check_row(SESSION_INDEX, at, value)
    } else if at.in_table(PARENT_INDEX.decl()) {
        rows::check_row(PARENT_INDEX, at, value)
    } else if at.in_table(FORK_PARENT_INDEX.decl()) {
        rows::check_row(FORK_PARENT_INDEX, at, value)
    } else if proposals::owns(at) {
        proposals::check(at, value)
    } else if promotion::owns(at) {
        promotion::check(at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// A finalized or stranded revision with its opened author back; one whose
/// author did not open names no one, as the erase leaves it.
fn join(
    _: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if at.in_table(RECORDS.decl()) {
        let revision = rows::join_actors(RECORDS, value, parts, put_author)?;
        return RECORDS.encode_value(&revision).map(Some);
    }
    if proposals::owns(at) {
        return proposals::join(value, parts).map(Some);
    }
    Err(rows::bad_part())
}

/// Puts `opened`'s code-revision rows back: content as it is, and each
/// revision with the author that opened.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, join)
}
