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
//! A revision's commit metadata names its author, and its integrity fold
//! binds those bytes, so no split leaves a no-one form: a revision that
//! carries one stays under the vault-wide seal, named with its session. No
//! revision row names another actor. Nothing calls this until KS7-5, and only
//! once CHECKPOINT_PAYLOADS_ENABLED is on.
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
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator, Unresolved,
};

/// The carrier a revision's commit metadata is: it names the author, and the
/// revision's integrity fold binds it.
const COMMIT_AUTHOR: &str = "code revision commit metadata names its author";

/// Files a revision's row under its session, or leaves it under the
/// vault-wide seal when its commit metadata names an author.
pub(crate) fn revision_row(
    out: &mut Captured,
    revision: &CodeRevision,
    at: RowLocator,
    bytes: Vec<u8>,
) {
    let owner = OwnerRef::entity(&revision.session_id);
    if revision.commit_metadata.is_some() {
        out.unclassified(at, Some(owner), Unresolved::ActorSplit(COMMIT_AUTHOR));
    } else {
        out.exact(owner, at, bytes);
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
        revision_row(&mut out, &row.value, row.at, row.bytes);
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

/// Puts `opened`'s code-revision rows back exactly.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, rows::no_join)
}
