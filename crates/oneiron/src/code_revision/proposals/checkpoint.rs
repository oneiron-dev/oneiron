//! The stranded revision proposals (KS7-2), each whole (its revision, folds
//! and artifact body) under the session its revision belongs to. The
//! code-revision getter reads them.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeMap;

use heed::RoTxn;

use super::super::storage::checkpoint::revision_row;
use super::PROPOSALS;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{self, Captured, RowLocator, Unresolved};

/// Files each proposal under its revision's session, and records that
/// session for the rows keyed by the revision.
pub(crate) fn capture(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    sessions: &mut BTreeMap<EntityId, EntityId>,
    out: &mut Captured,
) -> Result<()> {
    for row in rows::typed_rows(dbs, txn, PROPOSALS, out)? {
        let revision = &row.value.revision;
        if revision.revision_id != row.key {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        sessions.entry(row.key).or_insert(revision.session_id);
        revision_row(out, revision, row.at, row.bytes);
    }
    Ok(())
}

pub(crate) fn owns(at: &RowLocator) -> bool {
    at.in_table(PROPOSALS.decl())
}

pub(crate) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    rows::check_row(PROPOSALS, at, value)
}
