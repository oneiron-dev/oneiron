//! The stranded revision proposals (KS7-2), each (its revision, folds and
//! artifact body) under the session its revision belongs to, its revision's
//! author an actor part (FIX 6258). The code-revision getter reads them.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeMap;

use heed::RoTxn;

use super::super::storage::checkpoint::{put_author, take_author};
use super::PROPOSALS;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OwnerRef, RowLocator, Unresolved,
};

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
        let owner = OwnerRef::entity(&revision.session_id);
        rows::split_actors(out, owner, PROPOSALS, row, |proposal| {
            take_author(&mut proposal.revision)
        })?;
    }
    Ok(())
}

pub(crate) fn owns(at: &RowLocator) -> bool {
    at.in_table(PROPOSALS.decl())
}

pub(crate) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    rows::check_row(PROPOSALS, at, value)
}

/// A proposal with its revision's opened author back, re-encoded.
pub(crate) fn join(value: &[u8], parts: &[&ActorPart]) -> Result<Vec<u8>> {
    let proposal = rows::join_actors(PROPOSALS, value, parts, |proposal, field, actor| {
        put_author(&mut proposal.revision, field, actor)
    })?;
    PROPOSALS.encode_value(&proposal)
}
