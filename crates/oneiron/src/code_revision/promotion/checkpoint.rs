//! The promotion receipts (KS7-2), each under the session of the revision it
//! promoted. The code-revision getter reads them.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeMap;

use heed::RoTxn;

use super::super::storage::checkpoint::by_revision;
use super::PROMOTIONS;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{self, Captured, RowLocator};

/// Files each receipt under its revision's session in `sessions`.
pub(crate) fn capture(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    sessions: &BTreeMap<EntityId, EntityId>,
    out: &mut Captured,
) -> Result<()> {
    for row in rows::typed_rows(dbs, txn, PROMOTIONS, out)? {
        by_revision(out, sessions, &row.key, row.at, row.bytes);
    }
    Ok(())
}

pub(crate) fn owns(at: &RowLocator) -> bool {
    at.in_table(PROMOTIONS.decl())
}

pub(crate) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    rows::check_row(PROMOTIONS, at, value)
}
