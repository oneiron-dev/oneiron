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
use crate::store::Store;
use crate::store::checkpoint_payload::rows::descriptor::{AdapterTable, CapturedByAdapter};
use crate::store::checkpoint_payload::rows::{self, Captured};

/// The promotion receipts, which the code-revision getter's own capture
/// places.
pub(crate) const TABLE: &dyn AdapterTable = &CapturedByAdapter(PROMOTIONS);

/// Files each receipt under its revision's session in `sessions`.
pub(crate) fn capture(
    store: &Store,
    txn: &RoTxn<'_>,
    sessions: &BTreeMap<EntityId, EntityId>,
    out: &mut Captured,
) -> Result<()> {
    for row in rows::typed_rows(store, txn, PROMOTIONS, out)? {
        by_revision(out, sessions, &row.key, row.at, row.bytes);
    }
    Ok(())
}
