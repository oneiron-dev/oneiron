//! An actor erased before a decision's append, under the same writer.

use std::borrow::Cow;

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{hard_erased_ids_in_txn, names_no_actor_in_txn};
use crate::store::{ManifestDbs, legal_hold};

use super::super::types::GateDecisionRecord;

/// A held partition keeps its original bytes and owes each matching actor's
/// scrub. The append records that debt only after its row and indexes land.
pub(super) fn prepare_record<'a>(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    record: &'a GateDecisionRecord,
) -> Result<(Cow<'a, GateDecisionRecord>, Vec<EntityId>)> {
    let mut erased = Vec::new();
    for actor in hard_erased_ids_in_txn(store, txn)? {
        if record.names_actor(&actor) && !names_no_actor_in_txn(store, txn, &actor)? {
            erased.push(actor);
        }
    }
    if erased.is_empty() {
        return Ok((Cow::Borrowed(record), erased));
    }
    if legal_hold::partition_held_in_txn(store, txn, record.claim_id.as_ref())? {
        return Ok((Cow::Borrowed(record), erased));
    }
    let mut scrubbed = record.clone();
    for actor in &erased {
        scrubbed.scrub_actor(actor);
    }
    Ok((Cow::Owned(scrubbed), Vec::new()))
}
