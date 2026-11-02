//! Every milestone claim by the attempt it names, bound to a local queue row
//! or not (FIX 10766): the verified read of an attempt another device ran
//! reads that attempt's claims by key, never every milestone claim. Its rows
//! are written and dropped on every claim put, replay and erase door, beside
//! the bound durable index (`index_dreamer_milestone_claim_for_put`,
//! `deindex_dreamer_milestone_claim`), so they hold exactly the stored
//! claims that name each attempt. It admits nothing: the read still judges
//! each claim readable and verified, and resume keeps the bound index.

use crate::attempt_queue::AttemptId;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::super::constants::DREAMER_MILESTONE_PREDICATE;
use super::decode_milestone_value;

/// Each milestone claim, keyed by the attempt its value names, then the
/// claim.
const ATTEMPT_CLAIM: SideTable<(AttemptId, EntityId), (), Named> =
    SideTable::new(&side_table::DREAMER_MILESTONE_INDEX_ATTEMPT_CLAIM);
/// The attempt each indexed milestone claim names, for the door that drops
/// the claim's row.
const CLAIM_ATTEMPT: SideTable<EntityId, AttemptId, Named> =
    SideTable::new(&side_table::DREAMER_MILESTONE_INDEX_CLAIM_ATTEMPT);

/// Indexes `claim_id` under the attempt its stored `body` names, when it is
/// a milestone claim whose value decodes, in the put's own writer.
pub(super) fn index_milestone_claim_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
) -> Result<()> {
    if body.predicate != DREAMER_MILESTONE_PREDICATE {
        return Ok(());
    }
    let Ok((attempt_id, _, _)) = decode_milestone_value(&body.value) else {
        return Ok(());
    };
    ATTEMPT_CLAIM.put(store, wtxn, &(attempt_id, *claim_id), &())?;
    CLAIM_ATTEMPT.put(store, wtxn, claim_id, &attempt_id)
}

/// Drops `claim_id`'s row, in the writer that replaces or removes the claim.
pub(super) fn deindex_milestone_claim_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
) -> Result<()> {
    let Some(attempt_id) = CLAIM_ATTEMPT.get(store, &*wtxn, claim_id)? else {
        return Ok(());
    };
    ATTEMPT_CLAIM.delete(store, wtxn, &(attempt_id, *claim_id))?;
    CLAIM_ATTEMPT.delete(store, wtxn, claim_id).map(drop)
}

/// The stored milestone claims that name `attempt_id`, in claim order.
#[cfg(feature = "sync")]
pub(super) fn milestone_claims_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
) -> Result<Vec<EntityId>> {
    Ok(ATTEMPT_CLAIM
        .scan_keys(store, rtxn, attempt_id.as_bytes())?
        .into_iter()
        .map(|(_, claim_id)| claim_id)
        .collect())
}
