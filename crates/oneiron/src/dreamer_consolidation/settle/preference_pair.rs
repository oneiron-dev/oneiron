//! OF-023 (FIX 3079): the Memory door's observed-versus-stated preference
//! markers, which stop asking once their pair no longer stands.

use crate::claim::{ClaimLifecycleStatus, ClaimSource};
use crate::error::Result;
use crate::{ClaimBody, Vault};

use super::marker_ids;

/// Whether `marker` is the Memory door's observed-versus-stated preference
/// marker whose pair no longer stands. The door's marker names `[observed,
/// stated]` in its evidence refs and the observed claim's predicate as its
/// value. Its pair no longer stands once either claim is superseded,
/// retracted or past its valid end. A later observation, agreeing or not,
/// supersedes the observed claim (a disagreeing one opens its own marker),
/// and a restated answer supersedes the stated one. Either way the marker's
/// question is moot and it is no open conflict. A marker of any other shape,
/// or one whose claims do not read, answers false and is read as before.
/// Callers ask only of a marker no reverted settlement reopened: a revert
/// may restore a member under a new id the marker's history links, which
/// its refs do not name (REVIEW-6431).
pub(super) fn preference_pair_moot_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    marker: &ClaimBody,
) -> Result<bool> {
    let Some(evidence) = marker.evidence.as_ref() else {
        return Ok(false);
    };
    let refs: Vec<_> = marker_ids(evidence, "refs").collect();
    let [observed, stated] = refs.as_slice() else {
        return Ok(false);
    };
    let (Some(observed), Some(stated)) = (
        vault.get_claim_in_txn(txn, observed)?,
        vault.get_claim_in_txn(txn, stated)?,
    ) else {
        return Ok(false);
    };
    if stated.source != Some(ClaimSource::UserStated)
        || !crate::claim::is_observed_preference(observed.source, &observed.predicate)
        || marker.value.as_str() != Some(observed.predicate.as_str())
    {
        return Ok(false);
    }
    let now = vault.store.clock.now_recorded_at();
    let stands = |body: &ClaimBody| {
        body.lifecycle == ClaimLifecycleStatus::Active
            && !body.valid_to.is_some_and(|end| end <= now)
    };
    Ok(!stands(&observed) || !stands(&stated))
}
