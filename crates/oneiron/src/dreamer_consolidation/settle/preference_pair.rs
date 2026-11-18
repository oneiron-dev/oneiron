//! OF-023 (FIX 3079): the observed-versus-stated preference markers of the
//! Memory door and of the derive Claim item, which stop asking once their
//! pair no longer stands.

use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
};
use crate::{ClaimBody, Vault};

use super::{marker_ids, string_at};

/// Whether `marker` is an observed-versus-stated preference marker whose
/// pair no longer stands. Its writers (`crate::claim::conflict_marker`: the
/// Memory door and the derive Claim item) give it the observed claim's
/// predicate as its value and name `[observed, stated]` in its evidence
/// refs. A stamped body holds those refs under the write envelope's
/// candidate evidence entry; a raw body, whose evidence has no actor stamp,
/// holds them in its evidence itself (`ClaimBody::evidence_refs` reads the
/// same two places). The pair answers one key: the stated claim has the
/// observed claim's subject and predicate. It no longer stands once either
/// claim is superseded, retracted, refused or past its valid end. A later
/// observation, agreeing or not, supersedes the observed claim (a
/// disagreeing one opens its own marker), a restated answer supersedes the
/// stated one, a reverted derive batch retracts the observed claim, and the
/// owner's decline of a held observed claim refuses it (a MACHINE claim so
/// refused keeps its Active lifecycle). Either way the marker's question is
/// moot and it is no open conflict. A marker of any other shape, or one
/// whose claims do not read, answers false and is read as before. A
/// consolidation marker, whose value is a map and whose evidence cites
/// TURNs, is never read as a pair.
/// Nor is the coaching marker of a held replacement that closes a stated
/// claim on another predicate: the grant closes that claim first and then
/// answers the marker, which must still read open (`settle_coaching_in_txn`).
/// Callers ask only of a marker no reverted settlement reopened: a revert
/// may restore a member under a new id the marker's history links, which
/// its refs do not name (REVIEW-6431).
pub(super) fn preference_pair_moot_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    marker: &ClaimBody,
) -> Result<bool> {
    let Some(predicate) = marker
        .value
        .as_str()
        .filter(|predicate| crate::claim::is_preference_predicate(predicate))
    else {
        return Ok(false);
    };
    let Some(evidence) = marker.evidence.as_ref() else {
        return Ok(false);
    };
    // The actor stamp tells a write envelope's evidence from a raw body's.
    let named = if string_at(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY).is_some() {
        string_at(evidence, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY)
    } else {
        Some(evidence)
    };
    let Some(named) = named else {
        return Ok(false);
    };
    let refs: Vec<_> = marker_ids(named, "refs").collect();
    let [observed, stated] = refs.as_slice() else {
        return Ok(false);
    };
    // A claim read of a row that is no CLAIM is an error, not an absence.
    for id in [observed, stated] {
        if vault.get_entity_type_in_txn(txn, id)? != Some(ENTITY_TYPE_CLAIM) {
            return Ok(false);
        }
    }
    let (Some(observed), Some(stated)) = (
        vault.get_claim_in_txn(txn, observed)?,
        vault.get_claim_in_txn(txn, stated)?,
    ) else {
        return Ok(false);
    };
    if stated.source != Some(ClaimSource::UserStated)
        || !crate::claim::is_observed_preference(observed.source, &observed.predicate)
        || predicate != observed.predicate
        || stated.predicate != observed.predicate
        || stated.subject != observed.subject
    {
        return Ok(false);
    }
    let now = vault.store.clock.now_recorded_at();
    let stands = |body: &ClaimBody| {
        body.lifecycle == ClaimLifecycleStatus::Active
            && body.approval != ClaimApprovalStatus::Rejected
            && !body.valid_to.is_some_and(|end| end <= now)
    };
    Ok(!stands(&observed) || !stands(&stated))
}
