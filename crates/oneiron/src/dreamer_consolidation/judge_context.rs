//! Deterministic single-value resolution over an explicitly admitted prior.
use std::collections::BTreeMap;

use super::conflict::{ConflictSet, PriorHead};
use super::provenance::PromotionCandidate;
use crate::{ClaimSubject, EntityId};
use crate::claim::claim_source_widens_beyond;

pub(super) fn fast_path(
    policy: &crate::gate::PolicyManifestResolution,
    conflict: &ConflictSet,
    members: &[&PromotionCandidate],
    prior: Option<&PriorHead>,
) -> bool {
    members.len() == 1
        && policy.is_single_valued_predicate(&conflict.identity.predicate)
        && prior.is_some_and(|prior| {
            !claim_source_widens_beyond(
                prior
                    .body
                    .source
                    .unwrap_or(crate::claim::ClaimSource::UserStated),
                members[0].evidence_meet,
            )
        })
}

/// A lone candidate the extractor bound to the head it corrects replaces that
/// head with no verdict call: the binding is the extractor's own replace
/// decision (ARCH-0040, merge-vs-replace). `corrections` holds only bindings
/// to a head the listing showed and no other candidate in the pass stands on
/// (assembly drops the rest). The head must be the conflict's only one, read
/// with the conflict's subject and predicate. The source check still applies,
/// and the grant door judges the replacement after.
pub(super) fn bound_correction(
    corrections: &BTreeMap<EntityId, EntityId>,
    conflict: &ConflictSet,
    members: &[&PromotionCandidate],
    prior: Option<&PriorHead>,
) -> bool {
    let ([member], Some(prior)) = (members, prior) else {
        return false;
    };
    corrections.get(&member.claim_id) == Some(&prior.claim_id)
        && conflict.prior_heads == [prior.claim_id]
        && prior.body.subject == ClaimSubject::Entity(conflict.identity.subject)
        && prior.body.predicate == conflict.identity.predicate
        && !claim_source_widens_beyond(
            prior
                .body
                .source
                .unwrap_or(crate::claim::ClaimSource::UserStated),
            member.evidence_meet,
        )
}
