//! Deterministic single-value resolution over an explicitly admitted prior.
use super::conflict::{ConflictSet, PriorHead};
use super::provenance::PromotionCandidate;
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
