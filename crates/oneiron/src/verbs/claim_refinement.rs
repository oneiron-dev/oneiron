//! The owner's claim-refinement doors (FIX [SKILL-HUB-PROMOTION-VERBS]): the
//! held-out reserve of a claim base and the offer of one session-branch edit.
//! The merge stays the owner's approve route (`/v1/owner/claims/refinements`),
//! which asks the useful-upstream question and replays the held-out split.
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
use crate::consent::AuthenticatedOwner;
use crate::error::Error;
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError, MemoryResult};
use crate::{TimeRange, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::claim_refinement::{
    ClaimRefinementHoldoutRequest, ClaimRefinementHoldoutReserved, ClaimRefinementOfferRequest,
    ClaimRefinementOffered, ClaimRefinementSource,
};

/// The owner reserves the held-out split of one active claim base. The
/// engine refuses a label that is not an independent owner-adjudicated claim
/// on the base's subject.
pub fn claim_refinement_holdout_reserve_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ClaimRefinementHoldoutRequest,
) -> MemoryResult<ClaimRefinementHoldoutReserved> {
    vault.reserve_claim_refinement_holdout(owner, input.base, &input.labels)?;
    let mut labels = input.labels.clone();
    labels.sort_unstable();
    Ok(ClaimRefinementHoldoutReserved {
        base: input.base,
        labels,
    })
}

/// The owner stages one edit of an active claim on a resident agent's
/// session branch. The edit is built on the base's target (predicate,
/// subject, world, relationships, scope), so only its value, confidence,
/// source and evidence are the caller's; it stays a proposed branch claim
/// until the owner's merge door rules on it.
pub fn claim_refinement_offer_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ClaimRefinementOfferRequest,
) -> MemoryResult<ClaimRefinementOffered> {
    owner.revalidate(vault)?;
    let base = vault.get_claim(&input.base)?.ok_or(Error::EntityNotFound)?;
    let proposal = branch_proposal(&base, input)?;
    let candidate = vault.submit_local_claim_refinement(
        input.base,
        input.resident,
        &input.session_tag,
        &proposal,
        TimeRange {
            start: input.occurred.start,
            end: input.occurred.end,
        },
        input.learned_at,
    )?;
    Ok(ClaimRefinementOffered {
        candidate,
        base: input.base,
        resident: input.resident,
        session_tag: input.session_tag.clone(),
    })
}

fn branch_proposal(
    base: &ClaimBody,
    input: &ClaimRefinementOfferRequest,
) -> MemoryResult<ClaimBody> {
    if !input.confidence.is_finite() || !(0.0..=1.0).contains(&input.confidence) {
        return Err(MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            "a claim refinement's confidence is a number in [0, 1]",
            &[],
        ));
    }
    let mut proposal = ClaimBody::new(
        base.predicate.clone(),
        base.subject,
        crate::ingest::json_to_msgpack_value(&input.value),
        input.confidence as f32,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )?;
    proposal.world = base.world;
    proposal.rel = base.rel.clone();
    proposal.scope = base.scope.clone();
    proposal.scope_facet = base.scope_facet;
    proposal.scope_project = base.scope_project;
    proposal.source = Some(match input.source {
        ClaimRefinementSource::Inferred => ClaimSource::Inferred,
        ClaimRefinementSource::Generated => ClaimSource::Generated,
    });
    proposal.session_tag = Some(input.session_tag.clone());
    proposal.evidence = input
        .evidence
        .as_ref()
        .map(crate::ingest::json_to_msgpack_value);
    Ok(proposal)
}
