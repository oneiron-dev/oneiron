//! Mirrors native no-model rules at the retained conflict identity.

use crate::extraction_observations::{CandidateObservation, Observations, PriorObservation};
use crate::extraction_routing::{Correction, JudgeSet};

use super::Error;

fn anchor<'a>(
    set: &JudgeSet,
    observations: &'a Observations,
) -> Result<&'a CandidateObservation, Error> {
    observations
        .candidates
        .iter()
        .find(|row| row.identity_token == set.identity_token)
        .ok_or_else(|| Error::InvalidObservations("the retained identity has no anchor row".into()))
}

fn member_prior<'a>(
    set: &JudgeSet,
    observations: &'a Observations,
) -> Result<Option<(usize, &'a PriorObservation)>, Error> {
    let ([member], Some(head)) = (set.candidate_indexes.as_slice(), &set.prior_head) else {
        return Ok(None);
    };
    let prior = observations
        .priors
        .iter()
        .find(|prior| &prior.claim == head)
        .ok_or_else(|| Error::InvalidObservations("the set's prior head has no row".into()))?;
    Ok(Some((*member, prior)))
}

/// Checks native's single-valued replacement rule at the retained identity.
///
/// # Errors
///
/// Rejects a missing identity anchor or a named prior head with no served row.
pub fn fast_path(set: &JudgeSet, observations: &Observations) -> Result<bool, Error> {
    let anchor = anchor(set, observations)?;
    let Some((member, prior)) = member_prior(set, observations)? else {
        return Ok(false);
    };
    Ok(anchor.single_valued && prior.non_widening_candidates.contains(&member))
}

/// Checks native's surviving bound-correction rule at the retained identity.
///
/// Member evidence must not widen the prior, while subject and predicate
/// equality is checked against the anchor rather than the surviving member.
///
/// # Errors
///
/// Rejects a missing identity anchor or a named prior head with no served row.
pub fn bound_correction(
    set: &JudgeSet,
    observations: &Observations,
    corrections: &[Correction],
) -> Result<bool, Error> {
    let anchor = anchor(set, observations)?;
    let Some((member, prior)) = member_prior(set, observations)? else {
        return Ok(false);
    };
    Ok(corrections.iter().any(|correction| {
        correction.representative_index == member && correction.head == prior.claim
    }) && set.prior_heads.as_slice() == [prior.claim.clone()]
        && prior
            .subject_predicate_equal_candidates
            .contains(&anchor.index)
        && prior.non_widening_candidates.contains(&member))
}
