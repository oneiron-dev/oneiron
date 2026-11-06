//! Owned claim JSON in foreign-code result proposals.

use oneiron::memory::foreign_code::{ForeignCodeEffect, ForeignCodeRunResult};

use super::{OneironError, lift_record};

pub(crate) fn lift_foreign_code_result(
    verb: &str,
    mut result: ForeignCodeRunResult,
) -> Result<crate::ForeignCodeRunResult, OneironError> {
    let claims: Vec<_> = result
        .proposals
        .iter_mut()
        .filter_map(|proposal| match &mut proposal.effect {
            ForeignCodeEffect::ClaimCandidate { claim } => Some(super::claims::lift_json(
                std::mem::take(&mut claim.value),
                claim.scope.take(),
            )),
            _ => None,
        })
        .collect();
    // Consume every proposal's JSON before returning the first error.
    let claims: Vec<_> = claims.into_iter().collect::<Result<_, _>>()?;
    let mut output: crate::ForeignCodeRunResult = lift_record(verb, &result)?;
    for (claim, (value, scope)) in output
        .proposals
        .iter_mut()
        .filter_map(|proposal| match &mut proposal.effect {
            crate::ForeignCodeEffect::ClaimCandidate { claim } => Some(claim),
            _ => None,
        })
        .zip(claims)
    {
        claim.value = value;
        claim.scope = scope;
    }
    Ok(output)
}
