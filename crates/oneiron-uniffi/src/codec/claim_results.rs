//! Owned claim JSON inside scoped, settlement and extraction results.

use oneiron::claim::ScopedReadResult;
use oneiron::memory::{ClaimSettlement, ClaimView, SignalExtractionResult};

use super::{OneironError, WireJson, lift_record};

type ClaimLeaves = (WireJson, Option<WireJson>);

pub(crate) fn lift_scoped_claim(
    verb: &str,
    mut read: ScopedReadResult<Option<ClaimView>>,
) -> Result<crate::ScopedReadResultOptionalClaimView, OneironError> {
    let leaves = take_claims(read.value.iter_mut())?;
    let mut output: crate::ScopedReadResultOptionalClaimView = lift_record(verb, &read)?;
    put_claims(output.value.iter_mut(), leaves);
    Ok(output)
}

pub(crate) fn lift_claim_settlement(
    verb: &str,
    mut settlement: ClaimSettlement,
) -> Result<crate::ClaimSettlement, OneironError> {
    let leaves = take_claims(std::iter::once(&mut settlement.claim))?;
    let mut output: crate::ClaimSettlement = lift_record(verb, &settlement)?;
    put_claims(std::iter::once(&mut output.claim), leaves);
    Ok(output)
}

pub(crate) fn lift_signal_extraction_result(
    verb: &str,
    mut result: Option<SignalExtractionResult>,
) -> Result<Option<crate::SignalExtractionResult>, OneironError> {
    let leaves = take_claims(
        result
            .iter_mut()
            .flat_map(|result| result.claims.iter_mut().map(|entry| &mut entry.claim)),
    )?;
    let mut output: Option<crate::SignalExtractionResult> = lift_record(verb, &result)?;
    put_claims(
        output
            .iter_mut()
            .flat_map(|result| result.claims.iter_mut().map(|entry| &mut entry.claim)),
        leaves,
    );
    Ok(output)
}

fn take_claims<'a>(
    claims: impl Iterator<Item = &'a mut ClaimView>,
) -> Result<Vec<ClaimLeaves>, OneironError> {
    let leaves: Vec<_> = claims
        .map(|claim| super::claims::lift_json(std::mem::take(&mut claim.value), claim.scope.take()))
        .collect();
    // Consume every claim's two JSON leaves before returning the first error.
    leaves.into_iter().collect()
}

fn put_claims<'a>(
    claims: impl Iterator<Item = &'a mut crate::WireClaimView>,
    leaves: Vec<ClaimLeaves>,
) {
    for (claim, (value, scope)) in claims.zip(leaves) {
        claim.value = value;
        claim.scope = scope;
    }
}
