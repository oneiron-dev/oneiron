//! Owned pending HyDE host-work claim outputs.

use super::{Lift, OneironError, lift_record};

pub(crate) fn lift_hyde_host_work(
    verb: &str,
    mut works: Vec<oneiron::query_expansion::host::HydeHostWork>,
) -> Result<Vec<crate::HydeHostWork>, OneironError> {
    let claims: Vec<_> = works
        .iter_mut()
        .filter_map(|work| match &mut work.input {
            oneiron::query_expansion::host::HydeHostInput::Evidence { candidates, .. } => {
                Some(candidates)
            }
            oneiron::query_expansion::host::HydeHostInput::Expansion { .. } => None,
        })
        .flatten()
        .map(|candidate| {
            candidate
                .claim
                .take()
                .map(crate::WireClaimView::lift)
                .transpose()
        })
        .collect();
    // The existing claim lift drains both leaves; visit every claim before returning an error.
    let claims = claims.into_iter().collect::<Result<Vec<_>, _>>()?;
    let mut output: Vec<crate::HydeHostWork> = lift_record(verb, &works)?;
    for (candidate, claim) in output
        .iter_mut()
        .filter_map(|work| match &mut work.input {
            crate::HydeHostInput::Evidence { candidates, .. } => Some(candidates),
            crate::HydeHostInput::Expansion { .. } => None,
        })
        .flatten()
        .zip(claims)
    {
        candidate.claim = claim;
    }
    Ok(output)
}
