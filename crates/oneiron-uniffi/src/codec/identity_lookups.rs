//! Owned identity-lookup output leaves.

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_identity_lookup(
    verb: &str,
    mut lookup: oneiron::memory::identity_doors::IdentityLookup,
) -> Result<crate::IdentityLookup, OneironError> {
    let evidence: Vec<_> = lookup
        .candidates
        .iter_mut()
        .flat_map(|candidate| &mut candidate.mention_evidence)
        .map(|entry| {
            entry
                .evidence
                .take()
                .filter(|value| !value.is_null())
                .map(WireJson::lift)
                .transpose()
        })
        .collect();
    // Consume every opaque leaf before propagating the first conversion error.
    let evidence = evidence.into_iter().collect::<Result<Vec<_>, _>>()?;
    let mut output: crate::IdentityLookup = lift_record(verb, &lookup)?;
    for (entry, evidence) in output
        .candidates
        .iter_mut()
        .flat_map(|candidate| &mut candidate.mention_evidence)
        .zip(evidence)
    {
        entry.evidence = evidence;
    }
    Ok(output)
}
