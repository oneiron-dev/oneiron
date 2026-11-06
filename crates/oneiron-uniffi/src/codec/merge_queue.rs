//! Owned schema differences in merge queue observation results.

use oneiron::contract_oracle::ContractDiff;
use oneiron::memory::merge_queue_doors::MergeQueueObservation;

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_merge_queue_observation(
    verb: &str,
    mut observation: MergeQueueObservation,
) -> Result<crate::MergeQueueObservation, OneironError> {
    let schemas: Vec<_> = observation
        .verdicts
        .iter_mut()
        .flat_map(|verdict| verdict.diffs.iter_mut())
        .filter_map(|diff| match diff {
            ContractDiff::SchemaDrift { before, after, .. } => Some((
                before
                    .take()
                    .filter(|value| !value.is_null())
                    .map(WireJson::lift)
                    .transpose(),
                after
                    .take()
                    .filter(|value| !value.is_null())
                    .map(WireJson::lift)
                    .transpose(),
            )),
            _ => None,
        })
        .collect();
    // Consume both sides of every schema diff before returning the first error.
    let schemas: Vec<_> = schemas
        .into_iter()
        .map(|(before, after)| Ok((before?, after?)))
        .collect::<Result<_, OneironError>>()?;
    let mut output: crate::MergeQueueObservation = lift_record(verb, &observation)?;
    let schema_diffs = output
        .verdicts
        .iter_mut()
        .flat_map(|verdict| verdict.diffs.iter_mut())
        .filter_map(|diff| match diff {
            crate::ContractDiff::SchemaDrift { before, after, .. } => Some((before, after)),
            _ => None,
        });
    for ((before, after), (lifted_before, lifted_after)) in schema_diffs.zip(schemas) {
        *before = lifted_before;
        *after = lifted_after;
    }
    Ok(output)
}
