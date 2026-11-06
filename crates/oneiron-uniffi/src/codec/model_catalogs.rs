//! Owned model metadata in catalog revision result records.

use oneiron::llm::catalog_doors::ModelCatalogRevision;

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_model_catalog_revision(
    verb: &str,
    mut revision: ModelCatalogRevision,
) -> Result<crate::ModelCatalogRevision, OneironError> {
    let metadata: Vec<_> = revision
        .catalog
        .rows
        .iter_mut()
        .chain(revision.rows.iter_mut())
        .map(|row| {
            std::mem::take(&mut row.catalog.metadata)
                .into_iter()
                .map(|(key, value)| (key, WireJson::lift(value)))
                .collect::<Vec<_>>()
        })
        .collect();
    // Consume every metadata value in both copies before returning the first error.
    let metadata: Vec<_> = metadata
        .into_iter()
        .map(|entries| {
            entries
                .into_iter()
                .map(|(key, value)| value.map(|value| (key, value)))
                .collect::<Result<std::collections::HashMap<_, _>, _>>()
                .map(|entries| (!entries.is_empty()).then_some(entries))
        })
        .collect::<Result<_, _>>()?;
    let mut output: crate::ModelCatalogRevision = lift_record(verb, &revision)?;
    for (row, metadata) in output
        .catalog
        .rows
        .iter_mut()
        .chain(output.rows.iter_mut())
        .zip(metadata)
    {
        row.catalog.metadata = metadata;
    }
    Ok(output)
}
