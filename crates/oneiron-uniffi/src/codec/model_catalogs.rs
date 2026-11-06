//! Owned model metadata in catalog result records.

use std::collections::HashMap;

use oneiron::llm::catalog_doors::{ModelCatalogDiff, ModelCatalogRevision};
use oneiron::llm::registry::ModelRegistryRow;

use super::{Lift, OneironError, WireJson, lift_record};

fn lift_metadata<'a>(
    rows: impl Iterator<Item = &'a mut ModelRegistryRow>,
) -> Result<Vec<Option<HashMap<String, WireJson>>>, OneironError> {
    let metadata: Vec<_> = rows
        .map(|row| {
            std::mem::take(&mut row.catalog.metadata)
                .into_iter()
                .map(|(key, value)| (key, WireJson::lift(value)))
                .collect::<Vec<_>>()
        })
        .collect();
    // Consume every metadata value before returning the first error.
    metadata
        .into_iter()
        .map(|entries| {
            entries
                .into_iter()
                .map(|(key, value)| value.map(|value| (key, value)))
                .collect::<Result<HashMap<_, _>, _>>()
                .map(|entries| (!entries.is_empty()).then_some(entries))
        })
        .collect()
}

pub(crate) fn lift_model_catalog_revision(
    verb: &str,
    mut revision: ModelCatalogRevision,
) -> Result<crate::ModelCatalogRevision, OneironError> {
    let metadata = lift_metadata(
        revision
            .catalog
            .rows
            .iter_mut()
            .chain(revision.rows.iter_mut()),
    )?;
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

pub(crate) fn lift_model_catalog_diff(
    verb: &str,
    mut diff: ModelCatalogDiff,
) -> Result<crate::ModelCatalogDiff, OneironError> {
    let metadata = lift_metadata(
        diff.changes
            .iter_mut()
            .flat_map(|change| change.previous.iter_mut().chain(change.current.iter_mut())),
    )?;
    let mut output: crate::ModelCatalogDiff = lift_record(verb, &diff)?;
    for (row, metadata) in output
        .changes
        .iter_mut()
        .flat_map(|change| change.previous.iter_mut().chain(change.current.iter_mut()))
        .zip(metadata)
    {
        row.catalog.metadata = metadata;
    }
    Ok(output)
}
