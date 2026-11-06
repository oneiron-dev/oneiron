//! Owned app-reported JSON inside AG-UI file observations.

use oneiron::ingest::AgUiFileRead;

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_ag_ui_file_read(
    verb: &str,
    mut read: AgUiFileRead,
) -> Result<crate::AgUiFileRead, OneironError> {
    let outcomes: Vec<_> = read
        .source
        .iter_mut()
        .flat_map(|source| source.observations.iter_mut())
        .map(|observation| {
            observation
                .outcome
                .take()
                .filter(|value| !value.is_null())
                .map(WireJson::lift)
                .transpose()
        })
        .collect();
    // Consume every observation before returning the first conversion error.
    let outcomes: Vec<_> = outcomes.into_iter().collect::<Result<_, _>>()?;
    let mut output: crate::AgUiFileRead = lift_record(verb, &read)?;
    for (observation, outcome) in output
        .source
        .iter_mut()
        .flat_map(|source| source.observations.iter_mut())
        .zip(outcomes)
    {
        observation.outcome = outcome;
    }
    Ok(output)
}
