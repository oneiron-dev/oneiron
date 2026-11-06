//! Owned replay-configuration JSON in retrieval evidence outputs.

use oneiron::task_verb::sdk::{RetrievalDiagnosticExport, RetrievalRunEvidence};

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_retrieval_run_evidences(
    verb: &str,
    mut runs: Vec<RetrievalRunEvidence>,
) -> Result<Vec<crate::RetrievalRunEvidence>, OneironError> {
    let configs = take_configs(runs.iter_mut())?;
    let mut output: Vec<crate::RetrievalRunEvidence> = lift_record(verb, &runs)?;
    put_configs(output.iter_mut(), configs);
    Ok(output)
}

pub(crate) fn lift_retrieval_run_evidence_opt(
    verb: &str,
    mut run: Option<RetrievalRunEvidence>,
) -> Result<Option<crate::RetrievalRunEvidence>, OneironError> {
    let configs = take_configs(run.iter_mut())?;
    let mut output: Option<crate::RetrievalRunEvidence> = lift_record(verb, &run)?;
    put_configs(output.iter_mut(), configs);
    Ok(output)
}

pub(crate) fn lift_retrieval_diagnostic_export(
    verb: &str,
    mut export: RetrievalDiagnosticExport,
) -> Result<crate::RetrievalDiagnosticExport, OneironError> {
    let configs = take_configs(export.runs.iter_mut())?;
    let mut output: crate::RetrievalDiagnosticExport = lift_record(verb, &export)?;
    put_configs(output.runs.iter_mut(), configs);
    Ok(output)
}

fn take_configs<'a>(
    runs: impl Iterator<Item = &'a mut RetrievalRunEvidence>,
) -> Result<Vec<WireJson>, OneironError> {
    let configs: Vec<_> = runs
        .filter_map(|evidence| evidence.run.replay_inputs.as_mut())
        .map(|input| WireJson::lift(std::mem::take(&mut input.config)))
        .collect();
    // Consume every run's required JSON before returning any conversion error.
    configs.into_iter().collect()
}

fn put_configs<'a>(
    runs: impl Iterator<Item = &'a mut crate::RetrievalRunEvidence>,
    configs: Vec<WireJson>,
) {
    for (input, config) in runs
        .filter_map(|evidence| evidence.run.replay_inputs.as_mut())
        .zip(configs)
    {
        input.config = config;
    }
}
