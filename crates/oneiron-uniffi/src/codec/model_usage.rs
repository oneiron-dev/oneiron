//! Owned provider JSON in image receipts and model-trial output bounds.

use oneiron::llm::{
    catalog_doors::{ModelBindingProposal, ModelTrialView},
    model_trials::ModelTrialRequest,
};

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_ask_image(
    verb: &str,
    mut answer: oneiron::task_verb::sdk::AskImageAnswer,
) -> Result<crate::AskImageAnswer, OneironError> {
    let provider = answer
        .receipt
        .usage
        .as_mut()
        .map(|usage| WireJson::lift(std::mem::take(&mut usage.raw_provider)))
        .transpose()?;
    let mut output: crate::AskImageAnswer = lift_record(verb, &answer)?;
    if let Some((usage, provider)) = output.receipt.usage.as_mut().zip(provider) {
        usage.raw_provider = provider;
    }
    Ok(output)
}

pub(crate) fn lift_model_trial(
    verb: &str,
    mut trial: ModelTrialView,
) -> Result<crate::ModelTrialView, OneironError> {
    let (incumbent, candidate) = take_trial_usage(&mut trial.request)?;
    let mut output: crate::ModelTrialView = lift_record(verb, &trial)?;
    output.request.incumbent_usage_bound.raw_provider = incumbent;
    output.request.candidate_usage_bound.raw_provider = candidate;
    Ok(output)
}

pub(crate) fn lift_model_binding_proposal(
    verb: &str,
    mut proposal: ModelBindingProposal,
) -> Result<crate::ModelBindingProposal, OneironError> {
    let (incumbent, candidate) = take_trial_usage(&mut proposal.trial.request)?;
    let mut output: crate::ModelBindingProposal = lift_record(verb, &proposal)?;
    output.trial.request.incumbent_usage_bound.raw_provider = incumbent;
    output.trial.request.candidate_usage_bound.raw_provider = candidate;
    Ok(output)
}

fn take_trial_usage(request: &mut ModelTrialRequest) -> Result<(WireJson, WireJson), OneironError> {
    let incumbent = WireJson::lift(std::mem::take(
        &mut request.incumbent_usage_bound.raw_provider,
    ));
    let candidate = WireJson::lift(std::mem::take(
        &mut request.candidate_usage_bound.raw_provider,
    ));
    // Both owned values are drained before either error can return.
    Ok((incumbent?, candidate?))
}
