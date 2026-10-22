//! Construction of typed calls from registered action arguments.
//! Entry: `build_sdk_verb`.
//! Action values belong to `code_run::actions`; call values belong to `code_run::types`.

use super::*;

pub(super) fn build_sdk_verb(verb: AgentVerb, args: &[ActionArgument]) -> Result<SelfCall> {
    let input = match args {
        [ActionArgument::Text(input)] => serde_json::from_str(input.as_str())
            .map_err(|_| invalid("verb-table action input is not JSON"))?,
        [ActionArgument::Json(input)] => input.value().clone(),
        _ => {
            return Err(invalid(
                "verb-table action takes its JSON input as one text or JSON",
            ));
        }
    };
    Ok(SelfCall::AgentVerb(SelfAgentVerbCall { verb, input }))
}
/// A run row's typed call, its defaults on the action's frozen clock in unix
/// seconds, as a code run's own clock is.
pub(super) fn build_run_verb(
    verb: RunVerb,
    args: &[ActionArgument],
    frozen_unix_ms: u64,
) -> Result<SelfCall> {
    let input = match args {
        [ActionArgument::Text(input)] => serde_json::from_str(input.as_str())
            .map_err(|_| invalid("run-row action input is not JSON"))?,
        [ActionArgument::Json(input)] => input.value().clone(),
        _ => {
            return Err(invalid(
                "run-row action takes its JSON input as one text or JSON",
            ));
        }
    };
    super::run_verb_call::run_verb_call(verb, input, frozen_unix_ms / 1000)
}
pub(super) fn build_inference_defaults_read(
    _: ActionBuildContext,
    args: &[ActionArgument],
) -> Result<SelfCall> {
    if !args.is_empty() {
        return Err(invalid("inference defaults read takes no arguments"));
    }
    Ok(SelfCall::InferenceDefaultsRead)
}
pub(super) fn build_inference_defaults_replace(
    _: ActionBuildContext,
    args: &[ActionArgument],
) -> Result<SelfCall> {
    let [ActionArgument::Text(value)] = args else {
        return Err(invalid("inference defaults replace requires JSON text"));
    };
    crate::llm::PurposeDefaultTable::from_json(value.as_str().as_bytes())?;
    Ok(SelfCall::InferenceDefaultsReplace(
        value.as_str().to_owned(),
    ))
}
pub(super) fn build_wake_policy_action(
    _ctx: ActionBuildContext,
    args: &[ActionArgument],
) -> Result<SelfCall> {
    let [ActionArgument::Text(value)] = args else {
        return Err(invalid("wake policy action needs one row"));
    };
    let policy: crate::dreamer_wake::DreamerWakePolicy = serde_json::from_str(value.as_str())
        .map_err(|_| invalid("wake policy action row does not decode"))?;
    Ok(SelfCall::WakePolicyWrite(
        crate::code_run::SelfWakePolicyWriteCall::new(policy.validate()?),
    ))
}
