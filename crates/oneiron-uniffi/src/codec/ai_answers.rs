//! Owned provider-usage JSON conversion for AI answer outputs (FIX 12936).

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_ai_answer(
    verb: &str,
    mut answer: oneiron::task_verb::sdk::AiAnswer,
) -> Result<crate::AiAnswer, OneironError> {
    let raw_provider = match std::mem::take(&mut answer.usage.raw_provider) {
        serde_json::Value::Null => None,
        value => Some(WireJson::lift(value)?),
    };
    let mut output: crate::AiAnswer = lift_record(verb, &answer)?;
    output.usage.raw_provider = raw_provider;
    Ok(output)
}
