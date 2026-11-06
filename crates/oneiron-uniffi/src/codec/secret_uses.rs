//! Owned operation JSON in secret-use output records.

use oneiron::task_verb::sdk::SecretUseAnswer;

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_secret_use_answer(
    verb: &str,
    mut answer: SecretUseAnswer,
) -> Result<crate::SecretUseAnswer, OneironError> {
    let result = answer
        .result
        .take()
        .filter(|value| !value.is_null())
        .map(WireJson::lift)
        .transpose()?;
    let mut output: crate::SecretUseAnswer = lift_record(verb, &answer)?;
    output.result = result;
    Ok(output)
}
