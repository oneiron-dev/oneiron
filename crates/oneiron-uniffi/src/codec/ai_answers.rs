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

pub(crate) fn lift_ai_video_job(
    verb: &str,
    job: oneiron::task_verb::sdk::AiVideoJob,
) -> Result<crate::AiVideoJob, OneironError> {
    match job {
        oneiron::task_verb::sdk::AiVideoJob::Done { answer } => Ok(crate::AiVideoJob::Done {
            answer: lift_ai_answer(verb, answer)?,
        }),
        other => lift_record(verb, &other),
    }
}
