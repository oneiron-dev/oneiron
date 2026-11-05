//! The persisted-row validation of an attempt row's branch signals and
//! asks: each field's shape, signal-key and ask-handle uniqueness, the
//! questions and their recipients, and each answer against its ask. The
//! attempt queue's signal door (`attempt_queue::run_signal`) admits and
//! settles the rows.
use crate::attempt_run_signal::RunAskQuestion;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::attempt_record_codec::field_validators::validate_optional_failure_reason;

/// A Signal field of any length is kept whole (ABC): only an empty field or
/// one with a control character is refused.
pub fn field(value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig("invalid run Signal field".into()));
    }
    Ok(())
}

pub fn validate_questions(questions: &[RunAskQuestion]) -> Result<()> {
    if questions.is_empty() {
        return Err(Error::InvalidConfig("invalid ask questions".into()));
    }
    let mut recipients = std::collections::HashSet::new();
    for question in questions {
        field(&question.who)?;
        field(&question.prompt)?;
        if !recipients.insert(&question.who) {
            return Err(Error::InvalidConfig("invalid ask question".into()));
        }
        for option in &question.options {
            field(option)?;
        }
    }
    Ok(())
}
