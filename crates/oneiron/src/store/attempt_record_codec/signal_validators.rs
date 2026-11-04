//! The persisted-row validation of an attempt row's branch signals and
//! asks: each field's shape, signal-key and ask-handle uniqueness, the
//! questions and their recipients, and each answer against its ask. The
//! attempt queue's signal door (`attempt_queue::run_signal`) admits and
//! settles the rows.
use crate::error::{Error, Result};
use crate::store::attempt_record::AttemptRecord;
use crate::store::attempt_run_signal::{RunAskQuestion, RunSignalKind};

use super::field_validators::{validate_cancel_actor, validate_optional_failure_reason};

/// A Signal field of any length is kept whole (ABC): only an empty field or
/// one with a control character is refused.
pub(crate) fn field(value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig("invalid run Signal field".into()));
    }
    Ok(())
}

pub(crate) fn validate_questions(questions: &[RunAskQuestion]) -> Result<()> {
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

/// Corrupted persisted intent data fails at the read door, not just admission.
pub(crate) fn validate_signal_rows(record: &AttemptRecord) -> Result<()> {
    let mut keys = std::collections::HashSet::new();
    for signal in &record.signals {
        field(&signal.key)?;
        field(&signal.actor)?;
        if !keys.insert(&signal.key) {
            return Err(Error::InvalidConfig("duplicate Signal key".into()));
        }
        match &signal.kind {
            RunSignalKind::Steer { instruction } => field(instruction)?,
            RunSignalKind::Interject { content } => field(content)?,
            RunSignalKind::Cancel { standing, reason } => {
                if !standing.may_request() {
                    return Err(Error::InvalidConfig(
                        "invalid Signal cancel standing".into(),
                    ));
                }
                if let Some(reason) = reason {
                    field(reason)?;
                }
                validate_signal_cancel(&signal.actor, reason.as_deref())?;
            }
            RunSignalKind::AskAnswer {
                handle,
                who,
                answer,
                kind,
            } => {
                field(handle)?;
                field(who)?;
                field(answer)?;
                if !record.asks.iter().any(|ask| {
                    ask.handle == *handle
                        && ask
                            .answers
                            .iter()
                            .any(|a| a.who == *who && a.answer == *answer && a.kind == *kind)
                }) {
                    return Err(Error::InvalidConfig("orphan Signal ask answer".into()));
                }
            }
        }
    }
    let mut handles = std::collections::HashSet::new();
    for ask in &record.asks {
        field(&ask.handle)?;
        if !handles.insert(&ask.handle) {
            return Err(Error::InvalidConfig("duplicate ask handle".into()));
        }
        validate_questions(&ask.questions)?;
        if ask.answers.len() > ask.questions.len() {
            return Err(Error::InvalidConfig("invalid ask answer count".into()));
        }
        let recipients: std::collections::HashSet<_> =
            ask.questions.iter().map(|q| &q.who).collect();
        let mut answered = std::collections::HashSet::new();
        for answer in &ask.answers {
            field(&answer.who)?;
            field(&answer.answer)?;
            if !recipients.contains(&answer.who) || !answered.insert(&answer.who) {
                return Err(Error::InvalidConfig("invalid ask answer recipient".into()));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_signal_cancel(actor: &str, reason: Option<&str>) -> crate::Result<()> {
    validate_cancel_actor(actor)?;
    validate_optional_failure_reason(reason)
}
