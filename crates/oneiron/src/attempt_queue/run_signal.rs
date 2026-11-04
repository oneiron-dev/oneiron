//! Durable branch signal and ask vocabulary with persisted-row validation.

use crate::attempt_queue::AttemptId;
use crate::error::{Error, Result};
pub(crate) use crate::store::attempt_run_signal::SignalIntent;
pub use crate::store::attempt_run_signal::{
    RunAsk, RunAskAnswer, RunAskAnswerKind, RunAskQuestion, RunBranchSignal, RunSignalKind,
    RunSignalState,
};

/// Caller-authenticated control intent; the adapter must resolve the actor and
/// cancel standing before calling this storage door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSignalInput {
    pub branch: AttemptId,
    pub run_id: String,
    pub key: String,
    pub actor: String,
    pub kind: RunSignalKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunAskState {
    Pending(RunAsk),
    Ready(RunAsk),
}

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
pub(crate) fn validate_signal_rows(record: &crate::attempt_queue::AttemptRecord) -> Result<()> {
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
                crate::attempt_queue::validate_signal_cancel(&signal.actor, reason.as_deref())?;
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
