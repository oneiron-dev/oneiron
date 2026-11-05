//! Core half of `store::attempt_record_codec::signal_validators`: its store-layer items live in `oneiron_store::attempt_record_codec::signal_validators` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::attempt_record_codec::signal_validators::*;

use super::field_validators::{validate_cancel_actor, validate_optional_failure_reason};
use crate::error::{Error, Result};
use crate::store::attempt_record::AttemptRecord;
use crate::store::attempt_run_signal::{RunAskQuestion, RunSignalKind};

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
