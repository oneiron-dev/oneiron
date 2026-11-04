//! The exact refusal of a turn whose witnessed message is not resident.

use crate::error::Error;

/// The refusal a TURN's text read gives while a MESSAGE its saved tags were
/// read from is away from this replica (a window demoted back to thin,
/// OF-534). It is a wait, not a fault: a prepared attempt takes it as
/// `AttemptPreparation::ResidencyDeferred`.
pub(crate) const MESSAGES_NOT_RESIDENT: &str = "witnessed turn message is not resident here";

/// Whether a text refusal is [`MESSAGES_NOT_RESIDENT`]'s wait.
pub(crate) fn residency_deferred(reason: &str) -> bool {
    reason == MESSAGES_NOT_RESIDENT
}

/// Whether `error` is that wait, the turn-text reader's exact
/// not-resident refusal, and nothing else.
pub(crate) fn waits_on_residency(error: &Error) -> bool {
    matches!(error, Error::InvalidClaimBody(reason) if residency_deferred(reason))
}
