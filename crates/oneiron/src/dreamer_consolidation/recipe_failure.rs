//! What a failed consolidation recipe step parks as (OF-193a, Engine
//! 10-21). A failure only an owner act clears (an authority, grant, consent
//! or hold the wake driver's owner-act check names) keeps its private park,
//! as before: each pass would only meet it again. So does a failure of the
//! attempt's own input that nothing clears (a stored MESSAGE whose `rel`
//! names no RELATIONSHIP row, FIX MESSAGE-REL-NOT-RELATIONSHIP-ROW): a
//! Retry would resume the same try and meet it on every pass. Any other (a
//! missing locality, an empty or unreadable model answer, a request that
//! did not hash, a failed or concurrent commit, a moved scope) parks as a
//! Retry a later pass resumes, as the same try, after its retry delay.

use crate::Error;
use crate::dreamer_runner::DreamerParkCause;

/// A failed recipe step, by what clears it.
#[derive(Clone, Copy)]
pub(super) enum RecipeFailure {
    /// Only an owner act clears it.
    OwnerAct,
    /// Nothing clears it: the attempt's own input refuses for good.
    Permanent,
    /// A later pass can clear it.
    Transient,
}

impl RecipeFailure {
    /// An engine `error` a recipe step met, by its typed kind; its text is
    /// never read.
    pub(super) fn of_error(error: &Error) -> Self {
        let kind = error.kind();
        if crate::dreamer_wake::waits_on_owner_act(kind) {
            Self::OwnerAct
        } else if matches!(kind, crate::error::ErrorKind::InvalidRelationship) {
            Self::Permanent
        } else {
            Self::Transient
        }
    }

    /// The cause its park takes: the private park no later pass resumes,
    /// for an owner-act wait or a permanent refusal, else a Retry.
    pub(super) const fn park_cause(self) -> DreamerParkCause {
        match self {
            Self::OwnerAct | Self::Permanent => DreamerParkCause::Other,
            Self::Transient => DreamerParkCause::Retry,
        }
    }
}
