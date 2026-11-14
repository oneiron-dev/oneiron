//! What an audience edit's erase came to (FIX 6337): its writer re-proves
//! the erase, and a re-proof that names no one cancels it before anything is
//! written (`workspace_roster::rooms::audience_erase`).

use super::DeleteEntityOutcome;

/// What an audience edit's erase came to (FIX 6337).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfirmedEraseOutcome {
    /// The erase ran as its rail runs it.
    Completed(DeleteEntityOutcome),
    /// Its re-proof named no one when its writer ran, before anything was
    /// written.
    Cancelled,
}
