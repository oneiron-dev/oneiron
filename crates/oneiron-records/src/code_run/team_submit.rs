//! Moved from `crates/oneiron/src/code_run/team_submit.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::code_run::team_submit::TeamSubmitInput;
use serde::Deserialize;
use serde::Serialize;

/// What `self.team.submit` answered: the review the owner answers. Submitted
/// is not accepted; the owner's answer settles the team.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamSubmitAnswer {
    pub team: String,
    /// The output under review, as the host pinned it.
    pub output_revision: String,
    /// The review claim the owner answers, hex.
    pub review_claim: String,
    /// The leader had already submitted this output: the review stands as
    /// it was first written, unchanged.
    pub already_submitted: bool,
}
